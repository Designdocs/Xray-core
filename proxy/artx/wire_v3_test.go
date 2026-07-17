package artx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

const (
	wireV3VectorEnvelope           = "030010000f101112131415161718191a1b1c1d1e1f4a94d7419f1832b401020304030b6578616d706c652e6e657401bbf58a80358d4f712f4afdabbf35a721e63bd5becf1bcb6aad14df19af557a0e78"
	wireV3VectorAuthorization      = "Bearer AwAQAA8QERITFBUWFxgZGhscHR4fSpTXQZ8YMrQBAgMEAwtleGFtcGxlLm5ldAG79YqANY1PcS9K_au_Nach5jvVvs8by2qtFN8Zr1V6Dng"
	wireV3VectorAuthenticationInfo = "rspauth=\"6wsIUpP3Pep2k-fRL8Z5bT90wxRFcIW61aHo_DcbkEU\""
)

func TestWireV3AuthenticationVector(t *testing.T) {
	psk, exporter, salt, destination := wireV3VectorInputs()
	init, err := newWireV3ClientInit(psk, salt, exporter, "example.com:8443", "/", destination, 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := init.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelope); got != wireV3VectorEnvelope {
		t.Fatalf("ClientInit = %s", got)
	}
	if got := formatWireV3Authorization(init); got != wireV3VectorAuthorization {
		t.Fatalf("Authorization = %q", got)
	}

	parsed, candidate, err := parseWireV3Authorization(wireV3VectorAuthorization)
	if err != nil || !candidate {
		t.Fatalf("parse Authorization: candidate=%v err=%v", candidate, err)
	}
	if !parsed.Verify(psk, exporter, "example.com:8443", "/") {
		t.Fatal("valid ClientInit rejected")
	}
	if got := formatWireV3AuthenticationInfo(calculateWireV3ServerProof(psk, exporter, parsed.ClientTag, 200)); got != wireV3VectorAuthenticationInfo {
		t.Fatalf("Authentication-Info = %q", got)
	}
	if !verifyWireV3AuthenticationInfo(wireV3VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 200) {
		t.Fatal("valid server proof rejected")
	}
}

func TestWireV3AuthenticationFailsClosed(t *testing.T) {
	psk, exporter, _, _ := wireV3VectorInputs()
	parsed, candidate, err := parseWireV3Authorization(wireV3VectorAuthorization)
	if err != nil || !candidate {
		t.Fatal(err)
	}
	if parsed.Verify(psk, exporter, "other.example:8443", "/") {
		t.Fatal("authority mutation accepted")
	}
	if parsed.Verify(psk, exporter, "example.com:8443", "/other") {
		t.Fatal("path mutation accepted")
	}
	if verifyWireV3AuthenticationInfo(wireV3VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 201) {
		t.Fatal("status mutation accepted")
	}
	if _, candidate, err := parseWireV3Authorization("Basic abc"); err != nil || candidate {
		t.Fatalf("non-candidate header: candidate=%v err=%v", candidate, err)
	}
	if _, candidate, err := parseWireV3Authorization("Bearer !!!"); err == nil || !candidate {
		t.Fatalf("malformed candidate: candidate=%v err=%v", candidate, err)
	}

	envelope, _ := hex.DecodeString(wireV3VectorEnvelope)
	for _, mutation := range []struct {
		name   string
		offset int
	}{
		{name: "version", offset: 0},
		{name: "flags", offset: 1},
		{name: "salt length", offset: 2},
		{name: "destination length", offset: 4},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := bytes.Clone(envelope)
			mutated[mutation.offset]++
			if _, err := parseWireV3ClientInit(mutated); err == nil {
				t.Fatal("mutated envelope accepted")
			}
		})
	}
	mutated := bytes.Clone(envelope)
	mutated[len(mutated)-1] ^= 1
	mutatedInit, err := parseWireV3ClientInit(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if mutatedInit.Verify(psk, exporter, "example.com:8443", "/") {
		t.Fatal("tag mutation accepted")
	}
}

func TestWireV3HTTP2TunnelEcho(t *testing.T) {
	certPEM, keyPEM := testCertificate(t)
	server, err := NewServer(context.Background(), &ServerConfig{
		Users:          []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings:    &transporttls.Config{Certificate: []*transporttls.Certificate{{Certificate: certPEM, Key: keyPEM}}},
		WireVersion:    3,
		ProfileVersion: 1,
		Fallback:       &FallbackConfig{Enabled: true, Origin: "http://127.0.0.1:60443/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	target, dispatcher := newEchoDispatcher()
	defer target.Close()
	clientRaw, serverRaw := stdnet.Pipe()
	processDone := make(chan error, 1)
	go func() { processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher) }()

	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{http2.NextProtoTLS}, ServerName: "localhost"}) //nolint:gosec -- self-signed test certificate
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(wireV3ExporterLabel, nil, wireV3ExporterLength)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := EncodeTCPDestination(xnet.TCPDestination(xnet.DomainAddress("example.net"), 443))
	if err != nil {
		t.Fatal(err)
	}
	init, err := newWireV3ClientInit([]byte("test-psk"), bytes.Repeat([]byte{7}, wireV3SaltLength), exporter, "localhost", wireV3Path, destination, uint32(time.Now().Unix()/bucketSeconds))
	if err != nil {
		t.Fatal(err)
	}
	requestReader, requestWriter := io.Pipe()
	request, err := http.NewRequest(http.MethodPost, "https://localhost/", requestReader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "localhost"
	request.Header.Set("Authorization", formatWireV3Authorization(init))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "")
	clientConnection, err := new(http2.Transport).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := clientConnection.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !verifyWireV3AuthenticationInfo(response.Header.Get("Authentication-Info"), []byte("test-psk"), exporter, init.ClientTag, response.StatusCode) {
		t.Fatalf("wire-v3 response status=%d auth=%q", response.StatusCode, response.Header.Get("Authentication-Info"))
	}
	payload := []byte("wire-v3 echo")
	if _, err := requestWriter.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := requestWriter.Close(); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(response.Body, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q", echo)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = clientConnection.Close()
	_ = client.Close()
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v3 server did not close with its client")
	}
	stats := server.Stats()
	if stats.TotalConnections != 1 || stats.AuthenticationSuccess != 1 || stats.AuthenticationFailure != 0 {
		t.Fatalf("wire-v3 stats = %#v", stats)
	}
}

func TestWireV3HTTP2TunnelClosesOnTargetDownloadEOF(t *testing.T) {
	certPEM, keyPEM := testCertificate(t)
	server, err := NewServer(context.Background(), &ServerConfig{
		Users:          []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings:    &transporttls.Config{Certificate: []*transporttls.Certificate{{Certificate: certPEM, Key: keyPEM}}},
		WireVersion:    3,
		ProfileVersion: 1,
		Fallback:       &FallbackConfig{Enabled: true, Origin: "http://127.0.0.1:60443/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	clientRaw, serverRaw := stdnet.Pipe()
	processDone := make(chan error, 1)
	go func() { processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher) }()

	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{http2.NextProtoTLS}, ServerName: "localhost"}) //nolint:gosec -- self-signed test certificate
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(wireV3ExporterLabel, nil, wireV3ExporterLength)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := EncodeTCPDestination(xnet.TCPDestination(xnet.DomainAddress("example.net"), 443))
	if err != nil {
		t.Fatal(err)
	}
	init, err := newWireV3ClientInit([]byte("test-psk"), bytes.Repeat([]byte{9}, wireV3SaltLength), exporter, "localhost", wireV3Path, destination, uint32(time.Now().Unix()/bucketSeconds))
	if err != nil {
		t.Fatal(err)
	}
	requestReader, requestWriter := io.Pipe()
	defer requestWriter.Close()
	request, err := http.NewRequest(http.MethodPost, "https://localhost/", requestReader)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "localhost"
	request.Header.Set("Authorization", formatWireV3Authorization(init))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "")
	clientConnection, err := new(http2.Transport).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConnection.Close()
	response, err := clientConnection.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !verifyWireV3AuthenticationInfo(response.Header.Get("Authentication-Info"), []byte("test-psk"), exporter, init.ClientTag, response.StatusCode) {
		t.Fatalf("wire-v3 response status=%d auth=%q", response.StatusCode, response.Header.Get("Authentication-Info"))
	}

	downlink := []byte("target-finished-downlink")
	if err := target.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(downlink)}); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(target.Writer); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(downlink))
	if _, err := io.ReadFull(response.Body, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, downlink) {
		t.Fatalf("downlink = %q", received)
	}

	readDone := make(chan error, 1)
	go func() {
		var payload [1]byte
		_, err := response.Body.Read(payload[:])
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("response read after target EOF = %v, want EOF", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("target download EOF did not close the response stream")
	}
	buffers, err := target.Reader.ReadMultiBuffer()
	bufferCount := len(buffers)
	buf.ReleaseMulti(buffers)
	if err == nil || bufferCount != 0 {
		t.Fatalf("target upload after download EOF: buffers=%d err=%v", bufferCount, err)
	}
}

func TestWireV3InvalidAuthUsesDecoyWithoutLeakingAuthorization(t *testing.T) {
	authorizationSeen := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorizationSeen <- request.Header.Get("Authorization")
		_, _ = writer.Write([]byte("decoy"))
	}))
	defer origin.Close()
	certPEM, keyPEM := testCertificate(t)
	server, err := NewServer(context.Background(), &ServerConfig{
		Users:          []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings:    &transporttls.Config{Certificate: []*transporttls.Certificate{{Certificate: certPEM, Key: keyPEM}}},
		WireVersion:    3,
		ProfileVersion: 1,
		Fallback:       &FallbackConfig{Enabled: true, Origin: origin.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := stdnet.Pipe()
	processDone := make(chan error, 1)
	dispatcher := &countingRejectingDispatcher{}
	go func() { processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher) }()
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{http2.NextProtoTLS}, ServerName: "localhost"}) //nolint:gosec -- self-signed test certificate
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(wireV3ExporterLabel, nil, wireV3ExporterLength)
	if err != nil {
		t.Fatal(err)
	}
	destination, _ := EncodeTCPDestination(xnet.TCPDestination(xnet.DomainAddress("example.net"), 443))
	init, err := newWireV3ClientInit([]byte("wrong-psk"), bytes.Repeat([]byte{8}, wireV3SaltLength), exporter, "localhost", wireV3Path, destination, uint32(time.Now().Unix()/bucketSeconds))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://localhost/", bytes.NewReader([]byte("probe")))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "localhost"
	request.Header.Set("Authorization", formatWireV3Authorization(init))
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("User-Agent", "")
	clientConnection, err := new(http2.Transport).NewClientConn(client)
	if err != nil {
		t.Fatal(err)
	}
	response, err := clientConnection.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "decoy" || response.Header.Get("Authentication-Info") != "" {
		t.Fatalf("decoy response status=%d body=%q auth=%q", response.StatusCode, body, response.Header.Get("Authentication-Info"))
	}
	if got := <-authorizationSeen; got != "" {
		t.Fatalf("origin received wire-v3 Authorization: %q", got)
	}
	if dispatcher.Calls() != 0 {
		t.Fatalf("invalid auth dispatched %d target(s)", dispatcher.Calls())
	}
	_ = response.Body.Close()
	_ = clientConnection.Close()
	_ = client.Close()
	<-processDone
	stats := server.Stats()
	if stats.AuthenticationFailure != 1 || stats.AuthenticationSuccess != 0 || stats.FallbackHits != 1 {
		t.Fatalf("invalid-auth stats = %#v", stats)
	}
}

func wireV3VectorInputs() ([]byte, []byte, []byte, []byte) {
	exporter := make([]byte, wireV3ExporterLength)
	for index := range exporter {
		exporter[index] = byte(index)
	}
	salt := make([]byte, wireV3SaltLength)
	for index := range salt {
		salt[index] = byte(0x10 + index)
	}
	destination := append([]byte{0x03, 0x0b}, []byte("example.net")...)
	destination = append(destination, 0x01, 0xbb)
	return []byte("test-psk"), exporter, salt, destination
}
