package artx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
)

const (
	wireV4VectorClientInit         = "0400101112131415161718191a1b1c1d1e1f4a94d7419f1832b4010203049e5af74154d3dd14e66ffd749476f37f42e62a357d1a88a16b41d6f6e0f36044"
	wireV4VectorProxyAuthorization = "Bearer BAAQERITFBUWFxgZGhscHR4fSpTXQZ8YMrQBAgMEnlr3QVTT3RTmb_10lHbzf0LmKjV9Goiha0HW9uDzYEQ"
	wireV4VectorAuthenticationInfo = "rspauth=\"Dis5apxthZBnnww8x6WE1fFBmuF1qZlQmJzInwv2xRY\""
)

func TestWireV4CanonicalVector(t *testing.T) {
	psk, exporter, salt := wireV4VectorInputs()
	init, err := newWireV4ClientInit(psk, salt, exporter, "example.com", "example.net:443", 0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := init.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelope); got != wireV4VectorClientInit {
		t.Fatalf("ClientInit = %s", got)
	}
	if got := formatWireV4ProxyAuthorization(init); got != wireV4VectorProxyAuthorization {
		t.Fatalf("Proxy-Authorization = %q", got)
	}
	parsed, candidate, err := parseWireV4ProxyAuthorization(wireV4VectorProxyAuthorization)
	if err != nil || !candidate {
		t.Fatalf("parse candidate = %v, %v", candidate, err)
	}
	if !parsed.Verify(psk, exporter, "example.com", "example.net:443") {
		t.Fatal("canonical ClientInit did not verify")
	}
	proof := calculateWireV4ServerProof(psk, exporter, parsed.ClientTag, 200)
	if got := formatWireV4ProxyAuthenticationInfo(proof); got != wireV4VectorAuthenticationInfo {
		t.Fatalf("Proxy-Authentication-Info = %q", got)
	}
	if !verifyWireV4ProxyAuthenticationInfo(wireV4VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 200) {
		t.Fatal("canonical ServerProof did not verify")
	}
}

func TestWireV4VectorBindings(t *testing.T) {
	psk, exporter, _ := wireV4VectorInputs()
	parsed, candidate, err := parseWireV4ProxyAuthorization(wireV4VectorProxyAuthorization)
	if err != nil || !candidate {
		t.Fatal(err)
	}
	for name, context := range map[string][2]string{
		"server name": {"other.example", "example.net:443"},
		"target":      {"example.com", "example.net:8443"},
	} {
		t.Run(name, func(t *testing.T) {
			if parsed.Verify(psk, exporter, context[0], context[1]) {
				t.Fatal("changed context verified")
			}
		})
	}
	if verifyWireV4ProxyAuthenticationInfo(wireV4VectorAuthenticationInfo, psk, exporter, parsed.ClientTag, 502) {
		t.Fatal("proof verified for changed status")
	}
}

func TestWireV4RejectsIPServerName(t *testing.T) {
	psk, exporter, salt := wireV4VectorInputs()
	if _, err := newWireV4ClientInit(psk, salt, exporter, "127.0.0.1", "example.net:443", 1); err == nil {
		t.Fatal("accepted IP literal as wire-v4 server name")
	}
}

func TestWireV4CanonicalAuthority(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		want      xnet.Destination
		valid     bool
	}{
		{name: "domain", authority: "example.net:443", want: xnet.TCPDestination(xnet.DomainAddress("example.net"), 443), valid: true},
		{name: "IPv4", authority: "192.0.2.1:80", want: xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 80), valid: true},
		{name: "IPv6", authority: "[2001:db8::1]:8443", want: xnet.TCPDestination(xnet.ParseAddress("2001:db8::1"), 8443), valid: true},
		{name: "upper case", authority: "Example.net:443"},
		{name: "leading zero port", authority: "example.net:0443"},
		{name: "path", authority: "example.net:443/path"},
		{name: "userinfo", authority: "user@example.net:443"},
		{name: "unbracketed IPv6", authority: "2001:db8::1:443"},
		{name: "empty port", authority: "example.net:"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseWireV4Authority(test.authority)
			if !test.valid {
				if err == nil {
					t.Fatalf("accepted %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("destination = %#v, want %#v", got, test.want)
			}
			canonical, err := formatWireV4Authority(got)
			if err != nil || canonical != test.authority {
				t.Fatalf("round trip = %q, %v", canonical, err)
			}
		})
	}
}

func TestWireV4HTTP1TunnelPreservesUploadHalfClose(t *testing.T) {
	server := newWireV4TestServer(t)
	target, dispatcher := newEchoDispatcher()
	defer target.Close()
	client, reader, init, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{7}, wireV4SaltLength), "test-psk")
	defer client.Close()

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusOK || !verifyWireV4ProxyAuthenticationInfo(response.Header.Get("Proxy-Authentication-Info"), []byte("test-psk"), init.exporter, init.clientInit.ClientTag, response.StatusCode) {
		t.Fatalf("wire-v4 response status=%d proof=%q", response.StatusCode, response.Header.Get("Proxy-Authentication-Info"))
	}
	payload := []byte("wire-v4 echo")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo = %q", echo)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after target response = %v, want EOF", err)
	}
	waitWireV4Process(t, processDone)
}

func TestWireV4TargetDownloadHalfCloseKeepsUploadOpen(t *testing.T) {
	server := newWireV4TestServer(t)
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, reader, init, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{9}, wireV4SaltLength), "test-psk")
	defer client.Close()

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusOK || !verifyWireV4ProxyAuthenticationInfo(response.Header.Get("Proxy-Authentication-Info"), []byte("test-psk"), init.exporter, init.clientInit.ClientTag, response.StatusCode) {
		t.Fatal("wire-v4 response proof rejected")
	}
	downlink := []byte("target-eof")
	if err := target.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(downlink)}); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(target.Writer); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(downlink))
	if _, err := io.ReadFull(reader, received); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("target half-close = %v, want EOF", err)
	}
	if _, err := client.Write([]byte("late-upload")); err != nil {
		t.Fatalf("upload after target EOF: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buffers, err := target.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	upload := make([]byte, buffers.Len())
	buffers.Copy(upload)
	buf.ReleaseMulti(buffers)
	if got := string(upload); got != "late-upload" {
		t.Fatalf("late upload = %q", got)
	}
	if _, err := target.Reader.ReadMultiBuffer(); err == nil {
		t.Fatal("target upload remained open after client CloseWrite")
	}
	waitWireV4Process(t, processDone)
}

func TestWireV4InvalidAuthUsesFallbackWithoutTargetDispatchOrCredentialLeak(t *testing.T) {
	originRequest := make(chan *http.Request, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		originRequest <- request.Clone(request.Context())
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer origin.Close()
	server := newWireV4TestServerWithFallback(t, origin.URL)
	dispatcher := &countingRejectingDispatcher{}
	client, reader, _, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{11}, wireV4SaltLength), "wrong-psk")
	defer client.Close()

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusMethodNotAllowed || response.Header.Get("Proxy-Authentication-Info") != "" {
		t.Fatalf("fallback status=%d proof=%q", response.StatusCode, response.Header.Get("Proxy-Authentication-Info"))
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("fallback did not close connection: %v", err)
	}
	waitWireV4Process(t, processDone)
	select {
	case request := <-originRequest:
		if request.Header.Get("Proxy-Authorization") != "" || request.Header.Get("Authorization") != "" {
			t.Fatalf("fallback origin received credentials: %#v", request.Header)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback origin did not receive CONNECT")
	}
	if dispatcher.Calls() != 0 {
		t.Fatalf("invalid auth dispatched %d target(s)", dispatcher.Calls())
	}
	stats := server.Stats()
	if stats.AuthenticationFailure != 1 || stats.AuthenticationSuccess != 0 || stats.FallbackHits != 1 {
		t.Fatalf("invalid-auth stats = %#v", stats)
	}
}

func TestWireV4FallbackNormalizesConnectSuccessAndCloses(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Proxy-Authentication-Info", "rspauth=decoy")
		writer.Header().Set("Proxy-Authenticate", "Basic realm=decoy")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("decoy"))
	}))
	defer origin.Close()
	server := newWireV4TestServerWithFallback(t, origin.URL)
	dispatcher := &countingRejectingDispatcher{}
	client, reader, _, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{12}, wireV4SaltLength), "wrong-psk")
	defer client.Close()

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("fallback status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	if response.Header.Get("Proxy-Authentication-Info") != "" || response.Header.Get("Proxy-Authenticate") != "" {
		t.Fatalf("fallback leaked authentication headers: %#v", response.Header)
	}
	payload, err := io.ReadAll(reader)
	if err != nil || string(payload) != "decoy" {
		t.Fatalf("fallback body = %q, %v", payload, err)
	}
	waitWireV4Process(t, processDone)
	if dispatcher.Calls() != 0 {
		t.Fatalf("fallback dispatched %d target(s)", dispatcher.Calls())
	}
}

func TestWireV4TargetRefusalReturnsSignedResponseWithoutTargetError(t *testing.T) {
	server := newWireV4TestServer(t)
	dispatcher := &countingRejectingDispatcher{}
	client, reader, init, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{13}, wireV4SaltLength), "test-psk")
	defer client.Close()

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusBadGateway || !verifyWireV4ProxyAuthenticationInfo(response.Header.Get("Proxy-Authentication-Info"), []byte("test-psk"), init.exporter, init.clientInit.ClientTag, response.StatusCode) {
		t.Fatalf("target refusal status=%d proof=%q", response.StatusCode, response.Header.Get("Proxy-Authentication-Info"))
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("target refusal did not close connection: %v", err)
	}
	select {
	case err := <-processDone:
		if err == nil || err.Error() != "artx: wire-v4 target unavailable" {
			t.Fatalf("process error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v4 target refusal did not close")
	}
	if dispatcher.Calls() != 1 {
		t.Fatalf("target refusal dispatch calls = %d", dispatcher.Calls())
	}
}

func TestWireV4WaitsForMatchingTargetReadyBeforeSignedSuccess(t *testing.T) {
	server := newWireV4TestServer(t)
	echo, baseDispatcher := newEchoDispatcher()
	defer echo.Close()
	dispatcher := newControlledTargetReadyDispatcher(baseDispatcher)
	client, reader, init, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{14}, wireV4SaltLength), "test-psk")
	defer client.Close()
	dispatch := dispatcher.wait(t)

	session.NotifyOutboundReady(dispatch.ctx, nil, xnet.TCPDestination(xnet.DomainAddress("wrong.example"), dispatch.destination.Port))
	assertWireV4NoResponse(t, client, reader)
	session.NotifyOutboundReady(dispatch.ctx, nil, dispatch.destination)

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusOK || !verifyWireV4ProxyAuthenticationInfo(response.Header.Get("Proxy-Authentication-Info"), []byte("test-psk"), init.exporter, init.clientInit.ClientTag, response.StatusCode) {
		t.Fatalf("target-ready response status=%d proof=%q", response.StatusCode, response.Header.Get("Proxy-Authentication-Info"))
	}
	payload := []byte("ready-after-proof")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	echoPayload := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echoPayload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoPayload, payload) {
		t.Fatalf("echo = %q", echoPayload)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after target response = %v, want EOF", err)
	}
	waitWireV4Process(t, processDone)
}

func TestWireV4AsyncTargetFailureReturnsSignedRefusalAndInterruptsLink(t *testing.T) {
	server := newWireV4TestServer(t)
	target, baseDispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	dispatcher := newControlledTargetReadyDispatcher(baseDispatcher)
	client, reader, init, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{15}, wireV4SaltLength), "test-psk")
	defer client.Close()
	dispatch := dispatcher.wait(t)

	session.SubmitOutboundErrorToOriginator(dispatch.ctx, errors.New("dial refused"))
	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusBadGateway || !verifyWireV4ProxyAuthenticationInfo(response.Header.Get("Proxy-Authentication-Info"), []byte("test-psk"), init.exporter, init.clientInit.ClientTag, response.StatusCode) {
		t.Fatalf("async refusal status=%d proof=%q", response.StatusCode, response.Header.Get("Proxy-Authentication-Info"))
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("async refusal did not close connection: %v", err)
	}
	waitWireV4TargetUnavailable(t, processDone)
	assertTargetReadyLinkInterrupted(t, target)
}

func TestWireV4TargetReadyTimeoutFailsClosedAndIgnoresLateReady(t *testing.T) {
	server := newWireV4TestServer(t)
	server.targetReadyWait = 40 * time.Millisecond
	target, baseDispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	dispatcher := newControlledTargetReadyDispatcher(baseDispatcher)
	client, reader, init, processDone := connectWireV4TestClient(t, server, dispatcher, bytes.Repeat([]byte{16}, wireV4SaltLength), "test-psk")
	defer client.Close()
	dispatch := dispatcher.wait(t)

	response := readWireV4TestResponse(t, reader)
	if response.StatusCode != http.StatusBadGateway || !verifyWireV4ProxyAuthenticationInfo(response.Header.Get("Proxy-Authentication-Info"), []byte("test-psk"), init.exporter, init.clientInit.ClientTag, response.StatusCode) {
		t.Fatalf("timeout refusal status=%d proof=%q", response.StatusCode, response.Header.Get("Proxy-Authentication-Info"))
	}
	session.NotifyOutboundReady(dispatch.ctx, nil, dispatch.destination)
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("timeout connection remained exposed after late ready: %v", err)
	}
	waitWireV4TargetUnavailable(t, processDone)
	assertTargetReadyLinkInterrupted(t, target)
}

type wireV4TestClient struct {
	exporter   []byte
	clientInit wireV4ClientInit
}

func newWireV4TestServer(t *testing.T) *Server {
	return newWireV4TestServerWithFallback(t, "http://127.0.0.1:60443/")
}

func newWireV4TestServerWithFallback(t *testing.T, fallbackOrigin string) *Server {
	t.Helper()
	certPEM, keyPEM := testCertificate(t)
	server, err := NewServer(context.Background(), &ServerConfig{
		Users:          []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings:    &transporttls.Config{Certificate: []*transporttls.Certificate{{Certificate: certPEM, Key: keyPEM}}},
		WireVersion:    4,
		ProfileVersion: 1,
		Fallback:       &FallbackConfig{Enabled: true, Origin: fallbackOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func connectWireV4TestClient(t *testing.T, server *Server, dispatcher routing.Dispatcher, salt []byte, password string) (*tls.Conn, *bufio.Reader, wireV4TestClient, <-chan error) {
	t.Helper()
	clientRaw, serverRaw := stdnet.Pipe()
	processDone := make(chan error, 1)
	go func() { processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher) }()
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		ServerName:         "localhost",
	})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(wireV4ExporterLabel, nil, wireV4ExporterLength)
	if err != nil {
		t.Fatal(err)
	}
	clientInit, err := newWireV4ClientInit([]byte(password), salt, exporter, "localhost", "example.net:443", uint32(time.Now().Unix()/bucketSeconds))
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: "example.net:443"},
		Host:   "example.net:443",
		Header: make(http.Header),
	}
	request.Header.Set("Proxy-Authorization", formatWireV4ProxyAuthorization(clientInit))
	request.Header.Set("User-Agent", "")
	if err := request.Write(client); err != nil {
		t.Fatal(err)
	}
	return client, bufio.NewReader(client), wireV4TestClient{exporter: exporter, clientInit: clientInit}, processDone
}

func readWireV4TestResponse(t *testing.T, reader *bufio.Reader) *http.Response {
	t.Helper()
	header := make([]byte, 0, 512)
	for !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		header = append(header, line...)
	}
	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func waitWireV4Process(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v4 server did not close")
	}
}

type controlledTargetReadyDispatch struct {
	ctx         context.Context
	destination xnet.Destination
}

type controlledTargetReadyDispatcher struct {
	*testDispatcher
	dispatched chan controlledTargetReadyDispatch
}

func newControlledTargetReadyDispatcher(dispatcher routing.Dispatcher) *controlledTargetReadyDispatcher {
	return &controlledTargetReadyDispatcher{
		testDispatcher: dispatcher.(*testDispatcher),
		dispatched:     make(chan controlledTargetReadyDispatch, 1),
	}
}

func (dispatcher *controlledTargetReadyDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	dispatcher.dispatched <- controlledTargetReadyDispatch{ctx: ctx, destination: destination}
	return dispatcher.link, nil
}

func (dispatcher *controlledTargetReadyDispatcher) wait(t *testing.T) controlledTargetReadyDispatch {
	t.Helper()
	select {
	case dispatch := <-dispatcher.dispatched:
		return dispatch
	case <-time.After(time.Second):
		t.Fatal("wire-v4 target dispatch did not start")
		return controlledTargetReadyDispatch{}
	}
}

func assertWireV4NoResponse(t *testing.T, client *tls.Conn, reader *bufio.Reader) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Peek(1); err == nil {
		t.Fatal("wire-v4 returned a response before matching target readiness")
	} else if timeout, ok := err.(interface{ Timeout() bool }); !ok || !timeout.Timeout() {
		t.Fatalf("pre-ready read = %v, want timeout", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
}

func waitWireV4TargetUnavailable(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err == nil || err.Error() != "artx: wire-v4 target unavailable" {
			t.Fatalf("process error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v4 target failure did not close")
	}
}

func assertTargetReadyLinkInterrupted(t *testing.T, target *transport.Link) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := target.Reader.ReadMultiBuffer()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("target-ready link reader was not interrupted")
		}
	case <-time.After(time.Second):
		t.Fatal("target-ready link interruption timed out")
	}
}

func wireV4VectorInputs() ([]byte, []byte, []byte) {
	exporter := make([]byte, wireV4ExporterLength)
	for index := range exporter {
		exporter[index] = byte(index)
	}
	salt := make([]byte, wireV4SaltLength)
	for index := range salt {
		salt[index] = byte(0x10 + index)
	}
	return []byte("test-psk"), exporter, salt
}
