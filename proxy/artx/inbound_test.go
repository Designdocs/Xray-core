package artx

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	stdnet "net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestArtXServerRequiresTLS13(t *testing.T) {
	server := newArtXTestServer(t)
	clientRaw, serverRaw := stdnet.Pipe()
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, &rejectingDispatcher{})
	}()

	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}) //nolint:gosec -- self-signed test certificate
	if err := client.Handshake(); err == nil {
		t.Fatal("TLS 1.2 handshake succeeded")
	}
	closeTLSNow(client)
	if err := <-processDone; err == nil {
		t.Fatal("server accepted TLS 1.2")
	}
}

func TestArtXServerValidatesProfileVersions(t *testing.T) {
	certificatePEM, keyPEM := testCertificate(t)
	baseConfig := ServerConfig{
		Users:       []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings: &transporttls.Config{Certificate: []*transporttls.Certificate{{Certificate: certificatePEM, Key: keyPEM}}},
		WireVersion: 1,
	}
	profileV3 := baseConfig
	profileV3.ProfileVersion = 3
	server, err := NewServer(context.Background(), &profileV3)
	if preciseSettingsDeadlineSupported {
		if err != nil {
			t.Fatalf("profile v3: %v", err)
		}
		if server.profileVersion != profileVersionTimedRecordShaping {
			t.Fatalf("profile version = %d, want 3", server.profileVersion)
		}
	} else if !errors.Is(err, errPreciseSettingsDeadlineUnsupported) {
		t.Fatalf("profile v3 error = %v, want %v", err, errPreciseSettingsDeadlineUnsupported)
	}

	profileV4 := baseConfig
	profileV4.ProfileVersion = 4
	if _, err := NewServer(context.Background(), &profileV4); err == nil {
		t.Fatal("profile v4 was accepted")
	}
}

func TestArtXAuthenticationBindsTLSExporterAndRejectsReplay(t *testing.T) {
	server := newArtXTestServer(t)
	server.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	firstExporter := bytes.Repeat([]byte{1}, ExporterLength)
	frame, err := NewAuthFrame([]byte("test-psk"), bytes.Repeat([]byte{2}, MinSaltLength), firstExporter, uint32(server.now().Unix()/bucketSeconds), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := server.authenticate(frame, firstExporter); err != nil {
		t.Fatal(err)
	}
	if _, err := server.authenticate(frame, firstExporter); !errors.Is(err, errReplay) {
		t.Fatalf("same-session replay error = %v", err)
	}
	otherSession := newArtXTestServer(t)
	otherSession.now = server.now
	if _, err := otherSession.authenticate(frame, bytes.Repeat([]byte{3}, ExporterLength)); err == nil {
		t.Fatal("cross-session exporter replay accepted")
	}
}

func TestArtXPreAuthFailuresUseUnifiedFallback(t *testing.T) {
	tests := []struct {
		name           string
		payload        func(*testing.T, *Server, *tls.Conn) []byte
		closeAfterSend bool
		replayRejected bool
	}{
		{name: "unexpected type", payload: func(_ *testing.T, _ *Server, _ *tls.Conn) []byte {
			return []byte{0x02, MinSaltLength}
		}},
		{name: "truncated auth", closeAfterSend: true, payload: func(_ *testing.T, _ *Server, _ *tls.Conn) []byte {
			return []byte{AuthFrameType, MinSaltLength, 0x01}
		}},
		{name: "invalid salt", payload: func(_ *testing.T, _ *Server, _ *tls.Conn) []byte {
			return []byte{AuthFrameType, MinSaltLength - 1}
		}},
		{name: "truncated padding", closeAfterSend: true, payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			encoded := validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds))
			return encoded[:len(encoded)-1]
		}},
		{name: "unknown locator", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			return validAuthPayload(t, client, "unknown-psk", uint32(server.now().Unix()/bucketSeconds))
		}},
		{name: "bad tag", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			encoded := validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds))
			encoded[2+MinSaltLength+UserLocatorLength+4] ^= 0xff
			return encoded
		}},
		{name: "past bucket", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			return validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds)-2)
		}},
		{name: "future bucket", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			return validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds)+2)
		}},
		{name: "replay", replayRejected: true, payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			encoded := validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds))
			state := client.ConnectionState()
			exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, ExporterLength)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := ReadAuthFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.authenticate(frame, exporter); err != nil {
				t.Fatal(err)
			}
			return encoded
		}},
		{name: "replay cache full", replayRejected: true, payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			server.replay.capacity = 0
			return validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds))
		}},
		{name: "garbage", payload: func(_ *testing.T, _ *Server, _ *tls.Conn) []byte {
			return []byte("garbage")
		}},
		{name: "half close", closeAfterSend: true, payload: func(_ *testing.T, _ *Server, _ *tls.Conn) []byte {
			return nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newArtXTestServer(t)
			fallback := &recordingFallback{}
			server.fallback = fallback
			dispatcher := &countingRejectingDispatcher{}
			clientRaw, serverRaw := stdnet.Pipe()
			processDone := make(chan error, 1)
			go func() {
				processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
			}()
			client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec -- self-signed test certificate
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			payload := test.payload(t, server, client)
			if len(payload) > 0 {
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if test.closeAfterSend {
				closeTLSNow(client)
			}
			select {
			case err := <-processDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("pre-auth failure did not reach fallback")
			}
			closeTLSNow(client)
			if calls := dispatcher.Calls(); calls != 0 {
				t.Fatalf("dispatcher calls = %d", calls)
			}
			if calls := fallback.Calls(); calls != 1 {
				t.Fatalf("fallback calls = %d", calls)
			}
			if captured := fallback.PrefixLength(); captured > maxAuthFrameSize {
				t.Fatalf("captured prefix = %d", captured)
			}
			stats := server.Stats()
			if stats.ActiveConnections != 0 || stats.TotalConnections != 1 || stats.AuthenticationFailure != 1 || stats.FallbackHits != 1 || stats.FallbackErrors != 0 {
				t.Fatalf("stats = %#v", stats)
			}
			wantReplay := uint64(0)
			if test.replayRejected {
				wantReplay = 1
			}
			if stats.ReplayRejected != wantReplay {
				t.Fatalf("replay rejected = %d, want %d", stats.ReplayRejected, wantReplay)
			}
		})
	}
}

func TestArtXRuntimeStatsCountsSuccessfulAuthentication(t *testing.T) {
	server := newArtXTestServer(t)
	client, processDone := authenticateArtXClient(t, server, &rejectingDispatcher{}, context.Background())
	stats := server.Stats()
	if stats.ActiveConnections != 1 || stats.TotalConnections != 1 || stats.AuthenticationSuccess != 1 || stats.AuthenticationFailure != 0 {
		t.Fatalf("stats during connection = %#v", stats)
	}
	closeTLSNow(client)
	<-processDone
	if stats := server.Stats(); stats.ActiveConnections != 0 {
		t.Fatalf("stats after connection = %#v", stats)
	}
}

func validAuthPayload(t *testing.T, client *tls.Conn, psk string, bucket uint32) []byte {
	t.Helper()
	state := client.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, ExporterLength)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := NewAuthFrame([]byte(psk), bytes.Repeat([]byte{4}, MinSaltLength), exporter, bucket, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestArtXSettingsAndFlowWindowValidation(t *testing.T) {
	settings := settingsForProfile(7)
	if err := validatePeerSettings(settings, 7); err != nil {
		t.Fatal(err)
	}
	settings[SettingMaxConcurrentStreams] = 2
	if err := validatePeerSettings(settings, 7); err == nil {
		t.Fatal("accepted a second concurrent stream")
	}

	window := newSendWindow()
	if err := window.consume(MaxDataPayload); err != nil {
		t.Fatal(err)
	}
	if err := window.update(ClientStreamID, MaxDataPayload); err != nil {
		t.Fatal(err)
	}
	if err := window.update(ClientStreamID, 1); err == nil {
		t.Fatal("stream window grew beyond its negotiated bound")
	}
}

func TestRelayUplinkProcessesWindowUpdatesWhileTargetWriteBlocked(t *testing.T) {
	client, server := stdnet.Pipe()
	target := newBlockingMultiBufferWriter()
	link := &transport.Link{Writer: target}
	frameWriter := &lockedFrameWriter{writer: server}
	sendWindow := newSendWindow()
	sendWindow.mu.Lock()
	sendWindow.stream = 0
	sendWindow.connection = 0
	sendWindow.mu.Unlock()

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- relayUplink(server, frameWriter, link, sendWindow, newSendWindow(), make(chan struct{}, 1))
	}()
	t.Cleanup(func() {
		target.Interrupt()
		_ = client.Close()
		_ = server.Close()
		select {
		case <-relayDone:
		case <-time.After(time.Second):
			t.Error("relayUplink did not stop")
		}
	})

	writeFrameForTest(t, client, Frame{Type: FrameData, StreamID: ClientStreamID, Payload: []byte("blocked")})
	select {
	case <-target.entered:
	case <-time.After(time.Second):
		t.Fatal("target writer was not entered")
	}

	consumeDone := make(chan error, 1)
	go func() { consumeDone <- sendWindow.waitConsume(context.Background(), 1) }()
	select {
	case err := <-consumeDone:
		t.Fatalf("send window recovered before WINDOW_UPDATE: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	updatesDone := make(chan error, 1)
	go func() {
		increment, _ := EncodeWindowUpdate(1)
		if err := writeFrame(client, Frame{Type: FrameWindowUpdate, Payload: increment}); err != nil {
			updatesDone <- err
			return
		}
		updatesDone <- writeFrame(client, Frame{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: increment})
	}()

	select {
	case err := <-consumeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("WINDOW_UPDATE was not processed while target write was blocked")
	}
	select {
	case err := <-updatesDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WINDOW_UPDATE writes did not complete")
	}
}

func TestRelayUplinkReplenishesWindowOnlyAfterTargetAcceptsData(t *testing.T) {
	client, server := stdnet.Pipe()
	target := newBlockingMultiBufferWriter()
	link := &transport.Link{Writer: target}
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- relayUplink(server, &lockedFrameWriter{writer: server}, link, newSendWindow(), newSendWindow(), make(chan struct{}, 1))
	}()
	t.Cleanup(func() {
		target.Interrupt()
		_ = client.Close()
		_ = server.Close()
		select {
		case <-relayDone:
		case <-time.After(time.Second):
			t.Error("relayUplink did not stop")
		}
	})

	payload := []byte("backpressure")
	writeFrameForTest(t, client, Frame{Type: FrameData, StreamID: ClientStreamID, Payload: payload})
	select {
	case <-target.entered:
	case <-time.After(time.Second):
		t.Fatal("target writer was not entered")
	}
	if err := client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(client); err == nil {
		t.Fatal("server replenished receive window before target accepted data")
	} else if timeout, ok := err.(stdnet.Error); !ok || !timeout.Timeout() {
		t.Fatalf("read before target acceptance = %v, want timeout", err)
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	target.Unblock()
	readWindowUpdates(t, client, uint32(len(payload)))
}

func TestArtXSingleStreamRelayChunksAndReplenishesWindows(t *testing.T) {
	server := newArtXTestServer(t)
	echoServer, dispatcher := newEchoDispatcher()
	defer echoServer.Close()
	client, processDone := connectArtXClient(t, server, dispatcher)
	defer client.Close()

	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: mustEncodeDestination(t, destination)})

	type queuedFrame struct {
		frame Frame
		done  chan error
	}
	writes := make(chan queuedFrame, 32)
	go func() {
		for write := range writes {
			encoded, err := write.frame.MarshalBinary()
			if err == nil {
				_, err = client.Write(encoded)
			}
			write.done <- err
		}
	}()
	defer close(writes)
	queueWrite := func(frame Frame) <-chan error {
		done := make(chan error, 1)
		writes <- queuedFrame{frame: frame, done: done}
		return done
	}
	waitWrites := func(pending []<-chan error) {
		for _, done := range pending {
			if err := <-done; err != nil {
				select {
				case processErr := <-processDone:
					t.Fatalf("client write: %v; server: %v", err, processErr)
				default:
					t.Fatal(err)
				}
			}
		}
	}

	payload := bytes.Repeat([]byte("x"), int(InitialStreamWindow)+MaxDataPayload)
	var echoed bytes.Buffer
	var streamUpdate, connectionUpdate uint32
	var pendingWrites []<-chan error
	handleFrame := func(frame Frame) {
		switch frame.Type {
		case FrameData:
			if len(frame.Payload) > MaxDataPayload {
				t.Fatalf("server DATA frame = %d bytes", len(frame.Payload))
			}
			echoed.Write(frame.Payload)
			increment, _ := EncodeWindowUpdate(uint32(len(frame.Payload)))
			pendingWrites = append(pendingWrites,
				queueWrite(Frame{Type: FrameWindowUpdate, Payload: increment}),
				queueWrite(Frame{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: increment}),
			)
		case FrameWindowUpdate:
			increment, err := DecodeWindowUpdate(frame.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if frame.StreamID == 0 {
				connectionUpdate += increment
			} else {
				streamUpdate += increment
			}
		}
	}
	for offset := 0; offset < len(payload); offset += MaxDataPayload {
		waitWrites(pendingWrites)
		pendingWrites = nil
		end := min(offset+MaxDataPayload, len(payload))
		waitWrites([]<-chan error{queueWrite(Frame{Type: FrameData, StreamID: ClientStreamID, Payload: payload[offset:end]})})
		wantUpdate := uint32(end)
		for streamUpdate < wantUpdate || connectionUpdate < wantUpdate {
			frame, err := ReadFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			handleFrame(frame)
		}
	}
	waitWrites(pendingWrites)
	pendingWrites = nil
	waitWrites([]<-chan error{queueWrite(Frame{Type: FrameFin, StreamID: ClientStreamID})})

	for {
		frame, err := ReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == FrameFin {
			if !bytes.Equal(echoed.Bytes(), payload) {
				t.Fatalf("echoed %d bytes, want %d", echoed.Len(), len(payload))
			}
			if streamUpdate < uint32(len(payload)) || connectionUpdate < uint32(len(payload)) {
				t.Fatalf("WINDOW_UPDATE stream=%d connection=%d", streamUpdate, connectionUpdate)
			}
			closeTLSNow(client)
			if err := <-processDone; err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			return
		}
		handleFrame(frame)
	}
}

func TestArtXUDPAssociationPreservesDatagramBoundaries(t *testing.T) {
	server := newArtXTestServer(t)
	server.udpEnabled = true
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, processDone := connectArtXClient(t, server, dispatcher)

	destination := xnet.UDPDestination(xnet.DomainAddress("dns.example"), 53)
	encodedDestination, err := EncodeUDPDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameUDPAssoc, StreamID: ClientStreamID, Payload: encodedDestination})

	requests := [][]byte{[]byte("dns-query"), bytes.Repeat([]byte{0xa5}, 1232)}
	for _, request := range requests {
		payload, err := EncodeDatagram(request)
		if err != nil {
			t.Fatal(err)
		}
		writeFrameForTest(t, client, Frame{Type: FrameDatagram, StreamID: ClientStreamID, Payload: payload})
		buffers, err := target.Reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		if len(buffers) != 1 || !bytes.Equal(buffers[0].Bytes(), request) {
			buf.ReleaseMulti(buffers)
			t.Fatalf("target datagram = %#v, want %d bytes", buffers, len(request))
		}
		if buffers[0].UDP == nil || buffers[0].UDP.String() != destination.String() {
			buf.ReleaseMulti(buffers)
			t.Fatalf("target destination = %#v", buffers[0].UDP)
		}
		buf.ReleaseMulti(buffers)
		readWindowUpdates(t, client, uint32(len(request)+2))
	}

	responses := [][]byte{[]byte("dns-response"), bytes.Repeat([]byte{0x5a}, 1200)}
	for _, response := range responses {
		if err := target.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(response)}); err != nil {
			t.Fatal(err)
		}
		for {
			frame, err := ReadFrame(client)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Type != FrameDatagram {
				continue
			}
			payload, err := DecodeDatagram(frame.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, response) {
				t.Fatalf("client datagram = %d bytes, want %d", len(payload), len(response))
			}
			break
		}
	}

	writeFrameForTest(t, client, Frame{Type: FrameFin, StreamID: ClientStreamID})
	readUntilFrame(t, client, FrameFin)
	closeTLSNow(client)
	if err := <-processDone; err != nil {
		t.Fatal(err)
	}
}

func TestArtXUDPAssociationRequiresServerSwitch(t *testing.T) {
	server := newArtXTestServer(t)
	dispatcher := &countingRejectingDispatcher{}
	client, processDone := connectArtXClient(t, server, dispatcher)
	destination, err := EncodeUDPDestination(xnet.UDPDestination(xnet.DomainAddress("dns.example"), 53))
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameUDPAssoc, StreamID: ClientStreamID, Payload: destination})
	if err := <-processDone; err == nil || !strings.Contains(err.Error(), "UDP is disabled") {
		t.Fatalf("disabled UDP error = %v", err)
	}
	if calls := dispatcher.Calls(); calls != 0 {
		t.Fatalf("dispatcher calls = %d", calls)
	}
	closeTLSNow(client)
}

func TestArtXClientFINStillReceivesTargetResponse(t *testing.T) {
	server := newArtXTestServer(t)
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, processDone := connectArtXClient(t, server, dispatcher)
	destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
	writeFrameForTest(t, client, Frame{Type: FrameData, StreamID: ClientStreamID, Payload: []byte("request")})
	readWindowUpdates(t, client, uint32(len("request")))
	writeFrameForTest(t, client, Frame{Type: FrameFin, StreamID: ClientStreamID})

	if got := readTargetPayload(t, target); got != "request" {
		t.Fatalf("target request = %q", got)
	}
	if _, err := target.Reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
		t.Fatalf("target did not receive client FIN: %v", err)
	}
	if err := target.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("response"))}); err != nil {
		t.Fatal(err)
	}
	if err := common.Close(target.Writer); err != nil {
		t.Fatal(err)
	}

	var response bytes.Buffer
	for {
		frame, err := ReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == FrameData {
			response.Write(frame.Payload)
		}
		if frame.Type == FrameFin {
			break
		}
	}
	if response.String() != "response" {
		t.Fatalf("client response = %q", response.String())
	}
	closeTLSNow(client)
	if err := <-processDone; err != nil {
		t.Fatal(err)
	}
}

func TestArtXTargetFINStillAcceptsClientUpload(t *testing.T) {
	server := newArtXTestServer(t)
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, processDone := connectArtXClient(t, server, dispatcher)
	destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
	if err := common.Close(target.Writer); err != nil {
		t.Fatal(err)
	}
	readUntilFrame(t, client, FrameFin)

	writeFrameForTest(t, client, Frame{Type: FrameData, StreamID: ClientStreamID, Payload: []byte("late request")})
	readWindowUpdates(t, client, uint32(len("late request")))
	writeFrameForTest(t, client, Frame{Type: FrameFin, StreamID: ClientStreamID})
	if got := readTargetPayload(t, target); got != "late request" {
		t.Fatalf("target request = %q", got)
	}
	if _, err := target.Reader.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
		t.Fatalf("target did not receive client FIN: %v", err)
	}
	closeTLSNow(client)
	if err := <-processDone; err != nil {
		t.Fatal(err)
	}
}

func TestArtXProcessCancellationUnblocksHandshakeFramesAndRelay(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		server := newArtXTestServer(t)
		ctx, cancel := context.WithCancel(context.Background())
		client, processDone := authenticateArtXClient(t, server, &rejectingDispatcher{}, ctx)
		assertCancellationStopsProcess(t, cancel, client, processDone)
	})

	t.Run("tcp_syn", func(t *testing.T) {
		server := newArtXTestServer(t)
		ctx, cancel := context.WithCancel(context.Background())
		client, processDone := authenticateArtXClient(t, server, &rejectingDispatcher{}, ctx)
		payload, _ := EncodeSettings(settingsList(server.profileVersion))
		writeFrameForTest(t, client, Frame{Type: FrameSettings, Payload: payload})
		assertCancellationStopsProcess(t, cancel, client, processDone)
	})

	t.Run("relay", func(t *testing.T) {
		server := newArtXTestServer(t)
		target, dispatcher, closer := newTargetDispatcher()
		defer closer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		client, processDone := connectArtXClientWithContext(t, server, dispatcher, ctx)
		destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
		writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
		_ = target
		assertCancellationStopsProcess(t, cancel, client, processDone)
	})
}

func TestArtXAuthorityTLSConfigHandlesConcurrentHandshakes(t *testing.T) {
	certificate, key := testAuthorityCertificate(t)
	server := newArtXTestServerWithCertificate(t, &transporttls.Certificate{
		Certificate: certificate,
		Key:         key,
		Usage:       transporttls.Certificate_AUTHORITY_ISSUE,
	})

	const connections = 32
	var wait sync.WaitGroup
	errorsFound := make(chan error, connections)
	for index := 0; index < connections; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			clientRaw, serverRaw := stdnet.Pipe()
			processDone := make(chan error, 1)
			go func() {
				processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, &rejectingDispatcher{})
			}()
			client := tls.Client(clientRaw, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec -- test authority
				MinVersion:         tls.VersionTLS13,
				ServerName:         fmt.Sprintf("host-%d.example", index),
			})
			if err := client.Handshake(); err != nil {
				errorsFound <- err
			}
			closeTLSNow(client)
			<-processDone
		}(index)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}

func TestArtXRejectsSecondStreamAndHandlesRST(t *testing.T) {
	server := newArtXTestServer(t)
	firstEcho, dispatcher := newEchoDispatcher()
	defer firstEcho.Close()
	client, processDone := connectArtXClient(t, server, dispatcher)
	destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})

	var secondStream [FrameHeaderLength]byte
	secondStream[0] = FrameTCPSyn
	binary.BigEndian.PutUint32(secondStream[1:5], 3)
	putUint24(secondStream[5:8], len(destination))
	if _, err := client.Write(append(secondStream[:], destination...)); err != nil {
		t.Fatal(err)
	}
	if err := <-processDone; err == nil {
		t.Fatal("server accepted a second stream")
	}
	closeTLSNow(client)

	server = newArtXTestServer(t)
	secondEcho, dispatcher := newEchoDispatcher()
	defer secondEcho.Close()
	client, processDone = connectArtXClient(t, server, dispatcher)
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
	writeFrameForTest(t, client, Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}})
	if err := <-processDone; err != nil {
		t.Fatalf("RST returned %v", err)
	}
	closeTLSNow(client)
}

func TestRelaySingleStreamRSTWinsConcurrentDownlinkFailure(t *testing.T) {
	encodedRST, err := (Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	connection := newRSTOnCloseConnection(encodedRST)
	link := &transport.Link{
		Reader: errorMultiBufferReader{err: io.ErrClosedPipe},
		Writer: discardMultiBufferWriter{},
	}

	if err := relaySingleStream(context.Background(), connection, &lockedFrameWriter{writer: connection}, link); err != nil {
		t.Fatalf("RST was hidden by concurrent downlink failure: %v", err)
	}
}

func TestArtXKnownOutOfOrderSettingsFailsAndUnknownFrameIsIgnored(t *testing.T) {
	t.Run("settings_after_stream_open", func(t *testing.T) {
		server := newArtXTestServer(t)
		_, dispatcher, closer := newTargetDispatcher()
		defer closer.Close()
		client, processDone := connectArtXClient(t, server, dispatcher)
		destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
		writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
		payload, _ := EncodeSettings(settingsList(server.profileVersion))
		writeFrameForTest(t, client, Frame{Type: FrameSettings, Payload: payload})
		if err := <-processDone; err == nil {
			t.Fatal("SETTINGS after stream open was accepted")
		}
		closeTLSNow(client)
	})

	t.Run("unknown_frame", func(t *testing.T) {
		server := newArtXTestServer(t)
		_, dispatcher, closer := newTargetDispatcher()
		defer closer.Close()
		client, processDone := connectArtXClient(t, server, dispatcher)
		destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
		writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
		writeFrameForTest(t, client, Frame{Type: 0x7f, StreamID: 99})
		writeFrameForTest(t, client, Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}})
		if err := <-processDone; err != nil {
			t.Fatalf("unknown frame was not ignored: %v", err)
		}
		closeTLSNow(client)
	})
}

func connectArtXClient(t *testing.T, server *Server, dispatcher routing.Dispatcher) (*tls.Conn, <-chan error) {
	return connectArtXClientWithContext(t, server, dispatcher, context.Background())
}

func connectArtXClientWithContext(t *testing.T, server *Server, dispatcher routing.Dispatcher, ctx context.Context) (*tls.Conn, <-chan error) {
	t.Helper()
	client, processDone := authenticateArtXClient(t, server, dispatcher, ctx)
	payload, _ := EncodeSettings(settingsList(server.profileVersion))
	writeFrameForTest(t, client, Frame{Type: FrameSettings, Payload: payload})
	return client, processDone
}

func authenticateArtXClient(t *testing.T, server *Server, dispatcher routing.Dispatcher, ctx context.Context) (*tls.Conn, <-chan error) {
	t.Helper()
	clientRaw, serverRaw := stdnet.Pipe()
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContextFrom(ctx), xnet.Network_TCP, serverRaw, dispatcher)
	}()
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec -- self-signed test certificate
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, ExporterLength)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthFrame([]byte("test-psk"), bytes.Repeat([]byte{4}, MinSaltLength), exporter, uint32(time.Now().Unix()/bucketSeconds), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := auth.MarshalBinary()
	if _, err := client.Write(encoded); err != nil {
		t.Fatal(err)
	}
	serverSettings, err := ReadFrame(client)
	if err != nil || serverSettings.Type != FrameSettings {
		t.Fatalf("server SETTINGS = %#v, %v", serverSettings, err)
	}
	return client, processDone
}

func newArtXTestServer(t *testing.T) *Server {
	t.Helper()
	certPEM, keyPEM := testCertificate(t)
	return newArtXTestServerWithCertificate(t, &transporttls.Certificate{Certificate: certPEM, Key: keyPEM})
}

func newArtXTestServerWithCertificate(t *testing.T, certificate *transporttls.Certificate) *Server {
	t.Helper()
	config := &ServerConfig{
		Users:          []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings:    &transporttls.Config{Certificate: []*transporttls.Certificate{certificate}},
		WireVersion:    1,
		ProfileVersion: 1,
	}
	server, err := NewServer(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func testAuthorityCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "ArtX test authority"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func testCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

type testDispatcher struct {
	link *transport.Link
}

func (dispatcher *testDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	session.NotifyOutboundReady(ctx, nil, destination)
	return dispatcher.link, nil
}
func (*testDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}
func (*testDispatcher) Start() error      { return nil }
func (*testDispatcher) Close() error      { return nil }
func (*testDispatcher) Type() interface{} { return routing.DispatcherType() }

type rejectingDispatcher struct{ testDispatcher }

func (rejectingDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, errors.New("unexpected dispatch")
}

type countingRejectingDispatcher struct {
	rejectingDispatcher
	mu    sync.Mutex
	calls int
}

func (dispatcher *countingRejectingDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	dispatcher.mu.Lock()
	dispatcher.calls++
	dispatcher.mu.Unlock()
	return nil, errors.New("unexpected dispatch")
}

func (dispatcher *countingRejectingDispatcher) Calls() int {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.calls
}

type recordingFallback struct {
	mu           sync.Mutex
	calls        int
	prefixLength int
}

func (fallback *recordingFallback) Serve(_ context.Context, _ stdnet.Conn, prefix []byte) error {
	fallback.mu.Lock()
	defer fallback.mu.Unlock()
	fallback.calls++
	fallback.prefixLength = len(prefix)
	return nil
}

func (fallback *recordingFallback) Calls() int {
	fallback.mu.Lock()
	defer fallback.mu.Unlock()
	return fallback.calls
}

func (fallback *recordingFallback) PrefixLength() int {
	fallback.mu.Lock()
	defer fallback.mu.Unlock()
	return fallback.prefixLength
}

func newEchoDispatcher() (io.Closer, routing.Dispatcher) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	echo := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}
	go func() {
		_ = buf.Copy(echo.Reader, echo.Writer)
		_ = common.Close(echo.Writer)
	}()
	return pipeCloser{uplinkWriter, downlinkWriter}, &testDispatcher{link: &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}}
}

func newTargetDispatcher() (*transport.Link, routing.Dispatcher, io.Closer) {
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	target := &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}
	server := &transport.Link{Reader: downlinkReader, Writer: uplinkWriter}
	return target, &testDispatcher{link: server}, pipeCloser{uplinkWriter, downlinkWriter}
}

type pipeCloser struct {
	uplink   *pipe.Writer
	downlink *pipe.Writer
}

func (closer pipeCloser) Close() error {
	_ = closer.uplink.Close()
	return closer.downlink.Close()
}

func testInboundContext() context.Context {
	return testInboundContextFrom(context.Background())
}

func testInboundContextFrom(ctx context.Context) context.Context {
	return session.ContextWithInbound(ctx, &session.Inbound{})
}

func assertCancellationStopsProcess(t *testing.T, cancel context.CancelFunc, client *tls.Conn, processDone <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-processDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Process cancellation error = %v", err)
		}
		closeTLSNow(client)
	case <-time.After(time.Second):
		closeTLSNow(client)
		<-processDone
		t.Fatal("Process did not stop after context cancellation")
	}
}

func readTargetPayload(t *testing.T, target *transport.Link) string {
	t.Helper()
	buffers, err := target.Reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	payload := buffers.String()
	buf.ReleaseMulti(buffers)
	return payload
}

func readUntilFrame(t *testing.T, reader io.Reader, frameType byte) Frame {
	t.Helper()
	for {
		frame, err := ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type == frameType {
			return frame
		}
	}
}

func readWindowUpdates(t *testing.T, reader io.Reader, amount uint32) {
	t.Helper()
	var connection, stream uint32
	for connection < amount || stream < amount {
		frame, err := ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != FrameWindowUpdate {
			t.Fatalf("frame type = 0x%02x, want WINDOW_UPDATE", frame.Type)
		}
		increment, err := DecodeWindowUpdate(frame.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if frame.StreamID == 0 {
			connection += increment
		} else {
			stream += increment
		}
	}
}

func mustEncodeDestination(t *testing.T, destination xnet.Destination) []byte {
	t.Helper()
	payload, err := EncodeTCPDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func writeFrameForTest(t *testing.T, writer io.Writer, frame Frame) {
	t.Helper()
	if err := writeFrame(writer, frame); err != nil {
		t.Fatal(err)
	}
}

func writeFrame(writer io.Writer, frame Frame) error {
	encoded, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	for len(encoded) > 0 {
		written, err := writer.Write(encoded)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

type blockingMultiBufferWriter struct {
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
	releaseOnce sync.Once
}

type rstOnCloseConnection struct {
	closed    chan struct{}
	closeOnce sync.Once
	reader    *bytes.Reader
}

func newRSTOnCloseConnection(payload []byte) *rstOnCloseConnection {
	return &rstOnCloseConnection{closed: make(chan struct{}), reader: bytes.NewReader(payload)}
}

func (connection *rstOnCloseConnection) Read(payload []byte) (int, error) {
	<-connection.closed
	return connection.reader.Read(payload)
}

func (*rstOnCloseConnection) Write(payload []byte) (int, error) {
	return len(payload), nil
}

func (connection *rstOnCloseConnection) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

type errorMultiBufferReader struct {
	err error
}

func (reader errorMultiBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, reader.err
}

type discardMultiBufferWriter struct{}

func (discardMultiBufferWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	buf.ReleaseMulti(buffers)
	return nil
}

func newBlockingMultiBufferWriter() *blockingMultiBufferWriter {
	return &blockingMultiBufferWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (writer *blockingMultiBufferWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	writer.enteredOnce.Do(func() { close(writer.entered) })
	<-writer.release
	buf.ReleaseMulti(buffers)
	return nil
}

func (writer *blockingMultiBufferWriter) Unblock() {
	writer.releaseOnce.Do(func() { close(writer.release) })
}

func (writer *blockingMultiBufferWriter) Interrupt() {
	writer.Unblock()
}

func closeTLSNow(connection *tls.Conn) {
	_ = connection.NetConn().Close()
}

var _ stat.Connection = (*tls.Conn)(nil)
