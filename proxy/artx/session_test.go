package artx

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestWireV2ReusesAuthenticatedSessionForSequentialStreams(t *testing.T) {
	firstCloser, first := newEchoDispatcher()
	defer firstCloser.Close()
	secondCloser, second := newEchoDispatcher()
	defer secondCloser.Close()
	dispatcher := &sequentialDispatcher{links: []*transport.Link{
		first.(*testDispatcher).link,
		second.(*testDispatcher).link,
	}}

	certPEM, keyPEM := testCertificate(t)
	server, err := NewServer(context.Background(), &ServerConfig{
		Users:          []*protocol.User{protocol.ToProtoUser(artxMemoryUser("user@example.com", "test-psk"))},
		TlsSettings:    &transporttls.Config{Certificate: []*transporttls.Certificate{{Certificate: certPEM, Key: keyPEM}}},
		WireVersion:    2,
		ProfileVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, processDone := authenticateArtXClient(t, server, dispatcher, context.Background())
	observedDone := make(chan error, 1)
	go func() {
		err := <-processDone
		t.Logf("wire-v2 process result: %v", err)
		observedDone <- err
	}()
	settings, _ := EncodeSettings(settingsListForWire(2, 1))
	writeWireV2Frame(t, client, observedDone, Frame{Type: FrameSettings, Payload: settings})

	destination := mustEncodeDestination(t, xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	for index, payload := range [][]byte{[]byte("first"), []byte("second")} {
		streamID := uint32(index*2 + 1)
		writeWireV2Frame(t, client, observedDone, Frame{Type: FrameTCPSyn, StreamID: streamID, Payload: destination})
		writeWireV2Frame(t, client, observedDone, Frame{Type: FrameData, StreamID: streamID, Payload: payload})
		writeWireV2Frame(t, client, observedDone, Frame{Type: FrameFin, StreamID: streamID})
		if got := readWireV2Payload(t, client, observedDone, streamID); !bytes.Equal(got, payload) {
			t.Fatalf("stream %d payload = %q", streamID, got)
		}
	}
	if dispatcher.Calls() != 2 {
		t.Fatalf("dispatch calls = %d", dispatcher.Calls())
	}
	closeTLSNow(client)
	select {
	case err := <-observedDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wire-v2 process did not stop")
	}
}

func TestNextReusableOpenSkipsTerminalWindowUpdates(t *testing.T) {
	frames := make(chan reusableFrameResult, 3)
	frames <- reusableFrameResult{frame: Frame{Type: FrameWindowUpdate}}
	frames <- reusableFrameResult{frame: Frame{Type: FrameWindowUpdate, StreamID: 1}}
	frames <- reusableFrameResult{frame: Frame{Type: FrameTCPSyn, StreamID: 3}}

	open, err := nextReusableOpen(context.Background(), frames, 1)
	if err != nil {
		t.Fatal(err)
	}
	if open.Type != FrameTCPSyn || open.StreamID != 3 {
		t.Fatalf("open = type %d stream %d", open.Type, open.StreamID)
	}
}

type sequentialDispatcher struct {
	testDispatcher
	mu    sync.Mutex
	links []*transport.Link
	calls int
}

func (dispatcher *sequentialDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.calls >= len(dispatcher.links) {
		return nil, io.EOF
	}
	link := dispatcher.links[dispatcher.calls]
	dispatcher.calls++
	return link, nil
}

func (dispatcher *sequentialDispatcher) Calls() int {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.calls
}

func writeWireV2Frame(t *testing.T, writer io.Writer, processDone <-chan error, frame Frame) {
	t.Helper()
	encoded, err := frame.marshal(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAll(writer, encoded); err != nil {
		select {
		case processErr := <-processDone:
			t.Fatalf("write error = %v; process error = %v", err, processErr)
		case <-time.After(100 * time.Millisecond):
			t.Fatal(err)
		}
	}
}

func readWireV2Payload(t *testing.T, reader io.Reader, processDone <-chan error, streamID uint32) []byte {
	t.Helper()
	var payload []byte
	for {
		frame, err := readFrame(reader, 2)
		if err != nil {
			select {
			case processErr := <-processDone:
				t.Fatalf("read error = %v; process error = %v", err, processErr)
			case <-time.After(100 * time.Millisecond):
				t.Fatal(err)
			}
		}
		if frame.StreamID != 0 && frame.StreamID != streamID {
			t.Fatalf("frame stream = %d, want %d", frame.StreamID, streamID)
		}
		switch frame.Type {
		case FrameData:
			payload = append(payload, frame.Payload...)
		case FrameFin:
			return payload
		}
	}
}

var _ routing.Dispatcher = (*sequentialDispatcher)(nil)
