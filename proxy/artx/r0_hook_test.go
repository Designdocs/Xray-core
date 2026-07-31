package artx

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

func TestCloseWireV4HijackedConnectionClosesHookFirst(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	connection := &r0CloseOrderConnection{Conn: client}
	hook := &r0CloseOrderHook{t: t, connection: connection}

	closeWireV4HijackedConnection(hook, connection)

	if !hook.closed {
		t.Fatal("R0 hook was not closed")
	}
	if !connection.closed.Load() {
		t.Fatal("hijacked connection was not closed")
	}
}

func TestR0ServerObservedLinkReportsPayloadAndFINOnce(t *testing.T) {
	hook := &recordingR0ServerHook{}
	reader := &r0TestBufferReader{buffers: buf.MultiBuffer{buf.FromBytes([]byte("down"))}, err: io.EOF}
	writer := &r0TestBufferWriter{}
	link := observeR0ServerLink(&transport.Link{Reader: reader, Writer: writer}, hook)

	downlink, err := link.Reader.ReadMultiBuffer()
	if err != io.EOF || downlink.Len() != 4 {
		t.Fatalf("downlink = %d, %v", downlink.Len(), err)
	}
	buf.ReleaseMulti(downlink)
	if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("up"))}); err != nil {
		t.Fatal(err)
	}
	if err := closeR0TestObject(link.Writer); err != nil {
		t.Fatal(err)
	}
	if err := closeR0TestObject(link.Writer); err != nil {
		t.Fatal(err)
	}

	hook.requireCount(t, r0ServerEventPayloadUplink, 1, 2)
	hook.requireCount(t, r0ServerEventPayloadDownlink, 1, 4)
	hook.requireCount(t, r0ServerEventClientFIN, 1, 0)
	hook.requireCount(t, r0ServerEventTargetFIN, 1, 0)
}

func TestR0TargetReadyObserverUsesDispatchContext(t *testing.T) {
	hook := &recordingR0ServerHook{}
	ctx := contextWithR0TargetReady(context.Background(), hook)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	session.NotifyOutboundReady(ctx, client, xnet.TCPDestination(xnet.DomainAddress("example.net"), 443))
	hook.requireCount(t, r0ServerEventTargetReady, 1, 0)
}

type r0TestBufferReader struct {
	buffers buf.MultiBuffer
	err     error
}

func (reader *r0TestBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffers := reader.buffers
	reader.buffers = nil
	return buffers, reader.err
}

type r0TestBufferWriter struct {
	closed bool
}

func (writer *r0TestBufferWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	buf.ReleaseMulti(buffers)
	return nil
}

func (writer *r0TestBufferWriter) Close() error {
	writer.closed = true
	return nil
}

type recordedR0ServerEvent struct {
	kind     uint8
	accepted int
}

type recordingR0ServerHook struct {
	events []recordedR0ServerEvent
}

func (hook *recordingR0ServerHook) Event(_ uint8, kind, _ uint8) {
	hook.events = append(hook.events, recordedR0ServerEvent{kind: kind})
}

func (hook *recordingR0ServerHook) IOEvent(_ uint8, kind, _ uint8, _, accepted int) {
	hook.events = append(hook.events, recordedR0ServerEvent{kind: kind, accepted: accepted})
}

func (hook *recordingR0ServerHook) Close() {}

func (hook *recordingR0ServerHook) requireCount(t *testing.T, kind uint8, wantCount, wantBytes int) {
	t.Helper()
	count := 0
	accepted := 0
	for _, event := range hook.events {
		if event.kind == kind {
			count++
			accepted += event.accepted
		}
	}
	if count != wantCount || accepted != wantBytes {
		t.Fatalf("kind %d = count %d bytes %d, want %d/%d", kind, count, accepted, wantCount, wantBytes)
	}
}

func closeR0TestObject(value any) error {
	closer, ok := value.(io.Closer)
	if !ok {
		return io.ErrClosedPipe
	}
	return closer.Close()
}

type r0CloseOrderConnection struct {
	net.Conn
	closed atomic.Bool
}

func (connection *r0CloseOrderConnection) Close() error {
	connection.closed.Store(true)
	return connection.Conn.Close()
}

type r0CloseOrderHook struct {
	t          *testing.T
	connection *r0CloseOrderConnection
	closed     bool
}

func (*r0CloseOrderHook) Event(uint8, uint8, uint8) {}

func (*r0CloseOrderHook) IOEvent(uint8, uint8, uint8, int, int) {}

func (hook *r0CloseOrderHook) Close() {
	if hook.connection.closed.Load() {
		hook.t.Fatal("hijacked connection closed before R0 hook")
	}
	hook.closed = true
}
