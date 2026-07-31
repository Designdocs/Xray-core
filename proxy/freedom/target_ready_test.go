package freedom

import (
	"bytes"
	"context"
	"errors"
	"io"
	stdnet "net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestPrepareTargetConnectionSignalsAfterProxyProtocolHeader(t *testing.T) {
	connection := &targetReadyTestConnection{}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.net"), 443)
	signaled := false
	bytesAtSignal := 0
	ctx := session.ContextWithOutboundReadyObserver(context.Background(), func(gotConnection stdnet.Conn, gotDestination xnet.Destination) {
		signaled = true
		bytesAtSignal = connection.Len()
		if gotConnection != connection || !sameFreedomTestDestination(gotDestination, destination) {
			t.Fatalf("ready signal = %v, %v", gotConnection, gotDestination)
		}
	})

	err := prepareTargetConnection(ctx, connection, destination, 1, &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.10"), Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	if !signaled || bytesAtSignal == 0 || bytesAtSignal != connection.Len() {
		t.Fatalf("signal=%v bytes-at-signal=%d final-bytes=%d", signaled, bytesAtSignal, connection.Len())
	}
	if got := connection.String(); !bytes.HasPrefix([]byte(got), []byte("PROXY TCP4 ")) {
		t.Fatalf("PROXY header = %q", got)
	}
}

func TestPrepareTargetConnectionDoesNotSignalAfterProxyProtocolFailure(t *testing.T) {
	connection := &targetReadyTestConnection{writeErr: io.ErrClosedPipe}
	destination := xnet.TCPDestination(xnet.DomainAddress("example.net"), 443)
	signaled := false
	ctx := session.ContextWithOutboundReadyObserver(context.Background(), func(stdnet.Conn, xnet.Destination) { signaled = true })

	err := prepareTargetConnection(ctx, connection, destination, 1, &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.10"), Port: 12345})
	if err == nil || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("prepare error = %v", err)
	}
	if signaled {
		t.Fatal("readiness signaled after failed PROXY protocol write")
	}
}

func sameFreedomTestDestination(left, right xnet.Destination) bool {
	return left.Network == right.Network && left.Port == right.Port && left.Address.String() == right.Address.String()
}

type targetReadyTestConnection struct {
	bytes.Buffer
	writeErr error
}

func (connection *targetReadyTestConnection) Write(payload []byte) (int, error) {
	if connection.writeErr != nil {
		return 0, connection.writeErr
	}
	return connection.Buffer.Write(payload)
}

func (*targetReadyTestConnection) Read([]byte) (int, error) { return 0, io.EOF }
func (*targetReadyTestConnection) Close() error             { return nil }
func (*targetReadyTestConnection) LocalAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.ParseIP("192.0.2.10"), Port: 12345}
}
func (*targetReadyTestConnection) RemoteAddr() stdnet.Addr {
	return &stdnet.TCPAddr{IP: stdnet.ParseIP("198.51.100.20"), Port: 443}
}
func (*targetReadyTestConnection) SetDeadline(time.Time) error      { return nil }
func (*targetReadyTestConnection) SetReadDeadline(time.Time) error  { return nil }
func (*targetReadyTestConnection) SetWriteDeadline(time.Time) error { return nil }
