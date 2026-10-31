package internet_test

import (
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

func TestDefaultListenerMPTCP(t *testing.T) {
	for _, test := range []struct {
		name    string
		options *internet.SocketConfig
		want    int
	}{
		{"nil", nil, unix.IPPROTO_TCP},
		{"disabled", &internet.SocketConfig{}, unix.IPPROTO_TCP},
		{"enabled", &internet.SocketConfig{TcpMptcp: true}, unix.IPPROTO_MPTCP},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("GODEBUG", "multipathtcp=2")
			var instance internet.DefaultListener
			listener, err := instance.Listen(context.Background(), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, test.options)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := listener.(*net.TCPListener).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var protocol int
			var socketErr error
			if err := raw.Control(func(fd uintptr) { protocol, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL) }); err != nil {
				t.Fatal(err)
			}
			if socketErr != nil {
				t.Fatal(socketErr)
			}
			if test.want == unix.IPPROTO_MPTCP && protocol == unix.IPPROTO_TCP {
				t.Skip("kernel does not support MPTCP; Go fell back to TCP")
			}
			if protocol != test.want {
				t.Fatalf("listener protocol = %d, want %d", protocol, test.want)
			}
		})
	}
}
