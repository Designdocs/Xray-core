package freedom

import (
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestForwardTCPHalfClose(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		optIn, dialerProxy, counted, wantFIN bool
	}{
		{name: "direct", optIn: true, wantFIN: true},
		{name: "counted direct", optIn: true, counted: true, wantFIN: true},
		{name: "ordinary outbound"},
		{name: "dialer proxy", optIn: true, dialerProxy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			target, err := ln.AcceptTCP()
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			deadline := time.Now().Add(3 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := target.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			var conn stat.Connection = client
			if tc.counted {
				conn = &stat.CounterConnection{Connection: client}
			}
			ob := &session.Outbound{Target: xnet.DestinationFromAddr(ln.Addr()), ForwardTCPHalfClose: tc.optIn}
			h := Handler{usesDialerProxy: tc.dialerProxy}
			h.forwardTCPHalfClose(ob, conn)
			var b [1]byte
			if tc.wantFIN {
				if n, err := target.Read(b[:]); n != 0 || err != io.EOF {
					t.Fatalf("target read = %d, %v; want EOF", n, err)
				}
			} else {
				if _, err := client.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(target, b[:]); err != nil || b[0] != 'x' {
					t.Fatalf("uplink = %q, %v", b, err)
				}
			}
			if _, err := target.Write([]byte("y")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(client, b[:]); err != nil || b[0] != 'y' {
				t.Fatalf("reply = %q, %v", b, err)
			}
		})
	}
}
