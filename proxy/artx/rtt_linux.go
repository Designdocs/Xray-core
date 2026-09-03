//go:build linux

package artx

import (
	"net"
	"syscall"

	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sys/unix"
)

// sampleSocketRTT reads the kernel's smoothed round-trip time for the
// underlying TCP socket. The ArtX negotiation point holds a TLS connection, so
// the stats wrapper is peeled first, exactly like the r0 hook does.
func sampleSocketRTT(connection net.Conn) autoRTTSample {
	if connection == nil {
		return autoRTTSample{}
	}
	syscallConnection, ok := stat.TryUnwrapStatsConn(connection).(syscall.Conn)
	if !ok {
		return autoRTTSample{}
	}
	rawConnection, err := syscallConnection.SyscallConn()
	if err != nil {
		return autoRTTSample{}
	}
	var info *unix.TCPInfo
	controlErr := rawConnection.Control(func(descriptor uintptr) {
		info, _ = unix.GetsockoptTCPInfo(int(descriptor), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if controlErr != nil || info == nil || info.Rtt == 0 {
		return autoRTTSample{}
	}
	return autoRTTSample{micros: uint64(info.Rtt), valid: true}
}
