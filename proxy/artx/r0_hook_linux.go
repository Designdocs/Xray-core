//go:build artxr0 && linux

package artx

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xtls/xray-core/transport/internet/stat"
	"golang.org/x/sys/unix"
)

const (
	r0ServerSchemaVersion = 1
	r0ServerRole          = 2
	r0ServerQueueCapacity = 4096
)

var (
	r0ServerStartedAt    = time.Now()
	r0ServerConnectionID atomic.Uint64
	r0ServerSinkOnce     sync.Once
	r0ServerSink         *r0ServerEventSink
)

type r0ServerEventSink struct {
	queue  chan r0ServerWireEvent
	file   *os.File
	mu     sync.Mutex
	failed atomic.Bool
}

type r0ServerWireEvent struct {
	Schema          uint8
	Role            uint8
	Kind            uint8
	Phase           uint8
	Result          uint8
	TCPInfoValid    uint8
	Connection      uint64
	Sequence        uint64
	MonotonicNS     int64
	WallUnixNS      int64
	WriteIndex      uint64
	AttemptedBytes  uint64
	WrittenBytes    uint64
	TotalRetrans    uint32
	BytesRetrans    uint64
	SegmentsOut     uint32
	DataSegmentsOut uint32
}

type r0ServerHookSession struct {
	raw        net.Conn
	sink       *r0ServerEventSink
	mu         sync.Mutex
	connection uint64
	sequence   uint64
	closed     bool
}

func newR0ServerHook(connection stat.Connection, wireVersion uint32) r0ServerHook {
	if wireVersion != 1 && wireVersion != 4 {
		return nil
	}
	sink := loadR0ServerSink()
	if sink == nil {
		return nil
	}
	if sink.failed.Load() {
		_ = connection.Close()
		return nil
	}
	hook := &r0ServerHookSession{
		raw: connection, sink: sink, connection: r0ServerConnectionID.Add(1),
	}
	hook.Event(r0ServerPhaseSetup, r0ServerEventConnectionStart, 1)
	return hook
}

func loadR0ServerSink() *r0ServerEventSink {
	r0ServerSinkOnce.Do(func() {
		descriptor, err := strconv.Atoi(os.Getenv("ARTX_R0_SERVER_TRACE_FD"))
		if err != nil || descriptor < 3 {
			return
		}
		file := os.NewFile(uintptr(descriptor), "artx-r0-server-trace")
		if file == nil {
			return
		}
		r0ServerSink = &r0ServerEventSink{
			queue: make(chan r0ServerWireEvent, r0ServerQueueCapacity), file: file,
		}
		go func() {
			for event := range r0ServerSink.queue {
				if err := r0ServerSink.write(event, false); err != nil {
					r0ServerSink.failed.Store(true)
				}
			}
		}()
	})
	return r0ServerSink
}

func (sink *r0ServerEventSink) write(event r0ServerWireEvent, syncFile bool) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if _, err := fmt.Fprintf(sink.file,
		"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
		event.Schema, event.Role, event.Kind, event.Phase, event.Result, event.TCPInfoValid,
		event.Connection, event.Sequence, event.MonotonicNS, event.WallUnixNS, event.WriteIndex,
		event.AttemptedBytes, event.WrittenBytes, event.TotalRetrans, event.BytesRetrans,
		event.SegmentsOut, event.DataSegmentsOut); err != nil {
		return err
	}
	if syncFile {
		return sink.file.Sync()
	}
	return nil
}

func (hook *r0ServerHookSession) Event(phase, kind, result uint8) {
	hook.emit(phase, kind, result, 0, 0)
}

func (hook *r0ServerHookSession) IOEvent(phase, kind, result uint8, attempted, accepted int) {
	hook.emit(phase, kind, result, attempted, accepted)
}

func (hook *r0ServerHookSession) Close() {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if hook.closed {
		return
	}
	hook.closed = true
	hook.emitLocked(r0ServerPhaseSetup, r0ServerEventConnectionEnd, 1, 0, 0)
}

func (hook *r0ServerHookSession) emit(phase, kind, result uint8, attempted, accepted int) {
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if hook.closed {
		return
	}
	hook.emitLocked(phase, kind, result, attempted, accepted)
}

func (hook *r0ServerHookSession) emitLocked(phase, kind, result uint8, attempted, accepted int) {
	now := time.Now()
	hook.sequence++
	event := r0ServerWireEvent{
		Schema: r0ServerSchemaVersion, Role: r0ServerRole, Kind: kind, Phase: phase, Result: result,
		Connection: hook.connection, Sequence: hook.sequence, MonotonicNS: time.Since(r0ServerStartedAt).Nanoseconds(),
		WallUnixNS: now.UnixNano(), AttemptedBytes: uint64(attempted), WrittenBytes: uint64(accepted),
	}
	if info, ok := sampleR0ServerTCPInfo(hook.raw); ok {
		event.TCPInfoValid = 1
		event.TotalRetrans = info.Total_retrans
		event.BytesRetrans = info.Bytes_retrans
		event.SegmentsOut = info.Segs_out
		event.DataSegmentsOut = info.Data_segs_out
	}
	select {
	case hook.sink.queue <- event:
	default:
		if hook.sink.failed.CompareAndSwap(false, true) {
			overflow := event
			overflow.Kind = r0ServerEventQueueOverflow
			overflow.Result = 2
			overflow.AttemptedBytes = 0
			overflow.WrittenBytes = 0
			_ = hook.sink.write(overflow, true)
		}
		_ = hook.raw.Close()
	}
}

func sampleR0ServerTCPInfo(connection net.Conn) (*unix.TCPInfo, bool) {
	connection = stat.TryUnwrapStatsConn(connection)
	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		return nil, false
	}
	rawConnection, err := syscallConnection.SyscallConn()
	if err != nil {
		return nil, false
	}
	var info *unix.TCPInfo
	controlErr := rawConnection.Control(func(descriptor uintptr) {
		info, _ = unix.GetsockoptTCPInfo(int(descriptor), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	return info, controlErr == nil && info != nil
}
