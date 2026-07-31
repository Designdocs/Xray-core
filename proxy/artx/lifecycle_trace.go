package artx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	lifecycleServerTraceFDEnvironment = "ARTX_LIFECYCLE_SERVER_TRACE_FD"
	lifecyclePacketMagic              = "AXM1"
	lifecyclePacketVersion            = byte(1)
	lifecyclePacketHeaderSize         = 52
)

var (
	lifecycleServerTraceOnce sync.Once
	lifecycleServerSink      *lifecycleServerTraceSink
)

type lifecycleServerTraceEvent struct {
	SchemaVersion  int    `json:"schema_version"`
	Role           string `json:"role"`
	AssociationID  uint64 `json:"association_id"`
	Disposition    string `json:"disposition"`
	Event          string `json:"event"`
	MonotonicNS    int64  `json:"monotonic_ns"`
	TerminalReason string `json:"terminal_reason,omitempty"`
}

type lifecycleServerTraceSink struct {
	started time.Time
	file    *os.File
	mu      sync.Mutex
	err     error
}

type udpAssociationLifecycle struct {
	sink        *lifecycleServerTraceSink
	mu          sync.Mutex
	association uint64
	disposition string
	terminal    bool
}

func newUDPAssociationLifecycle() *udpAssociationLifecycle {
	sink := loadLifecycleServerTraceSink()
	if sink == nil {
		return nil
	}
	return &udpAssociationLifecycle{sink: sink}
}

func loadLifecycleServerTraceSink() *lifecycleServerTraceSink {
	lifecycleServerTraceOnce.Do(func() {
		descriptor, err := strconv.Atoi(os.Getenv(lifecycleServerTraceFDEnvironment))
		if err != nil || descriptor < 3 {
			return
		}
		file := os.NewFile(uintptr(descriptor), "artx-lifecycle-server-trace")
		if file != nil {
			lifecycleServerSink = &lifecycleServerTraceSink{started: time.Now(), file: file}
		}
	})
	return lifecycleServerSink
}

func (lifecycle *udpAssociationLifecycle) Observe(payload []byte) error {
	association, disposition, observed := parseServerLifecycleAssociation(payload)
	if !observed {
		return nil
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.association != 0 {
		if lifecycle.association != association || lifecycle.disposition != disposition {
			return errors.New("artx lifecycle association changed within one UDP relay")
		}
		return nil
	}
	if err := lifecycle.sink.write(lifecycleServerTraceEvent{
		SchemaVersion: 1,
		Role:          "edge",
		AssociationID: association,
		Disposition:   disposition,
		Event:         "opened",
	}, false); err != nil {
		return err
	}
	lifecycle.association = association
	lifecycle.disposition = disposition
	return nil
}

func (lifecycle *udpAssociationLifecycle) Close(reason string) error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.association == 0 || lifecycle.terminal {
		return nil
	}
	lifecycle.terminal = true
	return lifecycle.sink.write(lifecycleServerTraceEvent{
		SchemaVersion:  1,
		Role:           "edge",
		AssociationID:  lifecycle.association,
		Disposition:    lifecycle.disposition,
		Event:          "terminal",
		TerminalReason: reason,
	}, true)
}

func (sink *lifecycleServerTraceSink) write(event lifecycleServerTraceEvent, syncFile bool) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	event.MonotonicNS = time.Since(sink.started).Nanoseconds()
	sink.err = json.NewEncoder(sink.file).Encode(event)
	if sink.err == nil && syncFile {
		sink.err = sink.file.Sync()
	}
	return sink.err
}

func parseServerLifecycleAssociation(payload []byte) (uint64, string, bool) {
	if len(payload) < lifecyclePacketHeaderSize ||
		string(payload[:4]) != lifecyclePacketMagic ||
		payload[4] != lifecyclePacketVersion {
		return 0, "", false
	}
	payloadLength := int(binary.BigEndian.Uint16(payload[32:34]))
	if len(payload) != lifecyclePacketHeaderSize+payloadLength ||
		binary.BigEndian.Uint64(payload[16:24]) != 0 {
		return 0, "", false
	}
	payloadHash := sha256.Sum256(payload[lifecyclePacketHeaderSize:])
	if !bytes.Equal(payloadHash[:16], payload[36:52]) {
		return 0, "", false
	}
	disposition := ""
	switch payload[5] {
	case 3:
		disposition = "normal"
	case 4:
		disposition = "cancel"
	default:
		return 0, "", false
	}
	association := binary.BigEndian.Uint64(payload[8:16])
	return association, disposition, association != 0
}
