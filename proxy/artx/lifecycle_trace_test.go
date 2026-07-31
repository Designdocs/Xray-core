package artx

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUDPAssociationLifecycleEmitsExactOpenAndTerminalEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "edge.ndjson")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle := &udpAssociationLifecycle{
		sink: &lifecycleServerTraceSink{started: time.Now(), file: file},
	}
	payload := make([]byte, lifecyclePacketHeaderSize)
	copy(payload, lifecyclePacketMagic)
	payload[4] = lifecyclePacketVersion
	payload[5] = 3
	binary.BigEndian.PutUint64(payload[8:16], 110001)
	payloadHash := sha256.Sum256(nil)
	copy(payload[36:52], payloadHash[:16])
	if err = lifecycle.Observe(payload); err != nil {
		t.Fatal(err)
	}
	if err = lifecycle.Close("client_fin"); err != nil {
		t.Fatal(err)
	}
	if err = lifecycle.Close("duplicate"); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	read, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	var events []lifecycleServerTraceEvent
	scanner := bufio.NewScanner(read)
	for scanner.Scan() {
		var event lifecycleServerTraceEvent
		if err = json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Event != "opened" ||
		events[1].Event != "terminal" || events[0].AssociationID != 110001 ||
		events[1].AssociationID != 110001 ||
		events[1].TerminalReason != "client_fin" ||
		events[1].MonotonicNS < events[0].MonotonicNS {
		t.Fatalf("unexpected lifecycle events: %+v", events)
	}
}
