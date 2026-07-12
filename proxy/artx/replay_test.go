package artx

import (
	"errors"
	"testing"
	"time"
)

func TestArtXReplayCacheRejectsReplayAndExpiresEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newReplayCache(2, 180*time.Second, func() time.Time { return now })
	key := replayKey{1}

	if err := cache.add(key); err != nil {
		t.Fatal(err)
	}
	if err := cache.add(key); !errors.Is(err, errReplay) {
		t.Fatalf("replay error = %v", err)
	}
	now = now.Add(181 * time.Second)
	if err := cache.add(key); err != nil {
		t.Fatalf("expired entry rejected: %v", err)
	}
}

func TestArtXReplayCacheFailsClosedWhenFull(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newReplayCache(1, 180*time.Second, func() time.Time { return now })

	if err := cache.add(replayKey{1}); err != nil {
		t.Fatal(err)
	}
	if err := cache.add(replayKey{2}); !errors.Is(err, errReplayCacheFull) {
		t.Fatalf("full cache error = %v", err)
	}
}

func TestArtXReplayCacheReclaimsOnlyExpiredFIFOEntries(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newReplayCache(3, 180*time.Second, func() time.Time { return now })
	for value := byte(1); value <= 3; value++ {
		if err := cache.add(replayKey{value}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}

	now = now.Add(177 * time.Second)
	if err := cache.add(replayKey{4}); err != nil {
		t.Fatalf("failed to reuse expired capacity: %v", err)
	}
	if len(cache.entries) != 3 {
		t.Fatalf("cache size = %d, want 3", len(cache.entries))
	}
	if _, found := cache.entries[replayKey{1}]; found {
		t.Fatal("oldest expired entry was not reclaimed")
	}
	if _, found := cache.entries[replayKey{2}]; !found {
		t.Fatal("unexpired FIFO entry was scanned away")
	}
}
