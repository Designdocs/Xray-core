package artx

import (
	"context"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
)

func TestRuntimeStatsMirrorUsesInboundTag(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	counters := runtimeCounters{manager: manager}
	counters.bind("artx-canary")
	counters.add(runtimeCounterTotalConnections, 1)
	counters.add(runtimeCounterActiveConnections, 1)
	counters.add(runtimeCounterAuthenticationSuccess, 1)
	counters.add(runtimeCounterAuthenticationFailure, 2)
	counters.add(runtimeCounterReplayRejected, 1)
	counters.add(runtimeCounterFallbackHits, 2)
	counters.add(runtimeCounterFallbackErrors, 1)
	counters.add(runtimeCounterActiveConnections, -1)

	got := RuntimeStatsFromManager(manager, "artx-canary")
	want := RuntimeStats{
		TotalConnections:      1,
		AuthenticationSuccess: 1,
		AuthenticationFailure: 2,
		ReplayRejected:        1,
		FallbackHits:          2,
		FallbackErrors:        1,
	}
	if got != want {
		t.Fatalf("RuntimeStatsFromManager() = %#v, want %#v", got, want)
	}
	if other := RuntimeStatsFromManager(manager, "other-node"); other != (RuntimeStats{}) {
		t.Fatalf("other inbound stats = %#v, want zero", other)
	}
}

func TestRuntimeStatsFromManagerClampsNegativeGauge(t *testing.T) {
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	counter, err := manager.RegisterCounter(runtimeCounterName("artx-canary", runtimeCounterActiveConnections))
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(-1)

	if got := RuntimeStatsFromManager(manager, "artx-canary").ActiveConnections; got != 0 {
		t.Fatalf("ActiveConnections = %d, want zero", got)
	}
}
