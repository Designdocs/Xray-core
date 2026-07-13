package artx

import (
	"strings"
	"sync"
	"sync/atomic"

	featurestats "github.com/xtls/xray-core/features/stats"
)

type RuntimeStats struct {
	ActiveConnections     uint64
	TotalConnections      uint64
	AuthenticationSuccess uint64
	AuthenticationFailure uint64
	ReplayRejected        uint64
	FallbackHits          uint64
	FallbackErrors        uint64
}

type runtimeCounters struct {
	activeConnections     atomic.Uint64
	totalConnections      atomic.Uint64
	authenticationSuccess atomic.Uint64
	authenticationFailure atomic.Uint64
	replayRejected        atomic.Uint64
	fallbackHits          atomic.Uint64
	fallbackErrors        atomic.Uint64
	manager               featurestats.Manager
	bindMu                sync.Mutex
	managed               [runtimeCounterCount]featurestats.Counter
	managedBound          atomic.Bool
}

type runtimeCounter int

const (
	runtimeCounterActiveConnections runtimeCounter = iota
	runtimeCounterTotalConnections
	runtimeCounterAuthenticationSuccess
	runtimeCounterAuthenticationFailure
	runtimeCounterReplayRejected
	runtimeCounterFallbackHits
	runtimeCounterFallbackErrors
	runtimeCounterCount
)

var runtimeCounterNames = [...]string{
	"active_connections",
	"total_connections",
	"authentication_success",
	"authentication_failure",
	"replay_rejected",
	"fallback_hits",
	"fallback_errors",
}

func (counters *runtimeCounters) snapshot() RuntimeStats {
	return RuntimeStats{
		ActiveConnections:     counters.activeConnections.Load(),
		TotalConnections:      counters.totalConnections.Load(),
		AuthenticationSuccess: counters.authenticationSuccess.Load(),
		AuthenticationFailure: counters.authenticationFailure.Load(),
		ReplayRejected:        counters.replayRejected.Load(),
		FallbackHits:          counters.fallbackHits.Load(),
		FallbackErrors:        counters.fallbackErrors.Load(),
	}
}

func (counters *runtimeCounters) bind(inboundTag string) {
	if counters.manager == nil || strings.TrimSpace(inboundTag) == "" || counters.managedBound.Load() {
		return
	}

	counters.bindMu.Lock()
	defer counters.bindMu.Unlock()
	if counters.managedBound.Load() {
		return
	}
	for metric := runtimeCounter(0); metric < runtimeCounterCount; metric++ {
		counter, _ := featurestats.GetOrRegisterCounter(
			counters.manager,
			runtimeCounterName(inboundTag, metric),
		)
		counters.managed[metric] = counter
	}
	counters.managedBound.Store(true)
}

func (counters *runtimeCounters) add(metric runtimeCounter, delta int64) {
	switch metric {
	case runtimeCounterActiveConnections:
		addAtomicUint64(&counters.activeConnections, delta)
	case runtimeCounterTotalConnections:
		addAtomicUint64(&counters.totalConnections, delta)
	case runtimeCounterAuthenticationSuccess:
		addAtomicUint64(&counters.authenticationSuccess, delta)
	case runtimeCounterAuthenticationFailure:
		addAtomicUint64(&counters.authenticationFailure, delta)
	case runtimeCounterReplayRejected:
		addAtomicUint64(&counters.replayRejected, delta)
	case runtimeCounterFallbackHits:
		addAtomicUint64(&counters.fallbackHits, delta)
	case runtimeCounterFallbackErrors:
		addAtomicUint64(&counters.fallbackErrors, delta)
	}

	if counters.managedBound.Load() {
		if counter := counters.managed[metric]; counter != nil {
			counter.Add(delta)
		}
	}
}

func addAtomicUint64(counter *atomic.Uint64, delta int64) {
	if delta >= 0 {
		counter.Add(uint64(delta))
		return
	}
	counter.Add(^uint64(uint64(-delta) - 1))
}

func runtimeCounterName(inboundTag string, metric runtimeCounter) string {
	return "inbound>>>" + inboundTag + ">>>artx>>>" + runtimeCounterNames[metric]
}

// RuntimeStatsFromManager returns the process-lifetime ArtX counters for one
// inbound tag. Missing counters are reported as zero so callers can sample a
// node before its first connection without special casing startup.
func RuntimeStatsFromManager(manager featurestats.Manager, inboundTag string) RuntimeStats {
	if manager == nil || strings.TrimSpace(inboundTag) == "" {
		return RuntimeStats{}
	}
	value := func(metric runtimeCounter) uint64 {
		counter := manager.GetCounter(runtimeCounterName(inboundTag, metric))
		if counter == nil {
			return 0
		}
		current := counter.Value()
		if current <= 0 {
			return 0
		}
		return uint64(current)
	}

	return RuntimeStats{
		ActiveConnections:     value(runtimeCounterActiveConnections),
		TotalConnections:      value(runtimeCounterTotalConnections),
		AuthenticationSuccess: value(runtimeCounterAuthenticationSuccess),
		AuthenticationFailure: value(runtimeCounterAuthenticationFailure),
		ReplayRejected:        value(runtimeCounterReplayRejected),
		FallbackHits:          value(runtimeCounterFallbackHits),
		FallbackErrors:        value(runtimeCounterFallbackErrors),
	}
}
