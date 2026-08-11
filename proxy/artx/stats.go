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
	NativeActive          uint64
	NativeAccepted        uint64
	NativeRejected        uint64
	NativeDatagramsUp     uint64
	NativeDatagramsDown   uint64
	NativeBytesUp         uint64
	NativeBytesDown       uint64
	NativeTransportErrors uint64
	NativeTargetErrors    uint64
}

type runtimeCounters struct {
	activeConnections     atomic.Uint64
	totalConnections      atomic.Uint64
	authenticationSuccess atomic.Uint64
	authenticationFailure atomic.Uint64
	replayRejected        atomic.Uint64
	fallbackHits          atomic.Uint64
	fallbackErrors        atomic.Uint64
	nativeActive          atomic.Uint64
	nativeAccepted        atomic.Uint64
	nativeRejected        atomic.Uint64
	nativeDatagramsUp     atomic.Uint64
	nativeDatagramsDown   atomic.Uint64
	nativeBytesUp         atomic.Uint64
	nativeBytesDown       atomic.Uint64
	nativeTransportErrors atomic.Uint64
	nativeTargetErrors    atomic.Uint64
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
	runtimeCounterNativeActive
	runtimeCounterNativeAccepted
	runtimeCounterNativeRejected
	runtimeCounterNativeDatagramsUp
	runtimeCounterNativeDatagramsDown
	runtimeCounterNativeBytesUp
	runtimeCounterNativeBytesDown
	runtimeCounterNativeTransportErrors
	runtimeCounterNativeTargetErrors
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
	"native_active_associations",
	"native_accepted_associations",
	"native_rejected_associations",
	"native_datagrams_up",
	"native_datagrams_down",
	"native_bytes_up",
	"native_bytes_down",
	"native_transport_errors",
	"native_target_errors",
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
		NativeActive:          counters.nativeActive.Load(),
		NativeAccepted:        counters.nativeAccepted.Load(),
		NativeRejected:        counters.nativeRejected.Load(),
		NativeDatagramsUp:     counters.nativeDatagramsUp.Load(),
		NativeDatagramsDown:   counters.nativeDatagramsDown.Load(),
		NativeBytesUp:         counters.nativeBytesUp.Load(),
		NativeBytesDown:       counters.nativeBytesDown.Load(),
		NativeTransportErrors: counters.nativeTransportErrors.Load(),
		NativeTargetErrors:    counters.nativeTargetErrors.Load(),
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
		counter, _ := counters.manager.GetOrRegisterCounter(runtimeCounterName(inboundTag, metric))
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
	case runtimeCounterNativeActive:
		addAtomicUint64(&counters.nativeActive, delta)
	case runtimeCounterNativeAccepted:
		addAtomicUint64(&counters.nativeAccepted, delta)
	case runtimeCounterNativeRejected:
		addAtomicUint64(&counters.nativeRejected, delta)
	case runtimeCounterNativeDatagramsUp:
		addAtomicUint64(&counters.nativeDatagramsUp, delta)
	case runtimeCounterNativeDatagramsDown:
		addAtomicUint64(&counters.nativeDatagramsDown, delta)
	case runtimeCounterNativeBytesUp:
		addAtomicUint64(&counters.nativeBytesUp, delta)
	case runtimeCounterNativeBytesDown:
		addAtomicUint64(&counters.nativeBytesDown, delta)
	case runtimeCounterNativeTransportErrors:
		addAtomicUint64(&counters.nativeTransportErrors, delta)
	case runtimeCounterNativeTargetErrors:
		addAtomicUint64(&counters.nativeTargetErrors, delta)
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
		NativeActive:          value(runtimeCounterNativeActive),
		NativeAccepted:        value(runtimeCounterNativeAccepted),
		NativeRejected:        value(runtimeCounterNativeRejected),
		NativeDatagramsUp:     value(runtimeCounterNativeDatagramsUp),
		NativeDatagramsDown:   value(runtimeCounterNativeDatagramsDown),
		NativeBytesUp:         value(runtimeCounterNativeBytesUp),
		NativeBytesDown:       value(runtimeCounterNativeBytesDown),
		NativeTransportErrors: value(runtimeCounterNativeTransportErrors),
		NativeTargetErrors:    value(runtimeCounterNativeTargetErrors),
	}
}
