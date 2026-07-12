package artx

import "sync/atomic"

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
