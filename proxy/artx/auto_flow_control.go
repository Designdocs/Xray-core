package artx

import (
	"math/bits"
	"sync"
)

const (
	// DefaultAutoTargetRate is the per-connection target throughput used when
	// the plan places no limit on the user: 200 Mbps expressed in bytes per
	// second.
	DefaultAutoTargetRate = uint64(25_000_000)

	// autoWindowSafetyFactor over-provisions the bandwidth-delay product so a
	// single window stall does not cap the transfer at the measured rate.
	autoWindowSafetyFactor = uint64(2)

	microsPerSecond = uint64(1_000_000)
)

// autoRTTSample carries a smoothed round-trip time in microseconds read from
// the underlying socket. An invalid sample means the platform could not report
// one and the caller must fall back to the node maximum.
type autoRTTSample struct {
	micros uint64
	valid  bool
}

// UserRateLookup resolves the plan rate limit of an authenticated user, in
// bytes per second. Zero means "no limit", which selects DefaultAutoTargetRate.
type UserRateLookup func(userEmail string) uint64

// autoWindowNeeded is targetRate * rtt * autoWindowSafetyFactor, computed in
// 128-bit and saturated instead of wrapping.
func autoWindowNeeded(rttMicros, targetRate uint64) uint64 {
	hi, lo := bits.Mul64(targetRate, rttMicros)
	if hi >= microsPerSecond {
		return ^uint64(0)
	}
	needed, _ := bits.Div64(hi, lo, microsPerSecond)
	if needed > ^uint64(0)/autoWindowSafetyFactor {
		return ^uint64(0)
	}
	return needed * autoWindowSafetyFactor
}

// autoWindowScaleForBDP returns the smallest scale in [0, MaxWindowScale] whose
// stream window covers the bandwidth-delay product. A zero targetRate means the
// user is unlimited and gets DefaultAutoTargetRate.
func autoWindowScaleForBDP(rttMicros, targetRate uint64) uint32 {
	if targetRate == 0 {
		targetRate = DefaultAutoTargetRate
	}
	needed := autoWindowNeeded(rttMicros, targetRate)
	for scale := uint32(0); scale < MaxWindowScale; scale++ {
		if uint64(InitialStreamWindow)<<scale >= needed {
			return scale
		}
	}
	return MaxWindowScale
}

// negotiateAutoWindowScale is the auto policy counterpart of
// negotiateWindowScale. It keeps every legacy guard (wire version, client
// offer validity, node opt-out) and then sizes the window from the measured
// bandwidth-delay product, clamped by the client offer, the node maximum and
// the host pressure ceiling.
//
// The second return value reports that the RTT was unavailable and the node
// maximum was used instead.
func negotiateAutoWindowScale(
	settings map[uint16]uint32,
	serverMaximum, wireVersion uint32,
	rtt autoRTTSample,
	targetRate uint64,
	pressureCeiling uint32,
) (uint32, bool) {
	offered := negotiateWindowScale(settings, serverMaximum, wireVersion)
	if offered == 0 {
		return 0, false
	}
	if !rtt.valid || rtt.micros == 0 {
		return min(offered, min(serverMaximum, pressureCeiling)), true
	}
	scale := autoWindowScaleForBDP(rtt.micros, targetRate)
	return min(scale, min(offered, min(serverMaximum, pressureCeiling))), false
}

var sharedUserRates struct {
	mu     sync.RWMutex
	lookup UserRateLookup
}

// SetSharedUserRateLookup installs the process-wide plan rate resolver used by
// every ArtX inbound that has no resolver of its own. Passing nil removes it,
// which makes every user fall back to DefaultAutoTargetRate.
func SetSharedUserRateLookup(lookup UserRateLookup) {
	sharedUserRates.mu.Lock()
	sharedUserRates.lookup = lookup
	sharedUserRates.mu.Unlock()
}

// SharedUserRateLookup returns the process-wide plan rate resolver, or nil.
func SharedUserRateLookup() UserRateLookup {
	sharedUserRates.mu.RLock()
	lookup := sharedUserRates.lookup
	sharedUserRates.mu.RUnlock()
	return lookup
}
