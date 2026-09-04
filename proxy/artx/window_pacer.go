package artx

import (
	"sync"
	"time"
)

const (
	// windowGrowthFillPercent is how much of the live window the peer must
	// keep busy inside one measurement interval before the window is treated
	// as the limiter and grown one rung.
	windowGrowthFillPercent = uint64(50)

	// The measurement interval tracks the round-trip time, because that is the
	// timescale a credit window actually operates on: a window can be filled
	// at most once per round trip. The bounds keep a pathological RTT sample
	// from either stalling growth or making it jittery.
	minWindowGrowthInterval     = 20 * time.Millisecond
	maxWindowGrowthInterval     = 500 * time.Millisecond
	defaultWindowGrowthInterval = 100 * time.Millisecond
)

// windowPacer grows a credit window from the compatibility value towards a
// ceiling instead of committing the whole negotiated window up front.
//
// This turns the negotiated scale from an allocation into a ceiling. An idle
// connection costs the compatibility window no matter what it negotiated, so
// the host only pays for connections that actually move bytes. The ceiling is
// re-read on every decision, which is what lets a connection that arrived
// while the host was busy grow later once the budget frees up: credit-based
// flow control can never shrink a window, but it can withhold one.
type windowPacer struct {
	mu        sync.Mutex
	scale     uint32
	delivered uint64
	deadline  time.Time
	interval  time.Duration
	ceiling   func() uint32
	now       func() time.Time
}

// newWindowPacer builds a pacer that measures on the connection's own RTT and
// asks ceiling for the highest scale it may currently grow to. The ceiling
// function is called while the pacer lock is held, so it must not call back
// into the pacer.
func newWindowPacer(rtt autoRTTSample, ceiling func() uint32) *windowPacer {
	return &windowPacer{
		interval: windowGrowthInterval(rtt),
		ceiling:  ceiling,
		now:      time.Now,
	}
}

// windowGrowthInterval clamps a measured RTT into the range where growth
// decisions stay meaningful, and falls back to a fixed tick when the platform
// could not report one.
func windowGrowthInterval(rtt autoRTTSample) time.Duration {
	if !rtt.valid || rtt.micros == 0 {
		return defaultWindowGrowthInterval
	}
	interval := time.Duration(rtt.micros) * time.Microsecond
	return min(max(interval, minWindowGrowthInterval), maxWindowGrowthInterval)
}

// observe records bytes handed to the peer and grows the window by one rung
// when the peer kept the current window busy for a whole interval. A nil pacer
// is inert, which is how manual flow control opts out.
func (pacer *windowPacer) observe(window *sendWindow, delivered int) {
	if pacer == nil || window == nil || delivered <= 0 {
		return
	}
	pacer.mu.Lock()
	now := pacer.now()
	if pacer.deadline.IsZero() {
		pacer.deadline = now.Add(pacer.interval)
	}
	pacer.delivered += uint64(delivered)
	if now.Before(pacer.deadline) {
		pacer.mu.Unlock()
		return
	}
	busy := pacer.delivered
	scale := pacer.scale
	pacer.delivered = 0
	pacer.deadline = now.Add(pacer.interval)
	if scale >= pacer.currentCeiling() || !windowIsBusy(busy, scale) {
		pacer.mu.Unlock()
		return
	}
	pacer.scale = scale + 1
	pacer.mu.Unlock()
	// One rung doubles the window, so the delta equals the window it replaces.
	window.grow(InitialStreamWindow<<scale, InitialConnectionWindow<<scale)
}

// Scale reports the rung the pacer has grown to so far.
func (pacer *windowPacer) Scale() uint32 {
	if pacer == nil {
		return 0
	}
	pacer.mu.Lock()
	defer pacer.mu.Unlock()
	return pacer.scale
}

func (pacer *windowPacer) currentCeiling() uint32 {
	if pacer.ceiling == nil {
		return 0
	}
	return min(pacer.ceiling(), MaxWindowScale)
}

// windowIsBusy reports whether the peer consumed enough of the live window in
// one interval for the window itself to be the plausible limiter.
//
// The yardstick is the stream window rather than the connection window: this
// relay carries a single stream, so the per-stream credit is what actually
// binds, and measuring against the looser connection window would keep a
// saturated transfer below the threshold forever.
func windowIsBusy(delivered uint64, scale uint32) bool {
	live := uint64(InitialStreamWindow) << scale
	return delivered >= live*windowGrowthFillPercent/100
}
