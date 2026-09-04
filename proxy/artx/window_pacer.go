package artx

import (
	"sync"
	"time"
)

const (
	// A peer that keeps at least this much of the live window busy over one
	// interval is asking for more window; anything less is served fine by the
	// window it already has.
	windowGrowthFillPercent = uint64(50)

	minWindowGrowthInterval     = 20 * time.Millisecond
	maxWindowGrowthInterval     = 500 * time.Millisecond
	defaultWindowGrowthInterval = 100 * time.Millisecond
)

// windowPacer grows one direction of a connection's flow-control window while
// that direction stays busy, instead of handing out the whole negotiated window
// at handshake time. The negotiated scale becomes the ceiling of a ramp.
type windowPacer struct {
	mu        sync.Mutex
	scale     uint32
	delivered uint64
	deadline  time.Time
	interval  time.Duration
	ceiling   func() uint32
	// grow reports whether the rung was actually taken. The uplink declines
	// when the host's window budget cannot cover it.
	grow func(streamDelta, connectionDelta uint32) (bool, error)
	now  func() time.Time
}

// windowPacing carries what a connection needs to build its pacers once its
// windows exist. A nil pacing means the connection opens at its negotiated
// window and stays there.
type windowPacing struct {
	rtt     autoRTTSample
	ceiling func() uint32
	// ledger is this connection's share of the host's window budget. Only the
	// uplink spends it: downlink credit is memory the client commits, not this
	// host.
	ledger *windowCreditLedger
}

func newWindowPacer(rtt autoRTTSample, ceiling func() uint32, grow func(streamDelta, connectionDelta uint32) (bool, error)) *windowPacer {
	return &windowPacer{
		interval: windowGrowthInterval(rtt),
		ceiling:  ceiling,
		grow:     grow,
		now:      time.Now,
	}
}

// newDownlinkPacer grows the credit the client granted us for server-to-client
// data. Growing it is purely local bookkeeping: the client already advertised
// the full window and simply has not been asked to fill it yet.
func newDownlinkPacer(pacing *windowPacing, window *sendWindow) *windowPacer {
	if pacing == nil {
		return nil
	}
	return newWindowPacer(pacing.rtt, pacing.ceiling, func(streamDelta, connectionDelta uint32) (bool, error) {
		window.grow(streamDelta, connectionDelta)
		return true, nil
	})
}

// newUplinkPacer grows the credit we grant the client for client-to-server
// data. Here growth costs memory on this host, so it is spent only on a client
// that is demonstrably filling what it already has.
func newUplinkPacer(pacing *windowPacing, window *sendWindow, writer *lockedFrameWriter) *windowPacer {
	if pacing == nil {
		return nil
	}
	ledger := pacing.ledger
	return newWindowPacer(pacing.rtt, pacing.ceiling, func(streamDelta, connectionDelta uint32) (bool, error) {
		// The budget is charged the connection window, the cost unit that
		// bounds a connection's total in-flight bytes. A rung that does not fit
		// is not taken, and the next busy interval asks again.
		if !ledger.reserve(uint64(connectionDelta)) {
			return false, nil
		}
		return true, grantReceiveCredit(writer, window, streamDelta, connectionDelta)
	})
}

// windowGrowthInterval paces growth at roughly one round trip, the shortest
// span over which a peer's reaction to more window is visible. Both ends of the
// range are clamped so a bogus RTT sample cannot turn the ramp into a spike or
// stall it altogether.
func windowGrowthInterval(rtt autoRTTSample) time.Duration {
	if !rtt.valid || rtt.micros == 0 {
		return defaultWindowGrowthInterval
	}
	interval := time.Duration(rtt.micros) * time.Microsecond
	return min(max(interval, minWindowGrowthInterval), maxWindowGrowthInterval)
}

// observe records bytes this direction just moved and grows the window by one
// rung when an interval closes on a busy connection.
func (pacer *windowPacer) observe(delivered int) error {
	if pacer == nil || delivered <= 0 {
		return nil
	}
	pacer.mu.Lock()
	now := pacer.now()
	if pacer.deadline.IsZero() {
		pacer.deadline = now.Add(pacer.interval)
	}
	pacer.delivered += uint64(delivered)
	if now.Before(pacer.deadline) {
		pacer.mu.Unlock()
		return nil
	}
	busy := pacer.delivered
	scale := pacer.scale
	pacer.delivered = 0
	pacer.deadline = now.Add(pacer.interval)
	// The ceiling is re-read every interval on purpose: a connection accepted
	// while the host was loaded is not sentenced to the compatibility window
	// for life.
	if scale >= pacer.currentCeiling() || !windowIsBusy(busy, scale) {
		pacer.mu.Unlock()
		return nil
	}
	// One rung doubles the window, so the delta equals the window it replaces.
	// The lock is held across the grant so the scale advances only once the
	// window behind it really did, and never twice for one rung.
	granted, err := pacer.grow(InitialStreamWindow<<scale, InitialConnectionWindow<<scale)
	if granted {
		pacer.scale = scale + 1
	}
	pacer.mu.Unlock()
	return err
}

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

// windowIsBusy measures against the stream window rather than the connection
// window because this relay carries a single stream: the stream window is what
// actually runs out.
func windowIsBusy(delivered uint64, scale uint32) bool {
	live := uint64(InitialStreamWindow) << scale
	return delivered >= live*windowGrowthFillPercent/100
}
