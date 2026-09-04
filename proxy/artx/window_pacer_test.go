package artx

import (
	"testing"
	"time"
)

// testClock is a hand-cranked clock so growth decisions are driven by the test
// rather than by wall time.
type testClock struct {
	now time.Time
}

func (clock *testClock) advance(step time.Duration) { clock.now = clock.now.Add(step) }

func newTestPacer(t *testing.T, ceiling func() uint32) (*windowPacer, *sendWindow, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Unix(0, 0)}
	pacer := newWindowPacer(autoRTTSample{}, ceiling)
	pacer.now = func() time.Time { return clock.now }
	return pacer, newSendWindowWithLimits(legacyFlowControlLimits()), clock
}

// deliver hands the pacer a full interval worth of traffic: the bytes arrive
// inside the interval, then the clock crosses the deadline.
func deliver(pacer *windowPacer, window *sendWindow, bytes int, clock *testClock) {
	pacer.observe(window, bytes)
	clock.advance(pacer.interval + time.Millisecond)
	pacer.observe(window, 1)
}

func windowSizes(window *sendWindow) (uint32, uint32) {
	window.mu.Lock()
	defer window.mu.Unlock()
	return window.maxStream, window.maxConn
}

func TestWindowGrowthIntervalTracksRTT(t *testing.T) {
	cases := []struct {
		name string
		rtt  autoRTTSample
		want time.Duration
	}{
		{"no sample", autoRTTSample{}, defaultWindowGrowthInterval},
		{"zero sample", autoRTTSample{micros: 0, valid: true}, defaultWindowGrowthInterval},
		{"typical", autoRTTSample{micros: 200_000, valid: true}, 200 * time.Millisecond},
		{"clamped low", autoRTTSample{micros: 1_000, valid: true}, minWindowGrowthInterval},
		{"clamped high", autoRTTSample{micros: 2_000_000, valid: true}, maxWindowGrowthInterval},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := windowGrowthInterval(testCase.rtt); got != testCase.want {
				t.Fatalf("windowGrowthInterval() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestPacerGrowsOneRungPerBusyInterval(t *testing.T) {
	pacer, window, clock := newTestPacer(t, func() uint32 { return MaxWindowScale })

	stream, connection := windowSizes(window)
	if stream != InitialStreamWindow || connection != InitialConnectionWindow {
		t.Fatalf("opening window = %d/%d, want the compatibility window", stream, connection)
	}

	for rung := uint32(1); rung <= MaxWindowScale; rung++ {
		deliver(pacer, window, int(uint64(InitialStreamWindow)<<(rung-1)), clock)
		if got := pacer.Scale(); got != rung {
			t.Fatalf("after %d busy intervals scale = %d, want %d", rung, got, rung)
		}
		stream, connection = windowSizes(window)
		if stream != InitialStreamWindow<<rung || connection != InitialConnectionWindow<<rung {
			t.Fatalf("at rung %d window = %d/%d, want %d/%d",
				rung, stream, connection, InitialStreamWindow<<rung, InitialConnectionWindow<<rung)
		}
	}

	// The ceiling is the end of the ramp, not a rung it can pass.
	deliver(pacer, window, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	if got := pacer.Scale(); got != MaxWindowScale {
		t.Fatalf("scale = %d past the ceiling, want %d", got, MaxWindowScale)
	}
}

func TestPacerLeavesAnIdleConnectionAtTheCompatibilityWindow(t *testing.T) {
	pacer, window, clock := newTestPacer(t, func() uint32 { return MaxWindowScale })

	// A trickle: well under half the live stream window every interval.
	for range 10 {
		deliver(pacer, window, int(uint64(InitialStreamWindow)/8), clock)
	}

	if got := pacer.Scale(); got != 0 {
		t.Fatalf("idle connection grew to scale %d, want 0", got)
	}
	stream, connection := windowSizes(window)
	if stream != InitialStreamWindow || connection != InitialConnectionWindow {
		t.Fatalf("idle window = %d/%d, want the compatibility window", stream, connection)
	}
}

func TestPacerStopsAtTheCeiling(t *testing.T) {
	pacer, window, clock := newTestPacer(t, func() uint32 { return 2 })

	for range 6 {
		deliver(pacer, window, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	}

	if got := pacer.Scale(); got != 2 {
		t.Fatalf("scale = %d, want the ceiling 2", got)
	}
	stream, connection := windowSizes(window)
	if stream != InitialStreamWindow<<2 || connection != InitialConnectionWindow<<2 {
		t.Fatalf("window = %d/%d, want %d/%d", stream, connection, InitialStreamWindow<<2, InitialConnectionWindow<<2)
	}
}

// A connection that arrives while the host is loaded is not sentenced to the
// compatibility window for life: the ceiling is re-read on every decision, so
// it grows once the budget frees up. This is the case the accept-time clamp
// alone cannot fix.
func TestPacerFollowsACeilingThatRisesLater(t *testing.T) {
	ceiling := uint32(0)
	pacer, window, clock := newTestPacer(t, func() uint32 { return ceiling })

	for range 3 {
		deliver(pacer, window, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	}
	if got := pacer.Scale(); got != 0 {
		t.Fatalf("scale = %d under a zero ceiling, want 0", got)
	}

	ceiling = 3
	for range 3 {
		deliver(pacer, window, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	}
	if got := pacer.Scale(); got != 3 {
		t.Fatalf("scale = %d after the ceiling rose, want 3", got)
	}
}

// Growth raises the live credit and the ceiling together, so credit the peer
// already had in flight still fits when it lands. Getting this wrong does not
// slow a connection down, it kills it on the overflow guard.
func TestGrowKeepsAnInFlightReplenishValid(t *testing.T) {
	window := newSendWindowWithLimits(legacyFlowControlLimits())

	inFlight := 64 * 1024
	if err := window.consume(inFlight); err != nil {
		t.Fatalf("consume() = %v", err)
	}
	window.grow(InitialStreamWindow, InitialConnectionWindow)

	if err := window.update(0, uint32(inFlight)); err != nil {
		t.Fatalf("connection replenish after grow = %v, want nil", err)
	}
	if err := window.update(ClientStreamID, uint32(inFlight)); err != nil {
		t.Fatalf("stream replenish after grow = %v, want nil", err)
	}

	window.mu.Lock()
	defer window.mu.Unlock()
	if window.connection != window.maxConn || window.stream != window.maxStream {
		t.Fatalf("after the peer caught up window = %d/%d, want it full at %d/%d",
			window.stream, window.connection, window.maxStream, window.maxConn)
	}
}

func TestNilPacerIsInert(t *testing.T) {
	var pacer *windowPacer
	window := newSendWindowWithLimits(legacyFlowControlLimits())

	pacer.observe(window, 1<<20)

	if got := pacer.Scale(); got != 0 {
		t.Fatalf("nil pacer scale = %d, want 0", got)
	}
	stream, connection := windowSizes(window)
	if stream != InitialStreamWindow || connection != InitialConnectionWindow {
		t.Fatalf("nil pacer moved the window to %d/%d", stream, connection)
	}
}

// Manual flow control opts out of pacing: an operator who pinned a scale asked
// for that window, not for a ramp.
func TestDownlinkPacerOnlyExistsInAutoMode(t *testing.T) {
	withSharedPressureGovernor(t, nil)
	server := newArtXTestServer(t)

	if pacer := server.downlinkPacer(streamWindowPlan{scale: 3, staticCeiling: 3}); pacer != nil {
		t.Fatal("manual flow control produced a pacer")
	}
	pacer := server.downlinkPacer(streamWindowPlan{scale: 0, staticCeiling: 4, auto: true})
	if pacer == nil {
		t.Fatal("auto flow control produced no pacer")
	}
	if got := pacer.currentCeiling(); got != MaxWindowScale {
		t.Fatalf("auto pacer ceiling = %d, want %d", got, MaxWindowScale)
	}
}
