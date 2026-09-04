package artx

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
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
	window := newSendWindowWithLimits(legacyFlowControlLimits())
	pacer := newDownlinkPacer(&windowPacing{ceiling: ceiling}, window)
	pacer.now = func() time.Time { return clock.now }
	return pacer, window, clock
}

// deliver hands the pacer a full interval worth of traffic: the bytes arrive
// inside the interval, then the clock crosses the deadline.
func deliver(t *testing.T, pacer *windowPacer, bytes int, clock *testClock) {
	t.Helper()
	if err := pacer.observe(bytes); err != nil {
		t.Fatalf("observe() = %v", err)
	}
	clock.advance(pacer.interval + time.Millisecond)
	if err := pacer.observe(1); err != nil {
		t.Fatalf("observe() = %v", err)
	}
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
		deliver(t, pacer, int(uint64(InitialStreamWindow)<<(rung-1)), clock)
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
	deliver(t, pacer, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	if got := pacer.Scale(); got != MaxWindowScale {
		t.Fatalf("scale = %d past the ceiling, want %d", got, MaxWindowScale)
	}
}

func TestPacerLeavesAnIdleConnectionAtTheCompatibilityWindow(t *testing.T) {
	pacer, window, clock := newTestPacer(t, func() uint32 { return MaxWindowScale })

	// A trickle: well under half the live stream window every interval.
	for range 10 {
		deliver(t, pacer, int(uint64(InitialStreamWindow)/8), clock)
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
		deliver(t, pacer, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
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
	pacer, _, clock := newTestPacer(t, func() uint32 { return ceiling })

	for range 3 {
		deliver(t, pacer, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	}
	if got := pacer.Scale(); got != 0 {
		t.Fatalf("scale = %d under a zero ceiling, want 0", got)
	}

	ceiling = 3
	for range 3 {
		deliver(t, pacer, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
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

	if err := pacer.observe(1 << 20); err != nil {
		t.Fatalf("observe() = %v", err)
	}

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
func TestPacingOnlyExistsInAutoMode(t *testing.T) {
	withSharedPressureGovernor(t, nil)
	server := newArtXTestServer(t)

	if pacing := server.windowPacing(streamWindowPlan{scale: 3, staticCeiling: 3}); pacing != nil {
		t.Fatal("manual flow control produced a pacing plan")
	}
	pacing := server.windowPacing(streamWindowPlan{scale: 0, staticCeiling: 4, auto: true})
	if pacing == nil {
		t.Fatal("auto flow control produced no pacing plan")
	}
	if newDownlinkPacer(nil, nil) != nil || newUplinkPacer(nil, nil, nil) != nil {
		t.Fatal("a nil pacing plan produced a pacer")
	}
	pacer := newDownlinkPacer(pacing, newSendWindowWithLimits(legacyFlowControlLimits()))
	if got := pacer.currentCeiling(); got != MaxWindowScale {
		t.Fatalf("auto pacer ceiling = %d, want %d", got, MaxWindowScale)
	}
}

// The uplink pays for its window in memory on this host, so credit reaches the
// client one rung at a time and the server's own bookkeeping moves with it.
func TestUplinkPacerGrantsCreditARungAtATime(t *testing.T) {
	var output bytes.Buffer
	window := newSendWindowWithLimits(legacyFlowControlLimits())
	clock := &testClock{now: time.Unix(0, 0)}
	pacer := newUplinkPacer(&windowPacing{ceiling: func() uint32 { return 2 }}, window, &lockedFrameWriter{writer: &output})
	pacer.now = func() time.Time { return clock.now }

	for rung := uint32(1); rung <= 2; rung++ {
		deliver(t, pacer, int(uint64(InitialStreamWindow)<<(rung-1)), clock)

		assertWindowUpdateIncrement(t, readFrameForTest(t, &output), 0, InitialConnectionWindow<<(rung-1))
		assertWindowUpdateIncrement(t, readFrameForTest(t, &output), ClientStreamID, InitialStreamWindow<<(rung-1))

		stream, connection := windowSizes(window)
		if stream != InitialStreamWindow<<rung || connection != InitialConnectionWindow<<rung {
			t.Fatalf("at rung %d the server tracks %d/%d, want %d/%d",
				rung, stream, connection, InitialStreamWindow<<rung, InitialConnectionWindow<<rung)
		}
	}

	// The ceiling holds: no further grant reaches the wire.
	deliver(t, pacer, int(uint64(InitialStreamWindow)<<MaxWindowScale), clock)
	if output.Len() != 0 {
		t.Fatalf("%d bytes granted past the ceiling", output.Len())
	}
}

func readFrameForTest(t *testing.T, reader *bytes.Buffer) Frame {
	t.Helper()
	frame, err := ReadFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// A paced connection is not handed its window at handshake time: the first
// thing the client hears back is the payload it asked for.
func TestPacedHandshakeGrantsNoCreditUpFront(t *testing.T) {
	server := newArtXTestServer(t)
	server.flowControlAuto = true
	server.maxWindowScale = MaxWindowScale
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{micros: 50_000, valid: true} }
	server.SetUserRateLookup(func(string) uint64 { return testRate50Mbps })

	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, processDone := authenticateArtXClient(t, server, dispatcher, context.Background())
	defer closeTLSNow(client)

	settings := append(settingsList(server.profileVersion), Setting{Key: SettingMaxWindowScale, Value: MaxWindowScale})
	payload, err := EncodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameSettings, Payload: payload})
	destination, err := EncodeTCPDestination(xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})

	want := []byte("paced")
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- target.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(want)})
	}()
	frame, err := ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != FrameData || !bytes.Equal(frame.Payload, want) {
		t.Fatalf("first server frame = type 0x%02x %q, want the downlink payload", frame.Type, frame.Payload)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}

	writeFrameForTest(t, client, Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}})
	if err := <-processDone; err != nil {
		t.Fatal(err)
	}
}
