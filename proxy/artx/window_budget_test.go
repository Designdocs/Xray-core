package artx

import (
	"net"
	"testing"
	"time"
)

const (
	mib             = uint64(1) << 20
	testBudget240MB = 240 * mib
)

// memorySample builds a pressure sample that carries absolute memory sizes and
// an idle CPU/memory percentage, so only the budget clamp can move the ceiling.
func memorySample(total, available uint64) PressureSample {
	return PressureSample{CPUPercent: 1, MemoryPercent: 1, MemoryTotalBytes: total, MemoryAvailableBytes: available}
}

func TestWindowBudgetBytesUnknownWithoutMemorySizes(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{})
	if _, known := governor.WindowBudgetBytes(); known {
		t.Fatal("a fresh governor reported a known budget")
	}
	if _, known := (*PressureGovernor)(nil).WindowBudgetBytes(); known {
		t.Fatal("a nil governor reported a known budget")
	}

	// A sample without byte fields must leave the budget unknown, so an agent
	// that only reports percentages keeps today's behaviour exactly.
	governor.Observe(PressureSample{CPUPercent: 50, MemoryPercent: 50}, time.Unix(0, 0))
	if _, known := governor.WindowBudgetBytes(); known {
		t.Fatal("a percentage-only sample made the budget known")
	}
}

func TestWindowBudgetBytesTakesTheTighterOfShareAndReserve(t *testing.T) {
	total := 1000 * mib
	tests := []struct {
		name      string
		available uint64
		want      uint64
	}{
		// Plenty of headroom: the 25% share binds.
		{name: "share binds", available: 900 * mib, want: 250 * mib},
		// available - 20% reserve = 250 MiB, exactly the share.
		{name: "reserve meets share", available: 450 * mib, want: 250 * mib},
		// available - 20% reserve = 80 MiB, tighter than the share.
		{name: "reserve binds", available: 280 * mib, want: 80 * mib},
		// Available is already below the reserve: nothing may be committed.
		{name: "reserve breached", available: 200 * mib, want: 0},
		{name: "reserve exactly breached", available: 199 * mib, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, known := windowBudgetBytes(total, test.available)
			if !known {
				t.Fatal("budget reported unknown for a usable reading")
			}
			if got != test.want {
				t.Fatalf("windowBudgetBytes(%d, %d) = %d, want %d", total, test.available, got, test.want)
			}
		})
	}
}

func TestWindowBudgetTracksTheNewestReading(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{})
	at := time.Unix(0, 0)
	governor.Observe(memorySample(1000*mib, 900*mib), at)
	if got, _ := governor.WindowBudgetBytes(); got != 250*mib {
		t.Fatalf("budget = %d, want %d", got, 250*mib)
	}
	// Memory is not averaged: one fresh reading must move the budget at once,
	// because a burst of accepts can commit it between two samples.
	governor.Observe(memorySample(1000*mib, 280*mib), at.Add(time.Second))
	if got, _ := governor.WindowBudgetBytes(); got != 80*mib {
		t.Fatalf("budget after the newest reading = %d, want %d", got, 80*mib)
	}
}

func TestBudgetWindowScaleStepsDownDeterministically(t *testing.T) {
	// A 240 MiB budget divides evenly by every connection window, so each
	// boundary sits on an exact connection count:
	//   scale 4 (16 MiB) fits 15 connections, scale 3 (8 MiB) fits 30,
	//   scale 2 (4 MiB) fits 60, scale 1 (2 MiB) fits 120.
	tests := []struct {
		name   string
		active uint64
		want   uint32
	}{
		{name: "first connection", active: 0, want: 4},
		{name: "last that still fits at 16 MiB", active: 14, want: 4},
		{name: "16 MiB stops fitting", active: 15, want: 3},
		{name: "last that still fits at 8 MiB", active: 29, want: 3},
		{name: "8 MiB stops fitting", active: 30, want: 2},
		{name: "last that still fits at 4 MiB", active: 59, want: 2},
		{name: "4 MiB stops fitting", active: 60, want: 1},
		{name: "last that still fits at 2 MiB", active: 119, want: 1},
		{name: "2 MiB stops fitting", active: 120, want: 0},
		{name: "budget long gone", active: 100_000, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := budgetWindowScale(testBudget240MB, test.active); got != test.want {
				t.Fatalf("budgetWindowScale(240MiB, %d) = %d, want %d", test.active, got, test.want)
			}
		})
	}
}

func TestBudgetWindowScaleHonoursTheInequalityAtZeroConnections(t *testing.T) {
	// Even with no connection established the connection being negotiated has
	// to fit, so a budget under one connection window yields a lower scale.
	tests := []struct {
		budget uint64
		want   uint32
	}{
		{budget: 16 * mib, want: 4},
		{budget: 16*mib - 1, want: 3},
		{budget: uint64(InitialConnectionWindow), want: 0},
		{budget: uint64(InitialConnectionWindow) - 1, want: 0},
		{budget: 0, want: 0},
	}
	for _, test := range tests {
		if got := budgetWindowScale(test.budget, 0); got != test.want {
			t.Fatalf("budgetWindowScale(%d, 0) = %d, want %d", test.budget, got, test.want)
		}
	}
	// The +1 must not wrap at the extreme.
	if got := budgetWindowScale(testBudget240MB, ^uint64(0)); got != 0 {
		t.Fatalf("budgetWindowScale at max active = %d, want 0", got)
	}
}

func TestBudgetCeilingIsInactiveWithoutMemorySizes(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second})
	observeSeries(governor, time.Unix(0, 0), time.Second, 3, 10)
	if got := budgetCeiling(governor, governor.Ceiling(), 10_000); got != MaxWindowScale {
		t.Fatalf("ceiling with an unknown budget = %d, want %d", got, MaxWindowScale)
	}
	if got := budgetCeiling(nil, MaxWindowScale, 10_000); got != MaxWindowScale {
		t.Fatalf("ceiling with a nil governor = %d, want %d", got, MaxWindowScale)
	}
}

func TestBudgetCeilingTakesTheLowerOfPressureAndBudget(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{})
	governor.Observe(memorySample(960*mib, 900*mib), time.Unix(0, 0))
	budget, known := governor.WindowBudgetBytes()
	if !known || budget != 240*mib {
		t.Fatalf("budget = %d (known %v), want %d", budget, known, 240*mib)
	}
	// Budget is the tighter of the two.
	if got := budgetCeiling(governor, MaxWindowScale, 30); got != 2 {
		t.Fatalf("ceiling = %d, want 2", got)
	}
	// Pressure is the tighter of the two.
	if got := budgetCeiling(governor, 0, 0); got != 0 {
		t.Fatalf("ceiling under a saturated pressure rung = %d, want 0", got)
	}
}

// newBudgetedServer returns an auto-policy server whose governor sees a 960 MiB
// host with a healthy 240 MiB budget and no CPU/memory pressure at all, so any
// ceiling movement is the budget clamp's doing.
func newBudgetedServer(t *testing.T, active uint64) *Server {
	t.Helper()
	server := newArtXTestServer(t)
	server.flowControlAuto = true
	server.maxWindowScale = MaxWindowScale
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{} }

	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second})
	observeSeries(governor, time.Unix(0, 0), time.Second, 3, 10)
	governor.Observe(memorySample(960*mib, 900*mib), time.Unix(0, 0).Add(4*time.Second))
	if got := governor.Ceiling(); got != MaxWindowScale {
		t.Fatalf("pressure rung = %d, want %d on an idle host", got, MaxWindowScale)
	}
	server.SetPressureGovernor(governor)
	server.stats.add(runtimeCounterActiveConnections, int64(active))
	return server
}

func TestNegotiationCeilingClampsOnConcurrency(t *testing.T) {
	tests := []struct {
		name string
		// active includes the connection being negotiated, the way Process
		// counts it before the handshake reaches negotiation.
		active uint64
		want   uint32
	}{
		{name: "few users get the full scale", active: 1, want: 4},
		{name: "last connection at 16 MiB", active: 15, want: 4},
		{name: "16 MiB stops fitting", active: 16, want: 3},
		{name: "many users step down", active: 61, want: 1},
		{name: "hundred users", active: 100, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newBudgetedServer(t, test.active)
			if got := server.negotiationCeiling(); got != test.want {
				t.Fatalf("negotiationCeiling() with %d active = %d, want %d", test.active, got, test.want)
			}
		})
	}
}

func TestNegotiationSucceedsWithAnExhaustedBudget(t *testing.T) {
	server := newArtXTestServer(t)
	server.flowControlAuto = true
	server.maxWindowScale = MaxWindowScale
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{micros: 50_000, valid: true} }

	governor := NewPressureGovernor(PressureGovernorConfig{})
	// Available memory already sits below the 20% reserve: nothing left to
	// commit, so the clamp bottoms out.
	governor.Observe(memorySample(960*mib, 100*mib), time.Unix(0, 0))
	if budget, known := governor.WindowBudgetBytes(); !known || budget != 0 {
		t.Fatalf("budget = %d (known %v), want an exhausted budget", budget, known)
	}
	server.SetPressureGovernor(governor)
	server.stats.add(runtimeCounterActiveConnections, 1)

	if got := server.negotiationCeiling(); got != 0 {
		t.Fatalf("negotiationCeiling() = %d, want 0", got)
	}
	// The connection is still served: negotiation returns the legacy window
	// rather than failing or refusing anything.
	settings := map[uint16]uint32{SettingMaxWindowScale: MaxWindowScale}
	if got := server.negotiateStreamWindowScale(settings, nil, nil); got != 0 {
		t.Fatalf("negotiateStreamWindowScale() = %d, want 0", got)
	}
	if got := server.Stats().FlowControlPressureCeiling; got != 0 {
		t.Fatalf("reported ceiling = %d, want 0", got)
	}
}

func TestReportedCeilingReflectsTheBudgetNotOnlyPressure(t *testing.T) {
	withSharedPressureGovernor(t, nil)

	server := newBudgetedServer(t, 0)
	manager := newStatsManagerForTest(t)
	server.stats.manager = manager
	t.Cleanup(server.stats.release)
	server.stats.bind("artx-budgeted")

	// Idle: the pressure rung is wide open and so is the budget.
	if got := RuntimeStatsFromManager(manager, "artx-budgeted").FlowControlPressureCeiling; got != uint64(MaxWindowScale) {
		t.Fatalf("idle ceiling = %d, want %d", got, uint64(MaxWindowScale))
	}

	// Sixty live connections at an unchanged, idle pressure rung: only the
	// budget can explain the gauge stepping down to 1.
	server.stats.add(runtimeCounterActiveConnections, 60)
	publishPressureCeilings()
	if got := server.governor().Ceiling(); got != MaxWindowScale {
		t.Fatalf("pressure rung moved to %d; the gauge would not isolate the budget", got)
	}
	if got := RuntimeStatsFromManager(manager, "artx-budgeted").FlowControlPressureCeiling; got != 1 {
		t.Fatalf("ceiling with 60 live connections = %d, want 1", got)
	}
}
