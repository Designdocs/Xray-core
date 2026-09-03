package artx

import (
	"sync"
	"testing"
	"time"
)

func observeSeries(governor *PressureGovernor, start time.Time, step time.Duration, count int, load float64) time.Time {
	at := start
	for i := 0; i < count; i++ {
		governor.Observe(PressureSample{CPUPercent: load}, at)
		at = at.Add(step)
	}
	return at
}

func TestPressureGovernorStartsWideOpen(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{})
	if got := governor.Ceiling(); got != MaxWindowScale {
		t.Fatalf("Ceiling() = %d, want %d", got, MaxWindowScale)
	}
	if got := (*PressureGovernor)(nil).Ceiling(); got != MaxWindowScale {
		t.Fatalf("nil Ceiling() = %d, want %d", got, MaxWindowScale)
	}
}

func TestPressureGovernorLadder(t *testing.T) {
	tests := []struct {
		name string
		load float64
		want uint32
	}{
		{name: "idle", load: 10, want: 4},
		{name: "just below warm", load: 69.9, want: 4},
		{name: "warm", load: 70, want: 3},
		{name: "busy", load: 80, want: 2},
		{name: "saturated", load: 90, want: 0},
		{name: "overloaded", load: 100, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			governor := NewPressureGovernor(PressureGovernorConfig{})
			start := time.Unix(0, 0)
			observeSeries(governor, start, time.Second, 5, test.load)
			if got := governor.Ceiling(); got != test.want {
				t.Fatalf("Ceiling() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestPressureGovernorUsesHigherOfCPUAndMemory(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{})
	at := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		governor.Observe(PressureSample{CPUPercent: 5, MemoryPercent: 95}, at)
		at = at.Add(time.Second)
	}
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() = %d, want 0", got)
	}
}

func TestPressureGovernorNeedsThreeSamplesToDrop(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{})
	start := time.Unix(0, 0)
	observeSeries(governor, start, time.Second, 2, 95)
	if got := governor.Ceiling(); got != MaxWindowScale {
		t.Fatalf("Ceiling() after 2 samples = %d, want %d", got, MaxWindowScale)
	}
	governor.Observe(PressureSample{CPUPercent: 95}, start.Add(2*time.Second))
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() after 3 samples = %d, want 0", got)
	}
}

func TestPressureGovernorExpiresSamplesOutsideSustainWindow(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second, RecoverWindow: time.Hour})
	start := time.Unix(0, 0)
	observeSeries(governor, start, time.Second, 3, 75)
	if got := governor.Ceiling(); got != 3 {
		t.Fatalf("Ceiling() = %d, want 3", got)
	}
	// Three hot samples a minute later must be judged on their own: including the
	// stale 75%% samples would average to 87%% and stop at ceiling 2.
	observeSeries(governor, start.Add(time.Minute), time.Second, 3, 99)
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() = %d, want 0", got)
	}
}

func TestPressureGovernorRecoveryNeedsHysteresisAndFullWindow(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second, RecoverWindow: 100 * time.Second})
	start := time.Unix(0, 0)
	observeSeries(governor, start, time.Second, 5, 95)
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() = %d, want 0", got)
	}

	// 75% is below the ceiling-2 threshold (90) but not below 90-10=80... it is.
	// Use 85 instead: above the 80 hysteresis bar, so no recovery.
	at := start.Add(10 * time.Second)
	for i := 0; i < 60; i++ {
		governor.Observe(PressureSample{CPUPercent: 85}, at)
		at = at.Add(2 * time.Second)
	}
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() with load above hysteresis bar = %d, want 0", got)
	}

	// Now go quiet. Recovery may not happen before RecoverWindow of quiet history.
	quietStart := at
	governor.Observe(PressureSample{CPUPercent: 5}, at)
	at = at.Add(50 * time.Second)
	governor.Observe(PressureSample{CPUPercent: 5}, at)
	at = at.Add(10 * time.Second)
	governor.Observe(PressureSample{CPUPercent: 5}, at)
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() before RecoverWindow elapsed = %d, want 0", got)
	}
	if at.Sub(quietStart) >= 100*time.Second {
		t.Fatalf("test setup: quiet history already covers the recover window")
	}

	at = at.Add(45 * time.Second)
	governor.Observe(PressureSample{CPUPercent: 5}, at)
	if got := governor.Ceiling(); got != 2 {
		t.Fatalf("Ceiling() after RecoverWindow = %d, want 2 (single step up)", got)
	}

	// Another full quiet RecoverWindow lifts exactly one more step.
	for i := 0; i < 6; i++ {
		at = at.Add(20 * time.Second)
		governor.Observe(PressureSample{CPUPercent: 5}, at)
	}
	if got := governor.Ceiling(); got != 3 {
		t.Fatalf("Ceiling() after second RecoverWindow = %d, want 3", got)
	}
	for i := 0; i < 6; i++ {
		at = at.Add(20 * time.Second)
		governor.Observe(PressureSample{CPUPercent: 5}, at)
	}
	if got := governor.Ceiling(); got != 4 {
		t.Fatalf("Ceiling() after third RecoverWindow = %d, want 4", got)
	}
}

func TestPressureGovernorDropsImmediatelyAcrossMultipleSteps(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second})
	start := time.Unix(0, 0)
	observeSeries(governor, start, time.Second, 3, 75)
	if got := governor.Ceiling(); got != 3 {
		t.Fatalf("Ceiling() = %d, want 3", got)
	}
	observeSeries(governor, start.Add(20*time.Second), time.Second, 3, 99)
	if got := governor.Ceiling(); got != 0 {
		t.Fatalf("Ceiling() = %d, want 0", got)
	}
}

func TestPressureGovernorConcurrentObserveAndCeiling(t *testing.T) {
	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: time.Second})
	var waiter sync.WaitGroup
	start := time.Unix(0, 0)
	for writer := 0; writer < 4; writer++ {
		waiter.Add(1)
		go func(offset int) {
			defer waiter.Done()
			at := start
			for i := 0; i < 500; i++ {
				governor.Observe(PressureSample{CPUPercent: float64((i + offset) % 100)}, at)
				at = at.Add(10 * time.Millisecond)
			}
		}(writer * 7)
	}
	for reader := 0; reader < 4; reader++ {
		waiter.Add(1)
		go func() {
			defer waiter.Done()
			for i := 0; i < 2000; i++ {
				if got := governor.Ceiling(); got > MaxWindowScale {
					t.Errorf("Ceiling() = %d, out of range", got)
					return
				}
			}
		}()
	}
	waiter.Wait()
}
