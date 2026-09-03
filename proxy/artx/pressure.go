package artx

import (
	"sync"
	"time"
)

// Default windows for PressureGovernor. Downgrades look at the mean load over
// DefaultPressureSustainWindow; upgrades additionally require the qualifying
// condition to hold continuously for DefaultPressureRecoverWindow.
const (
	DefaultPressureSustainWindow = 120 * time.Second
	DefaultPressureRecoverWindow = 300 * time.Second

	// minPressureSamples is how many samples must sit inside the sustain window
	// before the governor is allowed to lower the ceiling. It keeps a single
	// spike right after startup from collapsing every connection to legacy
	// windows.
	minPressureSamples = 3

	// pressureHysteresis is how far below the target step's entry threshold the
	// sustained load has to sit before the governor steps back up.
	pressureHysteresis = 10.0
)

// PressureSample is one host utilisation observation. Both values are
// percentages in [0, 100]; the governor judges on whichever is higher.
type PressureSample struct {
	CPUPercent    float64
	MemoryPercent float64
}

func (sample PressureSample) load() float64 {
	if sample.MemoryPercent > sample.CPUPercent {
		return sample.MemoryPercent
	}
	return sample.CPUPercent
}

// PressureGovernorConfig tunes the governor windows. Zero values select the
// package defaults.
type PressureGovernorConfig struct {
	SustainWindow time.Duration
	RecoverWindow time.Duration
}

type pressureObservation struct {
	at   time.Time
	load float64
}

// PressureGovernor turns a stream of host utilisation samples into a window
// scale ceiling. It never samples anything itself: the embedding process feeds
// it through Observe, which keeps the type dependency-free and unit testable.
//
// Ladder (on the sustained mean of max(cpu, memory)):
//
//	load <  70%  -> ceiling 4
//	load <  80%  -> ceiling 3
//	load <  90%  -> ceiling 2
//	load >= 90%  -> ceiling 0 (legacy windows)
//
// Downgrades apply as soon as the window holds minPressureSamples samples.
// Upgrades move one rung at a time and require the sustained mean to stay
// pressureHysteresis points below the target rung's entry threshold for a full
// RecoverWindow.
type PressureGovernor struct {
	sustainWindow time.Duration
	recoverWindow time.Duration

	mu              sync.RWMutex
	samples         []pressureObservation
	ceiling         uint32
	qualifiedSince  time.Time
	qualifiedActive bool
}

// NewPressureGovernor returns a governor that starts wide open at
// MaxWindowScale.
func NewPressureGovernor(config PressureGovernorConfig) *PressureGovernor {
	sustain := config.SustainWindow
	if sustain <= 0 {
		sustain = DefaultPressureSustainWindow
	}
	recover := config.RecoverWindow
	if recover <= 0 {
		recover = DefaultPressureRecoverWindow
	}
	return &PressureGovernor{sustainWindow: sustain, recoverWindow: recover, ceiling: MaxWindowScale}
}

// Ceiling is the current window scale ceiling. A nil governor is treated as
// "no pressure known", i.e. the full MaxWindowScale.
func (governor *PressureGovernor) Ceiling() uint32 {
	if governor == nil {
		return MaxWindowScale
	}
	governor.mu.RLock()
	ceiling := governor.ceiling
	governor.mu.RUnlock()
	return ceiling
}

// Observe records one utilisation sample and re-evaluates the ceiling. Samples
// must be fed in non-decreasing time order; out-of-order samples are dropped.
func (governor *PressureGovernor) Observe(sample PressureSample, now time.Time) {
	if governor == nil {
		return
	}
	governor.mu.Lock()
	defer governor.mu.Unlock()

	if count := len(governor.samples); count > 0 && now.Before(governor.samples[count-1].at) {
		return
	}
	governor.samples = append(governor.samples, pressureObservation{at: now, load: sample.load()})
	governor.evictLocked(now)

	count, mean := governor.windowLocked(now)
	if count == 0 {
		return
	}

	if target := pressureCeilingForLoad(mean); target < governor.ceiling {
		if count >= minPressureSamples {
			governor.ceiling = target
			governor.qualifiedActive = false
		}
		return
	}

	next, ok := nextPressureCeiling(governor.ceiling)
	if !ok || mean >= pressureEntryThreshold(next)-pressureHysteresis {
		governor.qualifiedActive = false
		return
	}
	if !governor.qualifiedActive {
		governor.qualifiedActive = true
		governor.qualifiedSince = now
		return
	}
	if now.Sub(governor.qualifiedSince) >= governor.recoverWindow {
		governor.ceiling = next
		governor.qualifiedSince = now
	}
}

func (governor *PressureGovernor) evictLocked(now time.Time) {
	cutoff := now.Add(-governor.sustainWindow)
	keep := 0
	for keep < len(governor.samples) && !governor.samples[keep].at.After(cutoff) {
		keep++
	}
	if keep == 0 {
		return
	}
	governor.samples = append(governor.samples[:0], governor.samples[keep:]...)
}

func (governor *PressureGovernor) windowLocked(now time.Time) (int, float64) {
	cutoff := now.Add(-governor.sustainWindow)
	count := 0
	total := 0.0
	for _, observation := range governor.samples {
		if observation.at.After(cutoff) {
			count++
			total += observation.load
		}
	}
	if count == 0 {
		return 0, 0
	}
	return count, total / float64(count)
}

// sustainedSampleCount reports how many samples currently sit inside the
// sustain window. Exposed for tests only.
func (governor *PressureGovernor) sustainedSampleCount(now time.Time) int {
	governor.mu.RLock()
	defer governor.mu.RUnlock()
	count, _ := governor.windowLocked(now)
	return count
}

func pressureCeilingForLoad(load float64) uint32 {
	switch {
	case load < 70:
		return 4
	case load < 80:
		return 3
	case load < 90:
		return 2
	default:
		return 0
	}
}

// pressureEntryThreshold is the load below which a rung is allowed at all.
func pressureEntryThreshold(ceiling uint32) float64 {
	switch ceiling {
	case 4:
		return 70
	case 3:
		return 80
	case 2:
		return 90
	default:
		return 100
	}
}

// nextPressureCeiling is the single rung above the current one. Rung 1 is not
// part of the ladder, so recovery from 0 lands on 2.
func nextPressureCeiling(ceiling uint32) (uint32, bool) {
	switch ceiling {
	case 0:
		return 2, true
	case 2:
		return 3, true
	case 3:
		return 4, true
	default:
		return ceiling, false
	}
}

var sharedPressure struct {
	mu       sync.RWMutex
	governor *PressureGovernor
}

// SetSharedPressureGovernor installs the process-wide governor consulted by
// every ArtX inbound that has no governor of its own. Passing nil removes it,
// which restores the unrestricted MaxWindowScale ceiling.
func SetSharedPressureGovernor(governor *PressureGovernor) {
	sharedPressure.mu.Lock()
	sharedPressure.governor = governor
	sharedPressure.mu.Unlock()
}

// SharedPressureGovernor returns the process-wide governor, or nil.
func SharedPressureGovernor() *PressureGovernor {
	sharedPressure.mu.RLock()
	governor := sharedPressure.governor
	sharedPressure.mu.RUnlock()
	return governor
}

// ObserveHostPressure feeds one sample to the process-wide governor, creating
// it on first use so callers do not have to install one explicitly.
func ObserveHostPressure(sample PressureSample) {
	sharedPressure.mu.Lock()
	if sharedPressure.governor == nil {
		sharedPressure.governor = NewPressureGovernor(PressureGovernorConfig{})
	}
	governor := sharedPressure.governor
	sharedPressure.mu.Unlock()
	governor.Observe(sample, time.Now())
	// Fan the (possibly new) ceiling out to every bound inbound so the reported
	// gauge follows host pressure even on inbounds that are accepting nothing.
	publishPressureCeilings()
}
