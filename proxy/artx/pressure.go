package artx

import (
	"sync"
	"sync/atomic"
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

// PressureSample is one host utilisation observation. CPUPercent and
// MemoryPercent are percentages in [0, 100]; the sustained-load ladder judges
// on whichever is higher.
//
// MemoryTotalBytes and MemoryAvailableBytes carry the same memory reading in
// absolute bytes and drive the instantaneous window budget, which is a
// separate mechanism from the ladder. A zero in either field means "memory
// size unknown": the budget clamp then stays inactive and only the ladder
// applies.
type PressureSample struct {
	CPUPercent           float64
	MemoryPercent        float64
	MemoryTotalBytes     uint64
	MemoryAvailableBytes uint64
}

func (sample PressureSample) load() float64 {
	if sample.MemoryPercent > sample.CPUPercent {
		return sample.MemoryPercent
	}
	return sample.CPUPercent
}

// memoryKnown reports whether the sample carries usable absolute memory sizes.
func (sample PressureSample) memoryKnown() bool {
	return sample.MemoryTotalBytes > 0 && sample.MemoryAvailableBytes > 0
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
//	load >= 90%  -> ceiling 1
//
// Every rung costs exactly one scale, including the last one. The ladder used
// to drop straight from 2 to 0 above 90%, which quartered the window in a
// single step and, because the same rung is skipped on the way up, made the
// climb back out a double step gated on the 80% threshold. It is also the
// wrong reflex for the input: the ladder judges on max(cpu, memory), so a
// CPU-saturated host with free memory would surrender its receive windows for
// nothing. Scale 0 stays reachable through the window budget, which is the
// half of the policy that actually reads absolute memory.
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
	// memoryTotal and memoryAvailable hold the most recent known absolute
	// memory reading. They are deliberately not averaged: the window budget
	// has to react to the newest observation, because a burst of accepts can
	// commit the whole budget between two samples.
	memoryTotal     uint64
	memoryAvailable uint64
	// budget is the operator-tunable window budget policy. Always normalized,
	// so it is safe to use without re-checking.
	budget WindowBudgetPolicy

	// committedWindow is the receive-window credit connections currently hold,
	// in bytes. It is atomic rather than guarded by mu because it is written on
	// every window grant and read on every growth decision, while mu is held
	// across whole-sample bookkeeping.
	committedWindow atomic.Uint64
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
	return &PressureGovernor{
		sustainWindow: sustain,
		recoverWindow: recover,
		ceiling:       MaxWindowScale,
		budget:        DefaultWindowBudgetPolicy(),
	}
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
	if sample.memoryKnown() {
		governor.memoryTotal = sample.MemoryTotalBytes
		governor.memoryAvailable = sample.MemoryAvailableBytes
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
		return 1
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
		// Rung 1 is the ladder's floor: no load keeps a host out of it, so its
		// entry threshold is the top of the scale.
		return 100
	}
}

// nextPressureCeiling is the single rung above the current one. The ladder
// itself never selects 0 any more, but the rung is kept on the way up so a
// governor that somehow holds it can still climb out.
func nextPressureCeiling(ceiling uint32) (uint32, bool) {
	switch ceiling {
	case 0:
		return 1, true
	case 1:
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
	governor := sharedPressureGovernorForWrite()
	governor.Observe(sample, time.Now())
	// Fan the (possibly new) ceiling out to every bound inbound so the reported
	// gauge follows host pressure even on inbounds that are accepting nothing.
	publishPressureCeilings()
}

// SetSharedWindowBudgetPolicy configures the window budget on the process-wide
// governor, creating it on first use exactly as ObserveHostPressure does, so
// the policy can be installed before the first sample arrives.
//
// The budget is a host-level resource shared by every ArtX inbound in the
// process, so this is deliberately process-wide: the last caller wins.
func SetSharedWindowBudgetPolicy(policy WindowBudgetPolicy) {
	sharedPressureGovernorForWrite().SetWindowBudgetPolicy(policy)
	// The effective ceiling moves with the budget, so republish it.
	publishPressureCeilings()
}

// sharedPressureGovernorForWrite returns the process-wide governor, creating it
// if this is the first writer.
func sharedPressureGovernorForWrite() *PressureGovernor {
	sharedPressure.mu.Lock()
	if sharedPressure.governor == nil {
		sharedPressure.governor = NewPressureGovernor(PressureGovernorConfig{})
	}
	governor := sharedPressure.governor
	sharedPressure.mu.Unlock()
	return governor
}
