package artx

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"sync/atomic"
)

// The window budget is the instantaneous half of ArtX flow-control damping.
// PressureGovernor's ladder reacts to *sustained* CPU/memory load, so it can
// only move after the host is already loaded — a burst of accepts between two
// samples can each negotiate the widest window and keep it for the whole
// connection lifetime. The budget closes that gap: it divides a fixed slice of
// host memory across the connections that are live right now and clamps the
// scale offered to the next connection accordingly.
//
// The clamp applies at accept time only. Established connections keep the
// scale they negotiated until they close, and an exhausted budget never
// refuses or terminates a connection — it bottoms out at scale 0, the legacy
// window, and the connection is accepted as usual.
const (
	// DefaultWindowBudgetSharePercent is the share of total host memory ArtX
	// is allowed to commit to receive windows when the deployment does not
	// override it.
	DefaultWindowBudgetSharePercent = uint64(25)

	// DefaultWindowBudgetReservePercent is the share of total host memory that
	// must stay available to everything else. The budget is trimmed so ArtX's
	// windows cannot drive available memory below it.
	DefaultWindowBudgetReservePercent = uint64(20)

	// maxWindowBudgetSharePercent and maxWindowBudgetReservePercent bound what
	// an operator may configure. A share of 100% is allowed — the reserve
	// still holds it back from actually starving the host — but a reserve of
	// 100% would pin the budget at zero forever, which is what disabling the
	// ArtX flow-control policy is for, not what a percentage is for.
	maxWindowBudgetSharePercent   = uint64(100)
	maxWindowBudgetReservePercent = uint64(99)
)

// WindowBudgetPolicy is the operator-tunable half of the budget: which slice
// of host memory ArtX may commit to receive windows, and how much of the host
// must stay available regardless.
//
// A zero field means "use the default for that field", so the zero value of
// the whole struct is the default policy. That makes 0 unavailable as a way to
// spell "no reserve at all"; the settable reserve range is therefore 1..99.
type WindowBudgetPolicy struct {
	// SharePercent is the share of total memory ArtX may commit, 1..100.
	SharePercent uint64
	// ReservePercent is the share of total memory that must stay available to
	// everything else, 1..99.
	ReservePercent uint64
}

// DefaultWindowBudgetPolicy is the policy applied when nothing is configured.
func DefaultWindowBudgetPolicy() WindowBudgetPolicy {
	return WindowBudgetPolicy{
		SharePercent:   DefaultWindowBudgetSharePercent,
		ReservePercent: DefaultWindowBudgetReservePercent,
	}
}

// Validate reports the fields that are out of range. A zero field is not an
// error — it selects the default — so the only way to fail is to configure a
// percentage that cannot mean anything. Callers use this to log a rejected
// value; normalized() applies the fallback either way, so a caller that skips
// the check still gets a usable policy.
func (policy WindowBudgetPolicy) Validate() error {
	var rejected []string
	if policy.SharePercent > maxWindowBudgetSharePercent {
		rejected = append(rejected, fmt.Sprintf("share percent %d is above %d",
			policy.SharePercent, maxWindowBudgetSharePercent))
	}
	if policy.ReservePercent > maxWindowBudgetReservePercent {
		rejected = append(rejected, fmt.Sprintf("reserve percent %d is above %d",
			policy.ReservePercent, maxWindowBudgetReservePercent))
	}
	if len(rejected) == 0 {
		return nil
	}
	return errors.New("artx window budget: " + strings.Join(rejected, "; "))
}

// normalized substitutes the default for every field that is zero or out of
// range, so the result is always usable.
func (policy WindowBudgetPolicy) normalized() WindowBudgetPolicy {
	effective := DefaultWindowBudgetPolicy()
	if policy.SharePercent > 0 && policy.SharePercent <= maxWindowBudgetSharePercent {
		effective.SharePercent = policy.SharePercent
	}
	if policy.ReservePercent > 0 && policy.ReservePercent <= maxWindowBudgetReservePercent {
		effective.ReservePercent = policy.ReservePercent
	}
	return effective
}

// windowBudgetBytes computes the memory ArtX may commit to receive windows
// from one absolute memory reading and one policy:
//
//	min(SharePercent * total, available - ReservePercent * total), floored at 0
//
// The bool reports whether the reading was usable at all; false means the
// budget clamp must not be applied.
func windowBudgetBytes(total, available uint64, policy WindowBudgetPolicy) (uint64, bool) {
	if total == 0 || available == 0 {
		return 0, false
	}
	effective := policy.normalized()
	share := percentOf(total, effective.SharePercent)
	reserve := percentOf(total, effective.ReservePercent)
	if available <= reserve {
		return 0, true
	}
	if headroom := available - reserve; headroom < share {
		return headroom, true
	}
	return share, true
}

// WindowBudgetBytes is the current receive-window memory budget in bytes. The
// bool reports whether the governor has ever seen an absolute memory reading;
// false means "unknown", and callers must then skip the budget clamp entirely.
// A nil governor reports unknown.
func (governor *PressureGovernor) WindowBudgetBytes() (uint64, bool) {
	if governor == nil {
		return 0, false
	}
	governor.mu.RLock()
	total, available, policy := governor.memoryTotal, governor.memoryAvailable, governor.budget
	governor.mu.RUnlock()
	return windowBudgetBytes(total, available, policy)
}

// SetWindowBudgetPolicy replaces the budget policy. Out-of-range and zero
// fields fall back to their defaults, so the governor always holds a usable
// policy. The change takes effect on the next negotiation — established
// connections keep the window they already negotiated. A nil governor is a
// no-op.
func (governor *PressureGovernor) SetWindowBudgetPolicy(policy WindowBudgetPolicy) {
	if governor == nil {
		return
	}
	effective := policy.normalized()
	governor.mu.Lock()
	governor.budget = effective
	governor.mu.Unlock()
}

// WindowBudgetPolicy is the policy currently in force. A nil governor reports
// the defaults.
func (governor *PressureGovernor) WindowBudgetPolicy() WindowBudgetPolicy {
	if governor == nil {
		return DefaultWindowBudgetPolicy()
	}
	governor.mu.RLock()
	policy := governor.budget
	governor.mu.RUnlock()
	return policy
}

// budgetWindowScale is the largest scale in [0, MaxWindowScale] whose
// connection window fits in availableBytes:
//
//	(InitialConnectionWindow << scale) <= availableBytes
//
// The connection window, not the stream window, is the cost unit because it
// bounds a connection's total in-flight bytes across all of its streams.
//
// When not even the legacy window fits, the result is 0: the budget clamps the
// window, it never rejects the connection.
func budgetWindowScale(availableBytes uint64) uint32 {
	scale := uint32(0)
	for scale < MaxWindowScale && uint64(InitialConnectionWindow)<<(scale+1) <= availableBytes {
		scale++
	}
	return scale
}

// availableWindowCredit is the total credit a connection already holding
// ownCredit bytes may hold: the whole budget, less what every *other*
// connection holds. The bool reports whether the budget is known at all.
//
// Accounting the credit actually granted, rather than counting connections and
// assuming each will take the widest window, is what lets a host carry many
// idle connections and a few busy ones at the same time: an idle connection
// holds the compatibility window and costs the budget almost nothing.
func (governor *PressureGovernor) availableWindowCredit(ownCredit uint64) (uint64, bool) {
	budget, known := governor.WindowBudgetBytes()
	if !known {
		return 0, false
	}
	held := governor.committedWindow.Load()
	return saturatingSub(budget, saturatingSub(held, ownCredit)), true
}

// CommittedWindowBytes is the receive-window credit connections currently hold.
func (governor *PressureGovernor) CommittedWindowBytes() uint64 {
	if governor == nil {
		return 0
	}
	return governor.committedWindow.Load()
}

func saturatingSub(value, delta uint64) uint64 {
	if delta >= value {
		return 0
	}
	return value - delta
}

// budgetCeiling intersects a pressure ceiling with the budget clamp, for a
// connection currently holding ownCredit bytes of receive-window credit. An
// unknown budget leaves the pressure ceiling untouched.
func budgetCeiling(governor *PressureGovernor, pressureCeiling uint32, ownCredit uint64) uint32 {
	available, known := governor.availableWindowCredit(ownCredit)
	if !known {
		return pressureCeiling
	}
	return min(pressureCeiling, budgetWindowScale(available))
}

// windowCreditLedger is one connection's share of the budget. commit records
// credit the connection is entitled to regardless of the budget — a connection
// is never refused — while reserve asks whether one more rung fits. Release
// hands everything back when the connection ends.
//
// A reserve is not atomic against other connections, so a burst of simultaneous
// grants can overshoot the budget by a rung each. The next decision sees the
// real total and stops, which is the accuracy this clamp needs: it is a damper,
// not an allocator.
type windowCreditLedger struct {
	governor *PressureGovernor
	credit   atomic.Uint64
}

func newWindowCreditLedger(governor *PressureGovernor) *windowCreditLedger {
	return &windowCreditLedger{governor: governor}
}

func (ledger *windowCreditLedger) commit(bytes uint64) {
	if ledger == nil || ledger.governor == nil || bytes == 0 {
		return
	}
	ledger.credit.Add(bytes)
	ledger.governor.committedWindow.Add(bytes)
}

// reserve reports whether bytes more credit fits in the budget, and books it
// when it does. An unknown budget always fits.
func (ledger *windowCreditLedger) reserve(bytes uint64) bool {
	if ledger == nil || ledger.governor == nil {
		return true
	}
	held := ledger.credit.Load()
	available, known := ledger.governor.availableWindowCredit(held)
	if known && held+bytes > available {
		return false
	}
	ledger.commit(bytes)
	return true
}

func (ledger *windowCreditLedger) held() uint64 {
	if ledger == nil {
		return 0
	}
	return ledger.credit.Load()
}

func (ledger *windowCreditLedger) release() {
	if ledger == nil || ledger.governor == nil {
		return
	}
	held := ledger.credit.Swap(0)
	if held == 0 {
		return
	}
	// Add of the two's-complement negation: the counter only ever holds what
	// live ledgers hold, so it cannot go below zero unless a ledger is released
	// twice, which Swap already prevents.
	ledger.governor.committedWindow.Add(^(held - 1))
}

// percentOf is value * percent / 100 computed in 128 bits, so a large memory
// size cannot wrap and a small one is not rounded down by the division.
// percent is always <= 100 here, which is what keeps the quotient in range.
func percentOf(value, percent uint64) uint64 {
	hi, lo := bits.Mul64(value, percent)
	if hi >= 100 {
		return ^uint64(0)
	}
	result, _ := bits.Div64(hi, lo, 100)
	return result
}
