package artx

import "math/bits"

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
	// WindowBudgetSharePercent is the share of total host memory ArtX is
	// allowed to commit to receive windows.
	WindowBudgetSharePercent = uint64(25)

	// WindowBudgetReservePercent is the share of total host memory that must
	// stay available to everything else. The budget is trimmed so ArtX's
	// windows cannot drive available memory below it.
	WindowBudgetReservePercent = uint64(20)
)

// windowBudgetBytes computes the memory ArtX may commit to receive windows
// from one absolute memory reading:
//
//	min(SharePercent * total, available - ReservePercent * total), floored at 0
//
// The bool reports whether the reading was usable at all; false means the
// budget clamp must not be applied.
func windowBudgetBytes(total, available uint64) (uint64, bool) {
	if total == 0 || available == 0 {
		return 0, false
	}
	share := percentOf(total, WindowBudgetSharePercent)
	reserve := percentOf(total, WindowBudgetReservePercent)
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
	total, available := governor.memoryTotal, governor.memoryAvailable
	governor.mu.RUnlock()
	return windowBudgetBytes(total, available)
}

// budgetWindowScale is the largest scale in [0, MaxWindowScale] for which every
// connection — the activeConnections already established plus the one being
// negotiated — still fits inside budgetBytes:
//
//	(activeConnections + 1) * (InitialConnectionWindow << scale) <= budgetBytes
//
// The connection window, not the stream window, is the per-connection cost
// unit because it bounds a connection's total in-flight bytes across all of
// its streams.
//
// When not even the legacy window fits, the result is 0: the budget clamps the
// window, it never rejects the connection.
func budgetWindowScale(budgetBytes uint64, activeConnections uint64) uint32 {
	if budgetBytes == 0 || activeConnections == ^uint64(0) {
		return 0
	}
	// Dividing instead of multiplying keeps the comparison overflow-free:
	// for a positive integer x, connections*x <= budget iff x <= budget/connections.
	perConnection := budgetBytes / (activeConnections + 1)
	scale := uint32(0)
	for scale < MaxWindowScale && uint64(InitialConnectionWindow)<<(scale+1) <= perConnection {
		scale++
	}
	return scale
}

// budgetCeiling intersects a pressure ceiling with the budget clamp for a
// connection that is not yet counted in activeConnections. An unknown budget
// leaves the pressure ceiling untouched.
func budgetCeiling(governor *PressureGovernor, pressureCeiling uint32, activeConnections uint64) uint32 {
	budget, known := governor.WindowBudgetBytes()
	if !known {
		return pressureCeiling
	}
	return min(pressureCeiling, budgetWindowScale(budget, activeConnections))
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
