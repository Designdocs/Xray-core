package artx

import (
	"net"
	"testing"
)

// Retiering a live inbound is the whole point of SetFlowControl: the agent
// changes the panel's flow-control setting without rebuilding the inbound,
// which would close its listener and drop every session on it.
func TestSetFlowControlRetiersTheNextNegotiation(t *testing.T) {
	withSharedPressureGovernor(t, nil)
	server := newArtXTestServer(t)
	server.SetFlowControl(false, 0)

	settings := map[uint16]uint32{SettingMaxWindowScale: MaxWindowScale}
	if got := server.negotiateStreamWindowScale(settings, nil, nil); got != 0 {
		t.Fatalf("legacy tier negotiated scale %d, want 0", got)
	}

	server.SetFlowControl(false, 3)
	if got := server.negotiateStreamWindowScale(settings, nil, nil); got != 3 {
		t.Fatalf("after retier negotiated scale %d, want 3", got)
	}

	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{micros: 200_000, valid: true} }
	server.SetFlowControl(true, MaxWindowScale)
	auto, maxWindowScale := server.flowControlPolicy()
	if !auto || maxWindowScale != MaxWindowScale {
		t.Fatalf("flowControlPolicy() = (%v, %d), want (true, %d)", auto, maxWindowScale, MaxWindowScale)
	}
}

// The ceiling is a hard cap on what an operator can ask for, so a retier has
// to clamp the same way construction does.
func TestSetFlowControlClampsToTheMaxWindowScale(t *testing.T) {
	server := newArtXTestServer(t)
	server.SetFlowControl(false, MaxWindowScale+7)
	if _, maxWindowScale := server.flowControlPolicy(); maxWindowScale != MaxWindowScale {
		t.Fatalf("clamped scale = %d, want %d", maxWindowScale, MaxWindowScale)
	}
}
