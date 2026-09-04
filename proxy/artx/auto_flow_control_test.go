package artx

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

const (
	testRate200Mbps = uint64(25_000_000)
	testRate50Mbps  = uint64(6_250_000)
)

func TestAutoWindowScaleTable(t *testing.T) {
	tests := []struct {
		name       string
		rttMicros  uint64
		targetRate uint64
		want       uint32
	}{
		// 200 Mbps: needed = 50 MB * rtt_seconds, stream window = 256 KiB << scale.
		{name: "200mbps rtt 10ms", rttMicros: 10_000, targetRate: testRate200Mbps, want: 1},
		{name: "200mbps rtt 25ms", rttMicros: 25_000, targetRate: testRate200Mbps, want: 3},
		{name: "200mbps rtt 50ms", rttMicros: 50_000, targetRate: testRate200Mbps, want: 4},
		{name: "200mbps rtt 100ms", rttMicros: 100_000, targetRate: testRate200Mbps, want: 4},
		{name: "200mbps rtt 200ms", rttMicros: 200_000, targetRate: testRate200Mbps, want: 4},
		{name: "200mbps rtt 400ms", rttMicros: 400_000, targetRate: testRate200Mbps, want: 4},
		// 50 Mbps plan: needed = 12.5 MB * rtt_seconds.
		{name: "50mbps rtt 10ms", rttMicros: 10_000, targetRate: testRate50Mbps, want: 0},
		{name: "50mbps rtt 25ms", rttMicros: 25_000, targetRate: testRate50Mbps, want: 1},
		{name: "50mbps rtt 50ms", rttMicros: 50_000, targetRate: testRate50Mbps, want: 2},
		{name: "50mbps rtt 100ms", rttMicros: 100_000, targetRate: testRate50Mbps, want: 3},
		{name: "50mbps rtt 200ms", rttMicros: 200_000, targetRate: testRate50Mbps, want: 4},
		// Zero rate means "no plan limit" and falls back to the default target rate.
		{name: "unlimited plan uses default rate", rttMicros: 25_000, targetRate: 0, want: 3},
		// Sub-window BDP still needs the legacy window only.
		{name: "tiny bdp", rttMicros: 1, targetRate: 1_000, want: 0},
		// Saturating inputs must not overflow into a small scale.
		{name: "overflow rate", rttMicros: math.MaxUint64, targetRate: math.MaxUint64, want: 4},
		{name: "overflow rtt", rttMicros: math.MaxUint64, targetRate: testRate200Mbps, want: 4},
		{name: "overflow rate only", rttMicros: 1_000, targetRate: math.MaxUint64, want: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := autoWindowScaleForBDP(test.rttMicros, test.targetRate); got != test.want {
				t.Fatalf("autoWindowScaleForBDP(%d, %d) = %d, want %d", test.rttMicros, test.targetRate, got, test.want)
			}
		})
	}
}

func TestNegotiateAutoWindowScaleFallsBackToServerMaximumWithoutRTT(t *testing.T) {
	settings := map[uint16]uint32{SettingMaxWindowScale: MaxWindowScale}
	scale, fellBack := negotiateAutoWindowScale(settings, 3, 1, autoRTTSample{}, testRate200Mbps, MaxWindowScale)
	if !fellBack {
		t.Fatal("negotiateAutoWindowScale() did not report an RTT fallback")
	}
	if scale != 3 {
		t.Fatalf("scale = %d, want 3 (node maximum)", scale)
	}

	zeroRTT := autoRTTSample{micros: 0, valid: true}
	scale, fellBack = negotiateAutoWindowScale(settings, 3, 1, zeroRTT, testRate200Mbps, MaxWindowScale)
	if !fellBack || scale != 3 {
		t.Fatalf("zero RTT: scale = %d fellBack = %v, want 3 true", scale, fellBack)
	}
}

func TestNegotiateAutoWindowScaleClamps(t *testing.T) {
	// Uncapped, a 100 ms RTT at 200 Mbps wants scale 4.
	rtt := autoRTTSample{micros: 100_000, valid: true}
	tests := []struct {
		name    string
		offer   uint32
		server  uint32
		ceiling uint32
		want    uint32
	}{
		{name: "no clamp", offer: 4, server: 4, ceiling: 4, want: 4},
		{name: "client offer clamps", offer: 2, server: 4, ceiling: 4, want: 2},
		{name: "node maximum clamps", offer: 4, server: 1, ceiling: 4, want: 1},
		{name: "pressure ceiling clamps", offer: 4, server: 4, ceiling: 2, want: 2},
		{name: "pressure ceiling zero", offer: 4, server: 4, ceiling: 0, want: 0},
		{name: "lowest of three wins", offer: 3, server: 2, ceiling: 1, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := map[uint16]uint32{SettingMaxWindowScale: test.offer}
			scale, fellBack := negotiateAutoWindowScale(settings, test.server, 1, rtt, testRate200Mbps, test.ceiling)
			if fellBack {
				t.Fatal("unexpected RTT fallback")
			}
			if scale != test.want {
				t.Fatalf("scale = %d, want %d", scale, test.want)
			}
		})
	}
}

func TestNegotiateAutoWindowScaleKeepsLegacyGuards(t *testing.T) {
	rtt := autoRTTSample{micros: 200_000, valid: true}
	tests := []struct {
		name        string
		settings    map[uint16]uint32
		server      uint32
		wireVersion uint32
	}{
		{name: "missing offer", settings: map[uint16]uint32{}, server: 4, wireVersion: 1},
		{name: "zero offer", settings: map[uint16]uint32{SettingMaxWindowScale: 0}, server: 4, wireVersion: 1},
		{name: "invalid offer", settings: map[uint16]uint32{SettingMaxWindowScale: 5}, server: 4, wireVersion: 1},
		{name: "server disabled", settings: map[uint16]uint32{SettingMaxWindowScale: 4}, server: 0, wireVersion: 1},
		{name: "wire v2", settings: map[uint16]uint32{SettingMaxWindowScale: 4}, server: 4, wireVersion: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scale, fellBack := negotiateAutoWindowScale(test.settings, test.server, test.wireVersion, rtt, testRate200Mbps, MaxWindowScale)
			if scale != 0 || fellBack {
				t.Fatalf("scale = %d fellBack = %v, want 0 false", scale, fellBack)
			}
		})
	}
}

func runAutoNegotiationForTest(t *testing.T, server *Server) (uint32, RuntimeStats) {
	t.Helper()
	_, dispatcher, closer := newTargetDispatcher()
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

	// Automatic flow control hands its window out a rung at a time to a busy
	// connection, so its handshake carries no credit at all and the scale the
	// server settled on is read from its stats rather than off the wire. The
	// legacy policy still grants everything up front, and over a synchronous
	// pipe those frames have to be drained before the client can write back.
	if !server.flowControlAuto {
		readHandshakeCreditForTest(t, client)
	}
	writeFrameForTest(t, client, Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}})
	if err := <-processDone; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	stats := server.Stats()
	return negotiatedScaleFromStats(t, stats), stats
}

func readHandshakeCreditForTest(t *testing.T, client io.Reader) {
	t.Helper()
	for range 2 {
		frame, err := ReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != FrameWindowUpdate {
			t.Fatalf("handshake frame type = %d, want WINDOW_UPDATE", frame.Type)
		}
	}
}

func negotiatedScaleFromStats(t *testing.T, stats RuntimeStats) uint32 {
	t.Helper()
	negotiated, total := uint32(0), uint64(0)
	for scale, count := range stats.FlowControlScales {
		if count > 0 {
			negotiated = uint32(scale)
			total += count
		}
	}
	if total != 1 {
		t.Fatalf("FlowControlScales = %v, want exactly one negotiation", stats.FlowControlScales)
	}
	return negotiated
}

func TestAutoNegotiationSizesWindowFromBDP(t *testing.T) {
	server := newArtXTestServer(t)
	server.flowControlAuto = true
	server.maxWindowScale = MaxWindowScale
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{micros: 50_000, valid: true} }
	server.SetUserRateLookup(func(email string) uint64 {
		if email != "user@example.com" {
			t.Errorf("rate lookup email = %q", email)
		}
		return testRate50Mbps
	})

	scale, stats := runAutoNegotiationForTest(t, server)
	if scale != 2 {
		t.Fatalf("negotiated scale = %d, want 2", scale)
	}
	if stats.FlowControlScales[2] != 1 {
		t.Fatalf("FlowControlScales = %v, want one negotiation in bucket 2", stats.FlowControlScales)
	}
	if stats.FlowControlNegotiated != 1 {
		t.Fatalf("FlowControlNegotiated = %d, want 1", stats.FlowControlNegotiated)
	}
	if stats.FlowControlAutoFallback != 0 {
		t.Fatalf("FlowControlAutoFallback = %d, want 0", stats.FlowControlAutoFallback)
	}
	if stats.FlowControlPressureCeiling != uint64(MaxWindowScale) {
		t.Fatalf("FlowControlPressureCeiling = %d, want %d", stats.FlowControlPressureCeiling, MaxWindowScale)
	}
}

func TestAutoNegotiationFallsBackToNodeMaximumWithoutRTT(t *testing.T) {
	server := newArtXTestServer(t)
	server.flowControlAuto = true
	server.maxWindowScale = 3
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{} }

	scale, stats := runAutoNegotiationForTest(t, server)
	if scale != 3 {
		t.Fatalf("negotiated scale = %d, want 3", scale)
	}
	if stats.FlowControlScales[3] != 1 || stats.FlowControlAutoFallback != 1 {
		t.Fatalf("scales = %v fallback = %d", stats.FlowControlScales, stats.FlowControlAutoFallback)
	}
}

func TestAutoNegotiationHonoursPressureCeiling(t *testing.T) {
	server := newArtXTestServer(t)
	server.flowControlAuto = true
	server.maxWindowScale = MaxWindowScale
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{micros: 200_000, valid: true} }

	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second})
	observeSeries(governor, time.Unix(0, 0), time.Second, 3, 85)
	if got := governor.Ceiling(); got != 2 {
		t.Fatalf("governor ceiling = %d, want 2", got)
	}
	server.SetPressureGovernor(governor)

	scale, stats := runAutoNegotiationForTest(t, server)
	if scale != 2 {
		t.Fatalf("negotiated scale = %d, want 2", scale)
	}
	if stats.FlowControlPressureCeiling != 2 {
		t.Fatalf("FlowControlPressureCeiling = %d, want 2", stats.FlowControlPressureCeiling)
	}
}

func TestLegacyPolicyIgnoresPressureAndRTT(t *testing.T) {
	server := newArtXTestServer(t)
	server.maxWindowScale = MaxWindowScale
	server.sampleRTT = func(net.Conn) autoRTTSample { return autoRTTSample{micros: 1, valid: true} }
	governor := NewPressureGovernor(PressureGovernorConfig{SustainWindow: 10 * time.Second})
	observeSeries(governor, time.Unix(0, 0), time.Second, 3, 99)
	server.SetPressureGovernor(governor)

	scale, stats := runAutoNegotiationForTest(t, server)
	if scale != MaxWindowScale {
		t.Fatalf("negotiated scale = %d, want %d", scale, MaxWindowScale)
	}
	if stats.FlowControlPressureCeiling != 0 {
		t.Fatalf("FlowControlPressureCeiling = %d, want 0 (legacy policy must not publish it)", stats.FlowControlPressureCeiling)
	}
}
