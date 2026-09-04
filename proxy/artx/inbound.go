package artx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/internet/udp"
	"google.golang.org/protobuf/proto"
)

const (
	exporterLabel    = "EXPORTER-artx-auth-v1"
	bucketSeconds    = int64(60)
	timestampSkew    = int64(1)
	handshakeTimeout = 10 * time.Second
)

type Server struct {
	userMu   sync.RWMutex
	users    map[[UserLocatorLength]byte]*protocol.MemoryUser
	locators map[string][UserLocatorLength]byte

	tlsConfig         *tls.Config
	replay            *replayCache
	fallback          FallbackHandler
	stats             runtimeCounters
	wireVersion       uint32
	profileVersion    uint32
	udpEnabled        bool
	wireV3DummyPSK    [wireV3TagLength]byte
	wireV4DummyPSK    [wireV4TagLength]byte
	nativeUDPDummyPSK [nativeUDPTagLength]byte
	now               func() time.Time
	targetReadyWait   time.Duration

	sampleRTT func(net.Conn) autoRTTSample

	// autoMu guards the runtime-mutable half of the flow-control policy.
	// flowControlAuto and maxWindowScale live here rather than in the
	// immutable block above because the agent retiers a live node in
	// place: rebuilding the inbound to change a tier would close its
	// listener and drop every session on it.
	autoMu          sync.RWMutex
	flowControlAuto bool
	maxWindowScale  uint32
	pressure        *PressureGovernor
	userRates       UserRateLookup
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil || config.TlsSettings == nil || len(config.TlsSettings.Certificate) == 0 {
		return nil, errors.New("artx: TLS certificate is required")
	}
	if config.WireVersion != 1 && config.WireVersion != 2 && config.WireVersion != 3 && config.WireVersion != 4 {
		return nil, fmt.Errorf("artx: unsupported wire version %d", config.WireVersion)
	}
	if (config.WireVersion == 3 || config.WireVersion == 4) && (config.ProfileVersion != 1 || config.UdpEnabled || config.Fallback == nil || !config.Fallback.Enabled) {
		return nil, fmt.Errorf("artx: wire-v%d requires profile version 1, TCP-only, and enabled fallback", config.WireVersion)
	}
	if config.ProfileVersion < profileVersionUnshaped || config.ProfileVersion > profileVersionTimedRecordShaping {
		return nil, fmt.Errorf("artx: unsupported profile version %d", config.ProfileVersion)
	}
	if config.ProfileVersion == profileVersionTimedRecordShaping && !preciseSettingsDeadlineSupported {
		return nil, errPreciseSettingsDeadlineUnsupported
	}

	tlsSettings := proto.Clone(config.TlsSettings).(*transporttls.Config)
	for _, certificate := range tlsSettings.Certificate {
		// ponytail: snapshot ArtX certificates; rebuild the inbound after renewal instead of inheriting Xray's racy hot-reload slice.
		certificate.OneTimeLoading = true
	}
	managedTLSConfig := tlsSettings.GetTLSConfig()
	// Keep the runtime config immutable while the Xray certificate callback manages its locked authority cache.
	tlsConfig := managedTLSConfig.Clone()
	tlsConfig.Certificates = nil
	tlsConfig.NameToCertificate = nil
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.SessionTicketsDisabled = true
	if config.WireVersion == 4 {
		tlsConfig.NextProtos = []string{"http/1.1"}
	} else {
		tlsConfig.NextProtos = appendUnique(tlsConfig.NextProtos, "h2", "http/1.1")
	}
	server := &Server{
		tlsConfig:       tlsConfig,
		replay:          newReplayCache(replayCacheCapacity, replayCacheTTL, time.Now),
		wireVersion:     config.WireVersion,
		profileVersion:  config.ProfileVersion,
		udpEnabled:      config.UdpEnabled,
		maxWindowScale:  min(config.MaxWindowScale, MaxWindowScale),
		now:             time.Now,
		targetReadyWait: wireV4TargetReadyWait,
		flowControlAuto: config.FlowControlAuto,
		sampleRTT:       sampleSocketRTT,
	}
	if _, err := rand.Read(server.nativeUDPDummyPSK[:]); err != nil {
		return nil, fmt.Errorf("artx: initialize native UDP dummy key: %w", err)
	}
	if config.WireVersion == 3 {
		if _, err := rand.Read(server.wireV3DummyPSK[:]); err != nil {
			return nil, fmt.Errorf("artx: initialize wire-v3 dummy key: %w", err)
		}
	}
	if config.WireVersion == 4 {
		if _, err := rand.Read(server.wireV4DummyPSK[:]); err != nil {
			return nil, fmt.Errorf("artx: initialize wire-v4 dummy key: %w", err)
		}
	}
	if instance := core.FromContext(ctx); instance != nil {
		server.stats.manager, _ = instance.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	}
	server.stats.ceilingSource = server.pressureCeiling
	if config.Fallback != nil && config.Fallback.Enabled {
		fallback, err := NewHTTPFallback(config.Fallback.Origin)
		if err != nil {
			return nil, fmt.Errorf("artx: invalid fallback: %w", err)
		}
		server.fallback = fallback
	}
	server.replay.now = func() time.Time { return server.now() }
	for _, configuredUser := range config.Users {
		user, err := configuredUser.ToMemoryUser()
		if err != nil {
			return nil, fmt.Errorf("artx: invalid user: %w", err)
		}
		if err := server.AddUser(context.Background(), user); err != nil {
			return nil, err
		}
	}
	return server, nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UNIX}
}

func (s *Server) Process(ctx context.Context, network xnet.Network, connection stat.Connection, dispatcher routing.Dispatcher) (processErr error) {
	if network != xnet.Network_TCP && network != xnet.Network_UNIX {
		return errors.New("artx: TCP is required")
	}
	if connection == nil || dispatcher == nil {
		return errors.New("artx: connection and dispatcher are required")
	}
	r0Hook := newR0ServerHook(connection, s.wireVersion)
	defer closeR0ServerHook(r0Hook)
	if s.wireVersion != 4 {
		ctx = contextWithR0TargetReady(ctx, r0Hook)
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		s.stats.bind(inbound.Tag)
	}
	s.stats.add(runtimeCounterTotalConnections, 1)
	s.stats.add(runtimeCounterActiveConnections, 1)
	defer s.stats.add(runtimeCounterActiveConnections, -1)
	stopContextClose := context.AfterFunc(ctx, func() { closeTransport(connection) })
	defer func() {
		stopContextClose()
		if ctx.Err() != nil {
			processErr = ctx.Err()
		}
	}()
	_ = connection.SetDeadline(s.now().Add(handshakeTimeout))
	tlsConnection := tls.Server(connection, s.tlsConfig)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("artx: TLS handshake: %w", err)
	}
	emitR0ServerEvent(r0Hook, r0ServerEventTLSReady, 1)
	state := tlsConnection.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return s.handlePreAuthFailure(ctx, tlsConnection, nil, errors.New("artx: TLS 1.3 is required"))
	}
	if s.wireVersion == 3 {
		if state.NegotiatedProtocol != "h2" {
			return s.serveFallback(ctx, tlsConnection, nil)
		}
		exporter, err := state.ExportKeyingMaterial(wireV3ExporterLabel, nil, wireV3ExporterLength)
		if err != nil {
			return s.handlePreAuthFailure(ctx, tlsConnection, nil, fmt.Errorf("artx: wire-v3 TLS exporter: %w", err))
		}
		return s.processWireV3(ctx, tlsConnection, dispatcher, exporter, state.ServerName)
	}
	if s.wireVersion == 4 {
		if state.NegotiatedProtocol != "http/1.1" {
			return s.serveFallback(ctx, tlsConnection, nil)
		}
		exporter, err := state.ExportKeyingMaterial(wireV4ExporterLabel, nil, wireV4ExporterLength)
		if err != nil {
			return s.handlePreAuthFailure(ctx, tlsConnection, nil, fmt.Errorf("artx: wire-v4 TLS exporter: %w", err))
		}
		return s.processWireV4(ctx, tlsConnection, dispatcher, exporter, state.ServerName, r0Hook)
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, ExporterLength)
	if err != nil {
		return s.handlePreAuthFailure(ctx, tlsConnection, nil, fmt.Errorf("artx: TLS exporter: %w", err))
	}
	capture := newBoundedCapture(maxAuthFrameSize)
	auth, err := ReadAuthFrame(io.TeeReader(tlsConnection, capture))
	if err != nil {
		return s.handlePreAuthFailure(ctx, tlsConnection, capture.Bytes(), fmt.Errorf("artx: auth: %w", err))
	}
	user, err := s.authenticate(auth, exporter)
	if err != nil {
		return s.handlePreAuthFailure(ctx, tlsConnection, capture.Bytes(), err)
	}
	s.stats.add(runtimeCounterAuthenticationSuccess, 1)
	emitR0ServerEvent(r0Hook, r0ServerEventOpenAccepted, 1)
	_ = connection.SetDeadline(time.Time{})

	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.Name = protocolName
		inbound.User = user
		inbound.CanSpliceCopy = 0
	}

	writer := &lockedFrameWriter{writer: tlsConnection}
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("artx: authenticated user account is invalid")
	}
	settingsFlight, err := newServerSettingsFlightForWire(s.wireVersion, s.profileVersion, []byte(account.PSK), auth.Salt)
	if err != nil {
		return fmt.Errorf("artx: build server SETTINGS flight: %w", err)
	}
	var settingsWriteErr error
	if s.profileVersion == profileVersionTimedRecordShaping {
		settingsWriteErr = writer.writeChunksWithGap(ctx, settingsFlight.chunks, settingsFlight.targetStartGap, s.now, waitForSettingsDeadline)
	} else {
		settingsWriteErr = writer.writeChunks(settingsFlight.chunks...)
	}
	if settingsWriteErr != nil {
		return fmt.Errorf("artx: write server SETTINGS flight: %w", settingsWriteErr)
	}
	emitR0ServerEvent(r0Hook, r0ServerEventPeerAccept, 1)
	peerSettings, err := ReadFrame(tlsConnection)
	if err != nil {
		return err
	}
	if peerSettings.Type != FrameSettings || peerSettings.StreamID != 0 {
		return errors.New("artx: client SETTINGS required")
	}
	settings, err := DecodeSettings(peerSettings.Payload)
	if err != nil {
		return err
	}
	if err := validatePeerSettingsForWire(settings, s.wireVersion, s.profileVersion); err != nil {
		return err
	}
	emitR0ServerEvent(r0Hook, r0ServerEventInnerExposed, 1)
	if s.wireVersion == 2 {
		return s.processReusableSession(ctx, tlsConnection, dispatcher)
	}

	openFrame, err := ReadFrame(tlsConnection)
	if err != nil {
		return err
	}
	switch openFrame.Type {
	case FrameTCPSyn:
		plan := s.negotiateStreamWindowScale(settings, connection, user)
		limits := flowControlLimitsForScale(plan.scale)
		pacing := s.windowPacing(plan)
		// A paced connection is granted its uplink credit a rung at a time by
		// the pacer, so it must not be handed the whole window up front here.
		if pacing == nil {
			if err := writeExpandedReceiveCredit(writer, limits, true); err != nil {
				return fmt.Errorf("artx: expand receive window: %w", err)
			}
		}
		if plan.scale != 0 {
			s.stats.add(runtimeCounterFlowControlNegotiated, 1)
		}
		s.stats.add(flowControlScaleCounter(plan.scale), 1)
		destination, err := DecodeTCPDestination(openFrame.Payload)
		if err != nil {
			return err
		}
		link, err := dispatcher.Dispatch(ctx, destination)
		if err != nil {
			return fmt.Errorf("artx: dispatch: %w", err)
		}
		emitR0ServerEvent(r0Hook, r0ServerEventDispatchReturn, 1)
		return relaySingleStreamPaced(ctx, tlsConnection, writer, observeR0ServerLink(link, r0Hook), limits, pacing)
	case FrameUDPAssoc:
		if !s.udpEnabled {
			return errors.New("artx: UDP is disabled")
		}
		destination, err := DecodeUDPDestination(openFrame.Payload)
		if err != nil {
			return err
		}
		return relayUDPAssociation(ctx, tlsConnection, writer, dispatcher, destination)
	default:
		return errors.New("artx: first stream frame must be TCP_SYN or UDP_ASSOC on stream 1")
	}
}

// negotiateStreamWindowScale picks the wire-v1 window scale for one stream.
// The legacy policy just clamps the client offer to the node maximum; the auto
// policy additionally sizes the window from the connection's bandwidth-delay
// product and the current effective ceiling.
// streamWindowPlan is what negotiation produces: the scale the connection
// starts from, the ceiling it may grow to while it stays busy, and the RTT
// sample that sets the growth timescale.
type streamWindowPlan struct {
	scale uint32
	// staticCeiling is the part of the ceiling fixed for this connection: the
	// client offer, the node maximum and the bandwidth-delay product. The host
	// ceiling is applied on top and re-applied on every growth decision,
	// because unlike these it moves while the connection is alive.
	staticCeiling uint32
	rtt           autoRTTSample
	auto          bool
}

func (s *Server) negotiateStreamWindowScale(settings map[uint16]uint32, connection net.Conn, user *protocol.MemoryUser) streamWindowPlan {
	auto, maxWindowScale := s.flowControlPolicy()
	if !auto {
		scale := negotiateWindowScale(settings, maxWindowScale, s.wireVersion)
		return streamWindowPlan{scale: scale, staticCeiling: scale}
	}
	ceiling := s.negotiationCeiling()
	s.stats.set(runtimeCounterFlowControlPressureCeiling, uint64(ceiling))
	var rtt autoRTTSample
	if s.sampleRTT != nil {
		rtt = s.sampleRTT(connection)
	}
	staticCeiling, fellBack := negotiateAutoWindowScale(settings, maxWindowScale, s.wireVersion, rtt, s.targetRateFor(user), MaxWindowScale)
	if fellBack {
		s.stats.add(runtimeCounterFlowControlAutoFallback, 1)
	}
	return streamWindowPlan{
		scale:         min(staticCeiling, ceiling),
		staticCeiling: staticCeiling,
		rtt:           rtt,
		auto:          true,
	}
}

// windowPacing describes the ramp a connection's windows follow. Manual flow
// control gets nil: an operator who pinned a scale asked for that window, not
// for a ramp.
func (s *Server) windowPacing(plan streamWindowPlan) *windowPacing {
	if !plan.auto {
		return nil
	}
	return &windowPacing{
		rtt: plan.rtt,
		ceiling: func() uint32 {
			return min(plan.staticCeiling, s.pressureCeiling())
		},
	}
}

// governor resolves the pressure governor this inbound reads, falling back to
// the process-wide one.
func (s *Server) governor() *PressureGovernor {
	s.autoMu.RLock()
	governor := s.pressure
	s.autoMu.RUnlock()
	if governor == nil {
		governor = SharedPressureGovernor()
	}
	return governor
}

// pressureCeiling is the effective window scale ceiling for the next
// connection to arrive: the sustained-load rung intersected with the
// instantaneous memory budget clamp. It is what the reported gauge shows,
// because an operator needs to see the ceiling that actually applies rather
// than only the pressure half of it.
func (s *Server) pressureCeiling() uint32 {
	governor := s.governor()
	return budgetCeiling(governor, governor.Ceiling(), s.stats.activeConnections.Load())
}

// negotiationCeiling is pressureCeiling for a connection Process has already
// counted into the active gauge, so the budget's own "+1 for the connection
// being negotiated" is not charged twice.
func (s *Server) negotiationCeiling() uint32 {
	active := s.stats.activeConnections.Load()
	if active > 0 {
		active--
	}
	governor := s.governor()
	return budgetCeiling(governor, governor.Ceiling(), active)
}

func (s *Server) targetRateFor(user *protocol.MemoryUser) uint64 {
	if user == nil {
		return DefaultAutoTargetRate
	}
	s.autoMu.RLock()
	lookup := s.userRates
	s.autoMu.RUnlock()
	if lookup == nil {
		lookup = SharedUserRateLookup()
	}
	if lookup == nil {
		return DefaultAutoTargetRate
	}
	if rate := lookup(user.Email); rate != 0 {
		return rate
	}
	return DefaultAutoTargetRate
}

// flowControlPolicy snapshots the tier the next negotiation runs against.
// Both halves are read together so a concurrent retier can never be seen
// half-applied — an auto tier paired with the previous tier's ceiling would
// size windows against a bound the operator never chose.
func (s *Server) flowControlPolicy() (auto bool, maxWindowScale uint32) {
	s.autoMu.RLock()
	defer s.autoMu.RUnlock()
	return s.flowControlAuto, s.maxWindowScale
}

// SetFlowControl retiers a running inbound. Sessions already established keep
// the window they negotiated — a scale is fixed for the life of a stream —
// so the new tier takes effect as connections turn over, which is the price
// of not dropping every one of them to change a setting.
func (s *Server) SetFlowControl(auto bool, maxWindowScale uint32) {
	s.autoMu.Lock()
	s.flowControlAuto = auto
	s.maxWindowScale = min(maxWindowScale, MaxWindowScale)
	s.autoMu.Unlock()
}

// SetPressureGovernor installs a per-inbound host pressure governor. A nil
// governor makes the inbound fall back to the process-wide one.
func (s *Server) SetPressureGovernor(governor *PressureGovernor) {
	s.autoMu.Lock()
	s.pressure = governor
	s.autoMu.Unlock()
}

// SetUserRateLookup installs a per-inbound plan rate resolver. A nil lookup
// makes the inbound fall back to the process-wide one.
func (s *Server) SetUserRateLookup(lookup UserRateLookup) {
	s.autoMu.Lock()
	s.userRates = lookup
	s.autoMu.Unlock()
}

func (s *Server) Stats() RuntimeStats {
	return s.stats.snapshot()
}

// Close implements common.Closable. It only detaches this inbound's counters
// from the host pressure fan-out; there is no other teardown to do.
func (s *Server) Close() error {
	s.stats.release()
	return nil
}

func (s *Server) handlePreAuthFailure(ctx context.Context, connection *tls.Conn, prefix []byte, authErr error) error {
	s.stats.add(runtimeCounterAuthenticationFailure, 1)
	if errors.Is(authErr, errReplay) || errors.Is(authErr, errReplayCacheFull) {
		s.stats.add(runtimeCounterReplayRejected, 1)
	}
	if s.fallback == nil {
		return authErr
	}
	return s.serveFallback(ctx, connection, prefix)
}

func (s *Server) serveFallback(ctx context.Context, connection *tls.Conn, prefix []byte) error {
	if s.fallback == nil {
		return errors.New("artx: fallback is not configured")
	}
	s.stats.add(runtimeCounterFallbackHits, 1)
	_ = connection.SetDeadline(time.Time{})
	if err := s.fallback.Serve(ctx, connection, prefix); err != nil {
		s.stats.add(runtimeCounterFallbackErrors, 1)
		return fmt.Errorf("artx: fallback failed: %w", err)
	}
	return nil
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		found := false
		for _, value := range values {
			if value == addition {
				found = true
				break
			}
		}
		if !found {
			values = append(values, addition)
		}
	}
	return values
}

func (s *Server) authenticate(frame AuthFrame, exporter []byte) (*protocol.MemoryUser, error) {
	user := s.userByLocator(frame.UserLocator)
	if user == nil {
		return nil, errors.New("artx: authentication failed")
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok || !frame.Verify([]byte(account.PSK), exporter) {
		return nil, errors.New("artx: authentication failed")
	}
	currentBucket := s.now().Unix() / bucketSeconds
	frameBucket := int64(frame.TimestampBucket)
	if frameBucket < currentBucket-timestampSkew || frameBucket > currentBucket+timestampSkew {
		return nil, errors.New("artx: authentication failed")
	}
	if err := s.replay.add(replayKeyFor(frame)); err != nil {
		return nil, err
	}
	return user, nil
}

func settingsList(profileVersion uint32) []Setting {
	return settingsListForWire(1, profileVersion)
}

func settingsListForWire(wireVersion, profileVersion uint32) []Setting {
	settings := []Setting{
		{Key: SettingMaxConcurrentStreams, Value: 1},
		{Key: SettingInitialStreamWindow, Value: InitialStreamWindow},
		{Key: SettingInitialConnectionWindow, Value: InitialConnectionWindow},
		{Key: SettingPaddingProfileVersionAck, Value: profileVersion},
	}
	if wireVersion == 2 {
		settings = append(settings, Setting{Key: SettingSessionReuse, Value: 1})
	}
	return settings
}

func settingsForProfile(profileVersion uint32) map[uint16]uint32 {
	return settingsForWire(1, profileVersion)
}

func settingsForWire(wireVersion, profileVersion uint32) map[uint16]uint32 {
	settings := make(map[uint16]uint32, 4)
	for _, setting := range settingsListForWire(wireVersion, profileVersion) {
		settings[setting.Key] = setting.Value
	}
	return settings
}

func validatePeerSettings(settings map[uint16]uint32, profileVersion uint32) error {
	return validatePeerSettingsForWire(settings, 1, profileVersion)
}

func validatePeerSettingsForWire(settings map[uint16]uint32, wireVersion, profileVersion uint32) error {
	want := settingsForWire(wireVersion, profileVersion)
	for key, value := range want {
		if settings[key] != value {
			return fmt.Errorf("artx: incompatible setting 0x%04x", key)
		}
	}
	return nil
}

type lockedFrameWriter struct {
	mu          sync.Mutex
	writer      io.Writer
	wireVersion uint32
	streamID    uint32
}

func (writer *lockedFrameWriter) write(frame Frame) error {
	return writer.writeFrames(frame)
}

func (writer *lockedFrameWriter) writeFrames(frames ...Frame) error {
	chunks := make([][]byte, 0, len(frames))
	for _, frame := range frames {
		if writer.streamID != 0 && frame.StreamID == ClientStreamID {
			frame.StreamID = writer.streamID
		}
		wireVersion := writer.wireVersion
		if wireVersion == 0 {
			wireVersion = 1
		}
		encoded, err := frame.marshal(wireVersion)
		if err != nil {
			return err
		}
		chunks = append(chunks, encoded)
	}
	return writer.writeChunks(chunks...)
}

func (writer *lockedFrameWriter) writeChunks(chunks ...[]byte) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for _, chunk := range chunks {
		if err := writeAll(writer.writer, chunk); err != nil {
			return err
		}
	}
	return nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

type sendWindow struct {
	mu         sync.Mutex
	stream     uint32
	connection uint32
	maxStream  uint32
	maxConn    uint32
	changed    chan struct{}
}

func newSendWindow() *sendWindow {
	return newSendWindowWithLimits(legacyFlowControlLimits())
}

func newSendWindowWithLimits(limits flowControlLimits) *sendWindow {
	return &sendWindow{
		stream: limits.stream, connection: limits.connection,
		maxStream: limits.stream, maxConn: limits.connection,
		changed: make(chan struct{}),
	}
}

func (window *sendWindow) consume(amount int) error {
	window.mu.Lock()
	defer window.mu.Unlock()
	if amount < 0 || uint32(amount) > window.stream || uint32(amount) > window.connection {
		return errors.New("artx: flow-control window exhausted")
	}
	window.stream -= uint32(amount)
	window.connection -= uint32(amount)
	return nil
}

func (window *sendWindow) waitConsume(ctx context.Context, amount int) error {
	for {
		window.mu.Lock()
		if amount >= 0 && uint32(amount) <= window.stream && uint32(amount) <= window.connection {
			window.stream -= uint32(amount)
			window.connection -= uint32(amount)
			window.mu.Unlock()
			return nil
		}
		changed := window.changed
		window.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

// grow raises the live credit and the ceiling by the same amount.
//
// Raising them together is what makes growth safe: the invariant
// credit+in-flight == max is preserved, so a replenish the peer already had in
// flight still fits when it lands instead of tripping the overflow guard.
func (window *sendWindow) grow(streamDelta, connectionDelta uint32) {
	if streamDelta == 0 && connectionDelta == 0 {
		return
	}
	window.mu.Lock()
	window.stream += streamDelta
	window.maxStream += streamDelta
	window.connection += connectionDelta
	window.maxConn += connectionDelta
	close(window.changed)
	window.changed = make(chan struct{})
	window.mu.Unlock()
}

func (window *sendWindow) update(streamID, increment uint32) error {
	if increment == 0 {
		return errors.New("artx: zero WINDOW_UPDATE")
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	switch streamID {
	case 0:
		if increment > window.maxConn-window.connection {
			return errors.New("artx: connection window overflow")
		}
		window.connection += increment
	case ClientStreamID:
		if increment > window.maxStream-window.stream {
			return errors.New("artx: stream window overflow")
		}
		window.stream += increment
	default:
		return errors.New("artx: invalid WINDOW_UPDATE stream")
	}
	close(window.changed)
	window.changed = make(chan struct{})
	return nil
}

var errStreamReset = errors.New("artx: stream reset")

type relayDirection byte

const (
	relayUplinkDirection relayDirection = iota
	relayDownlinkDirection
)

type relayResult struct {
	direction relayDirection
	err       error
}

func relaySingleStream(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link) error {
	return relaySingleStreamWithLimits(ctx, connection, writer, link, legacyFlowControlLimits())
}

func relaySingleStreamWithLimits(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, limits flowControlLimits) error {
	return relaySingleStreamPaced(ctx, connection, writer, link, limits, nil)
}

// relaySingleStreamPaced relays one stream, optionally growing the downlink
// window on demand instead of committing the negotiated window up front.
func relaySingleStreamPaced(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, limits flowControlLimits, pacing *windowPacing) error {
	return relaySingleStreamFramesPaced(ctx, connection, writer, link, func() (Frame, error) {
		return ReadFrame(connection)
	}, limits, pacing)
}

func relaySingleStreamFrames(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, readFrame func() (Frame, error)) error {
	return relaySingleStreamFramesWithLimits(ctx, connection, writer, link, readFrame, legacyFlowControlLimits())
}

func relaySingleStreamFramesWithLimits(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, readFrame func() (Frame, error), limits flowControlLimits) error {
	return relaySingleStreamFramesPaced(ctx, connection, writer, link, readFrame, limits, nil)
}

func relaySingleStreamFramesPaced(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, readFrame func() (Frame, error), limits flowControlLimits, pacing *windowPacing) error {
	// While pacing, the negotiated limits describe the ceiling of a ramp rather
	// than the window the connection opens with: both directions start at the
	// compatibility window and climb while the peer keeps them busy.
	openingLimits := limits
	if pacing != nil {
		openingLimits = legacyFlowControlLimits()
	}
	sendWindow := newSendWindowWithLimits(openingLimits)
	receiveWindow := newSendWindowWithLimits(openingLimits)
	downlinkPacer := newDownlinkPacer(pacing, sendWindow)
	uplinkPacer := newUplinkPacer(pacing, receiveWindow, writer)
	clientFinished := make(chan struct{}, 1)
	results := make(chan relayResult, 2)
	go func() {
		results <- relayResult{direction: relayUplinkDirection, err: relayUplinkFrames(connection, writer, link, sendWindow, receiveWindow, clientFinished, readFrame, limits.stream, uplinkPacer)}
	}()
	go func() {
		results <- relayResult{direction: relayDownlinkDirection, err: relayDownlink(ctx, writer, link, sendWindow, downlinkPacer)}
	}()

	clientHalfClosed := false
	uplinkExited := false
	downlinkExited := false
	for {
		select {
		case <-ctx.Done():
			stopRelay(connection, link)
			waitRelayResults(results, uplinkExited, downlinkExited)
			return ctx.Err()
		case <-clientFinished:
			clientHalfClosed = true
			clientFinished = nil
			if downlinkExited {
				closeTransport(connection)
				waitRelayResults(results, uplinkExited, downlinkExited)
				return nil
			}
		case result := <-results:
			switch result.direction {
			case relayUplinkDirection:
				uplinkExited = true
			case relayDownlinkDirection:
				downlinkExited = true
			}
			if result.err != nil || result.direction == relayUplinkDirection {
				stopRelay(connection, link)
				remaining := waitRelayResults(results, uplinkExited, downlinkExited)
				if relayResultsContainStreamReset(result, remaining) {
					return nil
				}
				return result.err
			}
			if clientHalfClosed {
				closeTransport(connection)
				waitRelayResults(results, uplinkExited, downlinkExited)
				return nil
			}
		}
	}
}

func stopRelay(connection io.Closer, link *transport.Link) {
	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
	abortTransport(connection)
}

func waitRelayResults(results <-chan relayResult, uplinkDone, downlinkDone bool) []relayResult {
	remaining := 2
	if uplinkDone {
		remaining--
	}
	if downlinkDone {
		remaining--
	}
	collected := make([]relayResult, 0, remaining)
	for range remaining {
		collected = append(collected, <-results)
	}
	return collected
}

func relayResultsContainStreamReset(first relayResult, remaining []relayResult) bool {
	if errors.Is(first.err, errStreamReset) {
		return true
	}
	for _, result := range remaining {
		if errors.Is(result.err, errStreamReset) {
			return true
		}
	}
	return false
}

func closeTransport(connection io.Closer) {
	if deadline, ok := connection.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadline.SetDeadline(time.Now())
	}
	_ = connection.Close()
}

func abortTransport(connection io.Closer) {
	if tlsConnection, ok := connection.(*tls.Conn); ok {
		_ = tlsConnection.NetConn().Close()
		return
	}
	closeTransport(connection)
}

func relayUplink(connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, sendWindow, receiveWindow *sendWindow, clientFinished chan<- struct{}) error {
	return relayUplinkFrames(connection, writer, link, sendWindow, receiveWindow, clientFinished, func() (Frame, error) {
		return ReadFrame(connection)
	}, receiveWindow.maxStream, nil)
}

func relayUplinkFrames(connection io.ReadWriteCloser, writer *lockedFrameWriter, link *transport.Link, sendWindow, receiveWindow *sendWindow, clientFinished chan<- struct{}, readFrame func() (Frame, error), queueLimit uint32, pacer *windowPacer) error {
	// The buffer is sized for the ceiling rather than for today's window: what
	// bounds memory is the credit actually granted, and a buffer that shrank
	// below the granted credit would reject data the client was invited to send.
	queue := newUplinkQueue(max(queueLimit, receiveWindow.maxStream))
	pumpDone := make(chan error, 1)
	go func() {
		err := pumpUplink(writer, link, receiveWindow, queue, clientFinished, pacer)
		pumpDone <- err
		if err != nil {
			abortTransport(connection)
		}
	}()

	readErr := readUplinkFrameSource(readFrame, queue, sendWindow, receiveWindow)
	select {
	case pumpErr := <-pumpDone:
		if pumpErr != nil {
			return pumpErr
		}
		return readErr
	default:
	}

	queue.stop(readErr)
	if readErr != nil {
		common.Interrupt(link.Writer)
	}
	pumpErr := <-pumpDone
	if readErr != nil {
		return readErr
	}
	if pumpErr != nil {
		return pumpErr
	}
	return readErr
}

func readUplinkFrames(connection io.Reader, queue *uplinkQueue, sendWindow, receiveWindow *sendWindow) error {
	return readUplinkFrameSource(func() (Frame, error) { return ReadFrame(connection) }, queue, sendWindow, receiveWindow)
}

func readUplinkFrameSource(readFrame func() (Frame, error), queue *uplinkQueue, sendWindow, receiveWindow *sendWindow) error {
	clientWriteClosed := false
	for {
		frame, err := readFrame()
		if err != nil {
			if clientWriteClosed && errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch frame.Type {
		case FrameData:
			if clientWriteClosed {
				return errors.New("artx: DATA after FIN")
			}
			if err := receiveWindow.consume(len(frame.Payload)); err != nil {
				return err
			}
			if err := queue.enqueue(frame.Payload); err != nil {
				return err
			}
		case FrameFin:
			if clientWriteClosed || len(frame.Payload) != 0 {
				return errors.New("artx: invalid FIN")
			}
			clientWriteClosed = true
			queue.finish()
		case FrameRST:
			if len(frame.Payload) != 1 {
				return errors.New("artx: invalid RST")
			}
			return errStreamReset
		case FrameWindowUpdate:
			increment, err := DecodeWindowUpdate(frame.Payload)
			if err != nil {
				return err
			}
			if err := sendWindow.update(frame.StreamID, increment); err != nil {
				return err
			}
		case FramePadding:
			continue
		case FrameSettings:
			return errors.New("artx: SETTINGS after stream open")
		case FrameTCPSyn:
			return errors.New("artx: a second stream is not supported")
		default:
			continue
		}
	}
}

type uplinkQueue struct {
	mu      sync.Mutex
	data    bytes.Buffer
	limit   uint32
	fin     bool
	stopped bool
	err     error
	changed chan struct{}
}

func newUplinkQueue(limit uint32) *uplinkQueue {
	return &uplinkQueue{limit: limit, changed: make(chan struct{})}
}

func (queue *uplinkQueue) enqueue(payload []byte) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.fin {
		return errors.New("artx: DATA after FIN")
	}
	if len(payload) > int(queue.limit)-queue.data.Len() {
		return errors.New("artx: uplink receive buffer overflow")
	}
	_, _ = queue.data.Write(payload)
	queue.signalLocked()
	return nil
}

func (queue *uplinkQueue) finish() {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.fin = true
	queue.signalLocked()
}

func (queue *uplinkQueue) stop(err error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.stopped = true
	queue.err = err
	queue.signalLocked()
}

func (queue *uplinkQueue) next() ([]byte, bool, error) {
	for {
		queue.mu.Lock()
		if queue.stopped && queue.err != nil {
			err := queue.err
			queue.mu.Unlock()
			return nil, false, err
		}
		if queue.data.Len() > 0 {
			payload := bytes.Clone(queue.data.Next(min(queue.data.Len(), MaxDataPayload)))
			queue.mu.Unlock()
			return payload, false, nil
		}
		if queue.fin {
			queue.mu.Unlock()
			return nil, true, nil
		}
		if queue.stopped {
			err := queue.err
			queue.mu.Unlock()
			return nil, false, err
		}
		changed := queue.changed
		queue.mu.Unlock()
		<-changed
	}
}

func (queue *uplinkQueue) signalLocked() {
	close(queue.changed)
	queue.changed = make(chan struct{})
}

func pumpUplink(writer *lockedFrameWriter, link *transport.Link, receiveWindow *sendWindow, queue *uplinkQueue, clientFinished chan<- struct{}, pacer *windowPacer) error {
	for {
		payload, fin, err := queue.next()
		if err != nil {
			return err
		}
		if fin {
			if err := common.Close(link.Writer); err != nil {
				return err
			}
			clientFinished <- struct{}{}
			return nil
		}
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}); err != nil {
			return err
		}
		if err := replenishReceiveWindow(writer, receiveWindow, len(payload)); err != nil {
			return err
		}
		// Growth follows what this host managed to forward, not what arrived:
		// a client that outruns the outbound should not be invited to buffer
		// more of it here.
		if err := pacer.observe(len(payload)); err != nil {
			return err
		}
	}
}

func replenishReceiveWindow(writer *lockedFrameWriter, window *sendWindow, amount int) error {
	increment, err := EncodeWindowUpdate(uint32(amount))
	if err != nil {
		return err
	}
	if err := window.update(0, uint32(amount)); err != nil {
		return err
	}
	if err := window.update(ClientStreamID, uint32(amount)); err != nil {
		return err
	}
	return writer.writeFrames(
		Frame{Type: FrameWindowUpdate, Payload: increment},
		Frame{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: increment},
	)
}

func relayDownlink(ctx context.Context, writer *lockedFrameWriter, link *transport.Link, window *sendWindow, pacer *windowPacer) error {
	for {
		buffers, readErr := link.Reader.ReadMultiBuffer()
		for !buffers.IsEmpty() {
			size := min(int(buffers.Len()), MaxDataPayload)
			payload := make([]byte, size)
			var read int
			buffers, read = buf.SplitBytes(buffers, payload)
			payload = payload[:read]
			if err := window.waitConsume(ctx, len(payload)); err != nil {
				buf.ReleaseMulti(buffers)
				return err
			}
			if err := writer.write(Frame{Type: FrameData, StreamID: ClientStreamID, Payload: payload}); err != nil {
				buf.ReleaseMulti(buffers)
				return err
			}
			if err := pacer.observe(len(payload)); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return writer.write(Frame{Type: FrameFin, StreamID: ClientStreamID})
			}
			return readErr
		}
	}
}

func relayUDPAssociation(ctx context.Context, connection io.ReadWriteCloser, writer *lockedFrameWriter, dispatcher routing.Dispatcher, destination xnet.Destination) (relayErr error) {
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	lifecycle := newUDPAssociationLifecycle()
	terminalReason := "relay_complete"
	if lifecycle != nil {
		defer func() {
			if relayErr != nil && terminalReason == "relay_complete" {
				terminalReason = "relay_error"
			}
			if traceErr := lifecycle.Close(terminalReason); relayErr == nil && traceErr != nil {
				relayErr = traceErr
			}
		}()
	}

	sendWindow := newSendWindow()
	receiveWindow := newSendWindow()
	responseErr := make(chan error, 1)
	udpDispatcher := udp.NewDispatcher(dispatcher, func(_ context.Context, packet *protocoludp.Packet) {
		defer packet.Payload.Release()
		payload, err := EncodeDatagram(packet.Payload.Bytes())
		if err == nil {
			err = sendWindow.waitConsume(relayCtx, len(payload))
		}
		if err == nil {
			err = writer.write(Frame{Type: FrameDatagram, StreamID: ClientStreamID, Payload: payload})
		}
		if err != nil {
			select {
			case responseErr <- err:
			default:
			}
			cancel()
			abortTransport(connection)
		}
	})
	defer udpDispatcher.RemoveRay()

	clientFinished := false
	for {
		frame, err := ReadFrame(connection)
		if err != nil {
			select {
			case responseWriteErr := <-responseErr:
				return responseWriteErr
			default:
			}
			if clientFinished && errors.Is(err, io.EOF) {
				terminalReason = "client_fin_complete"
				return nil
			}
			terminalReason = "read_error"
			return err
		}
		switch frame.Type {
		case FrameDatagram:
			if clientFinished {
				return errors.New("artx: DATAGRAM after FIN")
			}
			payload, err := DecodeDatagram(frame.Payload)
			if err != nil {
				return err
			}
			if lifecycle != nil {
				if err := lifecycle.Observe(payload); err != nil {
					return err
				}
			}
			if err := receiveWindow.consume(len(frame.Payload)); err != nil {
				return err
			}
			packet := buf.FromBytes(payload)
			packet.UDP = &destination
			udpDispatcher.Dispatch(relayCtx, destination, packet)
			if err := replenishReceiveWindow(writer, receiveWindow, len(frame.Payload)); err != nil {
				return err
			}
		case FrameFin:
			if clientFinished || len(frame.Payload) != 0 {
				return errors.New("artx: invalid UDP FIN")
			}
			clientFinished = true
			udpDispatcher.RemoveRay()
			terminalReason = "client_fin"
			return writer.write(Frame{Type: FrameFin, StreamID: ClientStreamID})
		case FrameRST:
			if len(frame.Payload) != 1 {
				return errors.New("artx: invalid UDP RST")
			}
			terminalReason = "client_rst"
			return nil
		case FrameWindowUpdate:
			increment, err := DecodeWindowUpdate(frame.Payload)
			if err != nil {
				return err
			}
			if err := sendWindow.update(frame.StreamID, increment); err != nil {
				return err
			}
		case FramePadding:
			continue
		case FrameSettings:
			return errors.New("artx: SETTINGS after UDP association open")
		case FrameTCPSyn, FrameUDPAssoc, FrameData:
			return errors.New("artx: invalid frame in UDP association")
		default:
			continue
		}
	}
}
