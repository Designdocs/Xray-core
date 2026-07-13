package artx

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
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

	tlsConfig      *tls.Config
	replay         *replayCache
	fallback       FallbackHandler
	stats          runtimeCounters
	profileVersion uint32
	now            func() time.Time
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	if config == nil || config.TlsSettings == nil || len(config.TlsSettings.Certificate) == 0 {
		return nil, errors.New("artx: TLS certificate is required")
	}
	if config.WireVersion != 1 {
		return nil, fmt.Errorf("artx: unsupported wire version %d", config.WireVersion)
	}
	if config.ProfileVersion == 0 {
		return nil, errors.New("artx: profile version is required")
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
	tlsConfig.NextProtos = appendUnique(tlsConfig.NextProtos, "h2", "http/1.1")
	server := &Server{
		tlsConfig:      tlsConfig,
		replay:         newReplayCache(replayCacheCapacity, replayCacheTTL, time.Now),
		profileVersion: config.ProfileVersion,
		now:            time.Now,
	}
	if instance := core.FromContext(ctx); instance != nil {
		server.stats.manager, _ = instance.GetFeature(featurestats.ManagerType()).(featurestats.Manager)
	}
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
	state := tlsConnection.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		return s.handlePreAuthFailure(ctx, tlsConnection, nil, errors.New("artx: TLS 1.3 is required"))
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
	_ = connection.SetDeadline(time.Time{})

	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inbound.Name = protocolName
		inbound.User = user
		inbound.CanSpliceCopy = 0
	}

	writer := &lockedFrameWriter{writer: tlsConnection}
	if err := writer.write(Frame{Type: FrameSettings, Payload: mustEncodeSettings(s.profileVersion)}); err != nil {
		return err
	}
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
	if err := validatePeerSettings(settings, s.profileVersion); err != nil {
		return err
	}

	syn, err := ReadFrame(tlsConnection)
	if err != nil {
		return err
	}
	if syn.Type != FrameTCPSyn || syn.StreamID != ClientStreamID {
		return errors.New("artx: first stream frame must be TCP_SYN on stream 1")
	}
	destination, err := DecodeTCPDestination(syn.Payload)
	if err != nil {
		return err
	}
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return fmt.Errorf("artx: dispatch: %w", err)
	}
	return relaySingleStream(ctx, tlsConnection, writer, link)
}

func (s *Server) Stats() RuntimeStats {
	return s.stats.snapshot()
}

func (s *Server) handlePreAuthFailure(ctx context.Context, connection *tls.Conn, prefix []byte, authErr error) error {
	s.stats.add(runtimeCounterAuthenticationFailure, 1)
	if errors.Is(authErr, errReplay) || errors.Is(authErr, errReplayCacheFull) {
		s.stats.add(runtimeCounterReplayRejected, 1)
	}
	if s.fallback == nil {
		return authErr
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
	return []Setting{
		{Key: SettingMaxConcurrentStreams, Value: 1},
		{Key: SettingInitialStreamWindow, Value: InitialStreamWindow},
		{Key: SettingInitialConnectionWindow, Value: InitialConnectionWindow},
		{Key: SettingPaddingProfileVersionAck, Value: profileVersion},
	}
}

func settingsForProfile(profileVersion uint32) map[uint16]uint32 {
	settings := make(map[uint16]uint32, 4)
	for _, setting := range settingsList(profileVersion) {
		settings[setting.Key] = setting.Value
	}
	return settings
}

func mustEncodeSettings(profileVersion uint32) []byte {
	payload, _ := EncodeSettings(settingsList(profileVersion))
	return payload
}

func validatePeerSettings(settings map[uint16]uint32, profileVersion uint32) error {
	want := settingsForProfile(profileVersion)
	for key, value := range want {
		if settings[key] != value {
			return fmt.Errorf("artx: incompatible setting 0x%04x", key)
		}
	}
	return nil
}

type lockedFrameWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (writer *lockedFrameWriter) write(frame Frame) error {
	encoded, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	for len(encoded) > 0 {
		written, err := writer.writer.Write(encoded)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

type sendWindow struct {
	mu         sync.Mutex
	stream     uint32
	connection uint32
	changed    chan struct{}
}

func newSendWindow() *sendWindow {
	return &sendWindow{stream: InitialStreamWindow, connection: InitialConnectionWindow, changed: make(chan struct{})}
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

func (window *sendWindow) update(streamID, increment uint32) error {
	if increment == 0 {
		return errors.New("artx: zero WINDOW_UPDATE")
	}
	window.mu.Lock()
	defer window.mu.Unlock()
	switch streamID {
	case 0:
		if increment > InitialConnectionWindow-window.connection {
			return errors.New("artx: connection window overflow")
		}
		window.connection += increment
	case ClientStreamID:
		if increment > InitialStreamWindow-window.stream {
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
	sendWindow := newSendWindow()
	receiveWindow := newSendWindow()
	clientFinished := make(chan struct{}, 1)
	results := make(chan relayResult, 2)
	go func() {
		results <- relayResult{direction: relayUplinkDirection, err: relayUplink(connection, writer, link, sendWindow, receiveWindow, clientFinished)}
	}()
	go func() {
		results <- relayResult{direction: relayDownlinkDirection, err: relayDownlink(ctx, writer, link, sendWindow)}
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
	queue := newUplinkQueue()
	pumpDone := make(chan error, 1)
	go func() {
		err := pumpUplink(writer, link, receiveWindow, queue, clientFinished)
		pumpDone <- err
		if err != nil {
			abortTransport(connection)
		}
	}()

	readErr := readUplinkFrames(connection, queue, sendWindow, receiveWindow)
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
	clientWriteClosed := false
	for {
		frame, err := ReadFrame(connection)
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
	fin     bool
	stopped bool
	err     error
	changed chan struct{}
}

func newUplinkQueue() *uplinkQueue {
	return &uplinkQueue{changed: make(chan struct{})}
}

func (queue *uplinkQueue) enqueue(payload []byte) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.fin {
		return errors.New("artx: DATA after FIN")
	}
	if len(payload) > int(InitialStreamWindow)-queue.data.Len() {
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

func pumpUplink(writer *lockedFrameWriter, link *transport.Link, receiveWindow *sendWindow, queue *uplinkQueue, clientFinished chan<- struct{}) error {
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
	if err := writer.write(Frame{Type: FrameWindowUpdate, Payload: increment}); err != nil {
		return err
	}
	return writer.write(Frame{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: increment})
}

func relayDownlink(ctx context.Context, writer *lockedFrameWriter, link *transport.Link, window *sendWindow) error {
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
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return writer.write(Frame{Type: FrameFin, StreamID: ClientStreamID})
			}
			return readErr
		}
	}
}
