package artx

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

const (
	wireV4Version        = byte(0x04)
	wireV4Flags          = byte(0x00)
	wireV4SaltLength     = 16
	wireV4ExporterLength = sha256.Size
	wireV4TagLength      = sha256.Size
	wireV4ExporterLabel  = "EXPORTER-artx-auth-v4"
	wireV4ClientLabel    = "artx-wire-v4-client\x00"
	wireV4ServerLabel    = "artx-wire-v4-server\x00"
	wireV4Method         = "CONNECT"
)

const (
	wireV4ClientInitPrefixSize = 1 + 1 + wireV4SaltLength + UserLocatorLength + 4
	wireV4ClientInitSize       = wireV4ClientInitPrefixSize + wireV4TagLength
)

type wireV4ClientInit struct {
	Salt            [wireV4SaltLength]byte
	UserLocator     [UserLocatorLength]byte
	TimestampBucket uint32
	ClientTag       [wireV4TagLength]byte
}

func newWireV4ClientInit(psk, salt, exporter []byte, serverName, targetAuthority string, timestampBucket uint32) (wireV4ClientInit, error) {
	if len(psk) == 0 {
		return wireV4ClientInit{}, errors.New("artx: wire-v4 PSK is empty")
	}
	if len(salt) != wireV4SaltLength {
		return wireV4ClientInit{}, fmt.Errorf("artx: wire-v4 salt length is %d, want %d", len(salt), wireV4SaltLength)
	}
	if len(exporter) != wireV4ExporterLength {
		return wireV4ClientInit{}, fmt.Errorf("artx: wire-v4 exporter length is %d, want %d", len(exporter), wireV4ExporterLength)
	}
	if err := validateWireV4Context(serverName, targetAuthority); err != nil {
		return wireV4ClientInit{}, err
	}
	init := wireV4ClientInit{
		UserLocator:     CalculateUserLocator(psk),
		TimestampBucket: timestampBucket,
	}
	copy(init.Salt[:], salt)
	init.ClientTag = calculateWireV4ClientTag(psk, exporter, serverName, targetAuthority, init.marshalPrefix())
	return init, nil
}

func (init wireV4ClientInit) MarshalBinary() ([]byte, error) {
	prefix := init.marshalPrefix()
	return append(prefix, init.ClientTag[:]...), nil
}

func (init wireV4ClientInit) marshalPrefix() []byte {
	prefix := make([]byte, wireV4ClientInitPrefixSize)
	prefix[0], prefix[1] = wireV4Version, wireV4Flags
	offset := 2
	copy(prefix[offset:], init.Salt[:])
	offset += wireV4SaltLength
	copy(prefix[offset:], init.UserLocator[:])
	offset += UserLocatorLength
	binary.BigEndian.PutUint32(prefix[offset:], init.TimestampBucket)
	return prefix
}

func parseWireV4ClientInit(envelope []byte) (wireV4ClientInit, error) {
	if len(envelope) != wireV4ClientInitSize {
		return wireV4ClientInit{}, errors.New("artx: invalid wire-v4 ClientInit length")
	}
	if envelope[0] != wireV4Version || envelope[1] != wireV4Flags {
		return wireV4ClientInit{}, errors.New("artx: invalid wire-v4 ClientInit header")
	}
	var init wireV4ClientInit
	offset := 2
	copy(init.Salt[:], envelope[offset:])
	offset += wireV4SaltLength
	copy(init.UserLocator[:], envelope[offset:])
	offset += UserLocatorLength
	init.TimestampBucket = binary.BigEndian.Uint32(envelope[offset:])
	offset += 4
	copy(init.ClientTag[:], envelope[offset:])
	return init, nil
}

func (init wireV4ClientInit) Verify(psk, exporter []byte, serverName, targetAuthority string) bool {
	if len(psk) == 0 || len(exporter) != wireV4ExporterLength || validateWireV4Context(serverName, targetAuthority) != nil {
		return false
	}
	want := calculateWireV4ClientTag(psk, exporter, serverName, targetAuthority, init.marshalPrefix())
	return hmac.Equal(init.ClientTag[:], want[:])
}

func calculateWireV4ClientTag(psk, exporter []byte, serverName, targetAuthority string, prefix []byte) [wireV4TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV4ClientLabel))
	_, _ = mac.Write(exporter)
	writeWireV4LengthPrefixed(mac, serverName)
	writeWireV4LengthPrefixed(mac, wireV4Method)
	writeWireV4LengthPrefixed(mac, targetAuthority)
	_, _ = mac.Write(prefix)
	var tag [wireV4TagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func calculateWireV4ServerProof(psk, exporter []byte, clientTag [wireV4TagLength]byte, status int) [wireV4TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV4ServerLabel))
	_, _ = mac.Write(exporter)
	_, _ = mac.Write(clientTag[:])
	var encodedStatus [2]byte
	binary.BigEndian.PutUint16(encodedStatus[:], uint16(status))
	_, _ = mac.Write(encodedStatus[:])
	var proof [wireV4TagLength]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func formatWireV4ProxyAuthorization(init wireV4ClientInit) string {
	envelope, _ := init.MarshalBinary()
	return "Bearer " + base64.RawURLEncoding.EncodeToString(envelope)
}

func parseWireV4ProxyAuthorization(header string) (wireV4ClientInit, bool, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return wireV4ClientInit{}, false, nil
	}
	encoded := strings.TrimPrefix(header, "Bearer ")
	if len(encoded) != base64.RawURLEncoding.EncodedLen(wireV4ClientInitSize) || strings.TrimSpace(encoded) != encoded {
		return wireV4ClientInit{}, true, errors.New("artx: malformed wire-v4 Proxy-Authorization")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(envelope) != encoded {
		return wireV4ClientInit{}, true, errors.New("artx: malformed wire-v4 Proxy-Authorization")
	}
	init, err := parseWireV4ClientInit(envelope)
	return init, true, err
}

func formatWireV4ProxyAuthenticationInfo(proof [wireV4TagLength]byte) string {
	return `rspauth="` + base64.RawURLEncoding.EncodeToString(proof[:]) + `"`
}

func verifyWireV4ProxyAuthenticationInfo(header string, psk, exporter []byte, clientTag [wireV4TagLength]byte, status int) bool {
	prefix := `rspauth="`
	encodedLength := base64.RawURLEncoding.EncodedLen(wireV4TagLength)
	if len(header) != len(prefix)+encodedLength+1 || !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, `"`) {
		return false
	}
	encoded := header[len(prefix) : len(header)-1]
	proof, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(proof) != wireV4TagLength || base64.RawURLEncoding.EncodeToString(proof) != encoded {
		return false
	}
	want := calculateWireV4ServerProof(psk, exporter, clientTag, status)
	return hmac.Equal(proof, want[:])
}

func validateWireV4Context(serverName, targetAuthority string) error {
	if net.ParseIP(serverName) != nil {
		return errors.New("artx: invalid wire-v4 server name")
	}
	canonicalServerName, err := canonicalWireV4Domain(serverName)
	if err != nil || canonicalServerName != serverName {
		return errors.New("artx: invalid wire-v4 server name")
	}
	_, err = parseWireV4Authority(targetAuthority)
	return err
}

func formatWireV4Authority(destination xnet.Destination) (string, error) {
	if destination.Network != xnet.Network_TCP || destination.Address == nil || destination.Port == 0 {
		return "", errors.New("artx: invalid wire-v4 TCP destination")
	}
	var host string
	if destination.Address.Family().IsDomain() {
		var err error
		host, err = canonicalWireV4Domain(destination.Address.Domain())
		if err != nil {
			return "", err
		}
	} else {
		host = destination.Address.IP().String()
		if host == "" {
			return "", errors.New("artx: invalid wire-v4 IP destination")
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(destination.Port))), nil
}

func parseWireV4Authority(authority string) (xnet.Destination, error) {
	host, portText, err := net.SplitHostPort(authority)
	if err != nil || host == "" || portText == "" {
		return xnet.Destination{}, errors.New("artx: invalid wire-v4 authority")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return xnet.Destination{}, errors.New("artx: invalid wire-v4 authority port")
	}
	var address xnet.Address
	if ip := net.ParseIP(host); ip != nil {
		address = xnet.IPAddress(ip)
	} else {
		canonicalHost, hostErr := canonicalWireV4Domain(host)
		if hostErr != nil || canonicalHost != host {
			return xnet.Destination{}, errors.New("artx: non-canonical wire-v4 authority host")
		}
		address = xnet.DomainAddress(host)
	}
	destination := xnet.TCPDestination(address, xnet.Port(port))
	canonical, err := formatWireV4Authority(destination)
	if err != nil || canonical != authority {
		return xnet.Destination{}, errors.New("artx: non-canonical wire-v4 authority")
	}
	return destination, nil
}

func canonicalWireV4Domain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || len(value) > 253 {
		return "", errors.New("artx: invalid wire-v4 domain")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !wireV4DomainEdge(label[0]) || !wireV4DomainEdge(label[len(label)-1]) {
			return "", errors.New("artx: invalid wire-v4 domain label")
		}
		for index := 1; index < len(label)-1; index++ {
			if !wireV4DomainEdge(label[index]) && label[index] != '-' {
				return "", errors.New("artx: invalid wire-v4 domain label")
			}
		}
	}
	return value, nil
}

func wireV4DomainEdge(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func writeWireV4LengthPrefixed(writer interface{ Write([]byte) (int, error) }, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func (s *Server) processWireV4(ctx context.Context, connection *tls.Conn, dispatcher routing.Dispatcher, exporter []byte, serverName string, r0Hook r0ServerHook) error {
	fallback, ok := s.fallback.(*HTTPFallback)
	if !ok {
		return errors.New("artx: wire-v4 HTTP fallback is not configured")
	}
	setupDeadline := s.now().Add(s.targetReadyWait + wireV4RefusalWriteGrace)
	_ = connection.SetDeadline(setupDeadline)
	var claimed atomic.Bool
	var tunnelErr atomic.Pointer[wireV4TunnelError]
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.isWireV4Candidate(request) {
			s.serveWireV4FallbackRequest(fallback, writer, request)
			return
		}
		init, _, parseErr := parseWireV4ProxyAuthorization(request.Header.Get("Proxy-Authorization"))
		user, account, authErr := s.authenticateWireV4(init, exporter, serverName, request.RequestURI)
		if parseErr != nil || authErr != nil {
			s.stats.add(runtimeCounterAuthenticationFailure, 1)
			if errors.Is(authErr, errReplay) || errors.Is(authErr, errReplayCacheFull) {
				s.stats.add(runtimeCounterReplayRejected, 1)
			}
			s.serveWireV4FallbackRequest(fallback, writer, request)
			return
		}
		destination, err := parseWireV4Authority(request.RequestURI)
		if err != nil {
			s.stats.add(runtimeCounterAuthenticationFailure, 1)
			s.serveWireV4FallbackRequest(fallback, writer, request)
			return
		}
		if claimed.Swap(true) {
			tunnelErr.Store(&wireV4TunnelError{err: errors.New("artx: wire-v4 connection already claimed")})
			return
		}
		emitR0ServerEvent(r0Hook, r0ServerEventOpenAccepted, 1)
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			tunnelErr.Store(&wireV4TunnelError{err: errors.New("artx: wire-v4 HTTP/1.1 hijacking unavailable")})
			return
		}
		hijacked, buffered, err := hijacker.Hijack()
		if err != nil {
			tunnelErr.Store(&wireV4TunnelError{err: fmt.Errorf("artx: wire-v4 hijack: %w", err)})
			return
		}
		defer closeWireV4HijackedConnection(r0Hook, hijacked)
		if buffered.Reader.Buffered() != 0 {
			tunnelErr.Store(&wireV4TunnelError{err: errors.New("artx: wire-v4 early payload rejected")})
			return
		}
		requestCtx := request.Context()
		if inbound := session.InboundFromContext(requestCtx); inbound != nil {
			inbound.Name = protocolName
			inbound.User = user
			inbound.CanSpliceCopy = 0
		}
		readyBarrier := newTargetReadyBarrier(destination)
		requestCtx = contextWithTargetReadyBarrier(requestCtx, readyBarrier)
		link, err := dispatcher.Dispatch(requestCtx, destination)
		if err != nil {
			_ = s.writeWireV4Response(buffered.Writer, account, exporter, init.ClientTag, http.StatusBadGateway)
			tunnelErr.Store(&wireV4TunnelError{err: errors.New("artx: wire-v4 target unavailable")})
			return
		}
		emitR0ServerEvent(r0Hook, r0ServerEventDispatchReturn, 1)
		if err := readyBarrier.Wait(requestCtx, setupDeadline.Add(-wireV4RefusalWriteGrace)); err != nil {
			interruptTargetReadyLink(link)
			_ = s.writeWireV4Response(buffered.Writer, account, exporter, init.ClientTag, http.StatusBadGateway)
			tunnelErr.Store(&wireV4TunnelError{err: errors.New("artx: wire-v4 target unavailable")})
			return
		}
		emitR0ServerEvent(r0Hook, r0ServerEventTargetReady, 1)
		s.stats.add(runtimeCounterAuthenticationSuccess, 1)
		_ = connection.SetDeadline(time.Time{})
		if err := s.writeWireV4Response(buffered.Writer, account, exporter, init.ClientTag, http.StatusOK); err != nil {
			tunnelErr.Store(&wireV4TunnelError{err: err})
			return
		}
		emitR0ServerEvent(r0Hook, r0ServerEventPeerAccept, 1)
		emitR0ServerEvent(r0Hook, r0ServerEventInnerExposed, 1)
		if err := relayWireV4(requestCtx, connection, hijacked, observeR0ServerLink(link, r0Hook)); err != nil {
			tunnelErr.Store(&wireV4TunnelError{err: err})
		}
	})

	listener := newSingleConnectionListener(connection)
	server := newFallbackHTTPServer(handler, handshakeTimeout)
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	stopListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopListener()
	err := server.Serve(listener)
	if result := tunnelErr.Load(); result != nil {
		return result.err
	}
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func closeWireV4HijackedConnection(r0Hook r0ServerHook, connection net.Conn) {
	closeR0ServerHook(r0Hook)
	_ = connection.Close()
}

type wireV4TunnelError struct{ err error }

func (s *Server) isWireV4Candidate(request *http.Request) bool {
	if request.Method != http.MethodConnect || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.URL == nil ||
		request.URL.Host == "" || request.URL.Host != request.RequestURI || request.Host != request.RequestURI || request.URL.Path != "" ||
		request.URL.Scheme != "" || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" ||
		request.UserAgent() != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	if len(request.Header.Values("Proxy-Authorization")) != 1 || !strings.HasPrefix(request.Header.Get("Proxy-Authorization"), "Bearer ") {
		return false
	}
	for _, name := range []string{"Content-Length", "Transfer-Encoding", "Expect", "Trailer", "Connection", "Upgrade", "Proxy-Connection", "TE"} {
		if len(request.Header.Values(name)) != 0 {
			return false
		}
	}
	return true
}

func (s *Server) authenticateWireV4(init wireV4ClientInit, exporter []byte, serverName, targetAuthority string) (*protocol.MemoryUser, *MemoryAccount, error) {
	user := s.userByLocator(init.UserLocator)
	psk := s.wireV4DummyPSK[:]
	var account *MemoryAccount
	if user != nil {
		account, _ = user.Account.(*MemoryAccount)
		if account != nil {
			psk = []byte(account.PSK)
		}
	}
	verified := init.Verify(psk, exporter, serverName, targetAuthority)
	currentBucket := s.now().Unix() / bucketSeconds
	frameBucket := int64(init.TimestampBucket)
	if user == nil || account == nil || !verified || frameBucket < currentBucket-timestampSkew || frameBucket > currentBucket+timestampSkew {
		return nil, nil, errors.New("artx: wire-v4 authentication failed")
	}
	if err := s.replay.add(replayKeyForWireV4(init)); err != nil {
		return nil, nil, err
	}
	return user, account, nil
}

func replayKeyForWireV4(init wireV4ClientInit) replayKey {
	digestInput := make([]byte, 0, len(init.Salt)+len(init.ClientTag))
	digestInput = append(digestInput, init.Salt[:]...)
	digestInput = append(digestInput, init.ClientTag[:]...)
	digest := sha256.Sum256(digestInput)
	var key replayKey
	offset := copy(key[:], init.UserLocator[:])
	offset += copy(key[offset:], digest[:])
	binary.BigEndian.PutUint32(key[offset:], init.TimestampBucket)
	return key
}

func (s *Server) serveWireV4FallbackRequest(fallback *HTTPFallback, writer http.ResponseWriter, request *http.Request) {
	s.stats.add(runtimeCounterFallbackHits, 1)
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Authorization")
	request.Close = true
	state := &fallbackServeState{}
	fallback.proxyRequest(&wireV4FallbackResponseWriter{ResponseWriter: writer}, request, fallbackRequestTimeout, false, state.MarkFailed)
	if state.Err() != nil {
		s.stats.add(runtimeCounterFallbackErrors, 1)
	}
}

type wireV4FallbackResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (writer *wireV4FallbackResponseWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}
	writer.wroteHeader = true
	writer.Header().Del("Proxy-Authentication-Info")
	writer.Header().Del("Proxy-Authenticate")
	writer.Header().Set("Connection", "close")
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		status = http.StatusNotFound
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *wireV4FallbackResponseWriter) Write(payload []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(payload)
}

func (writer *wireV4FallbackResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (s *Server) writeWireV4Response(writer *bufio.Writer, account *MemoryAccount, exporter []byte, clientTag [wireV4TagLength]byte, status int) error {
	proof := calculateWireV4ServerProof([]byte(account.PSK), exporter, clientTag, status)
	if _, err := fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nProxy-Authentication-Info: %s\r\nCache-Control: no-store\r\n\r\n", status, wireV4StatusText(status), formatWireV4ProxyAuthenticationInfo(proof)); err != nil {
		return err
	}
	return writer.Flush()
}

func wireV4StatusText(status int) string {
	if status == http.StatusOK {
		return "Connection Established"
	}
	return http.StatusText(status)
}

func relayWireV4(ctx context.Context, connection *tls.Conn, outer net.Conn, link *transport.Link) error {
	results := make(chan relayResult, 2)
	go func() {
		err := buf.Copy(buf.NewReader(connection), link.Writer)
		if err == nil {
			err = common.Close(link.Writer)
		}
		results <- relayResult{direction: relayUplinkDirection, err: err}
	}()
	go func() {
		err := buf.Copy(link.Reader, buf.NewWriter(connection))
		if err == nil {
			err = connection.CloseWrite()
		}
		results <- relayResult{direction: relayDownlinkDirection, err: err}
	}()

	abort := func() {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		_ = connection.NetConn().Close()
		_ = outer.Close()
	}
	stopContextAbort := context.AfterFunc(ctx, abort)
	defer stopContextAbort()

	uplinkDone, downlinkDone := false, false
	var peerClosed <-chan error
	for !uplinkDone || !downlinkDone {
		select {
		case <-ctx.Done():
			abort()
			waitRelayResults(results, uplinkDone, downlinkDone)
			return ctx.Err()
		case peerErr := <-peerClosed:
			abort()
			waitRelayResults(results, uplinkDone, downlinkDone)
			return peerErr
		case result := <-results:
			if result.direction == relayUplinkDirection {
				uplinkDone = true
			} else {
				downlinkDone = true
			}
			if result.err != nil {
				abort()
				waitRelayResults(results, uplinkDone, downlinkDone)
				return result.err
			}
			if uplinkDone && !downlinkDone && peerClosed == nil {
				peerClosed = monitorWireV4PeerClose(connection.NetConn())
			}
		}
	}
	return nil
}

func monitorWireV4PeerClose(connection net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		var payload [1]byte
		count, err := connection.Read(payload[:])
		switch {
		case count != 0:
			done <- errors.New("artx: wire-v4 data after TLS close-notify")
		case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
			done <- nil
		default:
			done <- err
		}
	}()
	return done
}
