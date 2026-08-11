package artx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	stdnet "net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	protocoludp "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/udp"
)

const (
	nativeUDPPathPrefix         = "/.well-known/masque/udp/"
	nativeUDPMaxPayload         = 65527
	nativeUDPMaxAssociations    = 1024
	nativeUDPCapsuleProtocol    = "?1"
	nativeUDPAuthenticationSkew = int64(1)
)

type nativeUDPHandler struct {
	server     *Server
	dispatcher routing.Dispatcher
	tag        string
	slots      chan struct{}
}

type acceptedNativeUDPAuthorization struct {
	authorization nativeUDPAuthorization
	user          *protocol.MemoryUser
	account       *MemoryAccount
	exporter      []byte
	request       nativeUDPRequest
}

func (s *Server) NewNativeUDPHandler(dispatcher routing.Dispatcher, tag string) (http.Handler, error) {
	if dispatcher == nil || strings.TrimSpace(tag) == "" {
		return nil, errors.New("artx: native UDP dispatcher and tag are required")
	}
	s.stats.bind(tag)
	return newNativeUDPHandler(s, dispatcher, tag), nil
}

func (s *Server) NativeUDPTLSConfig() *tls.Config {
	config := s.tlsConfig.Clone()
	config.NextProtos = []string{http3.NextProtoH3}
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.SessionTicketsDisabled = true
	return config
}

func newNativeUDPHandler(server *Server, dispatcher routing.Dispatcher, tag string) *nativeUDPHandler {
	return &nativeUDPHandler{
		server:     server,
		dispatcher: dispatcher,
		tag:        tag,
		slots:      make(chan struct{}, nativeUDPMaxAssociations),
	}
}

func (handler *nativeUDPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	accepted, err := handler.server.authenticateNativeUDP(request)
	if err != nil {
		handler.server.stats.add(runtimeCounterNativeRejected, 1)
		handler.server.stats.add(runtimeCounterAuthenticationFailure, 1)
		if errors.Is(err, errReplay) || errors.Is(err, errReplayCacheFull) {
			handler.server.stats.add(runtimeCounterReplayRejected, 1)
		}
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		handler.server.stats.add(runtimeCounterNativeRejected, 1)
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	destination, err := parseNativeUDPTarget(request.URL.EscapedPath())
	if err != nil {
		handler.server.stats.add(runtimeCounterNativeRejected, 1)
		handler.server.stats.add(runtimeCounterNativeTargetErrors, 1)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	streamer, ok := writer.(http3.HTTPStreamer)
	if !ok {
		handler.server.stats.add(runtimeCounterNativeRejected, 1)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	proof, err := accepted.authorization.serverProof(
		[]byte(accepted.account.PSK),
		accepted.exporter,
		http.StatusOK,
		accepted.request.capsuleProtocol,
	)
	if err != nil {
		handler.server.stats.add(runtimeCounterNativeRejected, 1)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	requestContext := session.ContextWithInbound(request.Context(), &session.Inbound{
		Source:        nativeUDPSource(request.RemoteAddr),
		Tag:           handler.tag,
		Name:          protocolName,
		User:          accepted.user,
		CanSpliceCopy: 0,
	})
	writer.Header().Set(nativeUDPProofHeader, proof)
	writer.Header().Set(http3.CapsuleProtocolHeader, nativeUDPCapsuleProtocol)
	writer.WriteHeader(http.StatusOK)
	stream := streamer.HTTPStream()
	defer stream.Close()
	handler.server.stats.add(runtimeCounterAuthenticationSuccess, 1)
	handler.server.stats.add(runtimeCounterNativeAccepted, 1)
	handler.server.stats.add(runtimeCounterNativeActive, 1)
	defer handler.server.stats.add(runtimeCounterNativeActive, -1)
	if err := relayNativeUDP(requestContext, stream, handler.dispatcher, destination, &handler.server.stats); err != nil && requestContext.Err() == nil {
		handler.server.stats.add(runtimeCounterNativeTransportErrors, 1)
	}
}

func nativeUDPSource(remoteAddress string) xnet.Destination {
	host, portText, err := stdnet.SplitHostPort(remoteAddress)
	if err != nil {
		return xnet.Destination{}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return xnet.Destination{}
	}
	ip := stdnet.ParseIP(host)
	if ip == nil {
		return xnet.Destination{}
	}
	return xnet.UDPDestination(xnet.IPAddress(ip), xnet.Port(port))
}

func (s *Server) authenticateNativeUDP(request *http.Request) (acceptedNativeUDPAuthorization, error) {
	authorization, err := parseNativeUDPAuthorization(request.Header.Get(nativeUDPAuthHeader))
	if err != nil {
		return acceptedNativeUDPAuthorization{}, err
	}
	contract, err := nativeUDPRequestFromHTTP(request)
	if err != nil {
		return acceptedNativeUDPAuthorization{}, err
	}
	exporter, err := nativeUDPExporter(request.TLS)
	if err != nil {
		return acceptedNativeUDPAuthorization{}, err
	}
	user := s.userByLocator(authorization.locator)
	psk := s.nativeUDPDummyPSK[:]
	var account *MemoryAccount
	if user != nil {
		account, _ = user.Account.(*MemoryAccount)
		if account != nil {
			psk = []byte(account.PSK)
		}
	}
	valid := authorization.verify(psk, exporter, contract)
	currentBucket := s.now().Unix() / bucketSeconds
	bucket := int64(authorization.bucket)
	if user == nil || account == nil || !valid || bucket < currentBucket-nativeUDPAuthenticationSkew || bucket > currentBucket+nativeUDPAuthenticationSkew {
		return acceptedNativeUDPAuthorization{}, errors.New("artx: native UDP authentication failed")
	}
	if err := s.replay.add(nativeUDPReplayKey(authorization)); err != nil {
		return acceptedNativeUDPAuthorization{}, err
	}
	return acceptedNativeUDPAuthorization{
		authorization: authorization,
		user:          user,
		account:       account,
		exporter:      exporter,
		request:       contract,
	}, nil
}

func nativeUDPRequestFromHTTP(request *http.Request) (nativeUDPRequest, error) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" {
		return nativeUDPRequest{}, errors.New("artx: invalid native UDP request")
	}
	scheme := request.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}
	contract := nativeUDPRequest{
		method:          request.Method,
		protocol:        request.Proto,
		scheme:          scheme,
		authority:       request.Host,
		path:            request.URL.EscapedPath(),
		capsuleProtocol: request.Header.Get(http3.CapsuleProtocolHeader),
	}
	return contract, contract.validate()
}

func nativeUDPExporter(state *tls.ConnectionState) ([]byte, error) {
	if state == nil || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != http3.NextProtoH3 || state.DidResume {
		return nil, errors.New("artx: invalid native UDP TLS state")
	}
	exporter, err := state.ExportKeyingMaterial(nativeUDPExporterLabel, nil, nativeUDPExporterLength)
	if err != nil || len(exporter) != nativeUDPExporterLength {
		return nil, errors.New("artx: native UDP TLS exporter failed")
	}
	return exporter, nil
}

func nativeUDPReplayKey(authorization nativeUDPAuthorization) replayKey {
	var key replayKey
	offset := copy(key[:], authorization.locator[:])
	offset += copy(key[offset:], authorization.clientTag[:])
	binary.BigEndian.PutUint32(key[offset:], authorization.bucket)
	return key
}

func parseNativeUDPTarget(path string) (xnet.Destination, error) {
	if !strings.HasPrefix(path, nativeUDPPathPrefix) || !strings.HasSuffix(path, "/") {
		return xnet.Destination{}, errors.New("artx: invalid native UDP target path")
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, nativeUDPPathPrefix), "/"), "/")
	if len(parts) != 2 {
		return xnet.Destination{}, errors.New("artx: invalid native UDP target path")
	}
	host, err := url.PathUnescape(parts[0])
	if err != nil || escapeNativeUDPHost(host) != parts[0] || validateNativeUDPHost(host) != nil {
		return xnet.Destination{}, errors.New("artx: invalid native UDP target host")
	}
	port, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != parts[1] {
		return xnet.Destination{}, errors.New("artx: invalid native UDP target port")
	}
	return xnet.UDPDestination(xnet.ParseAddress(host), xnet.Port(port)), nil
}

func escapeNativeUDPHost(host string) string {
	return strings.ReplaceAll(url.PathEscape(host), ":", "%3A")
}

func validateNativeUDPHost(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return errors.New("scoped address")
		}
		return nil
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return errors.New("non-canonical DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return errors.New("invalid DNS label")
			}
		}
	}
	return nil
}

type nativeUDPDatagramStream interface {
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
}

func relayNativeUDP(ctx context.Context, stream nativeUDPDatagramStream, dispatcher routing.Dispatcher, destination xnet.Destination, counters *runtimeCounters) error {
	relayContext, cancel := context.WithCancel(ctx)
	defer cancel()
	var sendFailed atomic.Bool
	sendError := make(chan error, 1)
	udpDispatcher := udp.NewDispatcher(dispatcher, func(_ context.Context, packet *protocoludp.Packet) {
		defer packet.Payload.Release()
		payload := packet.Payload.Bytes()
		if len(payload) > nativeUDPMaxPayload {
			return
		}
		datagram := make([]byte, len(payload)+1)
		copy(datagram[1:], payload)
		if err := stream.SendDatagram(datagram); err != nil && sendFailed.CompareAndSwap(false, true) {
			sendError <- err
			cancel()
		} else if err == nil {
			counters.add(runtimeCounterNativeDatagramsDown, 1)
			counters.add(runtimeCounterNativeBytesDown, int64(len(payload)))
		}
	})
	defer udpDispatcher.RemoveRay()

	for {
		datagram, err := stream.ReceiveDatagram(relayContext)
		if err != nil {
			select {
			case sendErr := <-sendError:
				return sendErr
			default:
				return err
			}
		}
		contextID, offset, err := quicvarint.Parse(datagram)
		if err != nil {
			return fmt.Errorf("artx: malformed native UDP datagram: %w", err)
		}
		if contextID != 0 {
			continue
		}
		payload := datagram[offset:]
		if len(payload) == 0 || len(payload) > nativeUDPMaxPayload {
			continue
		}
		counters.add(runtimeCounterNativeDatagramsUp, 1)
		counters.add(runtimeCounterNativeBytesUp, int64(len(payload)))
		packet := buf.FromBytes(bytes.Clone(payload))
		packet.UDP = &destination
		udpDispatcher.Dispatch(relayContext, destination, packet)
	}
}
