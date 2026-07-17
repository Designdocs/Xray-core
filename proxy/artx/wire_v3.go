package artx

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/net/http2"
)

const (
	wireV3Version            = byte(0x03)
	wireV3Flags              = byte(0x00)
	wireV3SaltLength         = 16
	wireV3ExporterLength     = sha256.Size
	wireV3TagLength          = sha256.Size
	wireV3MaxDestinationSize = 259
	wireV3ExporterLabel      = "EXPORTER-artx-auth-v3"
	wireV3ClientLabel        = "artx-wire-v3-client\x00"
	wireV3ServerLabel        = "artx-wire-v3-server\x00"
	wireV3Path               = "/"
	wireV3DispatchFailure    = http.StatusBadGateway
	wireV3ImmediateFlushSize = 4 << 10
	wireV3DataChunkSize      = 16 << 10
)

const wireV3ClientInitPrefixSize = 1 + 1 + 1 + 2 + wireV3SaltLength + UserLocatorLength + 4

type wireV3ClientInit struct {
	Salt            [wireV3SaltLength]byte
	UserLocator     [UserLocatorLength]byte
	TimestampBucket uint32
	Destination     []byte
	ClientTag       [wireV3TagLength]byte
}

func newWireV3ClientInit(psk, salt, exporter []byte, authority, path string, destination []byte, timestampBucket uint32) (wireV3ClientInit, error) {
	if len(psk) == 0 {
		return wireV3ClientInit{}, errors.New("artx: wire-v3 PSK is empty")
	}
	if len(salt) != wireV3SaltLength {
		return wireV3ClientInit{}, fmt.Errorf("artx: wire-v3 salt length is %d, want %d", len(salt), wireV3SaltLength)
	}
	if len(exporter) != wireV3ExporterLength {
		return wireV3ClientInit{}, fmt.Errorf("artx: wire-v3 exporter length is %d, want %d", len(exporter), wireV3ExporterLength)
	}
	if err := validateWireV3Context(authority, path, destination); err != nil {
		return wireV3ClientInit{}, err
	}
	init := wireV3ClientInit{
		UserLocator:     CalculateUserLocator(psk),
		TimestampBucket: timestampBucket,
		Destination:     append([]byte(nil), destination...),
	}
	copy(init.Salt[:], salt)
	prefix, _ := init.marshalPrefix()
	init.ClientTag = calculateWireV3ClientTag(psk, exporter, authority, path, prefix)
	return init, nil
}

func (init wireV3ClientInit) MarshalBinary() ([]byte, error) {
	prefix, err := init.marshalPrefix()
	if err != nil {
		return nil, err
	}
	return append(prefix, init.ClientTag[:]...), nil
}

func (init wireV3ClientInit) marshalPrefix() ([]byte, error) {
	if len(init.Destination) == 0 || len(init.Destination) > wireV3MaxDestinationSize {
		return nil, fmt.Errorf("artx: wire-v3 destination length is %d", len(init.Destination))
	}
	prefix := make([]byte, wireV3ClientInitPrefixSize+len(init.Destination))
	prefix[0] = wireV3Version
	prefix[1] = wireV3Flags
	prefix[2] = wireV3SaltLength
	binary.BigEndian.PutUint16(prefix[3:5], uint16(len(init.Destination)))
	offset := 5
	copy(prefix[offset:], init.Salt[:])
	offset += wireV3SaltLength
	copy(prefix[offset:], init.UserLocator[:])
	offset += UserLocatorLength
	binary.BigEndian.PutUint32(prefix[offset:], init.TimestampBucket)
	offset += 4
	copy(prefix[offset:], init.Destination)
	return prefix, nil
}

func parseWireV3ClientInit(envelope []byte) (wireV3ClientInit, error) {
	if len(envelope) < wireV3ClientInitPrefixSize+1+wireV3TagLength {
		return wireV3ClientInit{}, errors.New("artx: wire-v3 ClientInit is truncated")
	}
	if envelope[0] != wireV3Version || envelope[1] != wireV3Flags || envelope[2] != wireV3SaltLength {
		return wireV3ClientInit{}, errors.New("artx: invalid wire-v3 ClientInit header")
	}
	destinationLength := int(binary.BigEndian.Uint16(envelope[3:5]))
	if destinationLength == 0 || destinationLength > wireV3MaxDestinationSize {
		return wireV3ClientInit{}, errors.New("artx: invalid wire-v3 destination length")
	}
	if len(envelope) != wireV3ClientInitPrefixSize+destinationLength+wireV3TagLength {
		return wireV3ClientInit{}, errors.New("artx: invalid wire-v3 ClientInit length")
	}
	init := wireV3ClientInit{Destination: make([]byte, destinationLength)}
	offset := 5
	copy(init.Salt[:], envelope[offset:])
	offset += wireV3SaltLength
	copy(init.UserLocator[:], envelope[offset:])
	offset += UserLocatorLength
	init.TimestampBucket = binary.BigEndian.Uint32(envelope[offset:])
	offset += 4
	copy(init.Destination, envelope[offset:offset+destinationLength])
	offset += destinationLength
	copy(init.ClientTag[:], envelope[offset:])
	return init, nil
}

func (init wireV3ClientInit) Verify(psk, exporter []byte, authority, path string) bool {
	if len(psk) == 0 || len(exporter) != wireV3ExporterLength || validateWireV3Context(authority, path, init.Destination) != nil {
		return false
	}
	prefix, err := init.marshalPrefix()
	if err != nil {
		return false
	}
	want := calculateWireV3ClientTag(psk, exporter, authority, path, prefix)
	return hmac.Equal(init.ClientTag[:], want[:])
}

func calculateWireV3ClientTag(psk, exporter []byte, authority, path string, prefix []byte) [wireV3TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV3ClientLabel))
	_, _ = mac.Write(exporter)
	writeWireV3LengthPrefixed(mac, authority)
	writeWireV3LengthPrefixed(mac, path)
	_, _ = mac.Write(prefix)
	var tag [wireV3TagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func calculateWireV3ServerProof(psk, exporter []byte, clientTag [wireV3TagLength]byte, status int) [wireV3TagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(wireV3ServerLabel))
	_, _ = mac.Write(exporter)
	_, _ = mac.Write(clientTag[:])
	var encodedStatus [2]byte
	binary.BigEndian.PutUint16(encodedStatus[:], uint16(status))
	_, _ = mac.Write(encodedStatus[:])
	var proof [wireV3TagLength]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func formatWireV3Authorization(init wireV3ClientInit) string {
	envelope, err := init.MarshalBinary()
	if err != nil {
		return ""
	}
	return "Bearer " + base64.RawURLEncoding.EncodeToString(envelope)
}

func parseWireV3Authorization(header string) (wireV3ClientInit, bool, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return wireV3ClientInit{}, false, nil
	}
	maxEnvelopeLength := wireV3ClientInitPrefixSize + wireV3MaxDestinationSize + wireV3TagLength
	if len(header) > len("Bearer ")+base64.RawURLEncoding.EncodedLen(maxEnvelopeLength) {
		return wireV3ClientInit{}, true, errors.New("artx: oversized wire-v3 Authorization")
	}
	encoded := strings.TrimPrefix(header, "Bearer ")
	if encoded == "" || strings.TrimSpace(encoded) != encoded {
		return wireV3ClientInit{}, true, errors.New("artx: malformed wire-v3 Authorization")
	}
	envelope, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return wireV3ClientInit{}, true, errors.New("artx: malformed wire-v3 Authorization")
	}
	init, err := parseWireV3ClientInit(envelope)
	return init, true, err
}

func formatWireV3AuthenticationInfo(proof [wireV3TagLength]byte) string {
	return `rspauth="` + base64.RawURLEncoding.EncodeToString(proof[:]) + `"`
}

func verifyWireV3AuthenticationInfo(header string, psk, exporter []byte, clientTag [wireV3TagLength]byte, status int) bool {
	prefix := `rspauth="`
	if !strings.HasPrefix(header, prefix) || !strings.HasSuffix(header, `"`) || len(header) <= len(prefix)+1 {
		return false
	}
	encoded := header[len(prefix) : len(header)-1]
	proof, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(proof) != wireV3TagLength {
		return false
	}
	want := calculateWireV3ServerProof(psk, exporter, clientTag, status)
	return hmac.Equal(proof, want[:])
}

func validateWireV3Context(authority, path string, destination []byte) error {
	if authority == "" || len(authority) > int(^uint16(0)) {
		return errors.New("artx: invalid wire-v3 authority")
	}
	if path == "" || len(path) > int(^uint16(0)) {
		return errors.New("artx: invalid wire-v3 path")
	}
	if len(destination) == 0 || len(destination) > wireV3MaxDestinationSize {
		return errors.New("artx: invalid wire-v3 destination")
	}
	return nil
}

func writeWireV3LengthPrefixed(mac interface{ Write([]byte) (int, error) }, value string) {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write([]byte(value))
}

func (s *Server) processWireV3(ctx context.Context, connection net.Conn, dispatcher routing.Dispatcher, exporter []byte, serverName string) error {
	fallback, ok := s.fallback.(*HTTPFallback)
	if !ok {
		return errors.New("artx: wire-v3 HTTP fallback is not configured")
	}
	_ = connection.SetDeadline(s.now().Add(handshakeTimeout))
	var claimed atomic.Bool
	var tunnelErr atomic.Pointer[wireV3TunnelError]
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !s.isWireV3Candidate(request, serverName) {
			s.serveWireV3FallbackRequest(fallback, writer, request, strings.HasPrefix(request.Header.Get("Authorization"), "Bearer "))
			return
		}
		init, _, err := parseWireV3Authorization(request.Header.Get("Authorization"))
		user, account, authErr := s.authenticateWireV3(init, exporter, request.Host, request.URL.Path)
		if err != nil || authErr != nil {
			s.stats.add(runtimeCounterAuthenticationFailure, 1)
			if errors.Is(authErr, errReplay) || errors.Is(authErr, errReplayCacheFull) {
				s.stats.add(runtimeCounterReplayRejected, 1)
			}
			s.serveWireV3FallbackRequest(fallback, writer, request, true)
			return
		}
		destination, err := DecodeTCPDestination(init.Destination)
		if err == nil {
			var canonical []byte
			canonical, err = EncodeTCPDestination(destination)
			if err == nil && !bytes.Equal(canonical, init.Destination) {
				err = errors.New("artx: non-canonical wire-v3 destination")
			}
		}
		if err != nil {
			s.stats.add(runtimeCounterAuthenticationFailure, 1)
			s.serveWireV3FallbackRequest(fallback, writer, request, true)
			return
		}
		if claimed.Swap(true) {
			_ = connection.SetDeadline(time.Now())
			return
		}
		requestCtx := request.Context()
		if inbound := session.InboundFromContext(requestCtx); inbound != nil {
			inbound.Name = protocolName
			inbound.User = user
			inbound.CanSpliceCopy = 0
		}
		s.stats.add(runtimeCounterAuthenticationSuccess, 1)
		link, err := dispatcher.Dispatch(requestCtx, destination)
		if err != nil {
			s.writeWireV3Response(writer, account, exporter, init.ClientTag, wireV3DispatchFailure)
			tunnelErr.Store(&wireV3TunnelError{err: fmt.Errorf("artx: wire-v3 dispatch: %w", err)})
			return
		}
		_ = connection.SetDeadline(time.Time{})
		s.writeWireV3Response(writer, account, exporter, init.ClientTag, http.StatusOK)
		if err := relayWireV3(requestCtx, request.Body, writer, link); err != nil {
			tunnelErr.Store(&wireV3TunnelError{err: err})
		}
	})

	server := &http2.Server{
		MaxConcurrentStreams:      1,
		MaxDecoderHeaderTableSize: 4 << 10,
		MaxEncoderHeaderTableSize: 4 << 10,
		MaxReadFrameSize:          16 << 10,
		IdleTimeout:               handshakeTimeout,
	}
	server.ServeConn(connection, &http2.ServeConnOpts{
		Handler:    handler,
		Context:    ctx,
		BaseConfig: &http.Server{ErrorLog: log.New(io.Discard, "", 0), MaxHeaderBytes: maxFallbackHeaders},
	})
	if result := tunnelErr.Load(); result != nil {
		return result.err
	}
	return nil
}

type wireV3TunnelError struct{ err error }

func (s *Server) isWireV3Candidate(request *http.Request, serverName string) bool {
	if request.Method != http.MethodPost || request.URL.Path != wireV3Path || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/octet-stream" || request.UserAgent() != "" {
		return false
	}
	if len(request.Header.Values("Authorization")) != 1 || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	host := request.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	return serverName != "" && strings.EqualFold(host, serverName)
}

func (s *Server) authenticateWireV3(init wireV3ClientInit, exporter []byte, authority, path string) (*protocol.MemoryUser, *MemoryAccount, error) {
	user := s.userByLocator(init.UserLocator)
	psk := s.wireV3DummyPSK[:]
	var account *MemoryAccount
	if user != nil {
		account, _ = user.Account.(*MemoryAccount)
		if account != nil {
			psk = []byte(account.PSK)
		}
	}
	verified := init.Verify(psk, exporter, authority, path)
	currentBucket := s.now().Unix() / bucketSeconds
	frameBucket := int64(init.TimestampBucket)
	if user == nil || account == nil || !verified || frameBucket < currentBucket-timestampSkew || frameBucket > currentBucket+timestampSkew {
		return nil, nil, errors.New("artx: wire-v3 authentication failed")
	}
	if err := s.replay.add(replayKeyForWireV3(init)); err != nil {
		return nil, nil, err
	}
	return user, account, nil
}

func replayKeyForWireV3(init wireV3ClientInit) replayKey {
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

func (s *Server) serveWireV3FallbackRequest(fallback *HTTPFallback, writer http.ResponseWriter, request *http.Request, stripAuthorization bool) {
	s.stats.add(runtimeCounterFallbackHits, 1)
	state := &fallbackServeState{}
	fallback.proxyRequest(writer, request, fallbackRequestTimeout, stripAuthorization, state.MarkFailed)
	if state.Err() != nil {
		s.stats.add(runtimeCounterFallbackErrors, 1)
	}
}

func (s *Server) writeWireV3Response(writer http.ResponseWriter, account *MemoryAccount, exporter []byte, clientTag [wireV3TagLength]byte, status int) {
	proof := calculateWireV3ServerProof([]byte(account.PSK), exporter, clientTag, status)
	writer.Header().Set("Authentication-Info", formatWireV3AuthenticationInfo(proof))
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}
}

func relayWireV3(ctx context.Context, requestBody io.ReadCloser, writer http.ResponseWriter, link *transport.Link) error {
	stopInterrupt := context.AfterFunc(ctx, func() {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	})
	defer stopInterrupt()
	uploadDone := make(chan error, 1)
	go func() {
		err := buf.Copy(wireV3RequestReader{reader: requestBody}, link.Writer)
		if err == nil {
			err = common.Close(link.Writer)
		}
		uploadDone <- err
	}()
	downloadDone := make(chan error, 1)
	go func() {
		downloadDone <- buf.Copy(link.Reader, &wireV3ResponseWriter{writer: wireV3FlushWriter{writer: writer}})
	}()
	select {
	case uploadErr := <-uploadDone:
		if uploadErr == nil {
			return <-downloadDone
		}
		_ = requestBody.Close()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		<-downloadDone
		return uploadErr
	case downloadErr := <-downloadDone:
		_ = requestBody.Close()
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		<-uploadDone
		return downloadErr
	}
}

type wireV3FlushWriter struct{ writer http.ResponseWriter }

func (writer wireV3FlushWriter) Write(payload []byte) (int, error) {
	written, err := writer.writer.Write(payload)
	if err == nil && written <= wireV3ImmediateFlushSize {
		if flusher, ok := writer.writer.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	return written, err
}

type wireV3ResponseWriter struct {
	writer wireV3FlushWriter
	chunk  [wireV3DataChunkSize]byte
}

func (writer *wireV3ResponseWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	defer buf.ReleaseMulti(buffers)
	for !buffers.IsEmpty() {
		var size int
		buffers, size = buf.SplitBytes(buffers, writer.chunk[:])
		if err := buf.WriteAllBytes(writer.writer, writer.chunk[:size], nil); err != nil {
			return err
		}
	}
	return nil
}

type wireV3RequestReader struct{ reader io.Reader }

func (reader wireV3RequestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffer := buf.NewWithSize(wireV3DataChunkSize)
	_, err := buffer.ReadFrom(reader.reader)
	if buffer.IsEmpty() {
		buffer.Release()
		return nil, err
	}
	return buf.MultiBuffer{buffer}, err
}
