package artx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

var (
	errFallbackDelivery = errors.New("fallback delivery failed")
	errFallbackTooLarge = errors.New("fallback response is too large")
)

const (
	maxAuthFrameSize              = 2 + MaxSaltLength + UserLocatorLength + 4 + AuthTagLength + 2 + maxAuthPadding
	maxFallbackBodyBytes          = 1 << 20
	maxFallbackHeaders            = 16 << 10
	fallbackConnectTimeout        = 3 * time.Second
	fallbackTLSHandshakeTimeout   = 5 * time.Second
	fallbackResponseHeaderTimeout = 5 * time.Second
	fallbackRequestTimeout        = 10 * time.Second
	fallbackLookaheadTimeout      = time.Second
	maxHTTP2ParserWindow          = 2 * time.Second
	minHTTP2ParserWindow          = 10 * time.Millisecond
	maxHTTP2UploadWindow          = 64 << 10
)

type FallbackHandler interface {
	Serve(context.Context, net.Conn, []byte) error
}

type HTTPFallback struct {
	origin         *url.URL
	proxy          *httputil.ReverseProxy
	transport      *http.Transport
	requestTimeout time.Duration
}

func ValidateFallbackOrigin(origin string) error {
	_, err := parseFallbackOrigin(origin)
	return err
}

func NewHTTPFallback(origin string) (*HTTPFallback, error) {
	parsed, err := parseFallbackOrigin(origin)
	if err != nil {
		return nil, err
	}
	transport := newFallbackTransport(parsed)
	handler := &HTTPFallback{
		origin:         parsed,
		transport:      transport,
		requestTimeout: fallbackRequestTimeout,
	}
	handler.proxy = handler.newReverseProxy()
	return handler, nil
}

func parseFallbackOrigin(origin string) (*url.URL, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, errors.New("invalid fallback origin")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("fallback origin must use http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("fallback origin host required")
	}
	if parsed.User != nil {
		return nil, errors.New("fallback origin must not contain credentials")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("fallback origin must not contain a fragment")
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("cleartext fallback origin must use a loopback host")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newFallbackTransport(origin *url.URL) *http.Transport {
	dialer := &net.Dialer{Timeout: fallbackConnectTimeout, KeepAlive: 30 * time.Second}
	dialContext := dialer.DialContext
	if origin.Scheme == "http" {
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !isLoopbackHost(host) {
				return nil, errors.New("cleartext fallback dial rejected")
			}
			return dialer.DialContext(ctx, network, address)
		}
	}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    fallbackTLSHandshakeTimeout,
		ResponseHeaderTimeout:  fallbackResponseHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        16,
		MaxResponseHeaderBytes: maxFallbackHeaders,
	}
}

func (handler *HTTPFallback) newReverseProxy() *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Transport: handler.transport,
		Rewrite: func(request *httputil.ProxyRequest) {
			path := request.In.URL.Path
			rawQuery := request.In.URL.RawQuery
			request.SetURL(handler.origin)
			request.Out.URL.Path = joinOriginPath(handler.origin.Path, path)
			request.Out.URL.RawPath = ""
			request.Out.URL.RawQuery = joinQueries(handler.origin.RawQuery, rawQuery)
			request.Out.Host = handler.origin.Host
			request.Out.RemoteAddr = ""
			stripForwardingHeaders(request.Out.Header)
		},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, _ error) {
		fallbackObserver(request.Context()).Report()
		http.Error(writer, "Bad Gateway", http.StatusBadGateway)
	}
	proxy.ModifyResponse = func(response *http.Response) error {
		observer := fallbackObserver(response.Request.Context())
		response.Body = newObservedResponseBody(response.Body, observer)
		return nil
	}
	return proxy
}

func joinOriginPath(base, path string) string {
	switch {
	case base == "":
		return path
	case path == "":
		return base
	case strings.HasSuffix(base, "/") && strings.HasPrefix(path, "/"):
		return base + path[1:]
	case !strings.HasSuffix(base, "/") && !strings.HasPrefix(path, "/"):
		return base + "/" + path
	default:
		return base + path
	}
}

func joinQueries(base, request string) string {
	if base == "" {
		return request
	}
	if request == "" {
		return base
	}
	return base + "&" + request
}

func stripForwardingHeaders(headers http.Header) {
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Real-IP"} {
		headers.Del(name)
	}
}

func (handler *HTTPFallback) Serve(ctx context.Context, connection net.Conn, prefix []byte) error {
	if handler == nil || handler.proxy == nil || handler.transport == nil || connection == nil {
		return errors.New("fallback handler is not configured")
	}
	timeout := handler.requestTimeout
	if timeout <= 0 {
		timeout = fallbackRequestTimeout
	}
	serveState := &fallbackServeState{}
	observed := &observedConnection{Conn: connection, observer: serveState.MarkFailed}
	deadline := time.Now().Add(timeout)
	_ = observed.SetDeadline(deadline)
	defer observed.SetDeadline(time.Time{})

	protocol := negotiatedProtocol(connection)
	transparent, replay := classifyFallbackRequest(observed, protocol, prefix, deadline)
	remaining := time.Until(deadline)
	if remaining <= 0 {
		serveState.MarkFailed()
		return serveState.Err()
	}
	if !transparent {
		if err := handler.serveSynthetic(ctx, observed, protocol, remaining); err != nil {
			serveState.MarkFailed()
		}
		return serveState.Err()
	}
	return handler.serveTransparent(ctx, observed, protocol, replay, serveState, remaining)
}

func negotiatedProtocol(connection net.Conn) string {
	if state, ok := connection.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return state.ConnectionState().NegotiatedProtocol
	}
	return ""
}

func classifyFallbackRequest(connection net.Conn, protocol string, prefix []byte, deadline time.Time) (bool, []byte) {
	replay := append([]byte(nil), prefix...)
	lookaheadDeadline := time.Now().Add(fallbackLookaheadTimeout)
	if deadline.Before(lookaheadDeadline) {
		lookaheadDeadline = deadline
	}
	_ = connection.SetReadDeadline(lookaheadDeadline)
	defer connection.SetReadDeadline(deadline)
	if protocol == http2.NextProtoTLS {
		return classifyHTTP2Preface(connection, replay)
	}
	return classifyHTTP1HeaderBlock(connection, replay)
}

func classifyHTTP2Preface(connection net.Conn, replay []byte) (bool, []byte) {
	preface := []byte(http2.ClientPreface)
	for len(replay) < len(preface) {
		if !bytes.Equal(replay, preface[:len(replay)]) {
			return false, replay
		}
		next, err := readLookaheadByte(connection)
		if err != nil {
			return false, replay
		}
		replay = append(replay, next)
	}
	return bytes.Equal(replay[:len(preface)], preface), replay
}

func classifyHTTP1HeaderBlock(connection net.Conn, replay []byte) (bool, []byte) {
	for len(replay) <= maxFallbackHeaders {
		if headerEnd := bytes.Index(replay, []byte("\r\n\r\n")); headerEnd >= 0 {
			return validHTTP1HeaderBlock(replay[:headerEnd+4]), replay
		}
		if !couldBeHTTP1RequestLine(replay) {
			return false, replay
		}
		if len(replay) == maxFallbackHeaders {
			return false, replay
		}
		next, err := readLookaheadByte(connection)
		if err != nil {
			return false, replay
		}
		replay = append(replay, next)
	}
	return false, replay
}

func readLookaheadByte(connection net.Conn) (byte, error) {
	var next [1]byte
	_, err := io.ReadFull(connection, next[:])
	return next[0], err
}

func couldBeHTTP1RequestLine(prefix []byte) bool {
	if len(prefix) == 0 {
		return false
	}
	space := bytes.IndexByte(prefix, ' ')
	if space < 0 {
		for _, method := range fallbackHTTPMethods {
			if bytes.HasPrefix([]byte(method), prefix) {
				return true
			}
		}
		return false
	}
	return isFallbackHTTPMethod(string(prefix[:space]))
}

func validHTTP1HeaderBlock(header []byte) bool {
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	return err == nil && isFallbackHTTPMethod(request.Method)
}

var fallbackHTTPMethods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

func isFallbackHTTPMethod(method string) bool {
	for _, candidate := range fallbackHTTPMethods {
		if method == candidate {
			return true
		}
	}
	return false
}

func (handler *HTTPFallback) serveTransparent(ctx context.Context, connection net.Conn, protocol string, prefix []byte, state *fallbackServeState, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var handlerInvoked atomic.Bool
	serveHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerInvoked.Store(true)
		if protocol == http2.NextProtoTLS {
			_ = connection.SetReadDeadline(deadline)
		}
		requestCtx, cancel := context.WithTimeout(request.Context(), timeout)
		defer cancel()
		observer := &fallbackRequestObserver{onError: state.MarkFailed}
		request = request.WithContext(context.WithValue(requestCtx, fallbackErrorObserverKey{}, observer))
		if request.ContentLength > maxFallbackBodyBytes {
			http.Error(writer, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxFallbackBodyBytes)
		handler.proxy.ServeHTTP(writer, request)
	})
	buffered := &prefixedConnection{Conn: connection, reader: io.MultiReader(bytes.NewReader(prefix), connection)}
	if protocol == http2.NextProtoTLS {
		parserWindow := http2ParserWindow(timeout)
		parserDeadline := time.Now().Add(parserWindow)
		_ = connection.SetReadDeadline(parserDeadline)
		http2Server := &http2.Server{
			MaxConcurrentStreams:         1,
			MaxDecoderHeaderTableSize:    4 << 10,
			MaxEncoderHeaderTableSize:    4 << 10,
			MaxReadFrameSize:             16 << 10,
			IdleTimeout:                  timeout,
			ReadIdleTimeout:              parserWindow,
			PingTimeout:                  time.Second,
			WriteByteTimeout:             timeout,
			MaxUploadBufferPerConnection: maxHTTP2UploadWindow,
			MaxUploadBufferPerStream:     maxHTTP2UploadWindow,
		}
		http2Server.ServeConn(buffered, &http2.ServeConnOpts{
			Handler:    serveHandler,
			Context:    ctx,
			BaseConfig: &http.Server{ErrorLog: log.New(io.Discard, "", 0)},
		})
		_ = connection.SetReadDeadline(deadline)
		if !handlerInvoked.Load() {
			parserTimedOut := !time.Now().Before(parserDeadline)
			remaining := time.Until(deadline)
			if remaining <= 0 {
				state.MarkFailed()
			} else if _, _, err := handler.fetchOrigin(ctx, remaining); err != nil {
				state.MarkFailed()
			}
			if parserTimedOut {
				state.MarkFailed()
			}
		}
		return state.Err()
	}

	listener := newSingleConnectionListener(buffered)
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()
	server := newFallbackHTTPServer(serveHandler, timeout)
	err := server.Serve(listener)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		state.MarkFailed()
	}
	return state.Err()
}

func http2ParserWindow(total time.Duration) time.Duration {
	if total <= 2*minHTTP2ParserWindow {
		return total / 2
	}
	window := total / 2
	if window < minHTTP2ParserWindow {
		window = minHTTP2ParserWindow
	}
	if window > maxHTTP2ParserWindow {
		window = maxHTTP2ParserWindow
	}
	return window
}

func (handler *HTTPFallback) serveSynthetic(parent context.Context, connection net.Conn, protocol string, timeout time.Duration) error {
	response, body, err := handler.fetchOrigin(parent, timeout)
	if err != nil {
		return err
	}
	if protocol == http2.NextProtoTLS {
		return writeHTTP2Rejection(connection)
	}
	return writeHTTP1Response(connection, response, body)
}

func (handler *HTTPFallback) fetchOrigin(parent context.Context, timeout time.Duration) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, handler.origin.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	request.Host = handler.origin.Host
	response, err := handler.transport.RoundTrip(request)
	if err != nil {
		return nil, nil, err
	}
	body, err := readBoundedResponse(response.Body)
	if err != nil {
		return nil, nil, err
	}
	return response, body, nil
}

func writeHTTP2Rejection(writer io.Writer) error {
	framer := http2.NewFramer(writer, nil)
	if err := framer.WriteSettings(
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16 << 10},
	); err != nil {
		return err
	}
	return framer.WriteGoAway(0, http2.ErrCodeProtocol, nil)
}

func readBoundedResponse(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	reader := io.LimitReader(body, maxFallbackBodyBytes+1)
	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxFallbackBodyBytes {
		return nil, errFallbackTooLarge
	}
	return payload, nil
}

func writeHTTP1Response(writer io.Writer, response *http.Response, body []byte) error {
	clone := new(http.Response)
	*clone = *response
	clone.Proto = "HTTP/1.1"
	clone.ProtoMajor = 1
	clone.ProtoMinor = 1
	clone.Body = io.NopCloser(bytes.NewReader(body))
	if clone.ContentLength < 0 {
		clone.TransferEncoding = []string{"chunked"}
	} else {
		clone.TransferEncoding = nil
	}
	clone.Close = true
	clone.Header = response.Header.Clone()
	clone.Header.Set("Connection", "close")
	clone.Request = &http.Request{Method: http.MethodGet}
	return clone.Write(writer)
}

func newFallbackHTTPServer(handler http.Handler, timeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: min(5*time.Second, timeout),
		ReadTimeout:       timeout,
		WriteTimeout:      timeout,
		IdleTimeout:       timeout,
		MaxHeaderBytes:    maxFallbackHeaders,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
}

type fallbackErrorObserverKey struct{}

type fallbackRequestObserver struct {
	once    sync.Once
	onError func()
}

func fallbackObserver(ctx context.Context) *fallbackRequestObserver {
	observer, _ := ctx.Value(fallbackErrorObserverKey{}).(*fallbackRequestObserver)
	if observer == nil {
		return &fallbackRequestObserver{onError: func() {}}
	}
	return observer
}

func (observer *fallbackRequestObserver) Report() {
	observer.once.Do(observer.onError)
}

type observedResponseBody struct {
	body      io.ReadCloser
	observer  *fallbackRequestObserver
	remaining int64
}

func newObservedResponseBody(body io.ReadCloser, observer *fallbackRequestObserver) *observedResponseBody {
	return &observedResponseBody{body: body, observer: observer, remaining: maxFallbackBodyBytes}
}

func (body *observedResponseBody) Read(payload []byte) (int, error) {
	if body.remaining == 0 {
		var extra [1]byte
		count, err := body.body.Read(extra[:])
		if count > 0 {
			body.observer.Report()
			return 0, errFallbackTooLarge
		}
		if err != nil && !errors.Is(err, io.EOF) {
			body.observer.Report()
		}
		return 0, err
	}
	if int64(len(payload)) > body.remaining {
		payload = payload[:body.remaining]
	}
	count, err := body.body.Read(payload)
	body.remaining -= int64(count)
	if err != nil && !errors.Is(err, io.EOF) {
		body.observer.Report()
	}
	return count, err
}

func (body *observedResponseBody) Close() error {
	err := body.body.Close()
	if err != nil {
		body.observer.Report()
	}
	return err
}

type fallbackServeState struct {
	failed atomic.Bool
}

func (state *fallbackServeState) MarkFailed() {
	state.failed.Store(true)
}

func (state *fallbackServeState) Err() error {
	if state.failed.Load() {
		return errFallbackDelivery
	}
	return nil
}

type observedConnection struct {
	net.Conn
	observer func()
}

func (connection *observedConnection) Write(payload []byte) (int, error) {
	written, err := connection.Conn.Write(payload)
	if err != nil || written != len(payload) {
		connection.observer()
	}
	return written, err
}

type boundedCapture struct {
	buffer bytes.Buffer
	limit  int
}

func newBoundedCapture(limit int) *boundedCapture {
	return &boundedCapture{limit: limit}
}

func (capture *boundedCapture) Write(payload []byte) (int, error) {
	remaining := max(capture.limit-capture.buffer.Len(), 0)
	if remaining > 0 {
		_, _ = capture.buffer.Write(payload[:min(len(payload), remaining)])
	}
	return len(payload), nil
}

func (capture *boundedCapture) Bytes() []byte {
	return append([]byte(nil), capture.buffer.Bytes()...)
}

type prefixedConnection struct {
	net.Conn
	reader io.Reader
}

func (connection *prefixedConnection) Read(payload []byte) (int, error) {
	return connection.reader.Read(payload)
}

type singleConnectionListener struct {
	connection *closingConnection
	once       sync.Once
}

func newSingleConnectionListener(connection net.Conn) *singleConnectionListener {
	return &singleConnectionListener{connection: &closingConnection{Conn: connection, closed: make(chan struct{})}}
}

func (listener *singleConnectionListener) Accept() (net.Conn, error) {
	accepted := false
	listener.once.Do(func() { accepted = true })
	if accepted {
		return listener.connection, nil
	}
	<-listener.connection.closed
	return nil, net.ErrClosed
}

func (listener *singleConnectionListener) Close() error {
	return listener.connection.Close()
}

func (listener *singleConnectionListener) Addr() net.Addr {
	return listener.connection.LocalAddr()
}

type closingConnection struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

func (connection *closingConnection) Close() error {
	connection.closeOnce.Do(func() {
		connection.err = connection.Conn.Close()
		close(connection.closed)
	})
	return connection.err
}
