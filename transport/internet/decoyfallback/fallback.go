// Package decoyfallback answers transport level rejections with a local decoy
// site instead of a bare 404.
//
// The ws and xhttp transports validate Host and Path before any proxy protocol
// sees the connection, so a browser reaching the node lands on a 404 that no
// protocol level "fallbacks" list can intercept. A node that serves TLS on 443
// and answers every browser with an empty 404 is itself a signal, and this
// package removes it by reverse proxying those rejected requests to a decoy
// web service running on loopback.
//
// Configuration arrives through the environment rather than through the
// transport config messages on purpose: adding a field would mean editing
// two config.proto files, regenerating both config.pb.go, and touching
// infra/conf/transport_internet.go, which upstream rewrites constantly. The
// environment keeps this fork's divergence to one call per rejection site.
// See scripts/decoy-transport-fallback.md.
package decoyfallback

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// OriginEnvironment holds the decoy origin URL, for example
// "http://127.0.0.1:60443". Empty or unset disables the fallback and every
// rejection keeps returning the plain 404 it returned before.
const OriginEnvironment = "N2X_DECOY_TRANSPORT_FALLBACK"

// Bounds for any client that talks to a decoy origin. Exported because
// proxy/artx builds its own connection level fallback on the same transport
// and must not drift from these.
const (
	ConnectTimeout         = 3 * time.Second
	TLSHandshakeTimeout    = 5 * time.Second
	ResponseHeaderTimeout  = 5 * time.Second
	IdleConnTimeout        = 30 * time.Second
	MaxResponseHeaderBytes = 16 << 10
)

// maxRequestBodyBytes caps what a rejected request may push to the decoy.
// Nothing legitimate arrives here: the decoy only answers GET and HEAD, and a
// request only reaches this path because its Host or Path did not match.
const maxRequestBodyBytes = 1 << 20

// resolved caches the proxy built for one exact environment value. A nil proxy
// records "this value yields no fallback" so an unset or malformed origin is
// not re-parsed, and not re-logged, on every rejected request.
type resolved struct {
	origin string
	proxy  *httputil.ReverseProxy
}

var (
	current      atomic.Pointer[resolved]
	rebuildMutex sync.Mutex
)

// ServeOrNotFound answers a request the transport refused. It reverse proxies
// to the configured decoy origin, and writes the original 404 when no usable
// origin is configured.
//
// It always writes a response, so callers replace their WriteHeader call with
// this one and return.
func ServeOrNotFound(writer http.ResponseWriter, request *http.Request) {
	proxy := lookup()
	if proxy == nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	outbound := request.Clone(request.Context())
	if outbound.Body != nil {
		outbound.Body = http.MaxBytesReader(writer, outbound.Body, maxRequestBodyBytes)
	}
	proxy.ServeHTTP(writer, outbound)
}

// Enabled reports whether a usable decoy origin is configured.
func Enabled() bool {
	return lookup() != nil
}

func lookup() *httputil.ReverseProxy {
	origin := strings.TrimSpace(os.Getenv(OriginEnvironment))
	if cached := current.Load(); cached != nil && cached.origin == origin {
		return cached.proxy
	}
	return rebuild(origin)
}

func rebuild(origin string) *httputil.ReverseProxy {
	rebuildMutex.Lock()
	defer rebuildMutex.Unlock()

	// Another goroutine may have rebuilt this exact value while we waited.
	if cached := current.Load(); cached != nil && cached.origin == origin {
		return cached.proxy
	}

	next := &resolved{origin: origin}
	if origin != "" {
		proxy, err := newReverseProxy(origin)
		if err != nil {
			errors.LogWarning(context.Background(),
				"decoy transport fallback disabled, serving 404: ", err)
		} else {
			next.proxy = proxy
		}
	}

	current.Store(next)
	return next.proxy
}

func newReverseProxy(origin string) (*httputil.ReverseProxy, error) {
	target, err := ParseOrigin(origin)
	if err != nil {
		return nil, err
	}

	proxy := &httputil.ReverseProxy{
		Transport: NewTransport(target),
		Rewrite: func(request *httputil.ProxyRequest) {
			path := request.In.URL.Path
			rawQuery := request.In.URL.RawQuery
			request.SetURL(target)
			request.Out.URL.Path = JoinPaths(target.Path, path)
			request.Out.URL.RawPath = ""
			request.Out.URL.RawQuery = JoinQueries(target.RawQuery, rawQuery)
			request.Out.Host = target.Host
			request.Out.RemoteAddr = ""
			// Rewrite starts from a clone of the inbound request, so a client
			// supplied forwarding header would otherwise reach the decoy and
			// hand it an attacker controlled client address to log.
			StripForwardingHeaders(request.Out.Header)
		},
		// A dead decoy must look like a web server with a dead backend, not
		// like a proxy leaking its own error text.
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			errors.LogInfo(context.Background(), "decoy fallback delivery failed: ", err)
			http.Error(writer, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return proxy, nil
}

// ValidateOrigin reports whether origin is a usable decoy origin.
func ValidateOrigin(origin string) error {
	_, err := ParseOrigin(origin)
	return err
}

// ParseOrigin validates a decoy origin and returns it parsed.
//
// The rules are shared with proxy/artx so a single review covers both: the
// scheme must be http or https, credentials and fragments are refused, and
// cleartext is confined to loopback.
func ParseOrigin(origin string) (*url.URL, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, errors.New("invalid decoy origin")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("decoy origin must use http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("decoy origin host required")
	}
	if parsed.User != nil {
		return nil, errors.New("decoy origin must not contain credentials")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("decoy origin must not contain a fragment")
	}
	// Cleartext to anywhere but loopback would turn a mismatched Host header
	// into an open relay out of this node.
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("cleartext decoy origin must use a loopback host")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewTransport builds a bounded HTTP client transport for a decoy origin.
// A cleartext origin is re-checked at dial time, so a hostname that starts
// resolving off loopback cannot turn this into a relay out of the node.
func NewTransport(target *url.URL) *http.Transport {
	dialer := &net.Dialer{Timeout: ConnectTimeout, KeepAlive: 30 * time.Second}
	dialContext := dialer.DialContext
	if target.Scheme == "http" {
		// The origin was checked once at parse time; re-check at dial time so a
		// hostname that later resolves off loopback cannot smuggle traffic out.
		dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !isLoopbackHost(host) {
				return nil, errors.New("cleartext decoy dial rejected")
			}
			return dialer.DialContext(ctx, network, address)
		}
	}

	return &http.Transport{
		Proxy:                  nil,
		DialContext:            dialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    TLSHandshakeTimeout,
		ResponseHeaderTimeout:  ResponseHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        IdleConnTimeout,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        16,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
	}
}

// JoinPaths joins an origin base path with a request path, collapsing the
// duplicate separator rather than producing "//".
func JoinPaths(base, path string) string {
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

// JoinQueries merges an origin query string with the request query string.
func JoinQueries(base, request string) string {
	if base == "" {
		return request
	}
	if request == "" {
		return base
	}
	return base + "&" + request
}

// StripForwardingHeaders removes client supplied forwarding headers so a
// forged value cannot hand the decoy an attacker chosen client address.
func StripForwardingHeaders(headers http.Header) {
	for _, name := range []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Forwarded-Port",
		"X-Real-IP",
	} {
		headers.Del(name)
	}
}
