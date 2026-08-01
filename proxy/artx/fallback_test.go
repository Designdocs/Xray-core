package artx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/decoyfallback"
	"golang.org/x/net/http2"
)

func TestNewHTTPFallbackValidatesOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		valid  bool
	}{
		{name: "http", origin: "http://127.0.0.1:60443/", valid: true},
		{name: "http ipv6 loopback", origin: "http://[::1]:60443/", valid: true},
		{name: "https", origin: "https://origin.example.com/", valid: true},
		{name: "localhost cleartext", origin: "http://localhost:60443/"},
		{name: "external cleartext", origin: "http://192.0.2.1/"},
		{name: "empty"},
		{name: "unsupported scheme", origin: "ftp://origin.example.com/"},
		{name: "missing host", origin: "https:///path"},
		{name: "credentials", origin: "https://user:pass@origin.example.com/"},
		{name: "fragment", origin: "https://origin.example.com/#fragment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewHTTPFallback(test.origin)
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && err == nil {
				t.Fatal("invalid origin accepted")
			}
		})
	}
}

func TestHTTPFallbackUsesDedicatedBoundedTransport(t *testing.T) {
	handler, err := NewHTTPFallback("http://127.0.0.1:60443/")
	if err != nil {
		t.Fatal(err)
	}
	transport := handler.transport
	if transport == nil || transport.DialContext == nil || transport.Proxy != nil {
		t.Fatalf("transport = %#v", transport)
	}
	// The bounds live with the transport in decoyfallback now, so assert
	// against that package rather than a local copy that could drift from it.
	if transport.TLSHandshakeTimeout != decoyfallback.TLSHandshakeTimeout ||
		transport.ResponseHeaderTimeout != decoyfallback.ResponseHeaderTimeout ||
		transport.MaxResponseHeaderBytes != decoyfallback.MaxResponseHeaderBytes ||
		transport.MaxConnsPerHost <= 0 {
		t.Fatalf("transport bounds = %#v", transport)
	}
}

func TestHTTPFallbackServesHTTP11FromCapturedPrefix(t *testing.T) {
	var expectedHost string
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/status" || request.URL.RawQuery != "source=test" {
			t.Errorf("upstream URL = %q", request.URL.String())
		}
		if request.Host != expectedHost {
			t.Errorf("upstream Host = %q, want %q", request.Host, expectedHost)
		}
		for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
			if value := request.Header.Get(name); value != "" {
				t.Errorf("upstream %s = %q", name, value)
			}
		}
		writer.Header().Set("X-Service", "ready")
		_, _ = io.WriteString(writer, "ordinary response")
	}))
	defer origin.Close()
	expectedHost = strings.TrimPrefix(origin.URL, "http://")
	handler, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	done := make(chan error, 1)
	prefix := []byte("GET /status?source=test HTTP/1.1\r\nHost: public.example\r\nForwarded: for=198.51.100.2\r\nX-Forwarded-For: 198.51.100.2\r\nX-Forwarded-Host: probe.example\r\nX-Forwarded-Proto: http\r\nX-Real-IP: 198.51.100.2\r\nConnection: close\r\n\r\n")
	go func() { done <- handler.Serve(context.Background(), server, prefix) }()

	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = client.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Service") != "ready" || string(body) != "ordinary response" {
		t.Fatalf("response = %d %#v %q", response.StatusCode, response.Header, body)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/1.1 fallback did not release the connection")
	}
}

func TestHTTPFallbackSyntheticResponsePreservesTransparentFraming(t *testing.T) {
	const body = "stable streamed decoy response"
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Service", "ready")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		_, _ = io.WriteString(writer, body)
	}))
	defer origin.Close()

	handler, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	transparent, transparentBody := readFallbackHTTP1Response(t, handler, []byte("GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n"))
	synthetic, syntheticBody := readFallbackHTTP1Response(t, handler, []byte("garbage"))
	if transparentBody != body || syntheticBody != body {
		t.Fatalf("response bodies differ: transparent=%q synthetic=%q", transparentBody, syntheticBody)
	}
	if transparent.ContentLength != -1 || !slices.Equal(transparent.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("transparent response is not unknown-length chunked framing: %#v", transparent)
	}
	if transparent.Header.Get("Content-Length") != synthetic.Header.Get("Content-Length") ||
		transparent.ContentLength != synthetic.ContentLength ||
		!slices.Equal(transparent.TransferEncoding, synthetic.TransferEncoding) ||
		transparent.Close != synthetic.Close {
		t.Fatalf("response framing differs: transparent=%#v synthetic=%#v", transparent, synthetic)
	}
}

func TestHTTPFallbackSyntheticResponsePreservesKnownLength(t *testing.T) {
	const body = "fixed decoy response"
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = io.WriteString(writer, body)
	}))
	defer origin.Close()

	handler, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	transparent, transparentBody := readFallbackHTTP1Response(t, handler, []byte("GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n"))
	synthetic, syntheticBody := readFallbackHTTP1Response(t, handler, []byte("garbage"))
	if transparentBody != body || syntheticBody != body {
		t.Fatalf("response bodies differ: transparent=%q synthetic=%q", transparentBody, syntheticBody)
	}
	if transparent.ContentLength != int64(len(body)) ||
		transparent.Header.Get("Content-Length") != synthetic.Header.Get("Content-Length") ||
		transparent.ContentLength != synthetic.ContentLength ||
		!slices.Equal(transparent.TransferEncoding, synthetic.TransferEncoding) ||
		transparent.Close != synthetic.Close {
		t.Fatalf("response framing differs: transparent=%#v synthetic=%#v", transparent, synthetic)
	}
}

func TestWriteHTTP1ResponseNormalizesHTTP2OriginMetadata(t *testing.T) {
	response := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("ordinary response")),
		ContentLength: -1,
	}
	var encoded bytes.Buffer
	if err := writeHTTP1Response(&encoded, response, []byte("ordinary response")); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded.String(), "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("response status line = %q", encoded.String())
	}
	parsed, err := http.ReadResponse(bufio.NewReader(&encoded), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = parsed.Body.Close()
	if string(payload) != "ordinary response" || !slices.Equal(parsed.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("response framing = %#v body=%q", parsed, payload)
	}
}

func readFallbackHTTP1Response(t *testing.T, handler *HTTPFallback, prefix []byte) (*http.Response, string) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		err := handler.Serve(context.Background(), server, prefix)
		_ = server.Close()
		done <- err
	}()

	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return response, string(payload)
}

func TestHTTPFallbackReturnsPrivacySafeGatewayError(t *testing.T) {
	handler, err := NewHTTPFallback("http://127.0.0.1:1/")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- handler.Serve(context.Background(), server, []byte("GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n"))
	}()
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	_ = client.Close()
	if err := <-done; !errors.Is(err, errFallbackDelivery) {
		t.Fatalf("Serve() error = %v", err)
	}
	text := strings.ToLower(string(body))
	for _, forbidden := range []string{"artx", "n2x", "anytls", "proxy"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("response leaked %q: %q", forbidden, body)
		}
	}
}

func TestHTTPFallbackBinaryH2HitsOriginThenSendsStableConnectionError(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(writer, "stable decoy response")
	}))
	defer origin.Close()
	handler, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	var signatures []string
	for _, prefix := range [][]byte{{AuthFrameType, MinSaltLength}, []byte("garbage")} {
		client, rawServer := net.Pipe()
		server := negotiatedConnection{Conn: rawServer, protocol: http2.NextProtoTLS}
		done := make(chan error, 1)
		go func() { done <- handler.Serve(context.Background(), server, prefix) }()
		framer := http2.NewFramer(io.Discard, client)
		settings, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		goAway, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		settingsFrame, ok := settings.(*http2.SettingsFrame)
		if !ok {
			t.Fatalf("first frame = %T", settings)
		}
		goAwayFrame, ok := goAway.(*http2.GoAwayFrame)
		if !ok || goAwayFrame.ErrCode != http2.ErrCodeProtocol || goAwayFrame.LastStreamID != 0 || len(goAwayFrame.DebugData()) != 0 {
			t.Fatalf("GOAWAY = %#v", goAway)
		}
		signatures = append(signatures, settingsFrame.String()+"|"+goAwayFrame.String())
		_ = client.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if originHits.Load() != 2 {
		t.Fatalf("origin hits = %d", originHits.Load())
	}
	if signatures[0] != signatures[1] {
		t.Fatalf("h2 signatures differ: %q != %q", signatures[0], signatures[1])
	}
}

func TestArtXProcessCountsFallbackOriginFailure(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	originURL := origin.URL
	origin.Close()

	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(originURL)
	if err != nil {
		t.Fatal(err)
	}
	server.fallback = fallback
	dispatcher := &countingRejectingDispatcher{}
	clientRaw, serverRaw := net.Pipe()
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
	}()
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	closeTLSNow(client)
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %q", response.StatusCode, body)
	}
	for _, forbidden := range []string{"artx", "n2x", "anytls", "proxy"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("response leaked %q: %q", forbidden, body)
		}
	}
	select {
	case err := <-processDone:
		if err == nil || !strings.Contains(err.Error(), "fallback failed") {
			t.Fatalf("Process() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fallback process did not finish")
	}
	if calls := dispatcher.Calls(); calls != 0 {
		t.Fatalf("dispatcher calls = %d", calls)
	}
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 1 || stats.AuthenticationFailure != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestArtXProcessCountsFallbackTimeout(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer origin.Close()
	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	fallback.requestTimeout = 50 * time.Millisecond
	server.fallback = fallback
	clientRaw, serverRaw := net.Pipe()
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, &countingRejectingDispatcher{})
	}()
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec -- self-signed test certificate
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("garbage")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-processDone:
		if err == nil {
			t.Fatal("timeout was not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("fallback timeout was not bounded")
	}
	closeTLSNow(client)
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestArtXProcessCountsResponseCopyFailure(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		connection, buffer, err := writer.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\nshort")
		_ = buffer.Flush()
		_ = connection.Close()
	}))
	defer origin.Close()
	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.fallback = fallback
	clientRaw, serverRaw := net.Pipe()
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, &countingRejectingDispatcher{})
	}()
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err == nil {
		if _, err := io.ReadAll(response.Body); err == nil {
			t.Fatal("truncated upstream response was accepted")
		}
		_ = response.Body.Close()
	} else if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	closeTLSNow(client)
	select {
	case err := <-processDone:
		if err == nil {
			t.Fatal("copy failure was not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("copy failure did not finish")
	}
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestArtXProcessCountsResponseWriteFailure(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "stable decoy response")
	}))
	defer origin.Close()
	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.fallback = fallback
	clientRaw, serverRaw := net.Pipe()
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, &countingRejectingDispatcher{})
	}()
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec -- self-signed test certificate
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("garbage")); err != nil {
		t.Fatal(err)
	}
	closeTLSNow(client)
	select {
	case err := <-processDone:
		if err == nil {
			t.Fatal("write failure was not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("write failure did not finish")
	}
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestArtXProcessServesHTTPFallback(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Service", "ready")
		_, _ = io.WriteString(writer, "ordinary response")
	}))
	defer origin.Close()

	for _, protocol := range []string{"http/1.1", http2.NextProtoTLS} {
		t.Run(protocol, func(t *testing.T) {
			server := newArtXTestServer(t)
			fallback, err := NewHTTPFallback(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			server.fallback = fallback
			dispatcher := &countingRejectingDispatcher{}
			clientRaw, serverRaw := net.Pipe()
			processDone := make(chan error, 1)
			go func() {
				processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
			}()
			client := tls.Client(clientRaw, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
				MinVersion:         tls.VersionTLS13,
				NextProtos:         []string{protocol},
			})
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}

			var response *http.Response
			if protocol == http2.NextProtoTLS {
				transport := &http2.Transport{}
				connection, err := transport.NewClientConn(client)
				if err != nil {
					t.Fatal(err)
				}
				request, err := http.NewRequest(http.MethodGet, "https://public.example/", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err = connection.RoundTrip(request)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
			} else {
				if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err = http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
				if err != nil {
					t.Fatal(err)
				}
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			closeTLSNow(client)
			select {
			case err := <-processDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("fallback process did not finish")
			}
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Service") != "ready" || string(body) != "ordinary response" {
				t.Fatalf("response = %d %#v %q", response.StatusCode, response.Header, body)
			}
			for _, forbidden := range []string{"artx", "n2x", "anytls", "proxy"} {
				if strings.Contains(strings.ToLower(string(body)), forbidden) {
					t.Fatalf("response leaked %q: %q", forbidden, body)
				}
			}
			if calls := dispatcher.Calls(); calls != 0 {
				t.Fatalf("dispatcher calls = %d", calls)
			}
			stats := server.Stats()
			if stats.FallbackHits != 1 || stats.FallbackErrors != 0 || stats.AuthenticationFailure != 1 {
				t.Fatalf("stats = %#v", stats)
			}
		})
	}
}

func TestArtXHTTP11FallbackPreservesMethodsAndBody(t *testing.T) {
	type upstreamRequest struct {
		method string
		body   string
	}
	requests := make(chan upstreamRequest, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		requests <- upstreamRequest{method: request.Method, body: string(body)}
		_, _ = io.WriteString(writer, "ordinary response")
	}))
	defer origin.Close()
	tests := []struct {
		method string
		body   string
	}{
		{method: http.MethodGet},
		{method: http.MethodHead},
		{method: http.MethodPost, body: "request body remains unread by lookahead"},
	}
	for _, test := range tests {
		t.Run(test.method, func(t *testing.T) {
			server := newArtXTestServer(t)
			fallback, err := NewHTTPFallback(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			server.fallback = fallback
			dispatcher := &countingRejectingDispatcher{}
			clientRaw, serverRaw := net.Pipe()
			processDone := make(chan error, 1)
			go func() {
				processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
			}()
			client := tls.Client(clientRaw, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
				MinVersion:         tls.VersionTLS13,
				NextProtos:         []string{"http/1.1"},
			})
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			request := test.method + " / HTTP/1.1\r\nHost: public.example\r\nContent-Length: " + fmt.Sprint(len(test.body)) + "\r\nConnection: close\r\n\r\n" + test.body
			if _, err := io.WriteString(client, request); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: test.method})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			closeTLSNow(client)
			got := <-requests
			if got.method != test.method || got.body != test.body {
				t.Fatalf("upstream request = %#v", got)
			}
			if test.method == http.MethodHead && len(body) != 0 {
				t.Fatalf("HEAD body = %q", body)
			}
			if err := <-processDone; err != nil {
				t.Fatal(err)
			}
			if calls := dispatcher.Calls(); calls != 0 {
				t.Fatalf("dispatcher calls = %d", calls)
			}
		})
	}
}

func TestArtXBinaryPreAuthFailuresReachOriginWithStableResponse(t *testing.T) {
	const signature = "decoy-v1"
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		writer.Header().Set("X-Decoy-Signature", signature)
		_, _ = io.WriteString(writer, "stable decoy response")
	}))
	defer origin.Close()

	tests := []struct {
		name       string
		payload    func(*testing.T, *Server, *tls.Conn) []byte
		closeWrite bool
	}{
		{name: "wrong key", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			return validAuthPayload(t, client, "wrong-psk", uint32(server.now().Unix()/bucketSeconds))
		}},
		{name: "replay", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			encoded := validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds))
			state := client.ConnectionState()
			exporter, err := state.ExportKeyingMaterial(exporterLabel, nil, ExporterLength)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := ReadAuthFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.authenticate(frame, exporter); err != nil {
				t.Fatal(err)
			}
			return encoded
		}},
		{name: "expired", payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			return validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds)-2)
		}},
		{name: "truncated", closeWrite: true, payload: func(t *testing.T, server *Server, client *tls.Conn) []byte {
			encoded := validAuthPayload(t, client, "test-psk", uint32(server.now().Unix()/bucketSeconds))
			return encoded[:len(encoded)-1]
		}},
		{name: "garbage", payload: func(*testing.T, *Server, *tls.Conn) []byte {
			return []byte("garbage")
		}},
		{name: "partial plausible malformed http1", payload: func(*testing.T, *Server, *tls.Conn) []byte {
			return []byte("GEX / HTTP/1.1\r\n")
		}},
		{name: "malformed request target", payload: func(*testing.T, *Server, *tls.Conn) []byte {
			return []byte("GET % HTTP/1.1\r\nHost: public.example\r\n\r\n")
		}},
		{name: "malformed header", payload: func(*testing.T, *Server, *tls.Conn) []byte {
			return []byte("GET / HTTP/1.1\r\nBad Header\r\n\r\n")
		}},
		{name: "half close", closeWrite: true, payload: func(*testing.T, *Server, *tls.Conn) []byte {
			return nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newArtXTestServer(t)
			fallback, err := NewHTTPFallback(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			server.fallback = fallback
			dispatcher := &countingRejectingDispatcher{}
			clientRaw, serverRaw := newTCPPair(t)
			processDone := make(chan error, 1)
			go func() {
				processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
			}()
			client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec -- self-signed test certificate
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			payload := test.payload(t, server, client)
			if len(payload) > 0 {
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			if test.closeWrite {
				if err := clientRaw.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			_ = clientRaw.Close()
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Decoy-Signature") != signature || string(body) != "stable decoy response" {
				t.Fatalf("response = %d %#v %q", response.StatusCode, response.Header, body)
			}
			select {
			case err := <-processDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("fallback process did not finish")
			}
			if calls := dispatcher.Calls(); calls != 0 {
				t.Fatalf("dispatcher calls = %d", calls)
			}
			stats := server.Stats()
			if stats.FallbackHits != 1 || stats.FallbackErrors != 0 || stats.AuthenticationFailure != 1 {
				t.Fatalf("stats = %#v", stats)
			}
		})
	}
	if got := originHits.Load(); got != int64(len(tests)) {
		t.Fatalf("origin hits = %d, want %d", got, len(tests))
	}
}

func TestArtXMalformedH2PrefixHitsOriginThenReturnsStableConnectionError(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(writer, "stable decoy response")
	}))
	defer origin.Close()
	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.fallback = fallback
	dispatcher := &countingRejectingDispatcher{}
	clientRaw, serverRaw := newTCPPair(t)
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
	}()
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("PRX malformed")); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(io.Discard, client)
	settings, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	goAway, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := settings.(*http2.SettingsFrame); !ok {
		t.Fatalf("first frame = %T", settings)
	}
	goAwayFrame, ok := goAway.(*http2.GoAwayFrame)
	if !ok || goAwayFrame.ErrCode != http2.ErrCodeProtocol || goAwayFrame.LastStreamID != 0 || len(goAwayFrame.DebugData()) != 0 {
		t.Fatalf("GOAWAY = %#v", goAway)
	}
	closeTLSNow(client)
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("malformed h2 fallback did not finish")
	}
	if originHits.Load() != 1 {
		t.Fatalf("origin hits = %d", originHits.Load())
	}
	if calls := dispatcher.Calls(); calls != 0 {
		t.Fatalf("dispatcher calls = %d", calls)
	}
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 0 || stats.AuthenticationFailure != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestArtXMalformedH2FrameBeforeHandlerStillHitsOrigin(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(writer, "stable decoy response")
	}))
	defer origin.Close()
	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	server.fallback = fallback
	dispatcher := &countingRejectingDispatcher{}
	clientRaw, serverRaw := newTCPPair(t)
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
	}()
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	invalidSettings := []byte{0, 0, 0, byte(http2.FrameSettings), 0, 0, 0, 0, 1}
	if _, err := client.Write(append([]byte(http2.ClientPreface), invalidSettings...)); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(io.Discard, client)
	if _, err := framer.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	goAway, ok := frame.(*http2.GoAwayFrame)
	if !ok || goAway.ErrCode == http2.ErrCodeNo || len(goAway.DebugData()) != 0 {
		t.Fatalf("GOAWAY = %#v", frame)
	}
	closeTLSNow(client)
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("malformed h2 frame fallback did not finish")
	}
	if originHits.Load() != 1 {
		t.Fatalf("origin hits = %d", originHits.Load())
	}
	if calls := dispatcher.Calls(); calls != 0 {
		t.Fatalf("dispatcher calls = %d", calls)
	}
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 0 || stats.AuthenticationFailure != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestArtXStalledH2FrameReservesOriginFetchBudget(t *testing.T) {
	var originHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		originHits.Add(1)
		_, _ = io.WriteString(writer, "stable decoy response")
	}))
	defer origin.Close()
	server := newArtXTestServer(t)
	fallback, err := NewHTTPFallback(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	fallback.requestTimeout = 150 * time.Millisecond
	server.fallback = fallback
	dispatcher := &countingRejectingDispatcher{}
	clientRaw, serverRaw := newTCPPair(t)
	processDone := make(chan error, 1)
	go func() {
		processDone <- server.Process(testInboundContext(), xnet.Network_TCP, serverRaw, dispatcher)
	}()
	client := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- self-signed test certificate
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http2.NextProtoTLS},
	})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	partialFrameHeader := []byte{0, 0, 0, byte(http2.FrameSettings), 0}
	started := time.Now()
	if _, err := client.Write(append([]byte(http2.ClientPreface), partialFrameHeader...)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-processDone:
		if err == nil || !strings.Contains(err.Error(), "fallback failed") {
			t.Fatalf("Process() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled h2 frame exceeded its total deadline")
	}
	elapsed := time.Since(started)
	closeTLSNow(client)
	if elapsed >= fallback.requestTimeout {
		t.Fatalf("origin fetch was not given reserved time: elapsed=%s total=%s", elapsed, fallback.requestTimeout)
	}
	if originHits.Load() != 1 {
		t.Fatalf("origin hits = %d", originHits.Load())
	}
	if calls := dispatcher.Calls(); calls != 0 {
		t.Fatalf("dispatcher calls = %d", calls)
	}
	stats := server.Stats()
	if stats.FallbackHits != 1 || stats.FallbackErrors != 1 || stats.AuthenticationFailure != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestAuthPrefixCaptureIsBounded(t *testing.T) {
	capture := newBoundedCapture(maxAuthFrameSize)
	payload := bytes.Repeat([]byte{0xff}, maxAuthFrameSize+1024)
	if written, err := capture.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	if got := len(capture.Bytes()); got != maxAuthFrameSize {
		t.Fatalf("captured = %d, want %d", got, maxAuthFrameSize)
	}
}

func TestRuntimeStatsSnapshotIsAtomic(t *testing.T) {
	stats := runtimeCounters{}
	const workers = 8
	const iterations = 1_000
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for range iterations {
				stats.totalConnections.Add(1)
				stats.authenticationFailure.Add(1)
				stats.fallbackHits.Add(1)
			}
		}()
	}
	group.Wait()
	snapshot := stats.snapshot()
	want := uint64(workers * iterations)
	if snapshot.TotalConnections != want || snapshot.AuthenticationFailure != want || snapshot.FallbackHits != want {
		t.Fatalf("snapshot = %#v, want counters %d", snapshot, want)
	}
}

func newTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		_ = client.Close()
		_ = listener.Close()
		t.Fatal(err)
	}
	_ = listener.Close()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

type negotiatedConnection struct {
	net.Conn
	protocol string
}

func (connection negotiatedConnection) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{NegotiatedProtocol: connection.protocol}
}
