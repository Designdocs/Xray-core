package decoyfallback

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tests must not run in parallel: they share the package level origin cache,
// and t.Setenv already refuses a parallel test.

type capturedRequest struct {
	path     string
	rawQuery string
	host     string
	headers  http.Header
}

// startDecoy stands in for the companion web service.
func startDecoy(t *testing.T, body string) (*httptest.Server, *capturedRequest) {
	t.Helper()

	captured := &capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		captured.path = request.URL.Path
		captured.rawQuery = request.URL.RawQuery
		captured.host = request.Host
		captured.headers = request.Header.Clone()
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(writer, body)
	}))
	t.Cleanup(server.Close)

	return server, captured
}

func serve(t *testing.T, method, target string, headers http.Header) *http.Response {
	t.Helper()

	request := httptest.NewRequest(method, target, nil)
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response := httptest.NewRecorder()
	ServeOrNotFound(response, request)
	return response.Result()
}

func TestServeOrNotFoundWithoutOriginKeeps404(t *testing.T) {
	t.Setenv(OriginEnvironment, "")

	result := serve(t, http.MethodGet, "/", nil)
	defer result.Body.Close()

	if result.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusNotFound)
	}
	if Enabled() {
		t.Fatal("Enabled() = true, want false")
	}
}

func TestServeOrNotFoundProxiesToDecoy(t *testing.T) {
	decoy, captured := startDecoy(t, "<html>a normal looking page</html>")
	t.Setenv(OriginEnvironment, decoy.URL)

	result := serve(t, http.MethodGet, "/", nil)
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusOK)
	}
	if !strings.Contains(string(body), "a normal looking page") {
		t.Fatalf("body = %q, want the decoy page", body)
	}
	if captured.path != "/" {
		t.Fatalf("decoy saw path %q, want %q", captured.path, "/")
	}
	if !Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
}

// A browser that gets the page immediately asks for its stylesheet, and that
// request is rejected by the transport for the same reason, so the original
// path has to survive the hop.
func TestServeOrNotFoundPreservesPathAndQuery(t *testing.T) {
	decoy, captured := startDecoy(t, "ok")
	t.Setenv(OriginEnvironment, decoy.URL)

	result := serve(t, http.MethodGet, "/assets/site.css?v=2", nil)
	defer result.Body.Close()

	if captured.path != "/assets/site.css" {
		t.Fatalf("decoy saw path %q, want %q", captured.path, "/assets/site.css")
	}
	if captured.rawQuery != "v=2" {
		t.Fatalf("decoy saw query %q, want %q", captured.rawQuery, "v=2")
	}
}

func TestServeOrNotFoundStripsForwardingHeaders(t *testing.T) {
	decoy, captured := startDecoy(t, "ok")
	t.Setenv(OriginEnvironment, decoy.URL)

	headers := http.Header{}
	headers.Set("Host", "attacker.example")
	headers.Set("X-Forwarded-For", "203.0.113.9")
	headers.Set("X-Real-IP", "203.0.113.9")
	headers.Set("Forwarded", "for=203.0.113.9")
	headers.Set("X-Forwarded-Host", "attacker.example")
	headers.Set("X-Forwarded-Proto", "https")
	headers.Set("X-Forwarded-Port", "443")

	result := serve(t, http.MethodGet, "/", headers)
	defer result.Body.Close()

	for _, name := range []string{
		"X-Forwarded-For", "X-Real-IP", "Forwarded",
		"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
	} {
		if value := captured.headers.Get(name); value != "" {
			t.Fatalf("decoy received %s = %q, want it stripped", name, value)
		}
	}

	// The decoy must be addressed as the origin, never as whatever Host the
	// caller supplied, so it cannot be steered by a forged Host header.
	if !strings.HasPrefix(decoy.URL, "http://"+captured.host) {
		t.Fatalf("decoy saw Host %q, want the origin host from %q", captured.host, decoy.URL)
	}
}

func TestServeOrNotFoundReturnsBadGatewayWhenDecoyIsDown(t *testing.T) {
	decoy, _ := startDecoy(t, "ok")
	origin := decoy.URL
	decoy.Close()
	t.Setenv(OriginEnvironment, origin)

	result := serve(t, http.MethodGet, "/", nil)
	defer result.Body.Close()

	if result.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusBadGateway)
	}
}

// A malformed or unsafe origin must degrade to the pre-existing behaviour
// rather than take the node's proxy service down with it.
func TestServeOrNotFoundRejectsUnsafeOrigins(t *testing.T) {
	tests := []struct {
		name   string
		origin string
	}{
		{name: "cleartext to public address", origin: "http://192.0.2.1:60443"},
		{name: "cleartext to hostname", origin: "http://decoy.example:60443"},
		{name: "unsupported scheme", origin: "ftp://127.0.0.1:60443"},
		{name: "no scheme", origin: "127.0.0.1:60443"},
		{name: "missing host", origin: "http://"},
		{name: "credentials", origin: "http://user:pass@127.0.0.1:60443"},
		{name: "fragment", origin: "http://127.0.0.1:60443/#private"},
		{name: "not a url", origin: "://"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(OriginEnvironment, test.origin)

			result := serve(t, http.MethodGet, "/", nil)
			defer result.Body.Close()

			if result.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", result.StatusCode, http.StatusNotFound)
			}
		})
	}
}

func TestServeOrNotFoundAcceptsLoopbackForms(t *testing.T) {
	for _, origin := range []string{
		"http://127.0.0.1:60443",
		"http://127.0.0.1:60443/",
		"http://[::1]:60443",
		"https://decoy.example:60443",
	} {
		t.Run(origin, func(t *testing.T) {
			t.Setenv(OriginEnvironment, origin)

			if !Enabled() {
				t.Fatalf("Enabled() = false for %q, want true", origin)
			}
		})
	}
}

// The origin is read from the environment on every rejected request, so a
// changed value has to take effect without restarting the process, and an
// unchanged value must not rebuild the proxy.
func TestOriginCacheTracksEnvironmentChanges(t *testing.T) {
	first, _ := startDecoy(t, "first page")
	second, _ := startDecoy(t, "second page")

	t.Setenv(OriginEnvironment, first.URL)
	built := lookup()
	if built == nil {
		t.Fatal("first origin did not build a proxy")
	}
	if reused := lookup(); reused != built {
		t.Fatal("unchanged origin rebuilt the proxy")
	}

	t.Setenv(OriginEnvironment, second.URL)
	result := serve(t, http.MethodGet, "/", nil)
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "second page") {
		t.Fatalf("body = %q, want the second decoy", body)
	}
}

func TestServeOrNotFoundTrimsSurroundingWhitespace(t *testing.T) {
	decoy, _ := startDecoy(t, "ok")
	t.Setenv(OriginEnvironment, "  "+decoy.URL+"  ")

	if !Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
}

func TestJoinPaths(t *testing.T) {
	tests := []struct {
		base string
		path string
		want string
	}{
		{base: "", path: "/", want: "/"},
		{base: "", path: "/assets/site.css", want: "/assets/site.css"},
		{base: "/", path: "/", want: "/"},
		{base: "/", path: "/assets/site.css", want: "/assets/site.css"},
		{base: "/base", path: "/leaf", want: "/base/leaf"},
		{base: "/base/", path: "/leaf", want: "/base/leaf"},
		{base: "/base", path: "", want: "/base"},
	}

	for _, test := range tests {
		if got := joinPaths(test.base, test.path); got != test.want {
			t.Fatalf("joinPaths(%q, %q) = %q, want %q", test.base, test.path, got, test.want)
		}
	}
}

func TestJoinQueries(t *testing.T) {
	tests := []struct {
		base    string
		request string
		want    string
	}{
		{base: "", request: "", want: ""},
		{base: "", request: "v=2", want: "v=2"},
		{base: "profile=web", request: "", want: "profile=web"},
		{base: "profile=web", request: "v=2", want: "profile=web&v=2"},
	}

	for _, test := range tests {
		if got := joinQueries(test.base, test.request); got != test.want {
			t.Fatalf("joinQueries(%q, %q) = %q, want %q", test.base, test.request, got, test.want)
		}
	}
}
