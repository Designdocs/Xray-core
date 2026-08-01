package splithttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xtls/xray-core/transport/internet/decoyfallback"
)

func decoyTestHandler(host, path string) *requestHandler {
	return &requestHandler{
		config:    &Config{Path: path},
		host:      host,
		path:      path,
		sessionMu: &sync.Mutex{},
	}
}

// xhttp is the case the protocol level fallback cannot reach at all: its
// clients prefer h2, and the VLESS fallback skips path matching for h2c, so
// the rejection has to be answered here in the transport.
func TestServeHTTPRejectionServesDecoy(t *testing.T) {
	decoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "<html>a normal looking page</html>")
	}))
	defer decoy.Close()
	t.Setenv(decoyfallback.OriginEnvironment, decoy.URL)

	tests := []struct {
		name    string
		handler *requestHandler
		target  string
		host    string
	}{
		{
			name:    "path prefix mismatch",
			handler: decoyTestHandler("", "/xh8k2m"),
			target:  "/",
		},
		{
			name:    "scanner probe",
			handler: decoyTestHandler("", "/xh8k2m"),
			target:  "/wp-admin",
		},
		{
			name:    "host mismatch",
			handler: decoyTestHandler("node.example", "/xh8k2m"),
			target:  "/xh8k2m/abc",
			host:    "scanner.example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			if test.host != "" {
				request.Host = test.host
			}
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, request)

			result := response.Result()
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
		})
	}
}

func TestServeHTTPRejectionKeeps404WithoutDecoy(t *testing.T) {
	t.Setenv(decoyfallback.OriginEnvironment, "")

	handler := decoyTestHandler("", "/xh8k2m")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
	if body := response.Body.String(); body != "" {
		t.Fatalf("body = %q, want empty", body)
	}
}

// The documented trap: an empty path normalises to "/", every request matches
// the prefix, and nothing ever reaches the rejection branch. Operators must
// give xhttp nodes a real path or the decoy silently never appears.
func TestEmptyPathNeverReachesTheRejection(t *testing.T) {
	decoy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "<html>a normal looking page</html>")
	}))
	defer decoy.Close()
	t.Setenv(decoyfallback.OriginEnvironment, decoy.URL)

	handler := decoyTestHandler("", "")
	if got := handler.config.GetNormalizedPath(); got != "/" {
		t.Fatalf("GetNormalizedPath() = %q, want %q", got, "/")
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if body := response.Body.String(); strings.Contains(body, "a normal looking page") {
		t.Fatal("an empty path served the decoy; the prefix match was expected to swallow the request")
	}
}
