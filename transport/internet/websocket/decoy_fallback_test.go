package websocket

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xtls/xray-core/transport/internet/decoyfallback"
)

// A browser reaching a ws node on 443 asks for "/" and never sends the
// WebSocket upgrade, so it is rejected here, before any proxy protocol runs.
// Without a decoy that rejection is an empty 404, which is exactly the signal
// the fallback exists to remove.
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
			name:    "path mismatch",
			handler: &requestHandler{path: "/real"},
			target:  "/",
		},
		{
			name:    "host mismatch",
			handler: &requestHandler{host: "node.example", path: "/real"},
			target:  "/real",
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

// With no decoy configured the rejection must stay byte for byte what it was
// before the hook existed.
func TestServeHTTPRejectionKeeps404WithoutDecoy(t *testing.T) {
	t.Setenv(decoyfallback.OriginEnvironment, "")

	handler := &requestHandler{path: "/real"}
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
