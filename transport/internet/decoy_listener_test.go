package internet_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	conf "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/decoyfallback"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/websocket"
	"google.golang.org/protobuf/proto"
)

func decoyStream(t *testing.T, network string, origin *string) *internet.MemoryStreamConfig {
	t.Helper()
	input := map[string]any{
		"network":       network,
		"wsSettings":    map[string]string{"path": "/transport/"},
		"xhttpSettings": map[string]string{"path": "/transport/"},
	}
	if origin != nil {
		input["decoyFallbackOrigin"] = *origin
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var parsed conf.StreamConfig
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	config, err := parsed.Build()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(internet.StreamConfig)
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	memory, err := internet.ToMemoryStreamConfig(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if (memory.DecoyFallbackOrigin == nil) != (origin == nil) || (origin != nil && *memory.DecoyFallbackOrigin != *origin) {
		t.Fatal("lost optional origin across configuration/protobuf/memory conversion")
	}
	return memory
}

func decoyPort(t *testing.T) xnet.Port {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := xnet.Port(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestDecoyListenerIsolation(t *testing.T) {
	for _, network := range []string{"ws", "xhttp"} {
		t.Run(network, func(t *testing.T) {
			decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "isolated-decoy") }))
			defer decoy.Close()
			t.Setenv(decoyfallback.OriginEnvironment, "")
			listen := websocket.ListenWS
			if network == "xhttp" {
				listen = splithttp.ListenXH
			}
			start := func(origin *string) internet.Listener {
				listener, err := listen(context.Background(), xnet.LocalHostIP, decoyPort(t), decoyStream(t, network, origin), func(conn stat.Connection) { _ = conn.Close() })
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				return listener
			}
			enabled := start(&decoy.URL)
			disabled := start(new(string))
			legacy := start(nil)
			client := &http.Client{Timeout: 5 * time.Second}
			check := func(listener internet.Listener, path string, wantPage bool) {
				t.Helper()
				request, err := http.NewRequest(http.MethodOptions, "http://"+listener.Addr().String()+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(body), "isolated-decoy") != wantPage {
					t.Fatalf("%s: status=%d body=%q, wantPage=%v", path, response.StatusCode, body, wantPage)
				}
				if path == "/" && !wantPage && response.StatusCode != http.StatusNotFound {
					t.Fatalf("disabled status=%d", response.StatusCode)
				}
			}
			check(enabled, "/", true)
			check(disabled, "/", false)
			check(legacy, "/", false)
			t.Setenv(decoyfallback.OriginEnvironment, decoy.URL)
			check(legacy, "/", true) // Old N2X sets the environment after AddNode.
			check(disabled, "/", false)
			check(enabled, "/transport/", false) // Matched transport requests never use the page.
			reloadPort := xnet.Port(disabled.Addr().(*net.TCPAddr).Port)
			if err := disabled.Close(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := listen(context.Background(), xnet.LocalHostIP, reloadPort, decoyStream(t, network, &decoy.URL), nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reloaded.Close() })
			check(reloaded, "/", true) // Reused HTTP clients must not retain the old handler.
			check(enabled, "/", true)
			t.Setenv(decoyfallback.OriginEnvironment, "")
			check(legacy, "/", false)
			check(enabled, "/", true)
		})
	}
}

func TestDecoyListenerRejectsInvalidOriginBeforeBinding(t *testing.T) {
	for _, network := range []string{"ws", "xhttp"} {
		t.Run(network, func(t *testing.T) {
			occupied, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()
			origin := "http://example.com/"
			listen := websocket.ListenWS
			if network == "xhttp" {
				listen = splithttp.ListenXH
			}
			listener, err := listen(context.Background(), xnet.LocalHostIP, xnet.Port(occupied.Addr().(*net.TCPAddr).Port), decoyStream(t, network, &origin), nil)
			if err == nil || listener != nil || !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("expected origin error before bind, listener=%v err=%v", listener, err)
			}
		})
	}
}
