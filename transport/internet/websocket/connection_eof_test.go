package websocket

import (
	"bytes"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestReadPreservesDataReturnedWithEOF(t *testing.T) {
	conn := &connection{reader: iotest.DataErrReader(strings.NewReader("final payload"))}
	output := make([]byte, 64)
	n, err := conn.Read(output)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(output[:n]) != "final payload" {
		t.Fatalf("final frame data=%q", output[:n])
	}
	if conn.reader != nil {
		t.Fatal("finished message reader retained")
	}
}

func TestReadAllHandlesOrderlyWebSocketClose(t *testing.T) {
	payload := bytes.Repeat([]byte("last queued bytes"), 4096)
	for _, code := range []int{websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseProtocolError} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if err = conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					return
				}
				conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(time.Second))
			}))
			defer server.Close()
			peer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			data, err := io.ReadAll(NewConnection(peer, peer.RemoteAddr(), nil, 0))
			if !bytes.Equal(data, payload) {
				t.Fatalf("received %d bytes, want %d", len(data), len(payload))
			}
			if code == websocket.CloseProtocolError {
				if !websocket.IsCloseError(err, code) {
					t.Fatalf("protocol error lost: %v", err)
				}
			} else if err != nil {
				t.Fatalf("orderly close returned an error: %v", err)
			}
		})
	}
}
