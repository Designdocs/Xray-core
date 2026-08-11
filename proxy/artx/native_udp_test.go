package artx

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func TestNativeUDPAuthenticationVector(t *testing.T) {
	psk := []byte("test-native-udp-psk")
	salt := decodeNativeUDPHex(t, "000102030405060708090a0b0c0d0e0f")
	exporter := decodeNativeUDPHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	request := nativeUDPRequest{
		method:          "CONNECT",
		protocol:        "connect-udp",
		scheme:          "https",
		authority:       "edge.example.com:443",
		path:            "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/",
		capsuleProtocol: "?1",
	}
	authorization, err := newNativeUDPAuthorization(psk, salt, exporter, request, 123456)
	if err != nil {
		t.Fatal(err)
	}
	const wantAuthorization = "ArtX AQAAAQIDBAUGBwgJCgsMDQ4PuvhTdc0L_McAAeJAYdDGUluy7-jK4l-XcvJEIJL4f5q4ONwMbbWqgUEiWDM"
	if got := authorization.header(); got != wantAuthorization {
		t.Fatalf("authorization = %q, want %q", got, wantAuthorization)
	}
	proof, err := authorization.serverProof(psk, exporter, 200, request.capsuleProtocol)
	if err != nil {
		t.Fatal(err)
	}
	const wantProof = `rspauth="yBw-OLgcAisFyLoduW64wDJL7IeWBs1gpzo9qlDQZQ8"`
	if proof != wantProof {
		t.Fatalf("proof = %q, want %q", proof, wantProof)
	}
}

func TestNativeUDPAuthenticatesBeforeTargetParsing(t *testing.T) {
	server := &Server{
		users:  make(map[[UserLocatorLength]byte]*protocol.MemoryUser),
		replay: newReplayCache(replayCacheCapacity, replayCacheTTL, time.Now),
		now:    time.Now,
	}
	handler := newNativeUDPHandler(server, &rejectingDispatcher{}, "native-udp-test")
	request := httptest.NewRequest(http.MethodConnect, "https://edge.example.com/not-a-target", nil)
	request.Proto = "connect-udp"
	request.Header.Set("Capsule-Protocol", "?1")
	request.Header.Set(nativeUDPAuthHeader, "ArtX malformed")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("body length = %d, want 0", recorder.Body.Len())
	}
	stats := server.Stats()
	if stats.AuthenticationFailure != 1 || stats.NativeRejected != 1 || stats.NativeAccepted != 0 || stats.NativeActive != 0 {
		t.Fatalf("native rejection stats = %#v", stats)
	}
}

func TestNativeUDPSource(t *testing.T) {
	for _, remote := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		source := nativeUDPSource(remote)
		if source.Network != xnet.Network_UDP || source.Port != 1234 || source.Address == nil {
			t.Fatalf("nativeUDPSource(%q) = %+v", remote, source)
		}
	}
	if source := nativeUDPSource("invalid"); source.Address != nil {
		t.Fatalf("nativeUDPSource(invalid) = %+v", source)
	}
}

func TestNativeUDPTargetParserRequiresCanonicalPath(t *testing.T) {
	destination, err := parseNativeUDPTarget("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/")
	if err != nil || destination.Address.IP().String() != "2001:db8::42" || destination.Port != 443 {
		t.Fatalf("destination = %v, error = %v", destination, err)
	}
	for _, path := range []string{
		"/.well-known/masque/udp/2001%3adb8%3a%3a42/443/",
		"/.well-known/masque/udp/example.com/0443/",
		"/.well-known/masque/udp/example.com/0/",
		"/.well-known/masque/udp/example.com/443/extra/",
	} {
		if _, err := parseNativeUDPTarget(path); err == nil {
			t.Fatalf("non-canonical path was accepted: %q", path)
		}
	}
}

func decodeNativeUDPHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
