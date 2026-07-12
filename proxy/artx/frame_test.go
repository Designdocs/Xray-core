package artx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	stdnet "net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestGoldenCommonFrames(t *testing.T) {
	settings, err := EncodeSettings([]Setting{
		{Key: SettingMaxConcurrentStreams, Value: 1},
		{Key: SettingInitialStreamWindow, Value: InitialStreamWindow},
		{Key: SettingInitialConnectionWindow, Value: InitialConnectionWindow},
		{Key: SettingPaddingProfileVersionAck, Value: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertFrameHex(t, Frame{Type: FrameSettings, Payload: settings}, "0200000000000018000100000001000200040000000300100000000500000001")

	destination := xnet.TCPDestination(xnet.DomainAddress("example.com"), 443)
	tcpSyn, err := EncodeTCPDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	assertFrameHex(t, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: tcpSyn}, "100000000100000f030b6578616d706c652e636f6d01bb")
	assertFrameHex(t, Frame{Type: FrameData, StreamID: ClientStreamID, Payload: []byte("GET / HTTP/1.1\r\n\r\n")}, "1100000001000012474554202f20485454502f312e310d0a0d0a")
	assertFrameHex(t, Frame{Type: FrameFin, StreamID: ClientStreamID}, "1200000001000000")

	got, err := DecodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	if got[SettingInitialConnectionWindow] != InitialConnectionWindow || got[SettingPaddingProfileVersionAck] != 1 {
		t.Fatalf("decoded settings = %#v", got)
	}
}

func TestFrameUint24AndLimits(t *testing.T) {
	payload := make([]byte, 0x010203)
	encoded, err := (Frame{Type: FramePadding, Payload: payload}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoded[5:8]); got != "010203" {
		t.Fatalf("uint24 length = %s", got)
	}
	decoded, err := ReadFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Payload) != len(payload) {
		t.Fatalf("decoded payload length = %d", len(decoded.Payload))
	}

	if _, err := (Frame{Type: FrameData, StreamID: ClientStreamID, Payload: make([]byte, MaxDataPayload)}).MarshalBinary(); err != nil {
		t.Fatalf("maximum DATA payload rejected: %v", err)
	}
	if _, err := (Frame{Type: FrameData, StreamID: ClientStreamID, Payload: make([]byte, MaxDataPayload+1)}).MarshalBinary(); err == nil {
		t.Fatal("oversized DATA payload accepted")
	}
	if _, err := (Frame{Type: FramePadding, Payload: make([]byte, MaxFramePayload+1)}).MarshalBinary(); err == nil {
		t.Fatal("oversized frame payload accepted")
	}

	for size := 0; size < FrameHeaderLength; size++ {
		if _, err := ReadFrame(bytes.NewReader(make([]byte, size))); err == nil || err != io.EOF && err != io.ErrUnexpectedEOF {
			t.Fatalf("truncated header length %d returned %v", size, err)
		}
	}
}

func TestKnownFrameStreamIDs(t *testing.T) {
	tests := []Frame{
		{Type: FrameSettings, StreamID: ClientStreamID},
		{Type: FramePadding, StreamID: ClientStreamID},
		{Type: FrameTCPSyn},
		{Type: FrameData, StreamID: 2},
		{Type: FrameFin},
		{Type: FrameRST, StreamID: 2},
		{Type: FrameWindowUpdate, StreamID: 2, Payload: []byte{0, 0, 0, 1}},
	}

	for _, frame := range tests {
		if _, err := frame.MarshalBinary(); err == nil {
			t.Fatalf("frame type 0x%02x accepted invalid stream %d", frame.Type, frame.StreamID)
		}
		raw := make([]byte, FrameHeaderLength+len(frame.Payload))
		raw[0] = frame.Type
		binary.BigEndian.PutUint32(raw[1:5], frame.StreamID)
		putUint24(raw[5:8], len(frame.Payload))
		copy(raw[FrameHeaderLength:], frame.Payload)
		if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
			t.Fatalf("reader accepted frame type 0x%02x with invalid stream %d", frame.Type, frame.StreamID)
		}
	}

	for _, frame := range []Frame{
		{Type: FrameWindowUpdate, Payload: []byte{0, 0, 0, 1}},
		{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: []byte{0, 0, 0, 1}},
		{Type: 0x7f, StreamID: 99},
	} {
		if _, err := frame.MarshalBinary(); err != nil {
			t.Fatalf("frame type 0x%02x stream %d rejected: %v", frame.Type, frame.StreamID, err)
		}
	}
}

func TestWindowUpdate(t *testing.T) {
	payload, err := EncodeWindowUpdate(65536)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(payload); got != "00010000" {
		t.Fatalf("WINDOW_UPDATE = %s", got)
	}
	if got, err := DecodeWindowUpdate(payload); err != nil || got != 65536 {
		t.Fatalf("decoded WINDOW_UPDATE = %d, %v", got, err)
	}
	if _, err := EncodeWindowUpdate(0); err == nil {
		t.Fatal("zero WINDOW_UPDATE accepted")
	}
}

func TestTCPDestinationFamilies(t *testing.T) {
	tests := []struct {
		name string
		dest xnet.Destination
		hex  string
	}{
		{"ipv4", xnet.TCPDestination(xnet.IPAddress(stdnet.ParseIP("192.0.2.1").To4()), 80), "01c00002010050"},
		{"domain", xnet.TCPDestination(xnet.DomainAddress("example.com"), 443), "030b6578616d706c652e636f6d01bb"},
		{"ipv6", xnet.TCPDestination(xnet.IPAddress(stdnet.ParseIP("2001:db8::1").To16()), 443), "0420010db800000000000000000000000101bb"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := EncodeTCPDestination(test.dest)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(encoded); got != test.hex {
				t.Fatalf("encoded destination = %s", got)
			}
			decoded, err := DecodeTCPDestination(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.String() != test.dest.String() {
				t.Fatalf("decoded destination = %s", decoded.String())
			}
		})
	}
}

func assertFrameHex(t *testing.T, frame Frame, want string) {
	t.Helper()
	encoded, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoded); got != want {
		t.Fatalf("frame = %s", got)
	}
}
