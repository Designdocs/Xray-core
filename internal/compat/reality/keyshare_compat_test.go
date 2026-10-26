package reality

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestRealityPeerPublicKeyCompatibility(t *testing.T) {
	classic := bytes.Repeat([]byte{1}, 32)
	hybrid := bytes.Repeat([]byte{2}, mlkem.EncapsulationKeySize768+32)
	c := keyShare{group: X25519, data: classic}
	h := keyShare{group: X25519MLKEM768, data: hybrid}
	for _, tc := range []struct {
		name   string
		shares []keyShare
		legacy bool
		want   []byte
	}{
		{"strict rejects legacy", []keyShare{c}, false, nil},
		{"compat accepts legacy", []keyShare{c}, true, classic},
		{"strict hybrid only", []keyShare{h}, false, hybrid[len(hybrid)-32:]},
		{"compat hybrid only", []keyShare{h}, true, hybrid[len(hybrid)-32:]},
		{"strict prefers classical authentication share", []keyShare{h, c}, false, classic},
		{"compat preserves modern behavior", []keyShare{h, c}, true, classic},
		{"ignore GREASE", []keyShare{{group: CurveID(0x0a0a), data: []byte{0}}, c}, true, classic},
		{"reject duplicate X25519", []keyShare{c, c}, true, nil},
		{"reject duplicate hybrid", []keyShare{h, h}, true, nil},
		{"reject hybrid after classical", []keyShare{c, h}, true, nil},
		{"reject short X25519", []keyShare{{group: X25519, data: classic[:31]}}, true, nil},
		{"reject short hybrid", []keyShare{{group: X25519MLKEM768, data: hybrid[:len(hybrid)-1]}, c}, true, nil},
		{"reject unsupported shares", []keyShare{{group: CurveP256, data: []byte{1}}}, true, nil},
		{"reject empty", nil, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := realityPeerPublicKey(tc.shares, tc.legacy); !bytes.Equal(got, tc.want) {
				t.Fatalf("public key = %x, want %x", got, tc.want)
			}
		})
	}
}

func TestClonePreservesLegacyCompatibility(t *testing.T) {
	if !(&Config{AllowLegacyX25519: true}).Clone().AllowLegacyX25519 {
		t.Fatal("clone lost legacy compatibility setting")
	}
	if (&Config{}).Clone().AllowLegacyX25519 {
		t.Fatal("clone enabled compatibility by default")
	}
}
