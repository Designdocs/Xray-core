package reality

import "testing"

func TestExplicitCompatibilityFloor(t *testing.T) {
	for _, tc := range []struct {
		name string
		min  []byte
		want bool
	}{
		{"upstream default", nil, false},
		{"explicit compatibility", []byte{0, 0, 0}, true},
		{"modern minimum", []byte{26, 3, 27}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := (&Config{PrivateKey: make([]byte, 32), MinClientVer: tc.min}).GetREALITYConfig()
			if c.AllowLegacyX25519 != tc.want {
				t.Fatalf("compatibility = %v, want %v", c.AllowLegacyX25519, tc.want)
			}
		})
	}
}
