package conf

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/artx"
)

func TestArtXInboundConfigBuild(t *testing.T) {
	config := &ArtXServerConfig{
		Users:          []*ArtXUser{{PSK: "secret", Email: "user@example.com", Level: 2}},
		TLSSettings:    &TLSConfig{},
		WireVersion:    1,
		ProfileVersion: 2,
		UDPEnabled:     true,
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	server, ok := built.(*artx.ServerConfig)
	if !ok {
		t.Fatalf("Build() = %T", built)
	}
	if server.WireVersion != 1 || server.ProfileVersion != 2 || !server.UdpEnabled || server.TlsSettings == nil || len(server.Users) != 1 {
		t.Fatalf("server config = %#v", server)
	}
	user, err := server.Users[0].ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	account, ok := user.Account.(*artx.MemoryAccount)
	if !ok || account.PSK != "secret" || user.Email != "user@example.com" || user.Level != 2 {
		t.Fatalf("user = %#v", user)
	}
}

func TestArtXInboundConfigBuildsProfileV3(t *testing.T) {
	config := &ArtXServerConfig{
		Users:          []*ArtXUser{{PSK: "secret"}},
		TLSSettings:    &TLSConfig{},
		WireVersion:    1,
		ProfileVersion: 3,
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	if profileVersion := built.(*artx.ServerConfig).ProfileVersion; profileVersion != 3 {
		t.Fatalf("profile version = %d, want 3", profileVersion)
	}
}

func TestArtXInboundConfigBuildsFallback(t *testing.T) {
	config := &ArtXServerConfig{
		Users:          []*ArtXUser{{PSK: "secret"}},
		TLSSettings:    &TLSConfig{},
		WireVersion:    1,
		ProfileVersion: 2,
		Fallback: &ArtXFallbackConfig{
			Enabled: true,
			Origin:  "http://127.0.0.1:60443/",
		},
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	server := built.(*artx.ServerConfig)
	if server.Fallback == nil || !server.Fallback.Enabled || server.Fallback.Origin != "http://127.0.0.1:60443/" {
		t.Fatalf("fallback = %#v", server.Fallback)
	}
}

func TestArtXInboundConfigBuildsIsolatedWireV3(t *testing.T) {
	config := &ArtXServerConfig{
		Users:          []*ArtXUser{{PSK: "secret"}},
		TLSSettings:    &TLSConfig{},
		WireVersion:    3,
		ProfileVersion: 1,
		Fallback:       &ArtXFallbackConfig{Enabled: true, Origin: "http://127.0.0.1:60443/"},
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	server := built.(*artx.ServerConfig)
	if server.WireVersion != 3 || server.ProfileVersion != 1 || server.UdpEnabled || server.Fallback == nil || !server.Fallback.Enabled {
		t.Fatalf("wire-v3 config = %#v", server)
	}
}

func TestArtXInboundConfigValidatesFallback(t *testing.T) {
	tests := []struct {
		name     string
		fallback *ArtXFallbackConfig
		wantErr  string
	}{
		{name: "missing", fallback: nil},
		{name: "disabled", fallback: &ArtXFallbackConfig{}},
		{name: "http", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "http://127.0.0.1:60443/"}},
		{name: "https", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "https://origin.example.com/"}},
		{name: "localhost cleartext", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "http://localhost:60443/"}, wantErr: "loopback"},
		{name: "external cleartext", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "http://192.0.2.1/"}, wantErr: "loopback"},
		{name: "enabled without origin", fallback: &ArtXFallbackConfig{Enabled: true}, wantErr: "origin required"},
		{name: "unsupported scheme", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "ftp://origin.example.com/"}, wantErr: "http or https"},
		{name: "missing host", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "https:///path"}, wantErr: "host required"},
		{name: "credentials", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "https://user:pass@origin.example.com/"}, wantErr: "credentials"},
		{name: "fragment", fallback: &ArtXFallbackConfig{Enabled: true, Origin: "https://origin.example.com/#fragment"}, wantErr: "fragment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &ArtXServerConfig{
				Users:          []*ArtXUser{{PSK: "secret"}},
				TLSSettings:    &TLSConfig{},
				WireVersion:    1,
				ProfileVersion: 1,
				Fallback:       test.fallback,
			}
			_, err := config.Build()
			if test.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("Build() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestArtXInboundConfigRejectsInvalidBoundaryValues(t *testing.T) {
	tests := []ArtXServerConfig{
		{Users: []*ArtXUser{{PSK: "   "}}, TLSSettings: &TLSConfig{}, WireVersion: 1, ProfileVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, WireVersion: 1, ProfileVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, TLSSettings: &TLSConfig{}, WireVersion: 3, ProfileVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, TLSSettings: &TLSConfig{}, WireVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, TLSSettings: &TLSConfig{}, WireVersion: 1, ProfileVersion: 4},
	}
	for index := range tests {
		if _, err := tests[index].Build(); err == nil {
			t.Fatalf("invalid config %d accepted", index)
		}
	}
}

func TestArtXInboundLoaderIsRegistered(t *testing.T) {
	raw, err := inboundConfigLoader.LoadWithID([]byte(`{"users":[{"psk":"secret"}],"tlsSettings":{},"wireVersion":1,"profileVersion":1}`), "artx")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.(*ArtXServerConfig); !ok {
		t.Fatalf("loader returned %T", raw)
	}
}
