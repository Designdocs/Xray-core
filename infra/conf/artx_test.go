package conf

import (
	"testing"

	"github.com/xtls/xray-core/proxy/artx"
)

func TestArtXInboundConfigBuild(t *testing.T) {
	config := &ArtXServerConfig{
		Users:          []*ArtXUser{{PSK: "secret", Email: "user@example.com", Level: 2}},
		TLSSettings:    &TLSConfig{},
		WireVersion:    1,
		ProfileVersion: 7,
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	server, ok := built.(*artx.ServerConfig)
	if !ok {
		t.Fatalf("Build() = %T", built)
	}
	if server.WireVersion != 1 || server.ProfileVersion != 7 || server.TlsSettings == nil || len(server.Users) != 1 {
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

func TestArtXInboundConfigRejectsInvalidBoundaryValues(t *testing.T) {
	tests := []ArtXServerConfig{
		{Users: []*ArtXUser{{PSK: "   "}}, TLSSettings: &TLSConfig{}, WireVersion: 1, ProfileVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, WireVersion: 1, ProfileVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, TLSSettings: &TLSConfig{}, WireVersion: 2, ProfileVersion: 1},
		{Users: []*ArtXUser{{PSK: "secret"}}, TLSSettings: &TLSConfig{}, WireVersion: 1},
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
