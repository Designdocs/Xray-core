package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/artx"
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

type ArtXUser struct {
	PSK   string `json:"psk"`
	Level byte   `json:"level"`
	Email string `json:"email"`
}

type ArtXServerConfig struct {
	Users          []*ArtXUser `json:"users"`
	TLSSettings    *TLSConfig  `json:"tlsSettings"`
	WireVersion    uint32      `json:"wireVersion"`
	ProfileVersion uint32      `json:"profileVersion"`
}

func (config *ArtXServerConfig) Build() (proto.Message, error) {
	if config.TLSSettings == nil {
		return nil, errors.New("ARTX: tlsSettings required")
	}
	if config.WireVersion != 1 {
		return nil, errors.New("ARTX: wireVersion must be 1")
	}
	if config.ProfileVersion == 0 {
		return nil, errors.New("ARTX: profileVersion required")
	}
	tlsSettings, err := config.TLSSettings.Build()
	if err != nil {
		return nil, err
	}
	built := &artx.ServerConfig{
		TlsSettings:    tlsSettings.(*transporttls.Config),
		WireVersion:    config.WireVersion,
		ProfileVersion: config.ProfileVersion,
		Users:          make([]*protocol.User, 0, len(config.Users)),
	}
	for _, user := range config.Users {
		if user == nil || strings.TrimSpace(user.PSK) == "" {
			return nil, errors.New("ARTX: user PSK required")
		}
		built.Users = append(built.Users, &protocol.User{
			Level: uint32(user.Level), Email: user.Email,
			Account: serial.ToTypedMessage(&artx.Account{Psk: user.PSK}),
		})
	}
	return built, nil
}
