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
	Users          []*ArtXUser         `json:"users"`
	TLSSettings    *TLSConfig          `json:"tlsSettings"`
	WireVersion    uint32              `json:"wireVersion"`
	ProfileVersion uint32              `json:"profileVersion"`
	Fallback       *ArtXFallbackConfig `json:"fallback"`
	UDPEnabled     bool                `json:"udpEnabled"`
	MaxWindowScale uint32              `json:"maxWindowScale"`
	// FlowControlAuto turns maxWindowScale into an upper bound and lets each
	// connection size its own window from the measured bandwidth-delay product.
	FlowControlAuto bool `json:"flowControlAuto"`
}

type ArtXFallbackConfig struct {
	Enabled bool   `json:"enabled"`
	Origin  string `json:"origin"`
}

func (config *ArtXServerConfig) Build() (proto.Message, error) {
	if config.TLSSettings == nil {
		return nil, errors.New("ARTX: tlsSettings required")
	}
	if config.WireVersion != 1 && config.WireVersion != 2 && config.WireVersion != 3 && config.WireVersion != 4 {
		return nil, errors.New("ARTX: wireVersion must be 1, 2, 3, or 4")
	}
	if config.ProfileVersion < 1 || config.ProfileVersion > 3 {
		return nil, errors.New("ARTX: profileVersion must be 1, 2, or 3")
	}
	if config.MaxWindowScale > artx.MaxWindowScale {
		return nil, errors.New("ARTX: maxWindowScale must be between 0 and 4")
	}
	if (config.WireVersion == 3 || config.WireVersion == 4) && (config.ProfileVersion != 1 || config.UDPEnabled || config.Fallback == nil || !config.Fallback.Enabled) {
		return nil, errors.New("ARTX: wireVersion 3 or 4 requires profileVersion 1, udpEnabled false, and enabled fallback")
	}
	tlsSettings, err := config.TLSSettings.Build()
	if err != nil {
		return nil, err
	}
	built := &artx.ServerConfig{
		TlsSettings:     tlsSettings.(*transporttls.Config),
		WireVersion:     config.WireVersion,
		ProfileVersion:  config.ProfileVersion,
		UdpEnabled:      config.UDPEnabled,
		MaxWindowScale:  config.MaxWindowScale,
		FlowControlAuto: config.FlowControlAuto,
		Users:           make([]*protocol.User, 0, len(config.Users)),
	}
	if config.Fallback != nil {
		origin := strings.TrimSpace(config.Fallback.Origin)
		if config.Fallback.Enabled && origin == "" {
			return nil, errors.New("ARTX: fallback origin required when enabled")
		}
		if origin != "" {
			if err := artx.ValidateFallbackOrigin(origin); err != nil {
				return nil, errors.New("ARTX: invalid fallback origin").Base(err)
			}
		}
		built.Fallback = &artx.FallbackConfig{Enabled: config.Fallback.Enabled, Origin: origin}
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
