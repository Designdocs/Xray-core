package artx

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	profileVersionUnshaped           = uint32(1)
	profileVersionEarlyRecordShaping = uint32(2)
	settingsShapeInfo                = "artx-shape-v1"
	settingsGreaseKey                = uint16(0x0a0a)
	settingsPaddingLength            = 14
	greasedFirstChunkLength          = 21
	paddedFirstChunkLength           = 45
)

type settingsFlightTemplate byte

const (
	settingsFlightGreased settingsFlightTemplate = iota
	settingsFlightPadded
)

type serverSettingsFlight struct {
	chunks   [][]byte
	template settingsFlightTemplate
}

func newServerSettingsFlight(profileVersion uint32, psk, salt []byte) (serverSettingsFlight, error) {
	if profileVersion == profileVersionUnshaped {
		encoded, err := marshalSettingsFrame(settingsList(profileVersion))
		if err != nil {
			return serverSettingsFlight{}, err
		}
		return serverSettingsFlight{chunks: [][]byte{encoded}}, nil
	}
	if profileVersion != profileVersionEarlyRecordShaping {
		return serverSettingsFlight{}, fmt.Errorf("artx: unsupported profile version %d", profileVersion)
	}
	if len(psk) == 0 {
		return serverSettingsFlight{}, errors.New("artx: shaping PSK is required")
	}
	if err := validateSalt(salt); err != nil {
		return serverSettingsFlight{}, err
	}

	seed := hkdf.New(sha256.New, psk, salt, []byte(settingsShapeInfo))
	template, err := selectSettingsFlightTemplate(seed)
	if err != nil {
		return serverSettingsFlight{}, err
	}
	switch template {
	case settingsFlightGreased:
		return newGreasedSettingsFlight(seed)
	case settingsFlightPadded:
		return newPaddedSettingsFlight(seed)
	default:
		return serverSettingsFlight{}, errors.New("artx: invalid settings flight template")
	}
}

func selectSettingsFlightTemplate(reader io.Reader) (settingsFlightTemplate, error) {
	var sample [1]byte
	for {
		if _, err := io.ReadFull(reader, sample[:]); err != nil {
			return 0, err
		}
		if sample[0] == 255 {
			continue
		}
		if sample[0]%3 < 2 {
			return settingsFlightGreased, nil
		}
		return settingsFlightPadded, nil
	}
}

func newGreasedSettingsFlight(reader io.Reader) (serverSettingsFlight, error) {
	var value [4]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return serverSettingsFlight{}, err
	}
	settings := append(settingsList(profileVersionEarlyRecordShaping), Setting{
		Key: settingsGreaseKey, Value: binary.BigEndian.Uint32(value[:]),
	})
	encoded, err := marshalSettingsFrame(settings)
	if err != nil {
		return serverSettingsFlight{}, err
	}
	return serverSettingsFlight{chunks: splitSettingsFlight(encoded, greasedFirstChunkLength), template: settingsFlightGreased}, nil
}

func newPaddedSettingsFlight(reader io.Reader) (serverSettingsFlight, error) {
	settings, err := marshalSettingsFrame(settingsList(profileVersionEarlyRecordShaping))
	if err != nil {
		return serverSettingsFlight{}, err
	}
	paddingPayload := make([]byte, settingsPaddingLength)
	if _, err := io.ReadFull(reader, paddingPayload); err != nil {
		return serverSettingsFlight{}, err
	}
	padding, err := (Frame{Type: FramePadding, Payload: paddingPayload}).MarshalBinary()
	if err != nil {
		return serverSettingsFlight{}, err
	}
	encoded := append(settings, padding...)
	return serverSettingsFlight{chunks: splitSettingsFlight(encoded, paddedFirstChunkLength), template: settingsFlightPadded}, nil
}

func marshalSettingsFrame(settings []Setting) ([]byte, error) {
	payload, err := EncodeSettings(settings)
	if err != nil {
		return nil, err
	}
	return (Frame{Type: FrameSettings, Payload: payload}).MarshalBinary()
}

func splitSettingsFlight(encoded []byte, firstChunkLength int) [][]byte {
	return [][]byte{encoded[:firstChunkLength], encoded[firstChunkLength:]}
}
