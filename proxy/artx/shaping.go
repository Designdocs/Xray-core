package artx

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	profileVersionUnshaped           = uint32(1)
	profileVersionEarlyRecordShaping = uint32(2)
	profileVersionTimedRecordShaping = uint32(3)
	settingsShapeInfo                = "artx-shape-v1"
	settingsGapInfo                  = "artx-shape-v3-gap"
	settingsGreaseKey                = uint16(0x0a0a)
	settingsPaddingLength            = 14
	greasedFirstChunkLength          = 21
	paddedFirstChunkLength           = 45
)

var errPreciseSettingsDeadlineUnsupported = errors.New("artx: profile version 3 requires Linux precise settings deadline waiting")

type settingsFlightTemplate byte

const (
	settingsFlightGreased settingsFlightTemplate = iota
	settingsFlightPadded
)

type serverSettingsFlight struct {
	chunks         [][]byte
	template       settingsFlightTemplate
	targetStartGap time.Duration
}

func newServerSettingsFlight(profileVersion uint32, psk, salt []byte) (serverSettingsFlight, error) {
	return newServerSettingsFlightForWire(1, profileVersion, psk, salt)
}

func newServerSettingsFlightForWire(wireVersion, profileVersion uint32, psk, salt []byte) (serverSettingsFlight, error) {
	if profileVersion == profileVersionUnshaped {
		encoded, err := marshalSettingsFrame(settingsListForWire(wireVersion, profileVersion))
		if err != nil {
			return serverSettingsFlight{}, err
		}
		return serverSettingsFlight{chunks: [][]byte{encoded}}, nil
	}
	if profileVersion != profileVersionEarlyRecordShaping && profileVersion != profileVersionTimedRecordShaping {
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
	var flight serverSettingsFlight
	switch template {
	case settingsFlightGreased:
		flight, err = newGreasedSettingsFlightForWire(wireVersion, profileVersion, seed)
	case settingsFlightPadded:
		flight, err = newPaddedSettingsFlightForWire(wireVersion, profileVersion, seed)
	default:
		return serverSettingsFlight{}, errors.New("artx: invalid settings flight template")
	}
	if err != nil || profileVersion != profileVersionTimedRecordShaping {
		return flight, err
	}
	gapSeed := hkdf.New(sha256.New, psk, salt, []byte(settingsGapInfo))
	targetStartGap, err := selectSettingsFlightGap(flight.template, gapSeed)
	if err != nil {
		return serverSettingsFlight{}, err
	}
	flight.targetStartGap = targetStartGap
	return flight, nil
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

func newGreasedSettingsFlight(profileVersion uint32, reader io.Reader) (serverSettingsFlight, error) {
	return newGreasedSettingsFlightForWire(1, profileVersion, reader)
}

func newGreasedSettingsFlightForWire(wireVersion, profileVersion uint32, reader io.Reader) (serverSettingsFlight, error) {
	var value [4]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return serverSettingsFlight{}, err
	}
	settings := append(settingsListForWire(wireVersion, profileVersion), Setting{
		Key: settingsGreaseKey, Value: binary.BigEndian.Uint32(value[:]),
	})
	encoded, err := marshalSettingsFrame(settings)
	if err != nil {
		return serverSettingsFlight{}, err
	}
	return serverSettingsFlight{chunks: splitSettingsFlight(encoded, greasedFirstChunkLength), template: settingsFlightGreased}, nil
}

func newPaddedSettingsFlight(profileVersion uint32, reader io.Reader) (serverSettingsFlight, error) {
	return newPaddedSettingsFlightForWire(1, profileVersion, reader)
}

func newPaddedSettingsFlightForWire(wireVersion, profileVersion uint32, reader io.Reader) (serverSettingsFlight, error) {
	settings, err := marshalSettingsFrame(settingsListForWire(wireVersion, profileVersion))
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

type settingsGapBucket struct {
	target     time.Duration
	cumulative uint32
}

var greasedSettingsGapCDF = [...]settingsGapBucket{
	{target: 30 * time.Microsecond, cumulative: 32768},
	{target: 49 * time.Microsecond, cumulative: 65536},
}

var paddedSettingsGapCDF = [...]settingsGapBucket{
	{target: 27 * time.Microsecond, cumulative: 3449},
	{target: 32 * time.Microsecond, cumulative: 6898},
	{target: 35 * time.Microsecond, cumulative: 10347},
	{target: 38 * time.Microsecond, cumulative: 13796},
	{target: 39 * time.Microsecond, cumulative: 17245},
	{target: 42 * time.Microsecond, cumulative: 20694},
	{target: 44 * time.Microsecond, cumulative: 24143},
	{target: 46 * time.Microsecond, cumulative: 27592},
	{target: 48 * time.Microsecond, cumulative: 31041},
	{target: 50 * time.Microsecond, cumulative: 34490},
	{target: 55 * time.Microsecond, cumulative: 37939},
	{target: 62 * time.Microsecond, cumulative: 41388},
	{target: 67 * time.Microsecond, cumulative: 44837},
	{target: 74 * time.Microsecond, cumulative: 48286},
	{target: 83 * time.Microsecond, cumulative: 51736},
	{target: 92 * time.Microsecond, cumulative: 55186},
	{target: 108 * time.Microsecond, cumulative: 58636},
	{target: 132 * time.Microsecond, cumulative: 62086},
	{target: 192 * time.Microsecond, cumulative: 65536},
}

func selectSettingsFlightGap(template settingsFlightTemplate, reader io.Reader) (time.Duration, error) {
	var sampleBytes [2]byte
	if _, err := io.ReadFull(reader, sampleBytes[:]); err != nil {
		return 0, err
	}
	sample := uint32(binary.BigEndian.Uint16(sampleBytes[:]))
	var cdf []settingsGapBucket
	switch template {
	case settingsFlightGreased:
		cdf = greasedSettingsGapCDF[:]
	case settingsFlightPadded:
		cdf = paddedSettingsGapCDF[:]
	default:
		return 0, errors.New("artx: invalid settings flight template")
	}
	for _, bucket := range cdf {
		if sample < bucket.cumulative {
			return bucket.target, nil
		}
	}
	return 0, errors.New("artx: invalid settings gap CDF")
}

type settingsDeadlineWaiter func(context.Context, time.Time) error

func (writer *lockedFrameWriter) writeChunksWithGap(
	ctx context.Context,
	chunks [][]byte,
	targetStartGap time.Duration,
	now func() time.Time,
	waitUntil settingsDeadlineWaiter,
) error {
	if len(chunks) != 2 || targetStartGap <= 0 {
		return errors.New("artx: invalid timed settings flight")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	firstWriteStarted := now()
	if err := writeAll(writer.writer, chunks[0]); err != nil {
		return err
	}
	if err := waitUntil(ctx, firstWriteStarted.Add(targetStartGap)); err != nil {
		return err
	}
	return writeAll(writer.writer, chunks[1])
}

func nonNegativeDuration(now, deadline time.Time) time.Duration {
	if !deadline.After(now) {
		return 0
	}
	return deadline.Sub(now)
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
