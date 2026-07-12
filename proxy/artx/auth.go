package artx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	AuthFrameType     = byte(0x01)
	MinSaltLength     = 16
	MaxSaltLength     = 32
	UserLocatorLength = 8
	ExporterLength    = 32
	AuthTagLength     = sha256.Size
	maxAuthPadding    = 1<<16 - 1
	userLocatorLabel  = "artx-user-locator-v1"
)

type AuthFrame struct {
	Salt            []byte
	UserLocator     [UserLocatorLength]byte
	TimestampBucket uint32
	AuthTag         [AuthTagLength]byte
	Padding         []byte
}

func NewAuthFrame(psk, salt, exporter []byte, timestampBucket uint32, padding []byte) (AuthFrame, error) {
	if len(psk) == 0 {
		return AuthFrame{}, errors.New("ArtX PSK is empty")
	}
	if err := validateSalt(salt); err != nil {
		return AuthFrame{}, err
	}
	if len(exporter) != ExporterLength {
		return AuthFrame{}, fmt.Errorf("ArtX TLS exporter length is %d, want %d", len(exporter), ExporterLength)
	}
	if len(padding) > maxAuthPadding {
		return AuthFrame{}, errors.New("ArtX auth padding is too large")
	}

	return AuthFrame{
		Salt:            append([]byte(nil), salt...),
		UserLocator:     CalculateUserLocator(psk),
		TimestampBucket: timestampBucket,
		AuthTag:         CalculateAuthTag(psk, salt, exporter, timestampBucket),
		Padding:         append([]byte(nil), padding...),
	}, nil
}

func CalculateUserLocator(psk []byte) [UserLocatorLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(userLocatorLabel))
	var locator [UserLocatorLength]byte
	copy(locator[:], mac.Sum(nil))
	return locator
}

func CalculateAuthTag(psk, salt, exporter []byte, timestampBucket uint32) [AuthTagLength]byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write(salt)
	_, _ = mac.Write(exporter)
	var bucket [4]byte
	binary.BigEndian.PutUint32(bucket[:], timestampBucket)
	_, _ = mac.Write(bucket[:])
	var tag [AuthTagLength]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

func (frame AuthFrame) Verify(psk, exporter []byte) bool {
	if len(psk) == 0 || len(exporter) != ExporterLength || validateSalt(frame.Salt) != nil {
		return false
	}
	want := CalculateAuthTag(psk, frame.Salt, exporter, frame.TimestampBucket)
	return hmac.Equal(frame.AuthTag[:], want[:])
}

func (frame AuthFrame) MarshalBinary() ([]byte, error) {
	if err := validateSalt(frame.Salt); err != nil {
		return nil, err
	}
	if len(frame.Padding) > maxAuthPadding {
		return nil, errors.New("ArtX auth padding is too large")
	}

	encoded := make([]byte, 2+len(frame.Salt)+UserLocatorLength+4+AuthTagLength+2+len(frame.Padding))
	offset := 0
	encoded[offset] = AuthFrameType
	offset++
	encoded[offset] = byte(len(frame.Salt))
	offset++
	copy(encoded[offset:], frame.Salt)
	offset += len(frame.Salt)
	copy(encoded[offset:], frame.UserLocator[:])
	offset += UserLocatorLength
	binary.BigEndian.PutUint32(encoded[offset:], frame.TimestampBucket)
	offset += 4
	copy(encoded[offset:], frame.AuthTag[:])
	offset += AuthTagLength
	binary.BigEndian.PutUint16(encoded[offset:], uint16(len(frame.Padding)))
	offset += 2
	copy(encoded[offset:], frame.Padding)
	return encoded, nil
}

func ReadAuthFrame(reader io.Reader) (AuthFrame, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return AuthFrame{}, err
	}
	if header[0] != AuthFrameType {
		return AuthFrame{}, fmt.Errorf("unexpected ArtX auth frame type 0x%02x", header[0])
	}
	saltLength := int(header[1])
	if err := validateSalt(make([]byte, saltLength)); err != nil {
		return AuthFrame{}, err
	}

	frame := AuthFrame{Salt: make([]byte, saltLength)}
	if _, err := io.ReadFull(reader, frame.Salt); err != nil {
		return AuthFrame{}, err
	}
	if _, err := io.ReadFull(reader, frame.UserLocator[:]); err != nil {
		return AuthFrame{}, err
	}
	var bucket [4]byte
	if _, err := io.ReadFull(reader, bucket[:]); err != nil {
		return AuthFrame{}, err
	}
	frame.TimestampBucket = binary.BigEndian.Uint32(bucket[:])
	if _, err := io.ReadFull(reader, frame.AuthTag[:]); err != nil {
		return AuthFrame{}, err
	}
	var paddingLength [2]byte
	if _, err := io.ReadFull(reader, paddingLength[:]); err != nil {
		return AuthFrame{}, err
	}
	frame.Padding = make([]byte, binary.BigEndian.Uint16(paddingLength[:]))
	if _, err := io.ReadFull(reader, frame.Padding); err != nil {
		return AuthFrame{}, err
	}
	return frame, nil
}

func validateSalt(salt []byte) error {
	if len(salt) < MinSaltLength || len(salt) > MaxSaltLength {
		return fmt.Errorf("ArtX salt length is %d, want %d..%d", len(salt), MinSaltLength, MaxSaltLength)
	}
	return nil
}
