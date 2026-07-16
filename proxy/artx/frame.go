package artx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	xnet "github.com/xtls/xray-core/common/net"
)

const (
	FrameHeaderLength = 8
	MaxFramePayload   = 1 << 20
	MaxDataPayload    = 64 << 10
	ClientStreamID    = uint32(1)

	InitialStreamWindow     = uint32(256 << 10)
	InitialConnectionWindow = uint32(1 << 20)
)

const (
	FrameSettings     = byte(0x02)
	FrameTCPSyn       = byte(0x10)
	FrameData         = byte(0x11)
	FrameFin          = byte(0x12)
	FrameRST          = byte(0x13)
	FrameWindowUpdate = byte(0x14)
	FrameUDPAssoc     = byte(0x15)
	FrameDatagram     = byte(0x16)
	FramePadding      = byte(0x20)
)

const maxDatagramPayload = int(^uint16(0))

const (
	SettingMaxConcurrentStreams     = uint16(0x0001)
	SettingInitialStreamWindow      = uint16(0x0002)
	SettingInitialConnectionWindow  = uint16(0x0003)
	SettingKeepaliveIntervalHint    = uint16(0x0004)
	SettingPaddingProfileVersionAck = uint16(0x0005)
	SettingResumptionTicketOffered  = uint16(0x0006)
	SettingSessionReuse             = uint16(0x0007)
	settingEncodedLength            = 6
	addressTypeIPv4                 = byte(0x01)
	addressTypeDomain               = byte(0x03)
	addressTypeIPv6                 = byte(0x04)
)

type Frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

type Setting struct {
	Key   uint16
	Value uint32
}

func (frame Frame) MarshalBinary() ([]byte, error) {
	return frame.marshal(1)
}

func (frame Frame) marshal(wireVersion uint32) ([]byte, error) {
	if err := validateFrameForWire(wireVersion, frame.Type, frame.StreamID, len(frame.Payload)); err != nil {
		return nil, err
	}
	encoded := make([]byte, FrameHeaderLength+len(frame.Payload))
	encoded[0] = frame.Type
	binary.BigEndian.PutUint32(encoded[1:5], frame.StreamID)
	putUint24(encoded[5:8], len(frame.Payload))
	copy(encoded[FrameHeaderLength:], frame.Payload)
	return encoded, nil
}

func ReadFrame(reader io.Reader) (Frame, error) {
	return readFrame(reader, 1)
}

func readFrame(reader io.Reader, wireVersion uint32) (Frame, error) {
	var header [FrameHeaderLength]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	payloadLength := readUint24(header[5:8])
	streamID := binary.BigEndian.Uint32(header[1:5])
	if err := validateFrameForWire(wireVersion, header[0], streamID, payloadLength); err != nil {
		return Frame{}, err
	}
	frame := Frame{
		Type:     header[0],
		StreamID: streamID,
		Payload:  make([]byte, payloadLength),
	}
	if _, err := io.ReadFull(reader, frame.Payload); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func EncodeSettings(settings []Setting) ([]byte, error) {
	if len(settings) > MaxFramePayload/settingEncodedLength {
		return nil, errors.New("too many ArtX settings")
	}
	encoded := make([]byte, len(settings)*settingEncodedLength)
	for index, setting := range settings {
		offset := index * settingEncodedLength
		binary.BigEndian.PutUint16(encoded[offset:], setting.Key)
		binary.BigEndian.PutUint32(encoded[offset+2:], setting.Value)
	}
	return encoded, nil
}

func DecodeSettings(payload []byte) (map[uint16]uint32, error) {
	if len(payload)%settingEncodedLength != 0 {
		return nil, errors.New("invalid ArtX SETTINGS payload length")
	}
	settings := make(map[uint16]uint32, len(payload)/settingEncodedLength)
	for offset := 0; offset < len(payload); offset += settingEncodedLength {
		settings[binary.BigEndian.Uint16(payload[offset:])] = binary.BigEndian.Uint32(payload[offset+2:])
	}
	return settings, nil
}

func EncodeWindowUpdate(increment uint32) ([]byte, error) {
	if increment == 0 {
		return nil, errors.New("ArtX WINDOW_UPDATE increment is zero")
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, increment)
	return payload, nil
}

func DecodeWindowUpdate(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, errors.New("invalid ArtX WINDOW_UPDATE payload length")
	}
	increment := binary.BigEndian.Uint32(payload)
	if increment == 0 {
		return 0, errors.New("ArtX WINDOW_UPDATE increment is zero")
	}
	return increment, nil
}

func EncodeTCPDestination(destination xnet.Destination) ([]byte, error) {
	if destination.Network != xnet.Network_TCP {
		return nil, errors.New("invalid ArtX TCP destination")
	}
	return encodeDestination(destination)
}

func DecodeTCPDestination(payload []byte) (xnet.Destination, error) {
	return decodeDestination(payload, xnet.Network_TCP)
}

func EncodeUDPDestination(destination xnet.Destination) ([]byte, error) {
	if destination.Network != xnet.Network_UDP {
		return nil, errors.New("invalid ArtX UDP destination")
	}
	return encodeDestination(destination)
}

func DecodeUDPDestination(payload []byte) (xnet.Destination, error) {
	return decodeDestination(payload, xnet.Network_UDP)
}

func EncodeDatagram(payload []byte) ([]byte, error) {
	if len(payload) > maxDatagramPayload {
		return nil, errors.New("ArtX DATAGRAM payload is too large")
	}
	encoded := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(encoded, uint16(len(payload)))
	copy(encoded[2:], payload)
	return encoded, nil
}

func DecodeDatagram(payload []byte) ([]byte, error) {
	if len(payload) < 2 || int(binary.BigEndian.Uint16(payload)) != len(payload)-2 {
		return nil, errors.New("invalid ArtX DATAGRAM payload length")
	}
	return payload[2:], nil
}

func encodeDestination(destination xnet.Destination) ([]byte, error) {
	if destination.Address == nil || destination.Port == 0 {
		return nil, errors.New("invalid ArtX destination")
	}

	var address []byte
	switch destination.Address.Family() {
	case xnet.AddressFamilyIPv4:
		address = append([]byte{addressTypeIPv4}, destination.Address.IP().To4()...)
	case xnet.AddressFamilyIPv6:
		address = append([]byte{addressTypeIPv6}, destination.Address.IP().To16()...)
	case xnet.AddressFamilyDomain:
		domain := destination.Address.Domain()
		if len(domain) == 0 || len(domain) > 255 {
			return nil, errors.New("invalid ArtX destination domain length")
		}
		address = make([]byte, 2+len(domain))
		address[0] = addressTypeDomain
		address[1] = byte(len(domain))
		copy(address[2:], domain)
	default:
		return nil, errors.New("unsupported ArtX destination address family")
	}

	encoded := make([]byte, len(address)+2)
	copy(encoded, address)
	binary.BigEndian.PutUint16(encoded[len(address):], uint16(destination.Port))
	return encoded, nil
}

func decodeDestination(payload []byte, network xnet.Network) (xnet.Destination, error) {
	if len(payload) < 3 {
		return xnet.Destination{}, errors.New("truncated ArtX destination")
	}

	var address xnet.Address
	addressLength := 0
	switch payload[0] {
	case addressTypeIPv4:
		addressLength = 4
		if len(payload) != 1+addressLength+2 {
			return xnet.Destination{}, errors.New("invalid ArtX IPv4 destination length")
		}
		address = xnet.IPAddress(payload[1 : 1+addressLength])
	case addressTypeIPv6:
		addressLength = 16
		if len(payload) != 1+addressLength+2 {
			return xnet.Destination{}, errors.New("invalid ArtX IPv6 destination length")
		}
		address = xnet.IPAddress(payload[1 : 1+addressLength])
	case addressTypeDomain:
		addressLength = int(payload[1])
		if addressLength == 0 || len(payload) != 2+addressLength+2 {
			return xnet.Destination{}, errors.New("invalid ArtX domain destination length")
		}
		address = xnet.DomainAddress(string(payload[2 : 2+addressLength]))
		port := binary.BigEndian.Uint16(payload[2+addressLength:])
		if port == 0 {
			return xnet.Destination{}, errors.New("invalid ArtX destination port")
		}
		return xnet.Destination{Network: network, Address: address, Port: xnet.Port(port)}, nil
	default:
		return xnet.Destination{}, fmt.Errorf("unsupported ArtX address type 0x%02x", payload[0])
	}

	port := binary.BigEndian.Uint16(payload[1+addressLength:])
	if port == 0 {
		return xnet.Destination{}, errors.New("invalid ArtX destination port")
	}
	return xnet.Destination{Network: network, Address: address, Port: xnet.Port(port)}, nil
}

func validateFrame(frameType byte, streamID uint32, payloadLength int) error {
	return validateFrameForWire(1, frameType, streamID, payloadLength)
}

func validateFrameForWire(wireVersion uint32, frameType byte, streamID uint32, payloadLength int) error {
	if payloadLength > MaxFramePayload {
		return errors.New("ArtX frame payload is too large")
	}
	if frameType == FrameData && payloadLength > MaxDataPayload {
		return errors.New("ArtX DATA payload is too large")
	}
	if frameType == FrameDatagram && payloadLength > maxDatagramPayload+2 {
		return errors.New("ArtX DATAGRAM payload is too large")
	}
	switch frameType {
	case FrameSettings, FramePadding:
		if streamID != 0 {
			return errors.New("ArtX connection frame has a stream ID")
		}
	case FrameTCPSyn, FrameData, FrameFin, FrameRST, FrameUDPAssoc, FrameDatagram:
		if !validStreamID(wireVersion, streamID) {
			return errors.New("ArtX stream frame has an invalid stream ID")
		}
	case FrameWindowUpdate:
		if streamID != 0 && !validStreamID(wireVersion, streamID) {
			return errors.New("ArtX WINDOW_UPDATE has an invalid stream ID")
		}
	}
	return nil
}

func validStreamID(wireVersion, streamID uint32) bool {
	return streamID == ClientStreamID || wireVersion == 2 && streamID != 0 && streamID&1 == 1
}

func putUint24(destination []byte, value int) {
	destination[0] = byte(value >> 16)
	destination[1] = byte(value >> 8)
	destination[2] = byte(value)
}

func readUint24(source []byte) int {
	return int(source[0])<<16 | int(source[1])<<8 | int(source[2])
}
