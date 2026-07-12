package artx

import (
	"errors"
	"strings"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

type MemoryAccount struct {
	PSK string
}

func (a *Account) AsAccount() (protocol.Account, error) {
	if strings.TrimSpace(a.Psk) == "" {
		return nil, errors.New("ArtX PSK is empty")
	}
	return &MemoryAccount{PSK: a.Psk}, nil
}

func (m *MemoryAccount) Equals(another protocol.Account) bool {
	other, ok := another.(*MemoryAccount)
	return ok && m.PSK == other.PSK
}

func (m *MemoryAccount) ToProto() proto.Message {
	return &Account{Psk: m.PSK}
}
