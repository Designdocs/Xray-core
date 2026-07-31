//go:build !artxr0 || !linux

package artx

import "github.com/xtls/xray-core/transport/internet/stat"

func newR0ServerHook(stat.Connection, uint32) r0ServerHook { return nil }
