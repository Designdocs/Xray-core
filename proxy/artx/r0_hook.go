package artx

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

const r0ServerPhaseSetup uint8 = 1

const (
	r0ServerEventConnectionStart uint8 = 1
	r0ServerEventTLSReady        uint8 = 2
	r0ServerEventOpenAccepted    uint8 = 3
	r0ServerEventDispatchReturn  uint8 = 4
	r0ServerEventTargetReady     uint8 = 5
	r0ServerEventPeerAccept      uint8 = 6
	r0ServerEventInnerExposed    uint8 = 7
	r0ServerEventPayloadUplink   uint8 = 8
	r0ServerEventPayloadDownlink uint8 = 9
	r0ServerEventClientFIN       uint8 = 10
	r0ServerEventTargetFIN       uint8 = 11
	r0ServerEventConnectionEnd   uint8 = 12
	r0ServerEventQueueOverflow   uint8 = 13
)

type r0ServerHook interface {
	Event(phase, kind, result uint8)
	IOEvent(phase, kind, result uint8, attempted, accepted int)
	Close()
}

func emitR0ServerEvent(hook r0ServerHook, kind, result uint8) {
	if hook != nil {
		hook.Event(r0ServerPhaseSetup, kind, result)
	}
}

func emitR0ServerIO(hook r0ServerHook, kind uint8, accepted int, err error) {
	if hook == nil {
		return
	}
	result := uint8(1)
	if err != nil {
		result = 2
	}
	hook.IOEvent(r0ServerPhaseSetup, kind, result, accepted, accepted)
}

func closeR0ServerHook(hook r0ServerHook) {
	if hook != nil {
		hook.Close()
	}
}

func contextWithR0TargetReady(ctx context.Context, hook r0ServerHook) context.Context {
	if hook == nil {
		return ctx
	}
	return session.ContextWithOutboundReadyObserver(ctx, func(net.Conn, xnet.Destination) {
		emitR0ServerEvent(hook, r0ServerEventTargetReady, 1)
	})
}

func observeR0ServerLink(link *transport.Link, hook r0ServerHook) *transport.Link {
	if hook == nil {
		return link
	}
	return &transport.Link{
		Reader: &r0ObservedBufferReader{reader: link.Reader, hook: hook},
		Writer: &r0ObservedBufferWriter{writer: link.Writer, hook: hook},
	}
}

type r0ObservedBufferWriter struct {
	writer buf.Writer
	hook   r0ServerHook
	fin    sync.Once
}

func (writer *r0ObservedBufferWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	accepted := int(buffers.Len())
	err := writer.writer.WriteMultiBuffer(buffers)
	emitR0ServerIO(writer.hook, r0ServerEventPayloadUplink, accepted, err)
	return err
}

func (writer *r0ObservedBufferWriter) Close() error {
	err := common.Close(writer.writer)
	if err == nil {
		writer.fin.Do(func() { emitR0ServerEvent(writer.hook, r0ServerEventClientFIN, 1) })
	}
	return err
}

func (writer *r0ObservedBufferWriter) Interrupt() {
	_ = common.Interrupt(writer.writer)
}

type r0ObservedBufferReader struct {
	reader buf.Reader
	hook   r0ServerHook
	fin    sync.Once
}

func (reader *r0ObservedBufferReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	buffers, err := reader.reader.ReadMultiBuffer()
	if size := int(buffers.Len()); size > 0 {
		emitR0ServerIO(reader.hook, r0ServerEventPayloadDownlink, size, nil)
	}
	if errors.Is(err, io.EOF) {
		reader.fin.Do(func() { emitR0ServerEvent(reader.hook, r0ServerEventTargetFIN, 1) })
	}
	return buffers, err
}

func (reader *r0ObservedBufferReader) Close() error {
	return common.Close(reader.reader)
}

func (reader *r0ObservedBufferReader) Interrupt() {
	_ = common.Interrupt(reader.reader)
}
