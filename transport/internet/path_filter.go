package internet

import (
	"bytes"
	"context"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"io"
	"net"
	"net/http"
)

// WrongPathFilter is called only for requests that miss the configured transport path.
type WrongPathFilter func(*http.Request) bool
type filterFactoryKey struct{}

// WithWrongPathFilter installs a per-inbound filter factory for embedded servers.
func WithWrongPathFilter(ctx context.Context, factory func(string) WrongPathFilter) context.Context {
	return context.WithValue(ctx, filterFactoryKey{}, factory)
}

func PathFilter(ctx context.Context) WrongPathFilter {
	var filter WrongPathFilter
	if factory, ok := ctx.Value(filterFactoryKey{}).(func(string) WrongPathFilter); ok {
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			filter = factory(inbound.Tag)
		}
	}
	return filter
}

// RejectedStreamFilter inspects only stream handshakes already rejected by authentication.
type RejectedStreamFilter func(string, net.Conn, []byte, io.Reader) bool
type rejectedStreamKey struct{}

func WithRejectedStreamFilter(ctx context.Context, f RejectedStreamFilter) context.Context {
	return context.WithValue(ctx, rejectedStreamKey{}, f)
}

func RejectUnauthenticatedStream(ctx context.Context, conn net.Conn, prefix []byte, remaining io.Reader) bool {
	f, _ := ctx.Value(rejectedStreamKey{}).(RejectedStreamFilter)
	in := session.InboundFromContext(ctx)
	return f != nil && in != nil && f(in.Tag, conn, prefix, remaining)
}

type sensitiveFilterKey struct{}

func WithSensitivePathFilter(ctx context.Context, factory func(string) WrongPathFilter) context.Context {
	return context.WithValue(ctx, sensitiveFilterKey{}, factory)
}
func SensitivePathFilter(ctx context.Context) WrongPathFilter {
	f, _ := ctx.Value(sensitiveFilterKey{}).(func(string) WrongPathFilter)
	in := session.InboundFromContext(ctx)
	if f == nil || in == nil {
		return nil
	}
	return f(in.Tag)
}

// RejectBufferedStream preserves any extra bytes read for a subsequent website fallback.
func RejectBufferedStream(ctx context.Context, conn net.Conn, first *buf.Buffer, reader *buf.BufferedReader) bool {
	f, _ := ctx.Value(rejectedStreamKey{}).(RejectedStreamFilter)
	in := session.InboundFromContext(ctx)
	if f == nil || in == nil {
		return false
	}
	var extra bytes.Buffer
	if f(in.Tag, conn, first.Bytes(), io.TeeReader(conn, &extra)) {
		return true
	}
	if extra.Len() > 0 {
		reader.Reader = buf.NewReader(io.MultiReader(&extra, conn))
	}
	return false
}

type inboundListenerWrapperKey struct{}

func HasInboundListenerWrapper(ctx context.Context) bool {
	return ctx != nil && ctx.Value(inboundListenerWrapperKey{}) != nil
}

func WithInboundListenerWrapper(ctx context.Context, f func(string, net.Listener) (net.Listener, error)) context.Context {
	return context.WithValue(ctx, inboundListenerWrapperKey{}, f)
}
func wrapInboundListener(ctx context.Context, l net.Listener) (net.Listener, error) {
	f, ok := ctx.Value(inboundListenerWrapperKey{}).(func(string, net.Listener) (net.Listener, error))
	in := session.InboundFromContext(ctx)
	if !ok || in == nil || in.Tag == "" {
		return l, nil
	}
	return f(in.Tag, l)
}
