package internet

import (
	"context"
	"github.com/xtls/xray-core/common/session"
	"net/http"
)

// WrongPathFilter is called only for requests that miss the configured transport path.
type WrongPathFilter func(*http.Request) bool
type filterFactoryKey struct{}

// WithWrongPathFilter installs a per-inbound filter factory for embedded servers.
func WithWrongPathFilter(ctx context.Context, factory func(string, bool) WrongPathFilter) context.Context {
	return context.WithValue(ctx, filterFactoryKey{}, factory)
}

func PathFilter(ctx context.Context, streamSettings *MemoryStreamConfig) WrongPathFilter {
	var filter WrongPathFilter
	if factory, ok := ctx.Value(filterFactoryKey{}).(func(string, bool) WrongPathFilter); ok {
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			filter = factory(inbound.Tag, streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol)
		}
	}
	return filter
}
