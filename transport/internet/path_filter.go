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
