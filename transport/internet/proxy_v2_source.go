package internet

import (
	"context"
	"crypto/tls"
	"github.com/pires/go-proxyproto"
	"net"
	"net/netip"
)

type proxyConnKey struct{}

// ProxyConnContext retains the actual socket without reading a header on the HTTP accept loop.
func ProxyConnContext(ctx context.Context, c net.Conn) context.Context {
	if t, ok := c.(*tls.Conn); ok {
		c = t.NetConn()
	}
	if p, ok := c.(*proxyproto.Conn); ok {
		return context.WithValue(ctx, proxyConnKey{}, p)
	}
	return ctx
}

// ProxyV2Source returns the physical TCP peer and the independently reported source.
// Invoke after the transport has successfully read the request.
func ProxyV2Source(ctx context.Context) (peer, visitor netip.Addr, ok bool) {
	p, _ := ctx.Value(proxyConnKey{}).(*proxyproto.Conn)
	if p == nil {
		return
	}
	raw, ok := p.Raw().(*net.TCPConn)
	if !ok {
		return
	}
	h := p.ProxyHeader()
	if h == nil || h.Version != 2 || h.Command != proxyproto.PROXY || (h.TransportProtocol != proxyproto.TCPv4 && h.TransportProtocol != proxyproto.TCPv6) {
		return peer, visitor, false
	}
	src, ok := h.SourceAddr.(*net.TCPAddr)
	if !ok {
		return
	}
	return raw.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap(), src.AddrPort().Addr().Unmap(), true
}
