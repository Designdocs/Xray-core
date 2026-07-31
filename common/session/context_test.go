package session

import (
	"context"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestOutboundReadyObserversRunSynchronouslyInInstallationOrder(t *testing.T) {
	var order []int
	ctx := ContextWithOutboundReadyObserver(context.Background(), func(_ net.Conn, _ net.Destination) {
		order = append(order, 1)
	})
	ctx = ContextWithOutboundReadyObserver(ctx, func(_ net.Conn, _ net.Destination) {
		order = append(order, 2)
	})

	NotifyOutboundReady(ctx, nil, net.TCPDestination(net.DomainAddress("example.net"), 443))
	if !reflect.DeepEqual(order, []int{1, 2}) {
		t.Fatalf("observer order = %v", order)
	}
}
