package artx

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

const (
	wireV4TargetReadyWait   = 9 * time.Second
	wireV4RefusalWriteGrace = time.Second
)

var errTargetReadyTimeout = errors.New("artx: target readiness timeout")

type targetReadyBarrier struct {
	expected xnet.Destination
	once     sync.Once
	result   chan error
}

func newTargetReadyBarrier(expected xnet.Destination) *targetReadyBarrier {
	return &targetReadyBarrier{
		expected: expected,
		result:   make(chan error, 1),
	}
}

func contextWithTargetReadyBarrier(ctx context.Context, barrier *targetReadyBarrier) context.Context {
	ctx = session.TrackedConnectionError(ctx, barrier)
	return session.ContextWithOutboundReadyObserver(ctx, barrier.Observe)
}

func (barrier *targetReadyBarrier) Observe(_ net.Conn, destination xnet.Destination) {
	if !sameTargetDestination(barrier.expected, destination) {
		return
	}
	barrier.resolve(nil)
}

func (barrier *targetReadyBarrier) SubmitError(err error) {
	if err != nil {
		barrier.resolve(err)
	}
}

func (barrier *targetReadyBarrier) Wait(ctx context.Context, deadline time.Time) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case result := <-barrier.result:
		return result
	case <-ctx.Done():
		barrier.resolve(ctx.Err())
		return <-barrier.result
	case <-timer.C:
		barrier.resolve(errTargetReadyTimeout)
		return <-barrier.result
	}
}

func (barrier *targetReadyBarrier) resolve(result error) {
	barrier.once.Do(func() { barrier.result <- result })
}

func sameTargetDestination(expected, actual xnet.Destination) bool {
	if expected.Address == nil || actual.Address == nil {
		return false
	}
	return expected.Network == actual.Network && expected.Port == actual.Port && expected.Address.String() == actual.Address.String()
}

func interruptTargetReadyLink(link *transport.Link) {
	if link == nil {
		return
	}
	_ = common.Interrupt(link.Reader)
	_ = common.Interrupt(link.Writer)
}
