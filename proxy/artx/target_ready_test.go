package artx

import (
	"context"
	"errors"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

func TestTargetReadyBarrierCancellationRejectsLateReady(t *testing.T) {
	destination := xnet.TCPDestination(xnet.DomainAddress("example.net"), 443)
	barrier := newTargetReadyBarrier(destination)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := barrier.Wait(ctx, time.Now().Add(time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v", err)
	}
	barrier.Observe(nil, destination)
	if len(barrier.result) != 0 {
		t.Fatal("late readiness changed a canceled barrier")
	}
}

func TestTargetReadyBarrierKeepsFirstOutboundFailure(t *testing.T) {
	destination := xnet.TCPDestination(xnet.DomainAddress("example.net"), 443)
	barrier := newTargetReadyBarrier(destination)
	want := errors.New("dial failed")
	barrier.SubmitError(want)
	barrier.Observe(nil, destination)

	if err := barrier.Wait(context.Background(), time.Now().Add(time.Second)); !errors.Is(err, want) {
		t.Fatalf("wait error = %v", err)
	}
}

func TestTargetReadyBarrierIgnoresInvalidDestination(t *testing.T) {
	destination := xnet.TCPDestination(xnet.DomainAddress("example.net"), 443)
	barrier := newTargetReadyBarrier(destination)
	barrier.Observe(nil, xnet.Destination{})

	deadline := time.Now().Add(20 * time.Millisecond)
	if err := barrier.Wait(context.Background(), deadline); !errors.Is(err, errTargetReadyTimeout) {
		t.Fatalf("wait error = %v", err)
	}
}
