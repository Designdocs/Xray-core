package encoding

import (
	"context"
	"github.com/xtls/xray-core/common/buf"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingStream struct {
	ctx              context.Context
	entered, release chan struct{}
	active           atomic.Bool
	overlap          atomic.Bool
	closes           atomic.Int32
}

func (s *blockingStream) Context() context.Context { return s.ctx }
func (s *blockingStream) SendMsg(any) error        { return nil }
func (s *blockingStream) RecvMsg(any) error        { return io.EOF }
func (s *blockingStream) CloseSend() error {
	if s.active.Load() {
		s.overlap.Store(true)
	}
	s.closes.Add(1)
	return nil
}
func (s *blockingStream) send() error {
	s.active.Store(true)
	close(s.entered)
	<-s.ctx.Done()
	<-s.release
	s.active.Store(false)
	return s.ctx.Err()
}

type blockingHunk struct{ *blockingStream }

func (s blockingHunk) Send(*Hunk) error     { return s.send() }
func (s blockingHunk) Recv() (*Hunk, error) { return nil, io.EOF }

type blockingMulti struct{ *blockingStream }

func (s blockingMulti) Send(*MultiHunk) error     { return s.send() }
func (s blockingMulti) Recv() (*MultiHunk, error) { return nil, io.EOF }

func TestCloseCancelsSendBeforeClosingGRPCStream(t *testing.T) {
	for _, multi := range []bool{false, true} {
		name := "hunk"
		if multi {
			name = "multi-hunk"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base := &blockingStream{ctx: ctx, entered: make(chan struct{}), release: make(chan struct{})}
			var closeStream func() error
			var send func() error
			if multi {
				conn := NewMultiHunkReadWriter(blockingMulti{base}, cancel)
				closeStream = conn.Close
				send = func() error { return conn.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("pending"))}) }
			} else {
				conn := NewHunkReadWriter(blockingHunk{base}, cancel)
				closeStream = conn.Close
				send = func() error { _, err := conn.Write([]byte("pending")); return err }
			}
			sent := make(chan error, 1)
			go func() { sent <- send() }()
			<-base.entered
			closed := make(chan error, 1)
			go func() { closed <- closeStream() }()
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("close did not cancel the blocked send")
			}
			// The sender remains blocked even after cancellation until released.
			time.Sleep(10 * time.Millisecond)
			early := base.closes.Load() != 0
			close(base.release)
			select {
			case <-sent:
			case <-time.After(time.Second):
				t.Fatal("send stayed blocked")
			}
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("close stayed blocked")
			}
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() { closeStream() })
			}
			wg.Wait()
			if early || base.overlap.Load() {
				t.Fatal("CloseSend overlapped an active Send")
			}
			if base.closes.Load() != 1 {
				t.Fatalf("CloseSend calls=%d, want 1", base.closes.Load())
			}
			if err := send(); err == nil {
				t.Fatal("write after close succeeded")
			}
		})
	}
}
