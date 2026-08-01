package splithttp

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

type trackedReadCloser struct {
	io.Reader
	closed atomic.Bool
}

func newTrackedReadCloser(payload string) *trackedReadCloser {
	return &trackedReadCloser{Reader: bytes.NewReader([]byte(payload))}
}

func (r *trackedReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

// The stream-down body arrives on a separate goroutine, so Set always races
// with a Read that is already waiting for it. Read must reach the body only
// through the Wait channel: the interface value is two words, and a torn read
// of it is a crash rather than a stale answer.
func TestWaitReadCloserSetRacesWithRead(t *testing.T) {
	for range 200 {
		waiter := &WaitReadCloser{Wait: make(chan struct{})}
		body := newTrackedReadCloser("payload")

		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			waiter.Set(body)
		}()
		go func() {
			defer group.Done()
			buffer := make([]byte, len("payload"))
			if _, err := io.ReadFull(waiter, buffer); err != nil {
				t.Errorf("Read() error = %v", err)
				return
			}
			if string(buffer) != "payload" {
				t.Errorf("Read() = %q, want %q", buffer, "payload")
			}
		}()
		group.Wait()
	}
}

// Close is what runs when the dialer gives up, and it can land at any point
// relative to the response arriving.
func TestWaitReadCloserSetRacesWithClose(t *testing.T) {
	for range 200 {
		waiter := &WaitReadCloser{Wait: make(chan struct{})}
		body := newTrackedReadCloser("payload")

		var group sync.WaitGroup
		group.Add(2)
		go func() {
			defer group.Done()
			waiter.Set(body)
		}()
		go func() {
			defer group.Done()
			if err := waiter.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		}()
		group.Wait()

		// Whichever order they landed in, the body must not be left open: Set
		// hands it over to a Close that already ran, or Close finds it there.
		if !body.closed.Load() {
			t.Fatal("the response body was leaked")
		}
	}
}

func TestWaitReadCloserSetThenRead(t *testing.T) {
	waiter := &WaitReadCloser{Wait: make(chan struct{})}
	waiter.Set(newTrackedReadCloser("payload"))

	buffer := make([]byte, len("payload"))
	if _, err := io.ReadFull(waiter, buffer); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if string(buffer) != "payload" {
		t.Fatalf("Read() = %q, want %q", buffer, "payload")
	}
}

func TestWaitReadCloserCloseThenRead(t *testing.T) {
	waiter := &WaitReadCloser{Wait: make(chan struct{})}
	if err := waiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if _, err := waiter.Read(make([]byte, 8)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read() error = %v, want %v", err, io.ErrClosedPipe)
	}
}

func TestWaitReadCloserCloseAfterSetClosesTheBody(t *testing.T) {
	waiter := &WaitReadCloser{Wait: make(chan struct{})}
	body := newTrackedReadCloser("payload")
	waiter.Set(body)

	if err := waiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("Close() left the response body open")
	}
}

// A response that arrives after the caller gave up has no reader left, so Set
// owns it and must close it rather than publish it.
func TestWaitReadCloserSetAfterCloseClosesTheBody(t *testing.T) {
	waiter := &WaitReadCloser{Wait: make(chan struct{})}
	if err := waiter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	body := newTrackedReadCloser("payload")
	waiter.Set(body)

	if !body.closed.Load() {
		t.Fatal("Set() after Close() leaked the response body")
	}
	if _, err := waiter.Read(make([]byte, 8)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read() error = %v, want %v", err, io.ErrClosedPipe)
	}
}

func TestWaitReadCloserCloseIsIdempotent(t *testing.T) {
	waiter := &WaitReadCloser{Wait: make(chan struct{})}
	body := newTrackedReadCloser("payload")
	waiter.Set(body)

	for range 3 {
		if err := waiter.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}

func TestWaitReadCloserConcurrentCloses(t *testing.T) {
	for range 200 {
		waiter := &WaitReadCloser{Wait: make(chan struct{})}
		waiter.Set(newTrackedReadCloser("payload"))

		var group sync.WaitGroup
		for range 4 {
			group.Add(1)
			go func() {
				defer group.Done()
				if err := waiter.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			}()
		}
		group.Wait()
	}
}
