//go:build artxr0 && linux

package artx

import (
	"net"
	"sync"
	"testing"
)

func TestCloseWireV4HijackedConnectionSamplesTCPInfoBeforeClose(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}

	sink := &r0ServerEventSink{queue: make(chan r0ServerWireEvent, 1)}
	hook := &r0ServerHookSession{raw: server, sink: sink, connection: 1}
	closeWireV4HijackedConnection(hook, server)

	event := <-sink.queue
	if event.Kind != r0ServerEventConnectionEnd {
		t.Fatalf("event kind = %d, want connection end", event.Kind)
	}
	if event.TCPInfoValid != 1 {
		t.Fatal("connection end must sample TCP_INFO before the hijacked connection closes")
	}
}

func TestR0ServerHookSerializesEventsAndClosesLast(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	sink := &r0ServerEventSink{queue: make(chan r0ServerWireEvent, 64)}
	hook := &r0ServerHookSession{raw: client, sink: sink, connection: 7}
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			hook.emit(r0ServerPhaseSetup, r0ServerEventPayloadUplink, 1, 1, 1)
		}()
	}
	workers.Wait()
	hook.Close()
	hook.emit(r0ServerPhaseSetup, r0ServerEventPayloadUplink, 1, 1, 1)
	if got := len(sink.queue); got != 33 {
		t.Fatalf("queued events = %d, want 33", got)
	}
	for wantSequence := uint64(1); wantSequence <= 33; wantSequence++ {
		event := <-sink.queue
		if event.Sequence != wantSequence {
			t.Fatalf("event sequence = %d, want %d", event.Sequence, wantSequence)
		}
		if wantSequence == 33 && event.Kind != r0ServerEventConnectionEnd {
			t.Fatalf("final event kind = %d, want connection end", event.Kind)
		}
	}
}
