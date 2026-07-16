package artx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

type reusableFrameResult struct {
	frame Frame
	err   error
}

type directRelayConnection struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newDirectRelayConnection() *directRelayConnection {
	return &directRelayConnection{closed: make(chan struct{})}
}

func (connection *directRelayConnection) Read([]byte) (int, error) {
	<-connection.closed
	return 0, io.EOF
}

func (connection *directRelayConnection) Write([]byte) (int, error) {
	return 0, net.ErrClosed
}

func (connection *directRelayConnection) Close() error {
	connection.closeOnce.Do(func() { close(connection.closed) })
	return nil
}

func (connection *directRelayConnection) readFrame(ctx context.Context, frames <-chan reusableFrameResult) (Frame, error) {
	select {
	case <-ctx.Done():
		return Frame{}, ctx.Err()
	case <-connection.closed:
		return Frame{}, io.EOF
	case result, ok := <-frames:
		if !ok {
			return Frame{}, io.EOF
		}
		return result.frame, result.err
	}
}

func (s *Server) processReusableSession(ctx context.Context, connection net.Conn, dispatcher routing.Dispatcher) error {
	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	defer connection.Close()
	frames := make(chan reusableFrameResult, 4)
	go readReusableFrames(readerCtx, connection, frames)

	nextStreamID := ClientStreamID
	previousStreamID := uint32(0)
	var pendingOpen *Frame
	for {
		var open Frame
		var err error
		if pendingOpen != nil {
			open, pendingOpen = *pendingOpen, nil
		} else {
			open, err = nextReusableOpen(ctx, frames, previousStreamID)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if open.StreamID != nextStreamID {
			return errors.New("artx: reusable stream ID is not the next odd ID")
		}

		writer := &lockedFrameWriter{writer: connection, wireVersion: 2, streamID: open.StreamID}
		relayDone := make(chan error, 1)
		var bridge net.Conn
		var directFrames chan reusableFrameResult
		switch open.Type {
		case FrameTCPSyn:
			destination, err := DecodeTCPDestination(open.Payload)
			if err != nil {
				return err
			}
			link, err := dispatcher.Dispatch(ctx, destination)
			if err != nil {
				return err
			}
			directFrames = make(chan reusableFrameResult, 4)
			relayConnection := newDirectRelayConnection()
			go func() {
				relayDone <- relaySingleStreamFrames(ctx, relayConnection, writer, link, func() (Frame, error) {
					return relayConnection.readFrame(ctx, directFrames)
				})
			}()
		case FrameUDPAssoc:
			if !s.udpEnabled {
				return errors.New("artx: UDP is disabled")
			}
			destination, err := DecodeUDPDestination(open.Payload)
			if err != nil {
				return err
			}
			sessionSide, relaySide := net.Pipe()
			bridge = sessionSide
			go func(destination xnet.Destination) {
				relayDone <- relayUDPAssociation(ctx, relaySide, writer, dispatcher, destination)
			}(destination)
		default:
			return errors.New("artx: reusable stream must open with TCP_SYN or UDP_ASSOC")
		}

		pendingOpen, err = forwardReusableStream(ctx, frames, bridge, directFrames, open.StreamID, relayDone)
		if err != nil {
			return err
		}
		previousStreamID = open.StreamID
		if nextStreamID > ^uint32(0)-2 {
			return nil
		}
		nextStreamID += 2
	}
}

func readReusableFrames(ctx context.Context, connection io.Reader, results chan<- reusableFrameResult) {
	defer close(results)
	for {
		frame, err := readFrame(connection, 2)
		select {
		case results <- reusableFrameResult{frame: frame, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func nextReusableOpen(ctx context.Context, frames <-chan reusableFrameResult, previousStreamID uint32) (Frame, error) {
	for {
		select {
		case <-ctx.Done():
			return Frame{}, ctx.Err()
		case result, ok := <-frames:
			if !ok {
				return Frame{}, io.EOF
			}
			if result.err != nil {
				return Frame{}, result.err
			}
			if result.frame.StreamID == 0 && (result.frame.Type == FramePadding || result.frame.Type == FrameWindowUpdate) {
				continue
			}
			if previousStreamID != 0 && result.frame.Type == FrameWindowUpdate && result.frame.StreamID == previousStreamID {
				continue
			}
			if result.frame.Type != FrameTCPSyn && result.frame.Type != FrameUDPAssoc {
				return Frame{}, errors.New("artx: reusable session requires a stream open frame")
			}
			return result.frame, nil
		}
	}
}

func forwardReusableStream(ctx context.Context, frames <-chan reusableFrameResult, bridge net.Conn, directFrames chan reusableFrameResult, streamID uint32, relayDone <-chan error) (*Frame, error) {
	if bridge != nil {
		defer bridge.Close()
	}
	if directFrames != nil {
		defer close(directFrames)
	}
	clientDone := false
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-relayDone:
			return nil, err
		case result, ok := <-frames:
			if !ok {
				if clientDone {
					return nil, <-relayDone
				}
				return nil, io.EOF
			}
			if result.err != nil {
				if clientDone && errors.Is(result.err, io.EOF) {
					return nil, <-relayDone
				}
				return nil, result.err
			}
			frame := result.frame
			if frame.Type == FramePadding && frame.StreamID == 0 {
				continue
			}
			if frame.StreamID != 0 && frame.StreamID != streamID {
				if frame.StreamID == streamID+2 && (frame.Type == FrameTCPSyn || frame.Type == FrameUDPAssoc) {
					return &frame, <-relayDone
				}
				return nil, fmt.Errorf("artx: frame for inactive reusable stream %d (active %d)", frame.StreamID, streamID)
			}
			if frame.StreamID != 0 {
				frame.StreamID = ClientStreamID
			}
			if frame.Type == FrameFin || frame.Type == FrameRST {
				clientDone = true
			}
			if directFrames != nil {
				select {
				case directFrames <- reusableFrameResult{frame: frame}:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				case err := <-relayDone:
					return nil, err
				}
			}
			encoded, err := frame.MarshalBinary()
			if err != nil {
				return nil, err
			}
			if err := writeAll(bridge, encoded); err != nil {
				select {
				case relayErr := <-relayDone:
					return nil, relayErr
				default:
					return nil, err
				}
			}
		}
	}
}
