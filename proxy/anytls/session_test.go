package anytls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func appendTestFrame(dst []byte, cmd byte, sid uint32, data string) []byte {
	var header [7]byte
	header[0] = cmd
	binary.BigEndian.PutUint32(header[1:5], sid)
	binary.BigEndian.PutUint16(header[5:7], uint16(len(data)))
	dst = append(dst, header[:]...)
	return append(dst, data...)
}

func TestLateStreamDataPreservesSession(t *testing.T) {
	for _, closedWriter := range []bool{false, true} {
		name := "removed stream"
		if closedWriter {
			name = "closed outbound writer"
		}
		t.Run(name, func(t *testing.T) {
			// A peer can still be sending (for example TLS close_notify) when
			// the outbound finishes. Its next stream must remain usable.
			input := appendTestFrame(nil, cmdPSH, 1, "late data")
			input = appendTestFrame(input, cmdPSH, 2, "healthy stream")
			input = appendTestFrame(input, cmdHeartRequest, 0, "")
			var output bytes.Buffer
			bw := buf.NewBufferedWriter(buf.NewWriter(&output))
			s := &session{
				br:      &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(input))},
				fw:      newFrameWriter(bw),
				streams: make(map[uint32]*stream),
			}
			reader, writer := pipe.New(pipe.WithoutSizeLimit())
			defer reader.Interrupt()
			defer writer.Close()
			s.streams[2] = &stream{sid: 2, link: &transport.Link{Reader: reader, Writer: writer}}
			if closedWriter {
				closedReader, closed := pipe.New(pipe.WithoutSizeLimit())
				defer closedReader.Interrupt()
				closed.Close()
				s.streams[1] = &stream{sid: 1, link: &transport.Link{Reader: closedReader, Writer: closed}}
			}
			if err := s.readLoop(context.Background()); !errors.Is(err, io.EOF) {
				t.Fatalf("session stopped before consuming all frames: %v", err)
			}
			if _, ok := s.streams[1]; ok {
				t.Fatal("closed stream was retained")
			}
			if _, ok := s.streams[2]; !ok {
				t.Fatal("unrelated stream was closed")
			}
			data, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatal(err)
			}
			defer buf.ReleaseMulti(data)
			if got := data.String(); got != "healthy stream" {
				t.Fatalf("unrelated stream payload = %q", got)
			}
			var want []byte
			if closedWriter {
				want = appendTestFrame(want, cmdFIN, 1, "")
			}
			want = appendTestFrame(want, cmdHeartResponse, 0, "")
			if !bytes.Equal(output.Bytes(), want) {
				t.Fatalf("session responses = %x, want %x", output.Bytes(), want)
			}
		})
	}
}
