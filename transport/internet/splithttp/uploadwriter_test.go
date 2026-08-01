package splithttp

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// WriteMultiBuffer hands the buffer to the pipe, and on the xhttp upload path a
// poster goroutine picks it up, drains it and releases it immediately. Anything
// uploadWriter still wants to know about that buffer has to be read first.
//
// Reading it afterwards is not only a data race: a drained buffer reports a
// length of zero, so Write undercounts and returns a short write to a caller
// that has every right to treat that as an error.
func TestUploadWriterReportsEverythingItWrote(t *testing.T) {
	const payloadSize = 3 * buf.Size

	reader, writer := pipe.New(pipe.WithSizeLimit(payloadSize))
	uploader := uploadWriter{Writer: writer, maxLen: buf.Size}

	payload := bytes.Repeat([]byte("N2X"), payloadSize/3)

	var received bytes.Buffer
	var drained sync.WaitGroup
	drained.Add(1)
	go func() {
		defer drained.Done()
		for {
			multiBuffer, err := reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			for _, buffer := range multiBuffer {
				_, _ = received.Write(buffer.Bytes())
				buffer.Release()
			}
			if received.Len() >= len(payload) {
				return
			}
		}
	}()

	written, err := uploader.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if written != len(payload) {
		t.Fatalf("Write() = %d, want %d — a short write makes io.Copy fail with %v",
			written, len(payload), io.ErrShortWrite)
	}

	drained.Wait()
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("the pipe delivered %d bytes, want %d", received.Len(), len(payload))
	}
}
