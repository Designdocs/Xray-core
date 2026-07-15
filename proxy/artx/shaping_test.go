package artx

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestServerSettingsFlightCanonicalVectors(t *testing.T) {
	tests := []struct {
		name       string
		salt       []byte
		wantShape  settingsFlightTemplate
		wantChunks []int
		wantHex    string
	}{
		{
			name:       "greased settings",
			salt:       []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantShape:  settingsFlightGreased,
			wantChunks: []int{21, 17},
			wantHex:    "020000000000001e0001000000010002000400000003001000000005000000020a0ad7ba73e7",
		},
		{
			name:       "settings and padding",
			salt:       []byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantShape:  settingsFlightPadded,
			wantChunks: []int{45, 9},
			wantHex:    "0200000000000018000100000001000200040000000300100000000500000002200000000000000efac323858f32cb6dd99c86d3d3f9",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flight, err := newServerSettingsFlight(2, []byte("test-psk"), test.salt)
			if err != nil {
				t.Fatal(err)
			}
			if flight.targetStartGap != 0 {
				t.Fatalf("profile v2 target gap = %s, want 0", flight.targetStartGap)
			}
			if flight.template != test.wantShape {
				t.Fatalf("template = %d, want %d", flight.template, test.wantShape)
			}
			if got := chunkLengths(flight.chunks); !equalInts(got, test.wantChunks) {
				t.Fatalf("chunk lengths = %v, want %v", got, test.wantChunks)
			}
			want, err := hex.DecodeString(test.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Join(flight.chunks, nil); !bytes.Equal(got, want) {
				t.Fatalf("flight = %x, want %x", got, want)
			}
			assertSettingsFlightDecodes(t, flight, profileVersionEarlyRecordShaping)
		})
	}
}

func TestProfileV3SettingsFlightCanonicalVectors(t *testing.T) {
	tests := []struct {
		name       string
		salt       []byte
		wantShape  settingsFlightTemplate
		wantGap    time.Duration
		wantChunks []int
		wantHex    string
	}{
		{
			name:       "greased settings",
			salt:       []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantShape:  settingsFlightGreased,
			wantGap:    30 * time.Microsecond,
			wantChunks: []int{21, 17},
			wantHex:    "020000000000001e0001000000010002000400000003001000000005000000030a0ad7ba73e7",
		},
		{
			name:       "settings and padding",
			salt:       []byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantShape:  settingsFlightPadded,
			wantGap:    44 * time.Microsecond,
			wantChunks: []int{45, 9},
			wantHex:    "0200000000000018000100000001000200040000000300100000000500000003200000000000000efac323858f32cb6dd99c86d3d3f9",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flight, err := newServerSettingsFlight(profileVersionTimedRecordShaping, []byte("test-psk"), test.salt)
			if err != nil {
				t.Fatal(err)
			}
			if flight.template != test.wantShape || flight.targetStartGap != test.wantGap {
				t.Fatalf("template/gap = %d/%s, want %d/%s", flight.template, flight.targetStartGap, test.wantShape, test.wantGap)
			}
			if got := chunkLengths(flight.chunks); !equalInts(got, test.wantChunks) {
				t.Fatalf("chunk lengths = %v, want %v", got, test.wantChunks)
			}
			want, err := hex.DecodeString(test.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Join(flight.chunks, nil); !bytes.Equal(got, want) {
				t.Fatalf("flight = %x, want %x", got, want)
			}
			assertSettingsFlightDecodes(t, flight, profileVersionTimedRecordShaping)
		})
	}
}

func TestSettingsTemplateSelectionUsesRejectionSampling(t *testing.T) {
	tests := []struct {
		input []byte
		want  settingsFlightTemplate
	}{
		{input: []byte{0}, want: settingsFlightGreased},
		{input: []byte{1}, want: settingsFlightGreased},
		{input: []byte{2}, want: settingsFlightPadded},
		{input: []byte{255, 2}, want: settingsFlightPadded},
	}
	for _, test := range tests {
		got, err := selectSettingsFlightTemplate(bytes.NewReader(test.input))
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("selection for %v = %d, want %d", test.input, got, test.want)
		}
	}
}

func TestSettingsGapCDFBoundaries(t *testing.T) {
	t.Run("greased", func(t *testing.T) {
		assertGapSample(t, settingsFlightGreased, 0, 30*time.Microsecond)
		assertGapSample(t, settingsFlightGreased, 32767, 30*time.Microsecond)
		assertGapSample(t, settingsFlightGreased, 32768, 49*time.Microsecond)
		assertGapSample(t, settingsFlightGreased, 65535, 49*time.Microsecond)
	})

	t.Run("padded", func(t *testing.T) {
		targets := []int{
			27, 32, 35, 38, 39, 42, 44, 46, 48, 50, 55, 62, 67, 74, 83, 92, 108, 132, 192,
		}
		var firstSample uint32
		for index, targetMicroseconds := range targets {
			weight := uint32(3449)
			if index >= 14 {
				weight = 3450
			}
			lastSample := firstSample + weight - 1
			target := time.Duration(targetMicroseconds) * time.Microsecond
			assertGapSample(t, settingsFlightPadded, uint16(firstSample), target)
			assertGapSample(t, settingsFlightPadded, uint16(lastSample), target)
			firstSample = lastSample + 1
		}
		if firstSample != 65536 {
			t.Fatalf("CDF covers %d samples, want 65536", firstSample)
		}
	})
}

func assertGapSample(t *testing.T, template settingsFlightTemplate, sample uint16, want time.Duration) {
	t.Helper()
	encoded := []byte{byte(sample >> 8), byte(sample)}
	got, err := selectSettingsFlightGap(template, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("template %d sample %d gap = %s, want %s", template, sample, got, want)
	}
}

func TestProfileV1SettingsFlightIsUnchanged(t *testing.T) {
	flight, err := newServerSettingsFlight(1, []byte("test-psk"), bytes.Repeat([]byte{1}, MinSaltLength))
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0200000000000018000100000001000200040000000300100000000500000001")
	if err != nil {
		t.Fatal(err)
	}
	if len(flight.chunks) != 1 || !bytes.Equal(flight.chunks[0], want) {
		t.Fatalf("profile v1 flight = %x, want one chunk %x", bytes.Join(flight.chunks, nil), want)
	}
	if flight.targetStartGap != 0 {
		t.Fatalf("profile v1 target gap = %s, want 0", flight.targetStartGap)
	}
}

func TestServerSettingsFlightIsDeterministicAndConnectionLocal(t *testing.T) {
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	want, err := newServerSettingsFlight(2, []byte("test-psk"), salt)
	if err != nil {
		t.Fatal(err)
	}
	wantBytes := bytes.Join(want.chunks, nil)

	var wait sync.WaitGroup
	errorsFound := make(chan error, 64)
	for range 64 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, err := newServerSettingsFlight(2, []byte("test-psk"), salt)
			if err != nil {
				errorsFound <- err
				return
			}
			if !bytes.Equal(bytes.Join(got.chunks, nil), wantBytes) {
				errorsFound <- errors.New("non-deterministic settings flight")
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}

	different, err := newServerSettingsFlight(2, []byte("different-psk"), salt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bytes.Join(different.chunks, nil), wantBytes) {
		t.Fatal("different PSK produced the same shaped flight")
	}
}

func TestLockedFrameWriterWritesChunksFully(t *testing.T) {
	target := &limitedWriter{limit: 3}
	writer := &lockedFrameWriter{writer: target}
	if err := writer.writeChunks([]byte("12345"), []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if got, want := target.String(), "12345abcdef"; got != want {
		t.Fatalf("written bytes = %q, want %q", got, want)
	}

	zero := &lockedFrameWriter{writer: zeroWriter{}}
	if err := zero.writeChunks([]byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress error = %v, want io.ErrShortWrite", err)
	}
	wantErr := errors.New("write failed")
	failing := &lockedFrameWriter{writer: errorWriter{err: wantErr}}
	if err := failing.writeChunks([]byte("x")); !errors.Is(err, wantErr) {
		t.Fatalf("write error = %v, want %v", err, wantErr)
	}
}

func TestProfileV3SettingsWriterUsesAbsoluteDeadline(t *testing.T) {
	base := time.Unix(100, 0)
	clock := base
	targetGap := 49 * time.Microsecond
	target := &timedWriter{now: &clock, advances: []time.Duration{10 * time.Microsecond}}
	waitedFor := time.Time{}
	waiter := func(_ context.Context, deadline time.Time) error {
		waitedFor = deadline
		if clock.Before(deadline) {
			clock = deadline
		}
		return nil
	}
	writer := &lockedFrameWriter{writer: target}
	if err := writer.writeChunksWithGap(context.Background(), [][]byte{[]byte("first"), []byte("second")}, targetGap, func() time.Time { return clock }, waiter); err != nil {
		t.Fatal(err)
	}
	if want := base.Add(targetGap); !waitedFor.Equal(want) {
		t.Fatalf("deadline = %s, want %s", waitedFor, want)
	}
	if len(target.starts) != 2 || !target.starts[0].Equal(base) || !target.starts[1].Equal(base.Add(targetGap)) {
		t.Fatalf("write starts = %v, want [%s %s]", target.starts, base, base.Add(targetGap))
	}
}

func TestProfileV3SettingsWriterCancellationAndShortWrite(t *testing.T) {
	t.Run("cancelled wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		target := &timedWriter{}
		writer := &lockedFrameWriter{writer: target}
		err := writer.writeChunksWithGap(ctx, [][]byte{[]byte("first"), []byte("second")}, 30*time.Microsecond, time.Now, waitForSettingsDeadline)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if len(target.starts) != 1 {
			t.Fatalf("writes = %d, want only the first chunk", len(target.starts))
		}
	})

	t.Run("zero progress", func(t *testing.T) {
		waited := false
		writer := &lockedFrameWriter{writer: zeroWriter{}}
		err := writer.writeChunksWithGap(context.Background(), [][]byte{[]byte("first"), []byte("second")}, 30*time.Microsecond, time.Now, func(context.Context, time.Time) error {
			waited = true
			return nil
		})
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("error = %v, want io.ErrShortWrite", err)
		}
		if waited {
			t.Fatal("waited after the first chunk failed")
		}
	})
}

func TestNonNegativeDuration(t *testing.T) {
	now := time.Unix(100, 0)
	if got := nonNegativeDuration(now, now.Add(-time.Microsecond)); got != 0 {
		t.Fatalf("past deadline wait = %s, want 0", got)
	}
	if got := nonNegativeDuration(now, now); got != 0 {
		t.Fatalf("current deadline wait = %s, want 0", got)
	}
	if got := nonNegativeDuration(now, now.Add(30*time.Microsecond)); got != 30*time.Microsecond {
		t.Fatalf("future deadline wait = %s, want 30us", got)
	}
}

func TestProfileV2AndV3TLSRecordLengths(t *testing.T) {
	tests := []struct {
		name        string
		profile     uint32
		salt        []byte
		wantLengths []int
	}{
		{name: "v2 greased settings", profile: 2, salt: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, wantLengths: []int{38, 34}},
		{name: "v2 settings and padding", profile: 2, salt: []byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, wantLengths: []int{62, 26}},
		{name: "v3 greased settings", profile: 3, salt: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, wantLengths: []int{38, 34}},
		{name: "v3 settings and padding", profile: 3, salt: []byte{4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, wantLengths: []int{62, 26}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flight, err := newServerSettingsFlight(test.profile, []byte("test-psk"), test.salt)
			if err != nil {
				t.Fatal(err)
			}
			got := captureTLSRecordLengths(t, flight)
			if !equalInts(got, test.wantLengths) {
				t.Fatalf("TLS record lengths = %v, want %v", got, test.wantLengths)
			}
		})
	}
}

func assertSettingsFlightDecodes(t *testing.T, flight serverSettingsFlight, profileVersion uint32) {
	t.Helper()
	reader := bytes.NewReader(bytes.Join(flight.chunks, nil))
	settingsFrame, err := ReadFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := DecodeSettings(settingsFrame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePeerSettings(settings, profileVersion); err != nil {
		t.Fatal(err)
	}
	if flight.template == settingsFlightPadded {
		padding, err := ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if padding.Type != FramePadding || len(padding.Payload) != 14 {
			t.Fatalf("padding frame = %#v", padding)
		}
	}
	if reader.Len() != 0 {
		t.Fatalf("settings flight left %d unread bytes", reader.Len())
	}
}

type timedWriter struct {
	now      *time.Time
	starts   []time.Time
	advances []time.Duration
}

func (writer *timedWriter) Write(payload []byte) (int, error) {
	if writer.now == nil {
		now := time.Time{}
		writer.now = &now
	}
	writer.starts = append(writer.starts, *writer.now)
	index := len(writer.starts) - 1
	if index < len(writer.advances) {
		*writer.now = writer.now.Add(writer.advances[index])
	}
	return len(payload), nil
}

func captureTLSRecordLengths(t *testing.T, flight serverSettingsFlight) []int {
	t.Helper()
	certificatePEM, keyPEM := testCertificate(t)
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	recorded := &recordingConn{Conn: serverRaw}
	server := tls.Server(recorded, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	client := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	t.Cleanup(func() { _ = clientRaw.Close(); _ = serverRaw.Close() })
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- client.Handshake() }()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshakeDone; err != nil {
		t.Fatal(err)
	}
	offset := recorded.size()
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(client, make([]byte, len(bytes.Join(flight.chunks, nil))))
		readDone <- err
	}()
	writer := &lockedFrameWriter{writer: server}
	if err := writer.writeChunks(flight.chunks...); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	return tlsRecordLengths(t, recorded.bytesAfter(offset))
}

func tlsRecordLengths(t *testing.T, payload []byte) []int {
	t.Helper()
	lengths := make([]int, 0, 2)
	for len(payload) > 0 {
		if len(payload) < 5 {
			t.Fatalf("truncated TLS record header: %x", payload)
		}
		length := int(binary.BigEndian.Uint16(payload[3:5]))
		if len(payload) < 5+length {
			t.Fatalf("truncated TLS record body: have %d, want %d", len(payload)-5, length)
		}
		lengths = append(lengths, length)
		payload = payload[5+length:]
	}
	return lengths
}

func chunkLengths(chunks [][]byte) []int {
	lengths := make([]int, len(chunks))
	for index, chunk := range chunks {
		lengths[index] = len(chunk)
	}
	return lengths
}

func equalInts(left, right []int) bool {
	return slices.Equal(left, right)
}

type limitedWriter struct {
	bytes.Buffer
	limit int
}

func (writer *limitedWriter) Write(payload []byte) (int, error) {
	if len(payload) > writer.limit {
		payload = payload[:writer.limit]
	}
	return writer.Buffer.Write(payload)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type errorWriter struct{ err error }

func (writer errorWriter) Write([]byte) (int, error) { return 0, writer.err }

type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (connection *recordingConn) Write(payload []byte) (int, error) {
	written, err := connection.Conn.Write(payload)
	connection.mu.Lock()
	connection.written = append(connection.written, payload[:written]...)
	connection.mu.Unlock()
	return written, err
}

func (connection *recordingConn) size() int {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return len(connection.written)
}

func (connection *recordingConn) bytesAfter(offset int) []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return append([]byte(nil), connection.written[offset:]...)
}
