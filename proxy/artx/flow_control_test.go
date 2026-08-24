package artx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestNegotiateWindowScalePreservesLegacyForMissingZeroAndInvalidOffers(t *testing.T) {
	tests := []struct {
		name     string
		settings map[uint16]uint32
		server   uint32
		want     uint32
	}{
		{name: "missing", settings: map[uint16]uint32{}, server: 4},
		{name: "zero", settings: map[uint16]uint32{SettingMaxWindowScale: 0}, server: 4},
		{name: "invalid", settings: map[uint16]uint32{SettingMaxWindowScale: 5}, server: 4},
		{name: "server disabled", settings: map[uint16]uint32{SettingMaxWindowScale: 4}, server: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := negotiateWindowScale(test.settings, test.server, 1); got != test.want {
				t.Fatalf("negotiateWindowScale() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestNegotiateWindowScaleClampsLegalOfferToServerLimit(t *testing.T) {
	tests := []struct {
		offer  uint32
		server uint32
		want   uint32
	}{
		{offer: 1, server: 4, want: 1},
		{offer: 4, server: 2, want: 2},
		{offer: 4, server: 9, want: 4},
	}
	for _, test := range tests {
		settings := map[uint16]uint32{SettingMaxWindowScale: test.offer}
		if got := negotiateWindowScale(settings, test.server, 1); got != test.want {
			t.Fatalf("negotiateWindowScale(offer=%d, server=%d) = %d, want %d", test.offer, test.server, got, test.want)
		}
	}
}

func TestWireV2WindowScaleOfferPreservesLegacyLimits(t *testing.T) {
	settings := map[uint16]uint32{SettingMaxWindowScale: MaxWindowScale}
	if got := negotiateWindowScale(settings, MaxWindowScale, 2); got != 0 {
		t.Fatalf("wire-v2 negotiated window scale %d, want legacy", got)
	}
}

func TestScaledFlowControlLimitsExpandWindowsAndUplinkQueue(t *testing.T) {
	limits := flowControlLimitsForScale(2)
	if limits.stream != 1<<20 || limits.connection != 4<<20 {
		t.Fatalf("scaled limits = stream %d, connection %d", limits.stream, limits.connection)
	}

	window := newSendWindowWithLimits(limits)
	if err := window.consume(int(InitialStreamWindow) + 1); err != nil {
		t.Fatalf("scaled stream window rejected expanded credit: %v", err)
	}

	queue := newUplinkQueue(limits.stream)
	chunk := bytes.Repeat([]byte{1}, MaxDataPayload)
	for queued := 0; queued < int(limits.stream); queued += len(chunk) {
		if err := queue.enqueue(chunk); err != nil {
			t.Fatalf("enqueue within scaled limit: %v", err)
		}
	}
	if err := queue.enqueue([]byte{1}); err == nil {
		t.Fatal("uplink queue accepted data beyond scaled limit")
	}
}

func TestMaximumWindowScaleUsesDocumentedLimits(t *testing.T) {
	limits := flowControlLimitsForScale(4)
	if limits.stream != 4<<20 || limits.connection != 16<<20 {
		t.Fatalf("maximum limits = stream %d, connection %d; want stream %d, connection %d", limits.stream, limits.connection, 4<<20, 16<<20)
	}
}

func TestExpandedReceiveCreditUsesWindowUpdateWithoutChangingServerSettings(t *testing.T) {
	settingsPayload, err := EncodeSettings(settingsList(profileVersionUnshaped))
	if err != nil {
		t.Fatal(err)
	}
	wantSettingsPayload := []byte{
		0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x02, 0x00, 0x04, 0x00, 0x00,
		0x00, 0x03, 0x00, 0x10, 0x00, 0x00,
		0x00, 0x05, 0x00, 0x00, 0x00, 0x01,
	}
	if !bytes.Equal(settingsPayload, wantSettingsPayload) {
		t.Fatalf("server SETTINGS payload changed: %x", settingsPayload)
	}
	profileV3Payload, err := EncodeSettings(settingsList(profileVersionTimedRecordShaping))
	if err != nil {
		t.Fatal(err)
	}
	wantProfileV3Payload := bytes.Clone(wantSettingsPayload)
	wantProfileV3Payload[len(wantProfileV3Payload)-1] = byte(profileVersionTimedRecordShaping)
	if !bytes.Equal(profileV3Payload, wantProfileV3Payload) {
		t.Fatalf("profile-v3 server SETTINGS payload changed: %x", profileV3Payload)
	}

	limits := flowControlLimitsForScale(2)
	var output bytes.Buffer
	if err := writeExpandedReceiveCredit(&lockedFrameWriter{writer: &output}, limits, true); err != nil {
		t.Fatal(err)
	}
	connectionUpdate, err := ReadFrame(&output)
	if err != nil {
		t.Fatal(err)
	}
	streamUpdate, err := ReadFrame(&output)
	if err != nil {
		t.Fatal(err)
	}
	assertWindowUpdateIncrement(t, connectionUpdate, 0, limits.connection-InitialConnectionWindow)
	assertWindowUpdateIncrement(t, streamUpdate, ClientStreamID, limits.stream-InitialStreamWindow)
}

func TestServerNegotiatesExpandedCreditAfterUnchangedSettingsFlight(t *testing.T) {
	server := newArtXTestServer(t)
	server.maxWindowScale = 3
	echoServer, dispatcher := newEchoDispatcher()
	defer echoServer.Close()
	client, processDone := authenticateArtXClient(t, server, dispatcher, context.Background())

	settings := append(settingsList(server.profileVersion), Setting{Key: SettingMaxWindowScale, Value: 2})
	payload, err := EncodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameSettings, Payload: payload})
	destination, err := EncodeTCPDestination(xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})

	limits := flowControlLimitsForScale(2)
	connectionUpdate, err := ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	streamUpdate, err := ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	assertWindowUpdateIncrement(t, connectionUpdate, 0, limits.connection-InitialConnectionWindow)
	assertWindowUpdateIncrement(t, streamUpdate, ClientStreamID, limits.stream-InitialStreamWindow)

	writeFrameForTest(t, client, Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}})
	if err := <-processDone; err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if got := server.Stats().FlowControlNegotiated; got != 1 {
		t.Fatalf("FlowControlNegotiated = %d, want 1", got)
	}
	closeTLSNow(client)
}

func TestNegotiatedScaleExpandsServerDownlinkWindow(t *testing.T) {
	server := newArtXTestServer(t)
	server.maxWindowScale = 1
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, processDone := authenticateArtXClient(t, server, dispatcher, context.Background())

	settings := append(settingsList(server.profileVersion), Setting{Key: SettingMaxWindowScale, Value: 1})
	payload, err := EncodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameSettings, Payload: payload})
	destination, err := EncodeTCPDestination(xnet.TCPDestination(xnet.DomainAddress("example.com"), 443))
	if err != nil {
		t.Fatal(err)
	}
	writeFrameForTest(t, client, Frame{Type: FrameTCPSyn, StreamID: ClientStreamID, Payload: destination})
	if _, err := ReadFrame(client); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(client); err != nil {
		t.Fatal(err)
	}

	want := bytes.Repeat([]byte{0xa5}, int(InitialStreamWindow)+MaxDataPayload)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- target.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(want)})
	}()
	var got bytes.Buffer
	for got.Len() < len(want) {
		frame, err := ReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != FrameData {
			t.Fatalf("downlink frame type = 0x%02x, want DATA", frame.Type)
		}
		got.Write(frame.Payload)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("downlink payload = %d bytes, want %d", got.Len(), len(want))
	}

	writeFrameForTest(t, client, Frame{Type: FrameRST, StreamID: ClientStreamID, Payload: []byte{1}})
	if err := <-processDone; err != nil {
		t.Fatal(err)
	}
	closeTLSNow(client)
}

func TestUDPAssociationIgnoresCraftedWindowScaleOffer(t *testing.T) {
	server := newArtXTestServer(t)
	server.maxWindowScale = MaxWindowScale
	server.udpEnabled = true
	target, dispatcher, closer := newTargetDispatcher()
	defer closer.Close()
	client, processDone := authenticateArtXClient(t, server, dispatcher, context.Background())
	defer closeTLSNow(client)

	settings := append(settingsList(server.profileVersion), Setting{Key: SettingMaxWindowScale, Value: MaxWindowScale})
	payload, err := EncodeSettings(settings)
	if err != nil {
		t.Fatal(err)
	}
	destination := xnet.UDPDestination(xnet.DomainAddress("dns.example"), 53)
	encodedDestination, err := EncodeUDPDestination(destination)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := EncodeDatagram([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	frames := []Frame{
		{Type: FrameSettings, Payload: payload},
		{Type: FrameUDPAssoc, StreamID: ClientStreamID, Payload: encodedDestination},
		{Type: FrameDatagram, StreamID: ClientStreamID, Payload: datagram},
	}
	var flight []byte
	for _, frame := range frames {
		encoded, err := frame.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		flight = append(flight, encoded...)
	}
	if err := writeAll(client, flight); err != nil {
		t.Fatal(err)
	}
	targetRead := make(chan error, 1)
	go func() {
		buffers, err := target.Reader.ReadMultiBuffer()
		buf.ReleaseMulti(buffers)
		targetRead <- err
	}()

	connectionUpdate, err := ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	streamUpdate, err := ReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	wantIncrement := uint32(len(datagram))
	assertWindowUpdateIncrement(t, connectionUpdate, 0, wantIncrement)
	assertWindowUpdateIncrement(t, streamUpdate, ClientStreamID, wantIncrement)
	if err := <-targetRead; err != nil {
		t.Fatal(err)
	}

	writeFrameForTest(t, client, Frame{Type: FrameFin, StreamID: ClientStreamID})
	readUntilFrame(t, client, FrameFin)
	if err := <-processDone; err != nil {
		t.Fatal(err)
	}
	if got := server.Stats().FlowControlNegotiated; got != 0 {
		t.Fatalf("FlowControlNegotiated = %d, want 0", got)
	}
}

func assertWindowUpdateIncrement(t *testing.T, frame Frame, streamID, want uint32) {
	t.Helper()
	if frame.Type != FrameWindowUpdate || frame.StreamID != streamID {
		t.Fatalf("WINDOW_UPDATE = type 0x%02x stream %d", frame.Type, frame.StreamID)
	}
	got, err := DecodeWindowUpdate(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("WINDOW_UPDATE increment = %d, want %d", got, want)
	}
}
