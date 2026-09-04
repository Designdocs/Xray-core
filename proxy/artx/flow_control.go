package artx

const MaxWindowScale = uint32(4)

type flowControlLimits struct {
	stream     uint32
	connection uint32
}

func legacyFlowControlLimits() flowControlLimits {
	return flowControlLimits{
		stream:     InitialStreamWindow,
		connection: InitialConnectionWindow,
	}
}

func flowControlLimitsForScale(scale uint32) flowControlLimits {
	if scale > MaxWindowScale {
		return legacyFlowControlLimits()
	}
	return flowControlLimits{
		stream:     InitialStreamWindow << scale,
		connection: InitialConnectionWindow << scale,
	}
}

func negotiateWindowScale(settings map[uint16]uint32, serverMaximum, wireVersion uint32) uint32 {
	if wireVersion != 1 {
		return 0
	}
	offer, present := settings[SettingMaxWindowScale]
	if !present || offer == 0 || offer > MaxWindowScale || serverMaximum == 0 {
		return 0
	}
	return min(offer, min(serverMaximum, MaxWindowScale))
}

func writeExpandedReceiveCredit(writer *lockedFrameWriter, limits flowControlLimits, includeConnection bool) error {
	legacy := legacyFlowControlLimits()
	if limits.stream <= legacy.stream || limits.connection <= legacy.connection {
		return nil
	}
	streamIncrement, err := EncodeWindowUpdate(limits.stream - legacy.stream)
	if err != nil {
		return err
	}
	streamUpdate := Frame{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: streamIncrement}
	if !includeConnection {
		return writer.write(streamUpdate)
	}
	connectionIncrement, err := EncodeWindowUpdate(limits.connection - legacy.connection)
	if err != nil {
		return err
	}
	return writer.writeFrames(
		Frame{Type: FrameWindowUpdate, Payload: connectionIncrement},
		streamUpdate,
	)
}

// grantReceiveCredit hands the client one more rung of uplink credit. The local
// bookkeeping moves first so a replenish racing this grant is measured against
// the larger window; the client cannot overrun the grant either way, because
// credit only ever counts up.
func grantReceiveCredit(writer *lockedFrameWriter, window *sendWindow, streamDelta, connectionDelta uint32) error {
	if streamDelta == 0 && connectionDelta == 0 {
		return nil
	}
	streamIncrement, err := EncodeWindowUpdate(streamDelta)
	if err != nil {
		return err
	}
	connectionIncrement, err := EncodeWindowUpdate(connectionDelta)
	if err != nil {
		return err
	}
	window.grow(streamDelta, connectionDelta)
	return writer.writeFrames(
		Frame{Type: FrameWindowUpdate, Payload: connectionIncrement},
		Frame{Type: FrameWindowUpdate, StreamID: ClientStreamID, Payload: streamIncrement},
	)
}
