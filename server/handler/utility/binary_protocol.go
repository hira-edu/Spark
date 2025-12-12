package utility

// Binary protocol operation codes shared across desktop streaming handlers.
const (
	BinaryOpFrameFull  byte = 0x00
	BinaryOpFrameDelta byte = 0x01
	BinaryOpFrameKey   byte = 0x02

	BinaryOpDesktopControl byte = 0x03
	BinaryOpShareControl   byte = 0x03
	BinaryOpWebcamControl  byte = 0x04
	BinaryOpAudioControl   byte = 0x05

	BinaryOpTerminalStream byte = 0x00
	BinaryOpTerminalJSON   byte = 0x01
)

// IsFrameOp reports whether the operation represents streaming frame data.
func IsFrameOp(op byte) bool {
	switch op {
	case BinaryOpFrameFull, BinaryOpFrameDelta, BinaryOpFrameKey:
		return true
	default:
		return false
	}
}

// MinBinaryHeaderSize is the minimum size for a valid binary protocol message.
// Header layout: magic(4) + service(1) + op(1) = 6 bytes minimum to read op code.
const MinBinaryHeaderSize = 6

// FullBinaryHeaderSize is the complete header size including event UUID and length.
// Header layout: magic(4) + service(1) + op(1) + event(16) + length(2) = 24 bytes.
const FullBinaryHeaderSize = 24

// ExtractRawData safely extracts binary data from a packet's Data map.
// Returns the data slice, operation byte, and success flag.
// This function prevents panics from nil pointers and type assertion failures.
func ExtractRawData(packetData map[string]any) (data []byte, op byte, ok bool) {
	if packetData == nil {
		return nil, 0, false
	}

	dataVal, exists := packetData["data"]
	if !exists || dataVal == nil {
		return nil, 0, false
	}

	dataPtr, isPtr := dataVal.(*[]byte)
	if !isPtr || dataPtr == nil {
		return nil, 0, false
	}

	data = *dataPtr
	if len(data) < MinBinaryHeaderSize {
		return nil, 0, false
	}

	return data, data[5], true
}

// ExtractRawDataWithPayload extracts data and validates it has a JSON payload.
// Returns the full data, the JSON payload (starting at byte 24), and success flag.
func ExtractRawDataWithPayload(packetData map[string]any) (data []byte, payload []byte, ok bool) {
	data, _, ok = ExtractRawData(packetData)
	if !ok {
		return nil, nil, false
	}

	if len(data) < FullBinaryHeaderSize {
		return nil, nil, false
	}

	return data, data[FullBinaryHeaderSize:], true
}
