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
