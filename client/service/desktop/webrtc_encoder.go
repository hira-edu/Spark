package desktop

import (
	"errors"
	"strings"
)

// ErrWebRTCEncoderTimeout signals that the encoder did not produce an output in
// time for the current request. Callers should treat this as a dropped frame,
// not as a fatal session error.
var ErrWebRTCEncoderTimeout = errors.New("webrtc encoder timeout")

// NewWebRTCEncoder returns an encoder for the requested codec.
// Codec negotiation happens at SDP time, so this helper intentionally does not
// cross-fallback to a different codec (that would desync the negotiated codec
// from the encoder output).
func NewWebRTCEncoder(codec WebRTCCodec, cfg WebRTCEncoderConfig) (WebRTCEncoder, WebRTCCodec, error) {
	requested := normalizeWebRTCCodec(codec)
	if requested == "" {
		requested = WebRTCCodecVP8
	}

	enc, err := newWebRTCEncoderForCodec(requested, cfg)
	return enc, requested, err
}

func normalizeWebRTCCodec(codec WebRTCCodec) WebRTCCodec {
	value := strings.ToLower(strings.TrimSpace(string(codec)))
	switch value {
	case "", "vp8":
		return WebRTCCodecVP8
	case "vp9":
		return WebRTCCodecVP9
	case "h264", "h.264":
		return WebRTCCodecH264
	default:
		// Unknown codec -> default to VP8 for compatibility.
		return WebRTCCodecVP8
	}
}

func newWebRTCEncoderForCodec(codec WebRTCCodec, cfg WebRTCEncoderConfig) (WebRTCEncoder, error) {
	switch normalizeWebRTCCodec(codec) {
	case WebRTCCodecH264:
		return NewH264Encoder(cfg)
	case WebRTCCodecVP8, WebRTCCodecVP9:
		return NewVPXEncoder(codec, cfg)
	default:
		return nil, errors.New("unsupported webrtc codec")
	}
}
