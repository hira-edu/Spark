//go:build windows

package desktop

// NewH264Encoder builds a Windows H.264 encoder backed by NVENC.
func NewH264Encoder(cfg WebRTCEncoderConfig) (WebRTCEncoder, error) {
	return NewNVENCEncoder(cfg)
}

var _ WebRTCEncoder = (*NVENCEncoder)(nil)
var _ frameEncoder = (*NVENCEncoder)(nil)
var _ keyFrameRequester = (*NVENCEncoder)(nil)
