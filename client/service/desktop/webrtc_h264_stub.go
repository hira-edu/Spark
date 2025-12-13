//go:build !windows

package desktop

// NewH264Encoder returns a stub on non-Windows platforms.
func NewH264Encoder(_ WebRTCEncoderConfig) (WebRTCEncoder, error) {
	return nil, ErrH264Unavailable
}
