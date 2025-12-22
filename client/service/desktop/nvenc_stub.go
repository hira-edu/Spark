//go:build !windows

package desktop

import (
	"image"
	"time"

	"github.com/pion/webrtc/v4/pkg/media"
)

// NVENCEncoder is a stub for non-Windows platforms.
type NVENCEncoder struct{}

// NewNVENCEncoder returns an error on non-Windows platforms.
func NewNVENCEncoder(_ WebRTCEncoderConfig) (*NVENCEncoder, error) {
	return nil, ErrH264Unavailable
}

// Encode is not supported on non-Windows platforms.
func (e *NVENCEncoder) Encode(_ *image.RGBA, _ time.Duration) (media.Sample, error) {
	return media.Sample{}, ErrH264Unavailable
}

// Close is a no-op on non-Windows platforms.
func (e *NVENCEncoder) Close() error {
	return nil
}
