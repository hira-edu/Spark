//go:build !cgo || !vpx
// +build !cgo !vpx

package desktop

import (
	"image"
	"time"

	"github.com/pion/webrtc/v4/pkg/media"
)

type noopVPXEncoder struct{}

func (noopVPXEncoder) Encode(_ *image.RGBA, _ time.Duration) (media.Sample, error) {
	return media.Sample{}, ErrVPXUnavailable
}

func (noopVPXEncoder) Close() error {
	return nil
}

// NewVPXEncoder returns a stub when libvpx is not compiled in.
func NewVPXEncoder(_ VPXCodec, _ VPXEncoderConfig) (VPXEncoder, error) {
	return noopVPXEncoder{}, ErrVPXUnavailable
}
