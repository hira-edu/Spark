//go:build !cgo || !vpx
// +build !cgo !vpx

package desktop

import (
	"Rocket/client/telemetry"
	"image"
	"sync"
	"time"

	"github.com/pion/webrtc/v4/pkg/media"
)

var warnVPXOnce sync.Once

type noopVPXEncoder struct{}

func (noopVPXEncoder) Encode(_ *image.RGBA, _ time.Duration) (media.Sample, error) {
	return media.Sample{}, ErrVPXUnavailable
}

func (noopVPXEncoder) Close() error {
	return nil
}

// NewVPXEncoder returns a stub when libvpx is not compiled in.
func NewVPXEncoder(_ VPXCodec, _ VPXEncoderConfig) (VPXEncoder, error) {
	warnVPXOnce.Do(func() {
		telemetry.LogStructured("WARN", "[WEBRTC_CODEC_DISABLED]", map[string]interface{}{
			"codec":   "vpx",
			"message": "libvpx not available (build with cgo + -tags vpx to enable WebRTC video encode)",
		})
	})
	return noopVPXEncoder{}, ErrVPXUnavailable
}
