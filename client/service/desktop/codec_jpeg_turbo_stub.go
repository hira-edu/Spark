//go:build !cgo || !libjpegturbo

package desktop

import "image"

// LibjpegTurboCodec stub - falls back to standard JPEG when libjpeg-turbo is unavailable.
// To enable libjpeg-turbo, build with: go build -tags "cgo,libjpegturbo"
type LibjpegTurboCodec struct {
	fallback *JPEGCodec
}

// NewLibjpegTurboCodec creates a fallback JPEG codec when libjpeg-turbo is unavailable.
func NewLibjpegTurboCodec(quality int) *LibjpegTurboCodec {
	return &LibjpegTurboCodec{
		fallback: NewJPEGCodec(quality),
	}
}

// Encode falls back to standard Go JPEG encoding.
func (c *LibjpegTurboCodec) Encode(img *image.RGBA) ([]byte, error) {
	return c.fallback.Encode(img)
}

// Name returns the codec identifier.
func (c *LibjpegTurboCodec) Name() string {
	return "jpeg" // Returns "jpeg" since it's actually using the fallback
}

// Type returns the codec type constant.
func (c *LibjpegTurboCodec) Type() int {
	return CodecTypeJPEG
}

// Quality returns the compression quality (0-100).
func (c *LibjpegTurboCodec) Quality() int {
	return c.fallback.Quality()
}

// IsHardwareAccelerated returns false.
func (c *LibjpegTurboCodec) IsHardwareAccelerated() bool {
	return false
}

// SetQuality updates the quality setting.
func (c *LibjpegTurboCodec) SetQuality(quality int) {
	c.fallback.baseQuality = quality
}
