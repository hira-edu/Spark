//go:build !cgo || !libjpegturbo

package desktop

import "image"

// ChromaSubsampling defines the chroma subsampling mode for JPEG encoding.
// This is a stub for builds without libjpeg-turbo - standard JPEG uses 4:2:0.
type ChromaSubsampling int

const (
	// Subsamp444 - No chroma subsampling. Best for text, sharp edges.
	Subsamp444 ChromaSubsampling = 0
	// Subsamp422 - Horizontal subsampling only.
	Subsamp422 ChromaSubsampling = 1
	// Subsamp420 - Full chroma subsampling (default).
	Subsamp420 ChromaSubsampling = 2
)

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

// NewLibjpegTurboCodecWithSubsampling creates a fallback codec (subsampling ignored).
// Standard Go JPEG encoder always uses 4:2:0 subsampling.
func NewLibjpegTurboCodecWithSubsampling(quality int, _ ChromaSubsampling) *LibjpegTurboCodec {
	return NewLibjpegTurboCodec(quality)
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

// Subsampling returns the current subsampling mode (always 4:2:0 in stub).
func (c *LibjpegTurboCodec) Subsampling() ChromaSubsampling {
	return Subsamp420 // Standard JPEG always uses 4:2:0
}

// SetSubsampling is a no-op in the stub (standard JPEG doesn't support this).
func (c *LibjpegTurboCodec) SetSubsampling(_ ChromaSubsampling) {}

// SetTextMode is a no-op in the stub (requires libjpeg-turbo for 4:4:4 support).
func (c *LibjpegTurboCodec) SetTextMode(_ bool) {}
