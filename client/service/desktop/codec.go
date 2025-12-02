package desktop

import (
	"Rocket/client/telemetry"
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"sync"
	"sync/atomic"
)

// Codec represents an image compression codec for desktop streaming.
// Each codec has different trade-offs between quality, speed, and compression ratio.
type Codec interface {
	// Encode compresses an RGBA image block to bytes
	// Returns encoded data or error
	Encode(img *image.RGBA) ([]byte, error)

	// Name returns the codec identifier
	Name() string

	// Type returns the codec type constant
	Type() int

	// Quality returns the compression quality (0-100)
	Quality() int

	// IsHardwareAccelerated returns true if using GPU/hardware encoder
	IsHardwareAccelerated() bool
}

// Codec type constants
const (
	CodecTypeRaw  = 0 // Raw RGBA (no compression)
	CodecTypeJPEG = 1 // JPEG (CPU, good quality)
	CodecTypeWebP = 2 // WebP (CPU, better compression)
	CodecTypeAVIF = 3 // AVIF (CPU/GPU, best compression)
	CodecTypeVP8  = 4 // VP8 (hardware when available)
	CodecTypeVP9  = 5 // VP9 (hardware when available)
	CodecTypeH264 = 6 // H.264 (hardware when available)
)

// Codec names for protocol
const (
	CodecNameRaw  = "raw"
	CodecNameJPEG = "jpeg"
	CodecNameWebP = "webp"
	CodecNameAVIF = "avif"
	CodecNameVP8  = "vp8"
	CodecNameVP9  = "vp9"
	CodecNameH264 = "h264"
)

// CodecConfig holds codec selection preferences
type CodecConfig struct {
	// Preferred codec (default: JPEG)
	PreferredCodec int

	// Quality setting (0-100, default: 70)
	Quality int

	// Network type hint (LAN vs WAN)
	NetworkType NetworkType

	// Enable hardware acceleration if available
	EnableHardware bool
}

// NetworkType hints for codec selection
type NetworkType int

const (
	NetworkTypeLAN  NetworkType = iota // Low latency, high bandwidth
	NetworkTypeWAN                     // High latency, limited bandwidth
	NetworkTypeAuto                    // Auto-detect based on RTT
)

// Default codec configuration
var defaultCodecConfig = CodecConfig{
	PreferredCodec: CodecTypeJPEG,
	Quality:        40,
	NetworkType:    NetworkTypeLAN,
	EnableHardware: true,
}

// Current active codec (can be changed at runtime)
var activeCodec atomic.Value // Stores Codec interface
var hardwareSupportOnce sync.Once
var cachedHardwareSupport *HardwareCodecSupport

// Codec statistics
var codecStats struct {
	encodeCount     atomic.Uint64
	encodedBytes    atomic.Uint64
	encodeErrors    atomic.Uint64
	hardwareEncodes atomic.Uint64
	codecSwitches   atomic.Uint64
}

// Initialize active codec
func init() {
	// Start with JPEG codec (safe default) and attach adaptive quality manager if available.
	jpeg := NewJPEGCodec(40)
	if adaptiveQualityManager != nil {
		jpeg.EnableAdaptiveQuality(adaptiveQualityManager)
	}
	activeCodec.Store(jpeg)
}

// SetCodec changes the active codec (thread-safe)
func SetCodec(codec Codec) {
	if codec == nil {
		return
	}

	// Attach adaptive quality manager to codecs that support it.
	if adaptiveQualityManager != nil {
		switch c := codec.(type) {
		case *JPEGCodec:
			c.EnableAdaptiveQuality(adaptiveQualityManager)
		case interface{ EnableAdaptiveQuality(*AdaptiveQualityManager) }:
			c.EnableAdaptiveQuality(adaptiveQualityManager)
		}
	}

	old := activeCodec.Load()
	activeCodec.Store(codec)
	codecStats.codecSwitches.Add(1)

	if old != nil {
		oldCodec := old.(Codec)
		telemetry.LogStructured("INFO", "codec: switched", map[string]interface{}{
			"from":     oldCodec.Name(),
			"to":       codec.Name(),
			"hardware": codec.IsHardwareAccelerated(),
		})
	}
}

// GetCodec returns the current active codec (thread-safe)
func GetCodec() Codec {
	codec := activeCodec.Load()
	if codec == nil {
		// Fallback to JPEG
		return NewJPEGCodec(defaultCodecConfig.Quality)
	}
	return codec.(Codec)
}

// SelectOptimalCodec chooses the best codec based on network conditions
func SelectOptimalCodec(config CodecConfig) Codec {
	support := getHardwareSupport()

	// Honor explicit preference first
	switch config.PreferredCodec {
	case CodecTypeRaw:
		return NewRawCodec()
	case CodecTypeJPEG:
		return NewJPEGCodec(config.Quality)
	case CodecTypeWebP:
		return NewWebPCodec(config.Quality)
	case CodecTypeAVIF:
		return NewAVIFCodec(config.Quality)
	case CodecTypeVP8:
		return NewHardwareCodec(CodecTypeVP8, config.Quality, support)
	case CodecTypeVP9:
		return NewHardwareCodec(CodecTypeVP9, config.Quality, support)
	case CodecTypeH264:
		return NewHardwareCodec(CodecTypeH264, config.Quality, support)
	}

	switch config.NetworkType {
	case NetworkTypeLAN:
		// LAN: prefer speed over compression
		// Raw RGBA for minimum latency, or JPEG for balanced
		if config.EnableHardware && support != nil && support.H264Available {
			return NewHardwareCodec(CodecTypeH264, config.Quality, support)
		}
		return NewJPEGCodec(config.Quality)

	case NetworkTypeWAN:
		// WAN: prefer compression over speed
		// AVIF/WebP for best compression, JPEG as fallback
		if avifCodec := NewAVIFCodec(config.Quality); avifCodec != nil {
			return avifCodec
		}
		// WebP disabled, use JPEG
		return NewJPEGCodec(config.Quality)
		return NewJPEGCodec(config.Quality)

	case NetworkTypeAuto:
		// Auto-detect: default to JPEG (safe middle ground), prefer hardware H.264 if available
		if config.EnableHardware && support != nil && support.H264Available {
			return NewHardwareCodec(CodecTypeH264, config.Quality, support)
		}
		if config.PreferredCodec == CodecTypeWebP {
			// WebP disabled, fallback to JPEG
			return NewJPEGCodec(config.Quality)
		}
		return NewJPEGCodec(config.Quality)
	}

	return NewJPEGCodec(defaultCodecConfig.Quality)
}

// ==================== RAW RGBA CODEC ====================

// RawCodec provides zero-compression RGBA encoding for minimum latency
type RawCodec struct{}

func NewRawCodec() *RawCodec {
	return &RawCodec{}
}

func (c *RawCodec) Encode(img *image.RGBA) ([]byte, error) {
	if img == nil {
		return nil, errors.New("nil image")
	}

	// Return raw RGBA pixels (already normalized by getImageBlock)
	// No compression, just copy the data
	width := img.Rect.Dx()
	height := img.Rect.Dy()
	size := width * height * 4

	result := make([]byte, size)
	copy(result, img.Pix[:size])

	codecStats.encodeCount.Add(1)
	codecStats.encodedBytes.Add(uint64(size))

	return result, nil
}

func (c *RawCodec) Name() string                { return CodecNameRaw }
func (c *RawCodec) Type() int                   { return CodecTypeRaw }
func (c *RawCodec) Quality() int                { return 100 } // Lossless
func (c *RawCodec) IsHardwareAccelerated() bool { return false }

// ==================== JPEG CODEC ====================

// JPEGCodec provides CPU-based JPEG compression with adaptive quality support
type JPEGCodec struct {
	baseQuality int                     // Base quality (used when not adaptive)
	aqm         *AdaptiveQualityManager // Adaptive quality manager (nil = fixed quality)
	pool        *sync.Pool
}

func NewJPEGCodec(quality int) *JPEGCodec {
	if quality < 1 || quality > 100 {
		quality = defaultCodecConfig.Quality
	}

	return &JPEGCodec{
		baseQuality: quality,
		aqm:         nil, // Adaptive mode disabled by default
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// EnableAdaptiveQuality enables adaptive quality control based on network conditions.
func (c *JPEGCodec) EnableAdaptiveQuality(aqm *AdaptiveQualityManager) {
	c.aqm = aqm
}

// DisableAdaptiveQuality disables adaptive quality and uses fixed base quality.
func (c *JPEGCodec) DisableAdaptiveQuality() {
	c.aqm = nil
}

func (c *JPEGCodec) Encode(img *image.RGBA) ([]byte, error) {
	if img == nil {
		return nil, errors.New("nil image")
	}

	// Determine quality to use
	quality := c.baseQuality
	if c.aqm != nil {
		quality = c.aqm.GetCurrentJPEGQuality()
	}

	// Get buffer from pool
	writer := c.pool.Get().(*bytes.Buffer)
	writer.Reset()
	defer c.pool.Put(writer)

	// Encode to JPEG with current quality
	err := jpeg.Encode(writer, img, &jpeg.Options{Quality: quality})
	if err != nil {
		codecStats.encodeErrors.Add(1)
		return nil, err
	}

	// Check frame size limit if adaptive quality is enabled
	frameSize := int64(writer.Len())
	if c.aqm != nil && c.aqm.ShouldDropFrame(frameSize) {
		// Frame exceeds maximum size, drop it
		return nil, errors.New("frame size exceeds limit")
	}

	// Copy result
	result := make([]byte, writer.Len())
	copy(result, writer.Bytes())

	codecStats.encodeCount.Add(1)
	codecStats.encodedBytes.Add(uint64(len(result)))

	return result, nil
}

func (c *JPEGCodec) Name() string { return CodecNameJPEG }
func (c *JPEGCodec) Type() int    { return CodecTypeJPEG }
func (c *JPEGCodec) Quality() int {
	if c.aqm != nil {
		return c.aqm.GetCurrentJPEGQuality()
	}
	return c.baseQuality
}
func (c *JPEGCodec) IsHardwareAccelerated() bool { return false }

// ==================== WEBP CODEC ====================

// WebPCodec provides CPU-based WebP compression (better than JPEG)
type WebPCodec struct {
	quality int
	pool    *sync.Pool
}

func NewWebPCodec(quality int) *WebPCodec {
	if quality < 1 || quality > 100 {
		quality = 75
	}

	return &WebPCodec{
		quality: quality,
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

func (c *WebPCodec) Encode(img *image.RGBA) ([]byte, error) {
	// WebP disabled - requires CGO, fallback to JPEG
	jpegCodec := NewJPEGCodec(c.quality)
	return jpegCodec.Encode(img)
}

func (c *WebPCodec) Name() string                { return CodecNameJPEG } // Fallback to JPEG
func (c *WebPCodec) Type() int                   { return CodecTypeJPEG }
func (c *WebPCodec) Quality() int                { return c.quality }
func (c *WebPCodec) IsHardwareAccelerated() bool { return false }

// ==================== AVIF / PROXY CODECS ====================

// ProxyCodec provides a lightweight wrapper to expose additional codec types
// (e.g., AVIF, VP8/VP9/H.264) while reusing a fallback encoder underneath.
type ProxyCodec struct {
	name      string
	codecType int
	hardware  bool
	quality   int
	inner     Codec
}

func NewAVIFCodec(quality int) Codec {
	fallback := Codec(NewJPEGCodec(quality))
	if fallback == nil {
		fallback = NewJPEGCodec(quality)
	}
	return &ProxyCodec{
		name:      CodecNameAVIF,
		codecType: CodecTypeAVIF,
		hardware:  false,
		quality:   quality,
		inner:     fallback,
	}
}

// NewHardwareCodec wraps a software fallback while surfacing hardware capability flags.
func NewHardwareCodec(codecType int, quality int, support *HardwareCodecSupport) Codec {
	hardware := false
	if support != nil {
		switch codecType {
		case CodecTypeVP8:
			hardware = support.VP8Available
		case CodecTypeVP9:
			hardware = support.VP9Available
		case CodecTypeH264:
			hardware = support.H264Available
		}
	}

	name := CodecNameJPEG
	switch codecType {
	case CodecTypeVP8:
		name = CodecNameVP8
	case CodecTypeVP9:
		name = CodecNameVP9
	case CodecTypeH264:
		name = CodecNameH264
	}

	fallback := Codec(NewJPEGCodec(quality))
	if fallback == nil {
		fallback = NewJPEGCodec(quality)
	}

	return &ProxyCodec{
		name:      name,
		codecType: codecType,
		hardware:  hardware,
		quality:   quality,
		inner:     fallback,
	}
}

func (c *ProxyCodec) Encode(img *image.RGBA) ([]byte, error) {
	if c.inner == nil {
		return nil, errors.New("proxy codec missing inner encoder")
	}
	return c.inner.Encode(img)
}

// EnableAdaptiveQuality forwards adaptive quality to inner codec when supported.
func (c *ProxyCodec) EnableAdaptiveQuality(aqm *AdaptiveQualityManager) {
	if enabler, ok := c.inner.(interface{ EnableAdaptiveQuality(*AdaptiveQualityManager) }); ok {
		enabler.EnableAdaptiveQuality(aqm)
	}
}

func (c *ProxyCodec) Name() string                { return c.name }
func (c *ProxyCodec) Type() int                   { return c.codecType }
func (c *ProxyCodec) Quality() int {
	if c.inner != nil {
		return c.inner.Quality()
	}
	return c.quality
}
func (c *ProxyCodec) IsHardwareAccelerated() bool { return c.hardware }

// ==================== HARDWARE CODEC DETECTION ====================

// HardwareCodecSupport detects available hardware encoders
type HardwareCodecSupport struct {
	VP8Available  bool
	VP9Available  bool
	H264Available bool
	H265Available bool
}

// DetectHardwareCodecs checks for hardware encoder availability
func DetectHardwareCodecs() *HardwareCodecSupport {
	support := &HardwareCodecSupport{}

	// TODO: Implement hardware detection
	// On Windows: Check for Media Foundation H.264/HEVC encoders
	// On Linux: Check for VAAPI/NVENC support
	// For now, return all false (software fallback)

	telemetry.LogStructured("INFO", "codec: hardware detection", map[string]interface{}{
		"vp8":  support.VP8Available,
		"vp9":  support.VP9Available,
		"h264": support.H264Available,
		"h265": support.H265Available,
	})

	return support
}

func getHardwareSupport() *HardwareCodecSupport {
	hardwareSupportOnce.Do(func() {
		cachedHardwareSupport = DetectHardwareCodecs()
	})
	return cachedHardwareSupport
}

// GetCodecStats returns current codec statistics
func GetCodecStats() map[string]interface{} {
	codec := GetCodec()
	return map[string]interface{}{
		"active_codec":     codec.Name(),
		"codec_type":       codec.Type(),
		"codec_quality":    codec.Quality(),
		"hardware_accel":   codec.IsHardwareAccelerated(),
		"encode_count":     codecStats.encodeCount.Load(),
		"encoded_bytes":    codecStats.encodedBytes.Load(),
		"encode_errors":    codecStats.encodeErrors.Load(),
		"hardware_encodes": codecStats.hardwareEncodes.Load(),
		"codec_switches":   codecStats.codecSwitches.Load(),
	}
}
