package desktop

import (
	"Rocket/client/telemetry"
	"bytes"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"sync"
	"sync/atomic"

	cpu "github.com/klauspost/cpuid/v2"
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
	CodecTypePNG  = 7 // PNG (lossless, best for text/diagrams)
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
	CodecNamePNG  = "png"
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
	Quality:        75,
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
	jpeg := NewJPEGCodec(imageQuality) // Use imageQuality constant for consistency
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
	case CodecTypePNG:
		return NewPNGCodecFast() // Use fast PNG for real-time streaming
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

// ==================== PNG CODEC ====================
// PNG provides lossless compression, optimal for text, terminals, and diagrams
// Based on noVNC's Tight encoding (lossless mode) and Guacamole's PNG support

// PNGCodec provides lossless PNG encoding for text-heavy content
type PNGCodec struct {
	compressionLevel png.CompressionLevel
	pool             *sync.Pool
}

// NewPNGCodec creates a new PNG codec with the specified compression level
// Compression levels: png.NoCompression, png.BestSpeed, png.BestCompression, png.DefaultCompression
func NewPNGCodec(compressionLevel png.CompressionLevel) *PNGCodec {
	return &PNGCodec{
		compressionLevel: compressionLevel,
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// NewPNGCodecFast creates a PNG codec optimized for speed (BestSpeed compression)
// Good for real-time streaming where latency matters more than size
func NewPNGCodecFast() *PNGCodec {
	return NewPNGCodec(png.BestSpeed)
}

// NewPNGCodecQuality creates a PNG codec optimized for size (BestCompression)
// Good for bandwidth-limited connections where size matters more than latency
func NewPNGCodecQuality() *PNGCodec {
	return NewPNGCodec(png.BestCompression)
}

func (c *PNGCodec) Encode(img *image.RGBA) ([]byte, error) {
	if img == nil {
		return nil, errors.New("nil image")
	}

	// Get buffer from pool
	writer := c.pool.Get().(*bytes.Buffer)
	writer.Reset()
	defer c.pool.Put(writer)

	// Create PNG encoder with specified compression level
	encoder := &png.Encoder{CompressionLevel: c.compressionLevel}

	// Encode to PNG
	err := encoder.Encode(writer, img)
	if err != nil {
		codecStats.encodeErrors.Add(1)
		return nil, err
	}

	// Copy result
	result := make([]byte, writer.Len())
	copy(result, writer.Bytes())

	codecStats.encodeCount.Add(1)
	codecStats.encodedBytes.Add(uint64(len(result)))

	return result, nil
}

func (c *PNGCodec) Name() string                { return CodecNamePNG }
func (c *PNGCodec) Type() int                   { return CodecTypePNG }
func (c *PNGCodec) Quality() int                { return 100 } // Lossless
func (c *PNGCodec) IsHardwareAccelerated() bool { return false }

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

func NewWebPCodec(quality int) Codec {
	// WebP encoding is not available in the default build (CGO/libwebp required).
	// Use a proxy wrapper so the wire header advertises the *actual* codec type
	// (JPEG) while config acks can still surface the requested codec + fallback.
	fallback := Codec(NewJPEGCodec(quality))
	if fallback == nil {
		fallback = NewJPEGCodec(quality)
	}
	proxy := &ProxyCodec{
		requestedName: CodecNameWebP,
		requestedType: CodecTypeWebP,
		quality:       quality,
		inner:         fallback,
	}
	proxy.logFallback("webp codec requires CGO/libwebp; using JPEG fallback")
	return proxy
}

// ==================== AVIF / PROXY CODECS ====================

// ProxyCodec provides a lightweight wrapper to expose additional codec types
// (e.g., AVIF, VP8/VP9/H.264) while reusing a fallback encoder underneath. It
// keeps track of the requested codec so telemetry/config responses can surface
// when a fallback is engaged.
type ProxyCodec struct {
	requestedName  string
	requestedType  int
	quality        int
	inner          Codec
	fallbackReason string
}

// RequestedName returns the codec name that was originally requested.
func (c *ProxyCodec) RequestedName() string {
	if c.requestedName != "" {
		return c.requestedName
	}
	return c.Name()
}

// RequestedType returns the codec type that was originally requested.
func (c *ProxyCodec) RequestedType() int {
	if c.requestedType != 0 {
		return c.requestedType
	}
	return c.Type()
}

// HasFallback reports whether the proxy is using a codec different from the one
// that was requested (e.g., requested h264 but actually encoding JPEG).
func (c *ProxyCodec) HasFallback() bool {
	if c.inner == nil {
		return false
	}
	return c.inner.Name() != c.RequestedName() || c.inner.Type() != c.RequestedType()
}

func (c *ProxyCodec) logFallback(reason string) {
	if !c.HasFallback() {
		return
	}
	c.fallbackReason = reason
	telemetry.LogStructured("WARN", "codec: fallback engaged", map[string]interface{}{
		"requested": c.RequestedName(),
		"actual":    c.inner.Name(),
		"reason":    reason,
	})
}

// FallbackReason returns the recorded reason when a proxy uses a fallback encoder.
func (c *ProxyCodec) FallbackReason() string {
	return c.fallbackReason
}

func NewAVIFCodec(quality int) Codec {
	fallback := Codec(NewJPEGCodec(quality))
	if fallback == nil {
		fallback = NewJPEGCodec(quality)
	}
	proxy := &ProxyCodec{
		requestedName: CodecNameAVIF,
		requestedType: CodecTypeAVIF,
		quality:       quality,
		inner:         fallback,
	}
	proxy.logFallback("avif codec requires CGO/libavif; using JPEG fallback")
	return proxy
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

	proxy := &ProxyCodec{
		requestedName: name,
		requestedType: codecType,
		quality:       quality,
		inner:         fallback,
	}

	if fallback != nil && fallback.Name() != name {
		reason := "hardware encoder unavailable on device"
		if hardware {
			reason = "hardware encoder requested but codec not built (enable CGO/libvpx)"
		}
		proxy.logFallback(reason)
	}

	return proxy
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

func (c *ProxyCodec) Name() string {
	if c.inner != nil {
		return c.inner.Name()
	}
	if c.requestedName != "" {
		return c.requestedName
	}
	return CodecNameJPEG
}

func (c *ProxyCodec) Type() int {
	if c.inner != nil {
		return c.inner.Type()
	}
	if c.requestedType != 0 {
		return c.requestedType
	}
	return CodecTypeJPEG
}

func (c *ProxyCodec) Quality() int {
	if c.inner != nil {
		return c.inner.Quality()
	}
	return c.quality
}
func (c *ProxyCodec) IsHardwareAccelerated() bool {
	if c.inner != nil {
		return c.inner.IsHardwareAccelerated()
	}
	return false
}

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
	support := platformHardwareProbe()
	if support == nil {
		support = &HardwareCodecSupport{}
	}

	// Fall back to CPU feature heuristics for VP8/VP9 support hints when the
	// underlying platform probe cannot determine availability. Most CPUs that
	// expose AVX/SSE4 perform well enough to at least advertise support.
	if !support.VP8Available {
		support.VP8Available = cpu.CPU.Supports(cpu.SSE4, cpu.AVX)
	}
	if !support.VP9Available {
		support.VP9Available = cpu.CPU.Supports(cpu.AVX2) || cpu.CPU.Supports(cpu.AVX)
	}

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
	stats := map[string]interface{}{
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

	if proxy, ok := codec.(*ProxyCodec); ok {
		stats["requested_codec"] = proxy.RequestedName()
		stats["requested_codec_type"] = proxy.RequestedType()
		stats["codec_fallback"] = proxy.HasFallback()
		if proxy.HasFallback() && proxy.FallbackReason() != "" {
			stats["codec_fallback_reason"] = proxy.FallbackReason()
		}
	} else {
		stats["requested_codec"] = codec.Name()
		stats["requested_codec_type"] = codec.Type()
		stats["codec_fallback"] = false
	}

	return stats
}
