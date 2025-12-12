// Package desktop provides Tight/ZRLE encoding for desktop streaming.
// Based on VNC RFB protocol encodings used by noVNC and TightVNC.
//
// Tight Encoding (RFB type 7):
// - Best compression for mixed content (photos + text)
// - Uses zlib compression with filter selection
// - Supports JPEG sub-encoding for photographic regions
//
// ZRLE Encoding (RFB type 16):
// - Zlib Run-Length Encoding
// - Good for large uniform areas (solid colors)
// - Lower CPU than Tight for simple screens
//
// References:
// - RFC 6143: The Remote Framebuffer Protocol
// - noVNC decoders/tight.js
// - libvncserver tight.c
package desktop

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"image"
	"image/jpeg"
	"io"
	"sync"
)

// Tight encoding constants (from RFB protocol)
const (
	// Control byte filters
	TightFilterCopy     = 0x00 // Raw pixel data
	TightFilterPalette  = 0x01 // Palette-based (<=256 colors)
	TightFilterGradient = 0x02 // Gradient filter (smooth transitions)

	// Control byte compression types
	TightCompressionBasic = 0x00 // Basic zlib
	TightCompressionFill  = 0x08 // Solid fill (single color)
	TightCompressionJPEG  = 0x09 // JPEG sub-encoding

	// Stream IDs for zlib (allows multiple compression streams)
	TightMaxStreams = 4
)

// TightCodec provides VNC Tight encoding for efficient desktop compression.
// Automatically selects best sub-encoding based on content analysis.
type TightCodec struct {
	quality     int
	jpegQuality int
	pool        *sync.Pool

	// Zlib compression streams (reused for efficiency)
	zlibWriters [TightMaxStreams]*zlib.Writer
	zlibMu      sync.Mutex

	// Analysis thresholds
	solidColorThreshold  int // Max unique colors for fill encoding
	paletteThreshold     int // Max colors for palette encoding
	jpegMinSize          int // Minimum block size for JPEG
	gradientSmoothness   float64
}

// NewTightCodec creates a Tight encoder with specified quality
func NewTightCodec(quality int) *TightCodec {
	if quality < 1 || quality > 100 {
		quality = 70
	}

	return &TightCodec{
		quality:             quality,
		jpegQuality:         quality,
		solidColorThreshold: 1,
		paletteThreshold:    256,
		jpegMinSize:         64, // 64x64 minimum for JPEG
		gradientSmoothness:  0.1,
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// Encode compresses an image block using Tight encoding
func (c *TightCodec) Encode(img *image.RGBA) ([]byte, error) {
	if img == nil {
		return nil, errors.New("nil image")
	}

	width := img.Rect.Dx()
	height := img.Rect.Dy()

	// Analyze block content
	colors := c.analyzeColors(img)

	// Select encoding based on content
	switch {
	case len(colors) == 1:
		// Solid fill - single color
		return c.encodeFill(colors[0])

	case len(colors) <= c.paletteThreshold && (width*height) < 4096:
		// Palette encoding - small block with few colors
		return c.encodePalette(img, colors)

	case width >= c.jpegMinSize && height >= c.jpegMinSize:
		// JPEG for larger blocks (photographic content)
		return c.encodeJPEG(img)

	default:
		// Basic zlib compression
		return c.encodeBasic(img)
	}
}

// analyzeColors counts unique colors in the image (up to threshold)
func (c *TightCodec) analyzeColors(img *image.RGBA) []uint32 {
	colorMap := make(map[uint32]bool)
	colors := make([]uint32, 0, c.paletteThreshold+1)

	bounds := img.Bounds()
	stride := img.Stride

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		row := img.Pix[y*stride : y*stride+bounds.Dx()*4]
		for x := 0; x < len(row); x += 4 {
			// Pack RGBA into uint32
			color := uint32(row[x])<<24 | uint32(row[x+1])<<16 | uint32(row[x+2])<<8 | uint32(row[x+3])
			if !colorMap[color] {
				colorMap[color] = true
				colors = append(colors, color)
				if len(colors) > c.paletteThreshold {
					return colors // Too many colors, stop counting
				}
			}
		}
	}

	return colors
}

// encodeFill encodes a solid color block
func (c *TightCodec) encodeFill(color uint32) ([]byte, error) {
	// Format: control(1) + RGB(3)
	buf := make([]byte, 4)
	buf[0] = TightCompressionFill
	buf[1] = byte(color >> 24) // R
	buf[2] = byte(color >> 16) // G
	buf[3] = byte(color >> 8)  // B
	return buf, nil
}

// encodePalette encodes using palette-based compression
func (c *TightCodec) encodePalette(img *image.RGBA, colors []uint32) ([]byte, error) {
	width := img.Rect.Dx()
	height := img.Rect.Dy()
	numColors := len(colors)

	// Build color index map
	colorIndex := make(map[uint32]byte)
	for i, color := range colors {
		colorIndex[color] = byte(i)
	}

	// Calculate bits per pixel (1, 2, 4, or 8)
	var bpp int
	switch {
	case numColors <= 2:
		bpp = 1
	case numColors <= 4:
		bpp = 2
	case numColors <= 16:
		bpp = 4
	default:
		bpp = 8
	}

	// Build output buffer
	buf := c.pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer c.pool.Put(buf)

	// Control byte: filter=palette + stream ID
	control := byte(TightFilterPalette << 4)
	buf.WriteByte(control)

	// Number of colors - 1 (0 means 1 color, 255 means 256)
	buf.WriteByte(byte(numColors - 1))

	// Palette (3 bytes per color: RGB)
	for _, color := range colors {
		buf.WriteByte(byte(color >> 24)) // R
		buf.WriteByte(byte(color >> 16)) // G
		buf.WriteByte(byte(color >> 8))  // B
	}

	// Pixel data (packed indices)
	pixelData := c.packPaletteIndices(img, colorIndex, bpp, width, height)

	// Compress pixel data with zlib
	compressed, err := c.zlibCompress(pixelData)
	if err != nil {
		return nil, err
	}

	// Compact length encoding
	c.writeCompactLength(buf, len(compressed))
	buf.Write(compressed)

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// packPaletteIndices packs color indices based on bits per pixel
func (c *TightCodec) packPaletteIndices(img *image.RGBA, colorIndex map[uint32]byte, bpp, width, height int) []byte {
	var result []byte

	if bpp == 8 {
		// Simple 1:1 mapping
		result = make([]byte, width*height)
		bounds := img.Bounds()
		stride := img.Stride
		i := 0
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			row := img.Pix[y*stride : y*stride+bounds.Dx()*4]
			for x := 0; x < len(row); x += 4 {
				color := uint32(row[x])<<24 | uint32(row[x+1])<<16 | uint32(row[x+2])<<8 | uint32(row[x+3])
				result[i] = colorIndex[color]
				i++
			}
		}
	} else {
		// Bit-packed indices
		pixelsPerByte := 8 / bpp
		bytesPerRow := (width + pixelsPerByte - 1) / pixelsPerByte
		result = make([]byte, bytesPerRow*height)

		bounds := img.Bounds()
		stride := img.Stride
		outIdx := 0

		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			row := img.Pix[y*stride : y*stride+bounds.Dx()*4]
			var currentByte byte
			bitPos := 0

			for x := 0; x < len(row); x += 4 {
				color := uint32(row[x])<<24 | uint32(row[x+1])<<16 | uint32(row[x+2])<<8 | uint32(row[x+3])
				idx := colorIndex[color]

				// Pack into current byte
				currentByte |= idx << (8 - bpp - bitPos)
				bitPos += bpp

				if bitPos >= 8 {
					result[outIdx] = currentByte
					outIdx++
					currentByte = 0
					bitPos = 0
				}
			}

			// Handle partial byte at end of row
			if bitPos > 0 {
				result[outIdx] = currentByte
				outIdx++
			}
		}
	}

	return result
}

// encodeBasic encodes using zlib compression with raw RGB
func (c *TightCodec) encodeBasic(img *image.RGBA) ([]byte, error) {
	width := img.Rect.Dx()
	height := img.Rect.Dy()

	// Extract RGB (drop alpha)
	rgbData := make([]byte, width*height*3)
	bounds := img.Bounds()
	stride := img.Stride
	i := 0

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		row := img.Pix[y*stride : y*stride+bounds.Dx()*4]
		for x := 0; x < len(row); x += 4 {
			rgbData[i] = row[x]     // R
			rgbData[i+1] = row[x+1] // G
			rgbData[i+2] = row[x+2] // B
			i += 3
		}
	}

	// Compress with zlib
	compressed, err := c.zlibCompress(rgbData)
	if err != nil {
		return nil, err
	}

	// Build output
	buf := c.pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer c.pool.Put(buf)

	// Control byte: basic + copy filter
	control := byte(TightFilterCopy << 4)
	buf.WriteByte(control)

	// Compressed data with length
	c.writeCompactLength(buf, len(compressed))
	buf.Write(compressed)

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// encodeJPEG encodes using JPEG sub-encoding
func (c *TightCodec) encodeJPEG(img *image.RGBA) ([]byte, error) {
	// Encode to JPEG
	jpegBuf := c.pool.Get().(*bytes.Buffer)
	jpegBuf.Reset()
	defer c.pool.Put(jpegBuf)

	err := jpeg.Encode(jpegBuf, img, &jpeg.Options{Quality: c.jpegQuality})
	if err != nil {
		return nil, err
	}

	// Build output
	buf := c.pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer c.pool.Put(buf)

	// Control byte: JPEG
	buf.WriteByte(TightCompressionJPEG)

	// JPEG data with compact length
	c.writeCompactLength(buf, jpegBuf.Len())
	buf.Write(jpegBuf.Bytes())

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// zlibCompress compresses data using zlib
func (c *TightCodec) zlibCompress(data []byte) ([]byte, error) {
	c.zlibMu.Lock()
	defer c.zlibMu.Unlock()

	buf := c.pool.Get().(*bytes.Buffer)
	buf.Reset()
	defer c.pool.Put(buf)

	// Get or create zlib writer
	streamID := 0 // Use first stream for simplicity
	if c.zlibWriters[streamID] == nil {
		c.zlibWriters[streamID] = zlib.NewWriter(buf)
	} else {
		c.zlibWriters[streamID].Reset(buf)
	}

	w := c.zlibWriters[streamID]
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// writeCompactLength writes length in VNC compact format (1-3 bytes)
func (c *TightCodec) writeCompactLength(w io.Writer, length int) {
	buf := make([]byte, 3)
	if length < 128 {
		buf[0] = byte(length)
		w.Write(buf[:1])
	} else if length < 16384 {
		buf[0] = byte(length&0x7F) | 0x80
		buf[1] = byte(length >> 7)
		w.Write(buf[:2])
	} else {
		buf[0] = byte(length&0x7F) | 0x80
		buf[1] = byte((length>>7)&0x7F) | 0x80
		buf[2] = byte(length >> 14)
		w.Write(buf[:3])
	}
}

func (c *TightCodec) Name() string                { return "tight" }
func (c *TightCodec) Type() int                   { return 7 } // VNC Tight encoding type
func (c *TightCodec) Quality() int                { return c.quality }
func (c *TightCodec) IsHardwareAccelerated() bool { return false }

// ==================== ZRLE CODEC ====================

// ZRLECodec provides VNC ZRLE (Zlib Run-Length Encoding)
// Best for screens with large uniform areas
type ZRLECodec struct {
	quality    int
	tileSize   int
	zlibWriter *zlib.Writer
	pool       *sync.Pool
	mu         sync.Mutex
}

// NewZRLECodec creates a ZRLE encoder
func NewZRLECodec(quality int) *ZRLECodec {
	if quality < 1 || quality > 100 {
		quality = 70
	}

	return &ZRLECodec{
		quality:  quality,
		tileSize: 64, // Standard ZRLE tile size
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// Encode compresses an image block using ZRLE encoding
func (c *ZRLECodec) Encode(img *image.RGBA) ([]byte, error) {
	if img == nil {
		return nil, errors.New("nil image")
	}

	width := img.Rect.Dx()
	height := img.Rect.Dy()

	// Encode tiles
	tileBuf := c.pool.Get().(*bytes.Buffer)
	tileBuf.Reset()
	defer c.pool.Put(tileBuf)

	for ty := 0; ty < height; ty += c.tileSize {
		for tx := 0; tx < width; tx += c.tileSize {
			tw := min(c.tileSize, width-tx)
			th := min(c.tileSize, height-ty)

			tileData := c.encodeTile(img, tx, ty, tw, th)
			tileBuf.Write(tileData)
		}
	}

	// Compress all tiles with zlib
	c.mu.Lock()
	defer c.mu.Unlock()

	outBuf := c.pool.Get().(*bytes.Buffer)
	outBuf.Reset()
	defer c.pool.Put(outBuf)

	if c.zlibWriter == nil {
		c.zlibWriter = zlib.NewWriter(outBuf)
	} else {
		c.zlibWriter.Reset(outBuf)
	}

	if _, err := c.zlibWriter.Write(tileBuf.Bytes()); err != nil {
		return nil, err
	}
	if err := c.zlibWriter.Close(); err != nil {
		return nil, err
	}

	// Add zlib length header
	result := make([]byte, 4+outBuf.Len())
	binary.BigEndian.PutUint32(result, uint32(outBuf.Len()))
	copy(result[4:], outBuf.Bytes())

	return result, nil
}

// encodeTile encodes a single ZRLE tile
func (c *ZRLECodec) encodeTile(img *image.RGBA, tx, ty, tw, th int) []byte {
	// Analyze tile for optimal sub-encoding
	colors := c.analyzeTileColors(img, tx, ty, tw, th)

	switch {
	case len(colors) == 1:
		// Solid color (subtype 1)
		return c.encodeSolidTile(colors[0])
	case len(colors) <= 16:
		// Packed palette RLE (subtype 130+)
		return c.encodePaletteTile(img, tx, ty, tw, th, colors)
	default:
		// Raw CPIXEL (subtype 0)
		return c.encodeRawTile(img, tx, ty, tw, th)
	}
}

func (c *ZRLECodec) analyzeTileColors(img *image.RGBA, tx, ty, tw, th int) []uint32 {
	colorMap := make(map[uint32]bool)
	colors := make([]uint32, 0, 17)

	stride := img.Stride
	for y := ty; y < ty+th; y++ {
		for x := tx; x < tx+tw; x++ {
			off := y*stride + x*4
			color := uint32(img.Pix[off])<<24 | uint32(img.Pix[off+1])<<16 | uint32(img.Pix[off+2])<<8
			if !colorMap[color] {
				colorMap[color] = true
				colors = append(colors, color)
				if len(colors) > 16 {
					return colors
				}
			}
		}
	}
	return colors
}

func (c *ZRLECodec) encodeSolidTile(color uint32) []byte {
	// Subtype 1 + CPIXEL (3 bytes RGB)
	return []byte{
		1, // Solid subtype
		byte(color >> 24),
		byte(color >> 16),
		byte(color >> 8),
	}
}

func (c *ZRLECodec) encodePaletteTile(img *image.RGBA, tx, ty, tw, th int, colors []uint32) []byte {
	buf := &bytes.Buffer{}

	// Subtype: 128 + paletteSize (2-16 colors)
	paletteSize := len(colors)
	buf.WriteByte(byte(128 + paletteSize))

	// Palette (CPIXEL format, 3 bytes each)
	colorIndex := make(map[uint32]byte)
	for i, color := range colors {
		colorIndex[color] = byte(i)
		buf.WriteByte(byte(color >> 24))
		buf.WriteByte(byte(color >> 16))
		buf.WriteByte(byte(color >> 8))
	}

	// Packed pixel data with RLE
	c.writePackedRLE(buf, img, tx, ty, tw, th, colorIndex, paletteSize)

	return buf.Bytes()
}

func (c *ZRLECodec) writePackedRLE(buf *bytes.Buffer, img *image.RGBA, tx, ty, tw, th int, colorIndex map[uint32]byte, paletteSize int) {
	// Calculate bits per pixel
	var bpp int
	switch {
	case paletteSize <= 2:
		bpp = 1
	case paletteSize <= 4:
		bpp = 2
	default:
		bpp = 4
	}

	stride := img.Stride
	_ = 8 / bpp // pixelsPerByte calculation kept for documentation

	for y := ty; y < ty+th; y++ {
		var currentByte byte
		bitPos := 0

		for x := tx; x < tx+tw; x++ {
			off := y*stride + x*4
			color := uint32(img.Pix[off])<<24 | uint32(img.Pix[off+1])<<16 | uint32(img.Pix[off+2])<<8
			idx := colorIndex[color]

			currentByte |= idx << (8 - bpp - bitPos)
			bitPos += bpp

			if bitPos >= 8 {
				buf.WriteByte(currentByte)
				currentByte = 0
				bitPos = 0
			}
		}

		if bitPos > 0 {
			buf.WriteByte(currentByte)
		}
	}
}

func (c *ZRLECodec) encodeRawTile(img *image.RGBA, tx, ty, tw, th int) []byte {
	buf := make([]byte, 1+tw*th*3)
	buf[0] = 0 // Raw subtype

	stride := img.Stride
	i := 1
	for y := ty; y < ty+th; y++ {
		for x := tx; x < tx+tw; x++ {
			off := y*stride + x*4
			buf[i] = img.Pix[off]     // R
			buf[i+1] = img.Pix[off+1] // G
			buf[i+2] = img.Pix[off+2] // B
			i += 3
		}
	}
	return buf
}

func (c *ZRLECodec) Name() string                { return "zrle" }
func (c *ZRLECodec) Type() int                   { return 16 } // VNC ZRLE encoding type
func (c *ZRLECodec) Quality() int                { return c.quality }
func (c *ZRLECodec) IsHardwareAccelerated() bool { return false }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
