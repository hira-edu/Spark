package colorconv

import (
	"errors"
	"image"
	"time"
	"unsafe"
)

// RGBAToNV12 converts RGBA to NV12 format (YUV 4:2:0).
//
// NV12 layout:
//   - Y plane: width*height bytes
//   - UV plane: width*height/2 bytes (interleaved U,V)
// Total: width*height*3/2 bytes.
//
// This implementation uses lookup tables to reduce per-pixel math cost.
var (
	yLookupR [256]int
	yLookupG [256]int
	yLookupB [256]int
	uLookupR [256]int
	uLookupG [256]int
	uLookupB [256]int
	vLookupR [256]int
	vLookupG [256]int
	vLookupB [256]int
)

func init() {
	// BT.601 full range coefficients scaled by 256.
	for i := 0; i < 256; i++ {
		yLookupR[i] = 66 * i
		yLookupG[i] = 129 * i
		yLookupB[i] = 25 * i

		uLookupR[i] = -38 * i
		uLookupG[i] = -74 * i
		uLookupB[i] = 112 * i

		vLookupR[i] = 112 * i
		vLookupG[i] = -94 * i
		vLookupB[i] = -18 * i
	}
}

func validateRGBAToNV12(src *image.RGBA, dst []byte, width, height int) error {
	if src == nil {
		return errors.New("nil source image")
	}
	if width <= 0 || height <= 0 {
		return errors.New("invalid dimensions")
	}
	if width%2 != 0 || height%2 != 0 {
		return errors.New("width and height must be even for NV12")
	}
	expectedSize := width * height * 3 / 2
	if len(dst) < expectedSize {
		return errors.New("destination buffer too small")
	}
	bounds := src.Bounds()
	if bounds.Dx() != width || bounds.Dy() != height {
		return errors.New("source image dimensions mismatch")
	}
	if len(src.Pix) == 0 {
		return errors.New("empty source buffer")
	}
	return nil
}

// RGBAToNV12 converts *image.RGBA to NV12 planar format.
func RGBAToNV12(src *image.RGBA, dst []byte, width, height int) error {
	if err := validateRGBAToNV12(src, dst, width, height); err != nil {
		return err
	}

	yPlane := dst[:width*height]
	uvPlane := dst[width*height:]

	srcPix := src.Pix
	srcStride := src.Stride

	for y := 0; y < height; y++ {
		srcRow := srcPix[y*srcStride:]
		yRow := yPlane[y*width:]
		for x := 0; x < width; x++ {
			r := srcRow[x*4+0]
			g := srcRow[x*4+1]
			b := srcRow[x*4+2]
			yVal := yLookupR[r] + yLookupG[g] + yLookupB[b]
			yRow[x] = clampU8((yVal>>8) + 16)
		}
	}

	for y := 0; y < height; y += 2 {
		row0 := srcPix[y*srcStride:]
		row1 := srcPix[(y+1)*srcStride:]
		uvRow := uvPlane[(y/2)*width:]

		for x := 0; x < width; x += 2 {
			r0 := row0[x*4+0]
			g0 := row0[x*4+1]
			b0 := row0[x*4+2]

			r1 := row0[(x+1)*4+0]
			g1 := row0[(x+1)*4+1]
			b1 := row0[(x+1)*4+2]

			r2 := row1[x*4+0]
			g2 := row1[x*4+1]
			b2 := row1[x*4+2]

			r3 := row1[(x+1)*4+0]
			g3 := row1[(x+1)*4+1]
			b3 := row1[(x+1)*4+2]

			rAvg := (uint32(r0) + uint32(r1) + uint32(r2) + uint32(r3)) >> 2
			gAvg := (uint32(g0) + uint32(g1) + uint32(g2) + uint32(g3)) >> 2
			bAvg := (uint32(b0) + uint32(b1) + uint32(b2) + uint32(b3)) >> 2

			uVal := uLookupR[rAvg] + uLookupG[gAvg] + uLookupB[bAvg]
			vVal := vLookupR[rAvg] + vLookupG[gAvg] + vLookupB[bAvg]

			uvRow[x] = clampU8((uVal>>8) + 128)
			uvRow[x+1] = clampU8((vVal>>8) + 128)
		}
	}

	return nil
}

// RGBAToNV12Fast is a bounds-check-light variant using unsafe pointer arithmetic.
func RGBAToNV12Fast(src *image.RGBA, dst []byte, width, height int) error {
	if err := validateRGBAToNV12(src, dst, width, height); err != nil {
		return err
	}

	yPlane := dst[:width*height]
	uvPlane := dst[width*height:]

	srcStride := src.Stride
	srcBase := unsafe.Pointer(&src.Pix[0])

	for y := 0; y < height; y++ {
		srcRow := unsafe.Add(srcBase, y*srcStride)
		yRow := yPlane[y*width:]
		for x := 0; x < width; x++ {
			px := unsafe.Add(srcRow, x*4)
			r := *(*uint8)(px)
			g := *(*uint8)(unsafe.Add(px, 1))
			b := *(*uint8)(unsafe.Add(px, 2))
			yVal := yLookupR[r] + yLookupG[g] + yLookupB[b]
			yRow[x] = clampU8((yVal>>8) + 16)
		}
	}

	for y := 0; y < height; y += 2 {
		row0 := unsafe.Add(srcBase, y*srcStride)
		row1 := unsafe.Add(srcBase, (y+1)*srcStride)
		uvRow := uvPlane[(y/2)*width:]

		for x := 0; x < width; x += 2 {
			p00 := unsafe.Add(row0, x*4)
			p01 := unsafe.Add(row0, (x+1)*4)
			p10 := unsafe.Add(row1, x*4)
			p11 := unsafe.Add(row1, (x+1)*4)

			r0 := uint32(*(*uint8)(p00))
			g0 := uint32(*(*uint8)(unsafe.Add(p00, 1)))
			b0 := uint32(*(*uint8)(unsafe.Add(p00, 2)))

			r1 := uint32(*(*uint8)(p01))
			g1 := uint32(*(*uint8)(unsafe.Add(p01, 1)))
			b1 := uint32(*(*uint8)(unsafe.Add(p01, 2)))

			r2 := uint32(*(*uint8)(p10))
			g2 := uint32(*(*uint8)(unsafe.Add(p10, 1)))
			b2 := uint32(*(*uint8)(unsafe.Add(p10, 2)))

			r3 := uint32(*(*uint8)(p11))
			g3 := uint32(*(*uint8)(unsafe.Add(p11, 1)))
			b3 := uint32(*(*uint8)(unsafe.Add(p11, 2)))

			rAvg := (r0 + r1 + r2 + r3) >> 2
			gAvg := (g0 + g1 + g2 + g3) >> 2
			bAvg := (b0 + b1 + b2 + b3) >> 2

			uVal := uLookupR[rAvg] + uLookupG[gAvg] + uLookupB[bAvg]
			vVal := vLookupR[rAvg] + vLookupG[gAvg] + vLookupB[bAvg]

			uvRow[x] = clampU8((uVal>>8) + 128)
			uvRow[x+1] = clampU8((vVal>>8) + 128)
		}
	}

	return nil
}

func clampU8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// Benchmark helper: measures conversion performance in ms per iteration.
func BenchmarkRGBAToNV12(src *image.RGBA, iterations int) (avgTimeMs float64) {
	if src == nil || iterations <= 0 {
		return 0
	}
	width := src.Bounds().Dx()
	height := src.Bounds().Dy()
	dst := make([]byte, width*height*3/2)

	_ = RGBAToNV12(src, dst, width, height)
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_ = RGBAToNV12(src, dst, width, height)
	}
	elapsed := time.Since(start)
	return float64(elapsed.Microseconds()) / 1000.0 / float64(iterations)
}

