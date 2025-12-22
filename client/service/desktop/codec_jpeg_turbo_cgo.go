//go:build cgo && libjpegturbo

package desktop

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lturbojpeg
#cgo windows CFLAGS: -I"C:/libjpeg-turbo64/include"
#cgo windows LDFLAGS: -L"C:/libjpeg-turbo64/lib" -lturbojpeg

#include <turbojpeg.h>
#include <stdlib.h>
#include <string.h>

// encode_jpeg_turbo encodes RGBA data to JPEG using libjpeg-turbo.
// Returns the encoded size, or -1 on error.
static int encode_jpeg_turbo(
    unsigned char* rgba,
    int width,
    int height,
    int stride,
    int quality,
    unsigned char** outBuf,
    unsigned long* outSize
) {
    tjhandle handle = tjInitCompress();
    if (handle == NULL) {
        return -1;
    }

    // Convert RGBA to RGB (libjpeg-turbo doesn't support RGBA directly)
    int rgbStride = width * 3;
    unsigned char* rgb = (unsigned char*)malloc(rgbStride * height);
    if (rgb == NULL) {
        tjDestroy(handle);
        return -2;
    }

    // RGBA -> RGB conversion
    for (int y = 0; y < height; y++) {
        unsigned char* rgbRow = rgb + y * rgbStride;
        unsigned char* rgbaRow = rgba + y * stride;
        for (int x = 0; x < width; x++) {
            rgbRow[x*3 + 0] = rgbaRow[x*4 + 0]; // R
            rgbRow[x*3 + 1] = rgbaRow[x*4 + 1]; // G
            rgbRow[x*3 + 2] = rgbaRow[x*4 + 2]; // B
            // Skip alpha
        }
    }

    *outBuf = NULL;
    *outSize = 0;

    int result = tjCompress2(
        handle,
        rgb,
        width,
        rgbStride,
        height,
        TJPF_RGB,
        outBuf,
        outSize,
        TJSAMP_420,  // 4:2:0 subsampling (good compression)
        quality,
        TJFLAG_FASTDCT | TJFLAG_NOREALLOC
    );

    free(rgb);
    tjDestroy(handle);

    if (result != 0) {
        if (*outBuf != NULL) {
            tjFree(*outBuf);
            *outBuf = NULL;
        }
        return -3;
    }

    return (int)(*outSize);
}

// free_jpeg_buffer frees a buffer allocated by libjpeg-turbo.
static void free_jpeg_buffer(unsigned char* buf) {
    if (buf != NULL) {
        tjFree(buf);
    }
}
*/
import "C"

import (
	"errors"
	"image"
	"sync"
	"unsafe"
)

// LibjpegTurboCodec implements the Codec interface using libjpeg-turbo.
// Provides 2-4x faster JPEG encoding compared to Go's standard library.
type LibjpegTurboCodec struct {
	quality int
	pool    *sync.Pool
}

// NewLibjpegTurboCodec creates a new libjpeg-turbo based JPEG codec.
func NewLibjpegTurboCodec(quality int) *LibjpegTurboCodec {
	if quality < 1 {
		quality = 1
	}
	if quality > 100 {
		quality = 100
	}

	return &LibjpegTurboCodec{
		quality: quality,
		pool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 0, 64*1024) // 64KB initial capacity
				return &buf
			},
		},
	}
}

// Encode compresses an RGBA image to JPEG using libjpeg-turbo.
func (c *LibjpegTurboCodec) Encode(img *image.RGBA) ([]byte, error) {
	if img == nil {
		return nil, errors.New("nil image")
	}

	bounds := img.Rect
	width := bounds.Dx()
	height := bounds.Dy()

	if width <= 0 || height <= 0 {
		return nil, errors.New("invalid image dimensions")
	}

	// Get pointer to pixel data
	pixPtr := (*C.uchar)(unsafe.Pointer(&img.Pix[0]))

	var outBuf *C.uchar
	var outSize C.ulong

	result := C.encode_jpeg_turbo(
		pixPtr,
		C.int(width),
		C.int(height),
		C.int(img.Stride),
		C.int(c.quality),
		&outBuf,
		&outSize,
	)

	if result < 0 {
		return nil, errors.New("libjpeg-turbo encoding failed")
	}

	// Copy result to Go slice
	encoded := C.GoBytes(unsafe.Pointer(outBuf), C.int(outSize))

	// Free the C buffer
	C.free_jpeg_buffer(outBuf)

	return encoded, nil
}

// Name returns the codec identifier.
func (c *LibjpegTurboCodec) Name() string {
	return "jpeg-turbo"
}

// Type returns the codec type constant.
func (c *LibjpegTurboCodec) Type() int {
	return CodecTypeJPEG
}

// Quality returns the compression quality (0-100).
func (c *LibjpegTurboCodec) Quality() int {
	return c.quality
}

// IsHardwareAccelerated returns false (libjpeg-turbo uses SIMD, not GPU).
func (c *LibjpegTurboCodec) IsHardwareAccelerated() bool {
	return false
}

// SetQuality updates the quality setting.
func (c *LibjpegTurboCodec) SetQuality(quality int) {
	if quality < 1 {
		quality = 1
	}
	if quality > 100 {
		quality = 100
	}
	c.quality = quality
}
