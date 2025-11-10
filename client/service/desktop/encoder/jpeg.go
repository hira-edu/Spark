package encoder

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
)

const defaultJPEGQuality = 70

type softwareJPEGEncoder struct{}

func newSoftwareJPEGEncoder() *softwareJPEGEncoder {
	return &softwareJPEGEncoder{}
}

func (softwareJPEGEncoder) Name() string {
	return "jpeg-software"
}

func (softwareJPEGEncoder) Capability() Capability {
	return Capability{
		Name:           "jpeg-software",
		Type:           "software-jpeg",
		Codec:          "jpeg",
		Lossless:       false,
		Hardware:       false,
		DefaultQuality: defaultJPEGQuality,
		Description:    "CPU JPEG encoder",
	}
}

func (e *softwareJPEGEncoder) Encode(req Request) ([]byte, error) {
	if req.Frame == nil {
		return nil, fmt.Errorf("encoder(%s): nil frame", e.Name())
	}
	if req.Rect.Empty() {
		return nil, fmt.Errorf("encoder(%s): empty rect", e.Name())
	}
	if !req.Rect.In(req.Frame.Rect) {
		return nil, fmt.Errorf("encoder(%s): rect %+v outside frame %+v", e.Name(), req.Rect, req.Frame.Rect)
	}
	width := req.Rect.Dx()
	height := req.Rect.Dy()
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("encoder(%s): invalid rect dimensions %dx%d", e.Name(), width, height)
	}
	buf := make([]byte, width*height*4)
	bufPos := 0
	imgPos := req.Frame.PixOffset(req.Rect.Min.X, req.Rect.Min.Y)
	for y := 0; y < height; y++ {
		copy(buf[bufPos:bufPos+width*4], req.Frame.Pix[imgPos:imgPos+width*4])
		bufPos += width * 4
		imgPos += req.Frame.Stride
	}
	subImg := &image.RGBA{
		Pix:    buf,
		Stride: width * 4,
		Rect:   image.Rect(0, 0, width, height),
	}
	quality := req.Quality
	if quality <= 0 {
		quality = defaultJPEGQuality
	}
	var writer bytes.Buffer
	if err := jpeg.Encode(&writer, subImg, &jpeg.Options{Quality: quality}); err != nil {
		return nil, fmt.Errorf("encoder(%s): jpeg encode failed: %w", e.Name(), err)
	}
	return writer.Bytes(), nil
}
