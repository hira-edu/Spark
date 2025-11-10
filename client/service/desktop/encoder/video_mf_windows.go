//go:build windows && cgo

package encoder

/*
#cgo CXXFLAGS: -std=c++17 -DUNICODE -D_UNICODE
#cgo LDFLAGS: -lmfplat -lmf -lmfcore -lmfuuid -lole32 -loleaut32 -lwmcodecdspuuid
#include "mf_h264.h"
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"
)

type mfH264Factory struct{}

func registerMediaFoundationEncoder(m *Manager) {
	if m == nil {
		return
	}
	m.registerVideoFactory(&mfH264Factory{})
}

func (mfH264Factory) Capability() Capability {
	return Capability{
		Name:         "mf-h264",
		Type:         "mediafoundation-h264",
		Codec:        "h264",
		Lossless:     false,
		Hardware:     true,
		Description:  "Media Foundation H.264 encoder",
		Experimental: true,
	}
}

func (mfH264Factory) Open(cfg VideoConfig) (VideoInstance, error) {
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return nil, fmt.Errorf("mf-h264: invalid dimensions %dx%d", cfg.Width, cfg.Height)
	}
	if cfg.FPS <= 0 {
		return nil, fmt.Errorf("mf-h264: fps must be > 0")
	}
	if cfg.Bitrate <= 0 {
		return nil, fmt.Errorf("mf-h264: bitrate must be > 0")
	}
	var handle C.SparkMFEncoderHandle
	hr := C.SparkMFEncoderCreate(
		C.int(cfg.Width),
		C.int(cfg.Height),
		C.int(cfg.FPS),
		C.int(cfg.Bitrate),
		&handle,
	)
	if hr != C.S_OK {
		return nil, fmt.Errorf("mf-h264: encoder init failed (HRESULT=0x%X)", uint32(uintptr(hr)))
	}
	return &mfH264Encoder{
		handle: handle,
		width:  cfg.Width,
		height: cfg.Height,
		fps:    cfg.FPS,
	}, nil
}

type mfH264Encoder struct {
	handle C.SparkMFEncoderHandle
	width  int
	height int
	fps    int
}

func (m *mfH264Encoder) Encode(frame VideoFrame) (VideoSample, error) {
	if m == nil || m.handle == nil {
		return VideoSample{}, fmt.Errorf("mf-h264: encoder closed")
	}
	if frame.Image == nil {
		return VideoSample{}, fmt.Errorf("mf-h264: nil frame")
	}
	if frame.Image.Rect.Dx() != m.width || frame.Image.Rect.Dy() != m.height {
		return VideoSample{}, fmt.Errorf("mf-h264: frame dimensions mismatch (%dx%d != %dx%d)", frame.Image.Rect.Dx(), frame.Image.Rect.Dy(), m.width, m.height)
	}
	pix := frame.Image.Pix
	if len(pix) == 0 {
		return VideoSample{}, fmt.Errorf("mf-h264: empty pixel buffer")
	}
	ts := frame.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	duration := frame.Duration
	if duration <= 0 && m.fps > 0 {
		duration = time.Second / time.Duration(m.fps)
	}
	var outPtr *C.uint8_t
	var outSize C.int
	var keyframe C.int
	hr := C.SparkMFEncoderEncode(
		m.handle,
		(*C.uint8_t)(unsafe.Pointer(&pix[0])),
		C.int(frame.Image.Stride),
		C.longlong(ts.UnixNano()/100),
		C.longlong(duration.Nanoseconds()/100),
		&outPtr,
		&outSize,
		&keyframe,
	)
	if hr == C.S_FALSE {
		return VideoSample{}, ErrNoVideoSample
	}
	if hr != C.S_OK {
		return VideoSample{}, fmt.Errorf("mf-h264: encode failed (HRESULT=0x%X)", uint32(uintptr(hr)))
	}
	defer C.SparkMFEncoderFreeBuffer(outPtr)
	data := C.GoBytes(unsafe.Pointer(outPtr), outSize)
	return VideoSample{
		Data:      data,
		Timestamp: ts,
		Duration:  duration,
		Keyframe:  keyframe != 0,
	}, nil
}

func (m *mfH264Encoder) Close() error {
	if m == nil {
		return nil
	}
	if m.handle != nil {
		C.SparkMFEncoderDestroy(m.handle)
		m.handle = nil
	}
	return nil
}

// Ensure mfH264Encoder implements VideoInstance.
var _ VideoInstance = (*mfH264Encoder)(nil)

// Ensure mfH264Factory implements VideoFactory.
var _ VideoFactory = (*mfH264Factory)(nil)
