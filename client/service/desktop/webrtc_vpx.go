//go:build cgo && vpx
// +build cgo,vpx

package desktop

import (
	"errors"
	"image"
	"io"
	"sync"
	"time"

	"github.com/pion/mediadevices/pkg/codec"
	"github.com/pion/mediadevices/pkg/codec/vpx"
	"github.com/pion/mediadevices/pkg/io/video"
	"github.com/pion/mediadevices/pkg/prop"
	"github.com/pion/webrtc/v4/pkg/media"
)

// vpxEncoder wraps libvpx VP8/VP9 encoding with encoder caching for performance.
// The encoder is created lazily and reused across frames of the same dimensions.
type vpxEncoder struct {
	codec            VPXCodec
	bitRate          int
	keyFrameInterval int

	// Cached encoder state
	mu          sync.Mutex
	cachedEnc   codec.ReadCloser
	cachedWidth int
	cachedHeight int
	frameQueue  chan *image.RGBA
	resultQueue chan encodeResult
	closed      bool
}

type encodeResult struct {
	sample media.Sample
	err    error
}

// NewVPXEncoder builds a VP8/VP9 encoder backed by libvpx (requires cgo + -tags vpx).
func NewVPXEncoder(codecType VPXCodec, cfg VPXEncoderConfig) (VPXEncoder, error) {
	switch codecType {
	case "", VPXCodecVP8:
		codecType = VPXCodecVP8
	case VPXCodecVP9:
	default:
		return nil, errors.New("unsupported vpx codec")
	}

	bitRate := cfg.BitRate
	if bitRate <= 0 {
		bitRate = 900_000
	}
	keyFrameInterval := cfg.KeyFrameInterval
	if keyFrameInterval <= 0 {
		keyFrameInterval = 60
	}

	return &vpxEncoder{
		codec:            codecType,
		bitRate:          bitRate,
		keyFrameInterval: keyFrameInterval,
	}, nil
}

func (e *vpxEncoder) Encode(img *image.RGBA, duration time.Duration) (media.Sample, error) {
	if img == nil {
		return media.Sample{}, errors.New("nil frame")
	}
	width := img.Bounds().Dx()
	height := img.Bounds().Dy()
	if width == 0 || height == 0 {
		return media.Sample{}, errors.New("invalid frame bounds")
	}
	if duration <= 0 {
		duration = time.Second / 30
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return media.Sample{}, errors.New("encoder closed")
	}

	// Check if we need to recreate the encoder (dimensions changed or first use)
	needNewEncoder := e.cachedEnc == nil || e.cachedWidth != width || e.cachedHeight != height

	if needNewEncoder {
		// Close existing encoder if any
		if e.cachedEnc != nil {
			e.cachedEnc.Close()
			e.cachedEnc = nil
		}

		// Create new encoder with proper dimensions
		builder, err := e.videoBuilder()
		if err != nil {
			return media.Sample{}, err
		}

		mediaProps := prop.Media{
			Video: prop.Video{
				Width:  width,
				Height: height,
			},
		}

		// Create a streaming frame reader
		reader := newStreamingFrameReader()
		enc, err := builder.BuildVideoEncoder(reader, mediaProps)
		if err != nil {
			return media.Sample{}, err
		}

		e.cachedEnc = enc
		e.cachedWidth = width
		e.cachedHeight = height
		e.frameQueue = reader.frameQueue
		e.resultQueue = make(chan encodeResult, 1)

		// Start background encoding goroutine
		go e.encodeLoop(enc, reader)
	}

	// Send frame to encoder
	select {
	case e.frameQueue <- img:
	default:
		// Drop frame if encoder is backed up
		return media.Sample{}, nil
	}

	// Wait for result
	select {
	case result := <-e.resultQueue:
		if result.err != nil {
			return media.Sample{}, result.err
		}
		result.sample.Duration = duration
		return result.sample, nil
	case <-time.After(100 * time.Millisecond):
		return media.Sample{}, errors.New("encoder timeout")
	}
}

func (e *vpxEncoder) encodeLoop(enc codec.ReadCloser, reader *streamingFrameReader) {
	for {
		data, release, err := enc.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			e.mu.Lock()
			if !e.closed && e.resultQueue != nil {
				select {
				case e.resultQueue <- encodeResult{err: err}:
				default:
				}
			}
			e.mu.Unlock()
			return
		}

		sample := media.Sample{
			Data: append([]byte(nil), data...),
		}
		if release != nil {
			release()
		}

		e.mu.Lock()
		if !e.closed && e.resultQueue != nil {
			select {
			case e.resultQueue <- encodeResult{sample: sample}:
			default:
			}
		}
		e.mu.Unlock()
	}
}

func (e *vpxEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.closed = true

	if e.frameQueue != nil {
		close(e.frameQueue)
		e.frameQueue = nil
	}

	if e.cachedEnc != nil {
		err := e.cachedEnc.Close()
		e.cachedEnc = nil
		return err
	}

	return nil
}

// streamingFrameReader provides frames to the encoder on demand
type streamingFrameReader struct {
	frameQueue chan *image.RGBA
}

func newStreamingFrameReader() *streamingFrameReader {
	return &streamingFrameReader{
		frameQueue: make(chan *image.RGBA, 2),
	}
}

func (r *streamingFrameReader) Read() (image.Image, func(), error) {
	frame, ok := <-r.frameQueue
	if !ok {
		return nil, nil, io.EOF
	}
	return frame, func() {}, nil
}

// Implement video.Reader interface
var _ video.Reader = (*streamingFrameReader)(nil)

func (e *vpxEncoder) videoBuilder() (codec.VideoEncoderBuilder, error) {
	switch e.codec {
	case VPXCodecVP9:
		params, err := vpx.NewVP9Params()
		if err != nil {
			return nil, err
		}
		params.BitRate = e.bitRate
		params.KeyFrameInterval = e.keyFrameInterval
		return &params, nil
	default:
		params, err := vpx.NewVP8Params()
		if err != nil {
			return nil, err
		}
		params.BitRate = e.bitRate
		params.KeyFrameInterval = e.keyFrameInterval
		return &params, nil
	}
}
