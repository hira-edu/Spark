package webrtc

import (
	"fmt"
	"image"
	"sync"
	"time"

	"Spark/client/service/desktop/encoder"
)

const (
	defaultVideoEncoderName = "mf-h264"
	videoFrameQueueSize     = 2
)

type videoPipeline struct {
	mu       sync.Mutex
	frames   chan videoFrame
	quit     chan struct{}
	running  bool
	encoder  encoder.VideoInstance
	cfg      encoder.VideoConfig
	lastDims image.Rectangle
}

type videoFrame struct {
	image     *image.RGBA
	timestamp time.Time
	duration  time.Duration
}

func newVideoPipeline() *videoPipeline {
	return &videoPipeline{
		frames: make(chan videoFrame, videoFrameQueueSize),
		quit:   make(chan struct{}),
	}
}

func (p *videoPipeline) submit(img *image.RGBA, fps int) {
	if p == nil || img == nil || fps <= 0 {
		return
	}
	frameCopy := cloneRGBA(img)
	select {
	case p.frames <- videoFrame{
		image:     frameCopy,
		timestamp: time.Now(),
		duration:  time.Second / time.Duration(fps),
	}:
	default:
		// Drop frame if encoder is backlogged.
	}
}

func (p *videoPipeline) start(m *Manager) {
	if p == nil || m == nil {
		return
	}
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.mu.Unlock()
	go p.loop(m)
}

func (p *videoPipeline) loop(m *Manager) {
	for {
		select {
		case frame := <-p.frames:
			sample, err := p.encode(frame)
			if err != nil {
				if err != encoder.ErrNoVideoSample {
					logger.Debugf("webrtc video encode error: %v", err)
				}
				continue
			}
			if len(sample.Data) == 0 {
				continue
			}
			m.broadcastVideoSample(sample)
		case <-p.quit:
			p.closeEncoder()
			return
		}
	}
}

func (p *videoPipeline) encode(frame videoFrame) (encoder.VideoSample, error) {
	if p == nil {
		return encoder.VideoSample{}, fmt.Errorf("video pipeline unavailable")
	}
	if frame.image == nil {
		return encoder.VideoSample{}, fmt.Errorf("video pipeline: nil frame")
	}
	if err := p.ensureEncoder(frame); err != nil {
		return encoder.VideoSample{}, err
	}
	return p.encoder.Encode(encoder.VideoFrame{
		Image:     frame.image,
		Timestamp: frame.timestamp,
		Duration:  frame.duration,
	})
}

func (p *videoPipeline) ensureEncoder(frame videoFrame) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	rect := frame.image.Rect
	if p.encoder != nil && rect.Eq(p.lastDims) {
		return nil
	}
	if p.encoder != nil {
		p.encoder.Close()
		p.encoder = nil
	}
	frameDur := frame.duration
	if frameDur <= 0 {
		frameDur = time.Second / 24
	}
	fps := int(time.Second / frameDur)
	cfg := encoder.VideoConfig{
		Name:    defaultVideoEncoderName,
		Width:   rect.Dx(),
		Height:  rect.Dy(),
		FPS:     fps,
		Bitrate: estimateBitrate(rect.Dx(), rect.Dy(), fps),
	}
	inst, err := encoder.Instance().OpenVideoEncoder(defaultVideoEncoderName, cfg)
	if err != nil {
		return err
	}
	p.encoder = inst
	p.cfg = cfg
	p.lastDims = rect
	return nil
}

func (p *videoPipeline) closeEncoder() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.encoder != nil {
		p.encoder.Close()
		p.encoder = nil
	}
}

func (p *videoPipeline) stop() {
	if p == nil {
		return
	}
	close(p.quit)
}

func cloneRGBA(src *image.RGBA) *image.RGBA {
	if src == nil {
		return nil
	}
	rect := src.Rect
	dst := image.NewRGBA(rect)
	rowBytes := rect.Dx() * 4
	for y := 0; y < rect.Dy(); y++ {
		copy(dst.Pix[y*dst.Stride:y*dst.Stride+rowBytes], src.Pix[y*src.Stride:y*src.Stride+rowBytes])
	}
	return dst
}

func estimateBitrate(width, height, fps int) int {
	if width <= 0 || height <= 0 || fps <= 0 {
		return 2_000_000
	}
	// Rough heuristic: bits per pixel * pixels * fps.
	bpp := 6 // ~6 bits per pixel.
	bitrate := width * height * fps * bpp
	min := 1_500_000
	max := 20_000_000
	if bitrate < min {
		return min
	}
	if bitrate > max {
		return max
	}
	return bitrate
}
