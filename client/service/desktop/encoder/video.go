package encoder

import (
	"fmt"
	"image"
	"time"
)

// VideoConfig describes the desired output properties for a video encoder.
type VideoConfig struct {
	Name    string
	Width   int
	Height  int
	FPS     int
	Bitrate int // bits per second
}

// VideoFrame encapsulates a captured RGBA frame ready for encoding.
type VideoFrame struct {
	Image     *image.RGBA
	Timestamp time.Time
	Duration  time.Duration
}

// VideoSample is the encoded output produced by a hardware/software encoder.
type VideoSample struct {
	Data      []byte
	Timestamp time.Time
	Duration  time.Duration
	Keyframe  bool
}

var ErrNoVideoSample = fmt.Errorf("video: no sample ready")

// VideoFactory can create VideoInstance encoders for a specific capability.
type VideoFactory interface {
	Capability() Capability
	Open(cfg VideoConfig) (VideoInstance, error)
}

// VideoInstance encodes RGBA frames into codec-specific samples (e.g., H264).
type VideoInstance interface {
	Encode(frame VideoFrame) (VideoSample, error)
	Close() error
}
