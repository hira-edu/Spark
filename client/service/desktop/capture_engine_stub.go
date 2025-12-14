//go:build !windows

package desktop

import (
	"errors"
	"image"
	"time"
)

var errCaptureEngineTimeout = errors.New("desktop capture engine timeout")

type desktopCaptureEngine struct{}

func newDesktopCaptureEngine(_ uint, _ image.Rectangle, _ CaptureBackendMode) *desktopCaptureEngine {
	return &desktopCaptureEngine{}
}

func (e *desktopCaptureEngine) Stop() {}

func (e *desktopCaptureEngine) Capture(_ time.Duration) (*CaptureFrame, error) {
	return nil, errCaptureEngineTimeout
}
