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

func CaptureEngineStats() map[string]any {
	return map[string]any{
		"engine_starts_total":   0,
		"engine_stops_total":    0,
		"engine_init_done":      false,
		"engine_capture_calls":  0,
		"engine_req_enqueued":   0,
		"engine_req_received":   0,
		"engine_resp_sent":      0,
		"engine_timeouts_total": 0,
		"engine_override":       "unsupported",
	}
}
