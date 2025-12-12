//go:build !windows
// +build !windows

package desktop

import (
	"Rocket/client/telemetry"
	"image"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/kbinani/screenshot"
)

// Capture statistics for non-Windows platforms
var (
	captureCount   atomic.Uint64
	captureErrors  atomic.Uint64
	captureLatency atomic.Int64 // nanoseconds (last capture)
)

// CaptureStats returns capture telemetry for non-Windows platforms.
func CaptureStats() map[string]interface{} {
	return map[string]interface{}{
		"captures_total":  captureCount.Load(),
		"errors_total":    captureErrors.Load(),
		"last_latency_us": captureLatency.Load() / 1000, // microseconds
		"platform":        runtime.GOOS,
		"arch":            runtime.GOARCH,
		"backend":         "kbinani/screenshot",
	}
}

type Screen struct {
	rect         image.Rectangle
	displayIndex uint
	initialized  bool
}

func (s *Screen) Init(displayIndex uint, rect image.Rectangle) {
	s.rect = rect
	s.displayIndex = displayIndex

	// Log initialization with platform info
	telemetry.LogStructured("INFO", "Desktop capture initialized", map[string]interface{}{
		"display":  displayIndex,
		"rect":     rect.String(),
		"platform": runtime.GOOS,
		"arch":     runtime.GOARCH,
		"backend":  "kbinani/screenshot", // X11/XCB on Linux, CoreGraphics on macOS
	})

	// Perform a test capture to validate the display is accessible
	testStart := time.Now()
	testImg, testErr := screenshot.CaptureRect(rect)
	testLatency := time.Since(testStart)

	if testErr != nil {
		telemetry.LogStructured("WARN", "Test capture failed during initialization", map[string]interface{}{
			"error":   testErr.Error(),
			"display": displayIndex,
		})
	} else if testImg == nil || testImg.Bounds().Empty() {
		telemetry.LogStructured("WARN", "Test capture returned empty image", map[string]interface{}{
			"display": displayIndex,
			"rect":    rect.String(),
		})
	} else {
		telemetry.LogStructured("INFO", "Test capture successful", map[string]interface{}{
			"display":    displayIndex,
			"latency_ms": testLatency.Milliseconds(),
			"width":      testImg.Bounds().Dx(),
			"height":     testImg.Bounds().Dy(),
		})
		s.initialized = true
	}
}

func (s *Screen) Capture() (*CaptureFrame, error) {
	start := time.Now()
	img, err := screenshot.CaptureRect(s.rect)
	latency := time.Since(start)

	captureLatency.Store(latency.Nanoseconds())
	captureCount.Add(1)

	if err != nil {
		captureErrors.Add(1)
		// Log errors periodically (every 100 errors) to avoid log spam
		if captureErrors.Load()%100 == 1 {
			telemetry.LogStructured("WARN", "Capture error", map[string]interface{}{
				"error":         err.Error(),
				"display":       s.displayIndex,
				"error_count":   captureErrors.Load(),
				"capture_count": captureCount.Load(),
			})
		}
		return nil, err
	}

	return &CaptureFrame{Image: img}, nil
}

func (s *Screen) Release() {
	if s.initialized {
		telemetry.LogStructured("INFO", "Desktop capture released", map[string]interface{}{
			"display":        s.displayIndex,
			"platform":       runtime.GOOS,
			"total_captures": captureCount.Load(),
			"total_errors":   captureErrors.Load(),
		})
	}
}
