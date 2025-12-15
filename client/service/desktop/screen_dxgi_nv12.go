//go:build windows

package desktop

import (
	"Rocket/client/telemetry"
	"image"
)

// ScreenDXGINV12 is a wrapper for DXGINV12Capturer that implements ScreenCapture interface.
//
// **Purpose**: Integrate GPU-native NV12 capture into the existing Screen.Init() framework
//
// **Performance**:
//   - Capture: ~1ms (vs 10ms DXGI RGBA)
//   - Color conversion: ~1ms GPU (vs 15-20ms CPU)
//   - Total: ~2ms (vs 25-30ms)
//   - Speedup: 12-15x
//
// **Output**: CaptureFrame with GPU NV12 texture (for zero-copy encoding)
type ScreenDXGINV12 struct {
	displayIndex uint
	rect         image.Rectangle
	capturer     *DXGINV12Capturer
}

// Init initializes the DXGI NV12 capture backend.
func (s *ScreenDXGINV12) Init(displayIndex uint, rect image.Rectangle) error {
	s.displayIndex = displayIndex
	s.rect = rect

	// Create GPU-native capturer
	capturer, err := NewDXGINV12Capturer(displayIndex, rect)
	if err != nil {
		telemetry.LogStructured("WARN", "Failed to create DXGI NV12 capturer", map[string]interface{}{
			"display": displayIndex,
			"error":   err.Error(),
		})
		return err
	}

	s.capturer = capturer

	telemetry.LogStructured("INFO", "DXGI NV12 capture initialized successfully", map[string]interface{}{
		"display":        displayIndex,
		"width":          rect.Dx(),
		"height":         rect.Dy(),
		"has_video_proc": capturer.videoProcessor != nil,
		"backend":        "dxgi_nv12",
	})

	return nil
}

// Capture returns a frame with GPU NV12 texture (zero CPU copy).
func (s *ScreenDXGINV12) Capture() (*CaptureFrame, error) {
	if s.capturer == nil {
		return nil, errNoImage
	}

	frame, err := s.capturer.Capture()
	if err != nil {
		// Don't log errNoImage (it's expected when no screen updates)
		if err != errNoImage {
			telemetry.LogStructured("WARN", "DXGI NV12 capture failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
		return nil, err
	}

	// Frame contains GPU NV12 texture in frame.GPU field
	// CPU image is nil (zero-copy path)
	return frame, nil
}

// Release cleans up capture resources.
func (s *ScreenDXGINV12) Release() {
	if s.capturer != nil {
		s.capturer.Release()
		s.capturer = nil
	}

	telemetry.LogStructured("INFO", "DXGI NV12 capture released", map[string]interface{}{
		"display": s.displayIndex,
	})
}

// GetD3D11Device returns the D3D11 device for device sharing (used by encoder).
func (s *ScreenDXGINV12) GetD3D11Device() *iD3D11Device {
	if s.capturer == nil {
		return nil
	}
	return s.capturer.device
}

// Stats returns capture statistics.
func (s *ScreenDXGINV12) Stats() map[string]interface{} {
	if s.capturer == nil {
		return nil
	}
	return s.capturer.Stats()
}
