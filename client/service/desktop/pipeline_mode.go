//go:build windows

package desktop

import (
	"os"
	"strings"
	"sync"
)

var (
	nvencAvailable     bool
	nvencAvailableOnce sync.Once
)

// checkNVENCAvailable tests if NVENC is available by attempting to load the DLL.
func checkNVENCAvailable() bool {
	nvencAvailableOnce.Do(func() {
		if err := loadNVENC(); err == nil {
			nvencAvailable = true
		}
	})
	return nvencAvailable
}

// isWindowsSinglePipeline reports whether the app should hard-lock to the
// Windows GPU pipeline (DXGI NV12 + hardware H.264 + WebRTC).
//
// Uses NVIDIA NVENC for hardware H.264 encoding, bypassing the unreliable
// Windows Media Foundation encoder which fires MEError and breaks after frame 1.
//
// Returns false if:
// - SPARK_DISABLE_NVENC=1 is set
// - NVENC is not available (no NVIDIA GPU or driver)
//
// When false, falls back to tile-based WebSocket encoding.
func isWindowsSinglePipeline() bool {
	val := strings.TrimSpace(os.Getenv("SPARK_DISABLE_NVENC"))
	if val == "1" || strings.ToLower(val) == "true" {
		return false
	}
	// Only enable single pipeline if NVENC is actually available
	return checkNVENCAvailable()
}
