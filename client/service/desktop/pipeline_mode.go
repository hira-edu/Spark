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

func isEnvTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// isWindowsSinglePipeline reports whether the app should hard-lock to the
// Windows GPU pipeline (DXGI NV12 + hardware H.264 + WebRTC).
//
// Uses NVIDIA NVENC for hardware H.264 encoding.
//
// Returns false if:
// - SPARK_FORCE_GDI=1 is set
// - SPARK_DISABLE_NVENC=1 is set
// - SPARK_CAPTURE_BACKEND selects a CPU backend
// - NVENC is not available (no NVIDIA GPU or driver)
//
// When false, falls back to CPU capture (DXGI/GDI) and tile-based transport.
func isWindowsSinglePipeline() bool {
	if isEnvTruthy(os.Getenv("SPARK_FORCE_GDI")) {
		return false
	}

	if raw := strings.TrimSpace(os.Getenv("SPARK_CAPTURE_BACKEND")); raw != "" {
		if mode, err := captureBackendFromString(raw); err == nil {
			if mode == CaptureBackendDXGI_NV12 {
				if isEnvTruthy(os.Getenv("SPARK_DISABLE_NVENC")) {
					return false
				}
				return checkNVENCAvailable()
			}
			return false
		}
	}

	if isEnvTruthy(os.Getenv("SPARK_DISABLE_NVENC")) {
		return false
	}

	if getConfiguredCaptureBackend() == CaptureBackendDXGI_NV12 {
		return checkNVENCAvailable()
	}

	if !isEnvTruthy(os.Getenv("SPARK_ENABLE_NVENC")) {
		return false
	}
	return checkNVENCAvailable()
}
