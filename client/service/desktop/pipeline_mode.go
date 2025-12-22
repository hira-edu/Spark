package desktop

import (
	"os"
	"strings"
)

// isWindowsSinglePipeline reports whether the app should hard-lock to the
// Windows GPU pipeline (DXGI NV12 + hardware H.264 + WebRTC).
//
// Uses NVIDIA NVENC for hardware H.264 encoding, bypassing the unreliable
// Windows Media Foundation encoder which fires MEError and breaks after frame 1.
//
// Set SPARK_DISABLE_NVENC=1 to disable and use fallback tile encoding.
func isWindowsSinglePipeline() bool {
	val := strings.TrimSpace(os.Getenv("SPARK_DISABLE_NVENC"))
	if val == "1" || strings.ToLower(val) == "true" {
		return false
	}
	return true
}
