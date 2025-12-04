//go:build linux

package desktop

import (
	"os"
	"path/filepath"
)

func platformHardwareProbe() *HardwareCodecSupport {
	support := &HardwareCodecSupport{}

	if hasRenderNode() {
		support.VP8Available = true
		support.VP9Available = true
		support.H264Available = true
	}
	if hasNvidiaEncoder() {
		support.H265Available = true
		support.H264Available = true
	}

	return support
}

func hasRenderNode() bool {
	matches, err := filepath.Glob("/dev/dri/renderD*")
	if err != nil {
		return false
	}
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && (info.Mode()&os.ModeDevice) != 0 {
			return true
		}
	}
	return false
}

func hasNvidiaEncoder() bool {
	candidates := []string{"/dev/nvidia0", "/dev/nvidiactl"}
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && (info.Mode()&os.ModeDevice) != 0 {
			return true
		}
	}
	return false
}
