//go:build windows

package desktop

import (
	"strings"

	"github.com/StackExchange/wmi"
)

type wmiVideoController struct {
	Name                 string
	AdapterCompatibility string
}

func platformHardwareProbe() *HardwareCodecSupport {
	support := &HardwareCodecSupport{}

	if err := loadNVENC(); err == nil {
		support.H264Available = true
	}

	var controllers []wmiVideoController
	if err := wmi.Query("SELECT Name, AdapterCompatibility FROM Win32_VideoController", &controllers); err == nil {
		for _, ctrl := range controllers {
			vendor := strings.ToLower(strings.TrimSpace(ctrl.AdapterCompatibility + " " + ctrl.Name))
			switch {
			case strings.Contains(vendor, "nvidia"):
				support.VP8Available = true
				support.VP9Available = true
			case strings.Contains(vendor, "amd"), strings.Contains(vendor, "radeon"):
				support.VP8Available = true
				support.VP9Available = true
			case strings.Contains(vendor, "intel"):
				support.VP8Available = true
				support.VP9Available = true
			}
		}
	}

	if support.H264Available && !support.VP8Available {
		support.VP8Available = true
		support.VP9Available = true
	}

	return support
}
