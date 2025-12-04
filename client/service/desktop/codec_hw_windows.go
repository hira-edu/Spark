//go:build windows

package desktop

import (
	"strings"

	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
)

type wmiVideoController struct {
	Name                 string
	AdapterCompatibility string
}

func platformHardwareProbe() *HardwareCodecSupport {
	support := &HardwareCodecSupport{}

	if err := windows.NewLazySystemDLL("mfplat.dll").Load(); err == nil {
		support.H264Available = true
	}

	hevcDLLs := []string{"mfhevcenc.dll", "mfh265enc.dll"}
	for _, dll := range hevcDLLs {
		if err := windows.NewLazySystemDLL(dll).Load(); err == nil {
			support.H265Available = true
			break
		}
	}

	var controllers []wmiVideoController
	if err := wmi.Query("SELECT Name, AdapterCompatibility FROM Win32_VideoController", &controllers); err == nil {
		for _, ctrl := range controllers {
			vendor := strings.ToLower(strings.TrimSpace(ctrl.AdapterCompatibility + " " + ctrl.Name))
			switch {
			case strings.Contains(vendor, "nvidia"):
				support.VP8Available = true
				support.VP9Available = true
				support.H264Available = true
				support.H265Available = true
			case strings.Contains(vendor, "amd"), strings.Contains(vendor, "radeon"):
				support.VP8Available = true
				support.VP9Available = true
				support.H264Available = true
			case strings.Contains(vendor, "intel"):
				support.VP8Available = true
				support.VP9Available = true
				support.H264Available = true
			}
		}
	}

	if support.H264Available && !support.VP8Available {
		support.VP8Available = true
		support.VP9Available = true
	}

	return support
}
