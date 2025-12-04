//go:build darwin

package desktop

func platformHardwareProbe() *HardwareCodecSupport {
	// macOS devices expose VideoToolbox by default which provides hardware
	// H.264/H.265 encoders backed by the system GPU.
	return &HardwareCodecSupport{
		VP8Available:  true,
		VP9Available:  true,
		H264Available: true,
		H265Available: true,
	}
}
