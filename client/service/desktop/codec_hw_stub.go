//go:build !windows && !linux && !darwin

package desktop

func platformHardwareProbe() *HardwareCodecSupport {
	return &HardwareCodecSupport{}
}
