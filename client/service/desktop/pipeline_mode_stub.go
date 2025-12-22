//go:build !windows

package desktop

// isWindowsSinglePipeline returns false on non-Windows platforms.
// Single pipeline mode (DXGI NV12 + NVENC) is only available on Windows.
func isWindowsSinglePipeline() bool {
	return false
}
