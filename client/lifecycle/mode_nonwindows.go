//go:build !windows
// +build !windows

package lifecycle

// Stub for non-Windows platforms.
func serviceInstalledAndRunning() bool {
	return false
}
