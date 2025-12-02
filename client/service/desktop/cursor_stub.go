//go:build !windows

package desktop

// StartCursorCapture is a no-op on non-Windows platforms
func StartCursorCapture(rawEvent []byte) {
	// Cursor capture only supported on Windows
}

// StopCursorCapture is a no-op on non-Windows platforms
func StopCursorCapture() {
	// No-op
}
