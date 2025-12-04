//go:build !windows

package desktop

import "sync/atomic"

// cursorSessionState holds per-session cursor capture state (stub for non-Windows)
type cursorSessionState struct {
	active      atomic.Bool
	lastHash    uint32
	lastVisible bool
	lastX       int32
	lastY       int32
}

// newCursorSessionState creates a new cursor state for a session
func newCursorSessionState() *cursorSessionState {
	return &cursorSessionState{}
}

// StartCursorCapture is a no-op on non-Windows platforms
func StartCursorCapture(rawEvent []byte) {
	// Cursor capture only supported on Windows
	// TODO: Implement for Linux (X11/Wayland) and macOS (CoreGraphics)
}

// StopCursorCapture is a no-op on non-Windows platforms
func StopCursorCapture() {
	// No-op
}
