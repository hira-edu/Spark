//go:build !windows

package main

// debugMsgBox is a no-op on non-Windows platforms
func debugMsgBox(title, message string) {
	// No GUI on non-Windows, just ignore
}
