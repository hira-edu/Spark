//go:build !windows

package lifecycle

// EnsureElevated is a no-op on non-Windows platforms.
func EnsureElevated() {}
