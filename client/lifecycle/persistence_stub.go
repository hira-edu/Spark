//go:build !windows

package lifecycle

// DisablePersistence is a no-op on non-Windows platforms.
func DisablePersistence(_ string) {}

// EnablePersistence is a no-op on non-Windows platforms.
func EnablePersistence(_ string) {}
