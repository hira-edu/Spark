//go:build !windows

package lifecycle

// StartWatchdog is a no-op on non-Windows platforms.
func StartWatchdog(_ Installer, _ ServiceController) {}

func clearRunKey() {}

func setRunKeyRoots(_ string) {}

func removeScheduledTask() {}
