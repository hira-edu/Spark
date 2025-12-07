//go:build !windows
// +build !windows

package lifecycle

import (
	"errors"
	"time"
)

// WindowsInstaller is a stub for non-Windows platforms
type WindowsInstaller struct{}

func (w *WindowsInstaller) Install() error {
	return errors.New("Windows installer not supported on this platform")
}

func (w *WindowsInstaller) IsInstalled() bool {
	return false
}

func (w *WindowsInstaller) GetInstallPath() string {
	return ""
}

// CleanupResult tracks what was cleaned during cleanOldInstall
type CleanupResult struct {
	PersistenceDisabled bool
	ServiceStopped      bool
	ServiceUninstalled  bool
	ProcessesKilled     bool
	TasksRemoved        bool
	Errors              []error
}

func (w *WindowsInstaller) cleanOldInstall() *CleanupResult {
	// No-op on non-Windows
	return nil
}

// acquireUpdateMutex is a no-op on non-Windows platforms
func acquireUpdateMutex(timeout time.Duration) (func(), error) {
	return func() {}, nil
}

// waitForServiceState is a no-op on non-Windows platforms
func waitForServiceState(ctrl ServiceController, desired string, timeout time.Duration) {
	time.Sleep(timeout / 5) // Brief wait as fallback
}

// scheduleSelfDelete is a no-op on non-Windows platforms
func scheduleSelfDelete(path string) {
	// No-op on non-Windows
}
