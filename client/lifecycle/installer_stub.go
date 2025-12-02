//go:build !windows
// +build !windows

package lifecycle

import "errors"

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

func (w *WindowsInstaller) cleanOldInstall() {
	// No-op on non-Windows
}
