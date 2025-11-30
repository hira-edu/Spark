//go:build !windows

package lifecycle

// NoopInstaller is a no-op implementation for non-Windows platforms
type NoopInstaller struct{}

// NewInstaller creates a no-op installer for non-Windows
func NewInstaller() *NoopInstaller {
	return &NoopInstaller{}
}

func (n *NoopInstaller) GetInstallPath() string { return "" }
func (n *NoopInstaller) IsInstalled() bool      { return false }
func (n *NoopInstaller) Install() error         { return nil }
