//go:build !windows

package lifecycle

import "context"

// RunAsService runs the application directly on non-Windows platforms
func RunAsService(app Application) error {
	return app.Run(context.Background())
}

// NoopServiceController is a no-op implementation for non-Windows platforms
type NoopServiceController struct{}

// WindowsServiceController is an alias for NoopServiceController on non-Windows platforms
// This allows runner.go type assertions to work (they'll just fail gracefully)
type WindowsServiceController = NoopServiceController

// NewServiceController creates a no-op service controller for non-Windows
func NewServiceController(execPath string) *NoopServiceController {
	return &NoopServiceController{}
}

func (n *NoopServiceController) Install() error          { return nil }
func (n *NoopServiceController) Uninstall() error        { return nil }
func (n *NoopServiceController) Start() error            { return nil }
func (n *NoopServiceController) Stop() error             { return nil }
func (n *NoopServiceController) Status() (string, error) { return "running", nil }
