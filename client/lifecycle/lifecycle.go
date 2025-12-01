package lifecycle

import "context"

// Application defines the core application contract
type Application interface {
	Run(ctx context.Context) error
}

// ServiceController manages Windows service lifecycle
type ServiceController interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Status() (string, error)
}

// Installer handles self-installation
type Installer interface {
	Install() error
	IsInstalled() bool
	GetInstallPath() string
}

// RunMode determines how application runs
type RunMode int

const (
	RunModeInstall RunMode = iota
	RunModeService
	RunModeConsole
	RunModeUninstall
	RunModeUpdate
	RunModeUIOnly
)
