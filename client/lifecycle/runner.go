package lifecycle

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kataras/golog"
)

// Runner orchestrates the application lifecycle based on run mode
type Runner struct {
	app       Application
	installer Installer
	svcCtrl   ServiceController
}

// NewRunner creates a new lifecycle runner
func NewRunner(app Application, installer Installer, svcCtrl ServiceController) *Runner {
	return &Runner{
		app:       app,
		installer: installer,
		svcCtrl:   svcCtrl,
	}
}

// Run executes the appropriate action based on mode
func (r *Runner) Run(mode RunMode) error {
	golog.Infof("runner: Running in mode: %d", mode)

	switch mode {
	case RunModeInstall:
		golog.Info("runner: Mode = INSTALL")
		// Check if already installed
		if r.installer.IsInstalled() {
			// Already installed - update to latest version
			golog.Info("runner: service already installed, performing update")
			selfPath, err := os.Executable()
			if err != nil {
				golog.Errorf("runner: failed to get executable path: %v", err)
				return err
			}
			golog.Infof("runner: updating from %s", selfPath)

			installPath := r.installer.GetInstallPath()
			golog.Infof("runner: target install path: %s", installPath)

			// Temporarily disable persistence to allow service to stop
			golog.Info("runner: disabling persistence")
			DisablePersistence(installPath)

			// Stop the service
			golog.Info("runner: stopping service")
			if err := r.svcCtrl.Stop(); err != nil {
				golog.Warnf("runner: service stop returned error (may be okay): %v", err)
			}

			// Wait for service to stop
			golog.Info("runner: waiting for service to stop")
			time.Sleep(3 * time.Second)

			// Read new binary
			golog.Info("runner: reading new binary")
			selfBytes, err := os.ReadFile(selfPath)
			if err != nil {
				golog.Errorf("runner: failed to read new binary: %v", err)
				return err
			}
			golog.Infof("runner: read %d bytes from new binary", len(selfBytes))

			// Overwrite the installed binary
			golog.Infof("runner: writing to %s", installPath)
			if err := writeBinaryWithRetry(installPath, selfBytes); err != nil {
				golog.Errorf("runner: failed to write binary: %v", err)
				return err
			}
			golog.Info("runner: binary updated successfully")

			// Re-enable persistence
			golog.Info("runner: re-enabling persistence")
			EnablePersistence(installPath)

			// Restart the service
			golog.Info("runner: starting service")
			if err := r.svcCtrl.Start(); err != nil {
				golog.Errorf("runner: failed to start service: %v", err)
				return err
			}

			golog.Info("runner: update completed successfully")
			// Exit after update
			os.Exit(0)
		}
		// Perform fresh installation
		golog.Info("runner: performing fresh installation")
		err := r.installer.Install()
		if err != nil {
			golog.Errorf("runner: installation failed: %v", err)
			return err
		}
		golog.Info("runner: installation completed successfully")
		// Exit after installation
		os.Exit(0)
		return nil

	case RunModeService:
		// Run as Windows service
		golog.Info("runner: Mode = SERVICE (running as Windows service)")
		return RunAsService(r.app)

	case RunModeUninstall:
		golog.Info("runner: Mode = UNINSTALL")
		// Allow intentional removal by disabling persistence/watchdog and Run key.
		golog.Info("runner: Disabling persistence")
		DisablePersistence(r.installer.GetInstallPath())
		golog.Info("runner: Clearing registry run key")
		clearRunKey()
		golog.Info("runner: Removing scheduled task")
		removeScheduledTask()
		// Stop and remove service
		golog.Info("runner: Stopping service")
		r.svcCtrl.Stop()
		golog.Info("runner: Uninstalling service")
		if err := r.svcCtrl.Uninstall(); err != nil {
			golog.Errorf("runner: Failed to uninstall service: %v", err)
			return err
		}
		// Remove installed artifacts when supported
		if remover, ok := r.installer.(interface{ Remove() error }); ok {
			golog.Info("runner: Removing installed files")
			if err := remover.Remove(); err != nil {
				golog.Errorf("runner: Failed to remove files: %v", err)
				return err
			}
		}
		golog.Info("runner: Uninstall completed successfully")
		return nil

	case RunModeConsole:
		// Run directly in console (for debugging)
		golog.Info("runner: Mode = CONSOLE (running in user session, will connect to server)")
		return r.app.Run(context.Background())

	case RunModeUpdate:
		// Update mode is handled separately in client.go
		golog.Info("runner: Mode = UPDATE")
		return nil

	default:
		golog.Warnf("runner: Unknown mode %d, defaulting to console mode", mode)
		return r.app.Run(context.Background())
	}
}

func writeBinaryWithRetry(path string, data []byte) error {
	if runtime.GOOS == "windows" {
		terminateProcessByPath(path)
	}
	var lastErr error
	for i := 0; i < 5; i++ {
		if i > 0 {
			time.Sleep(1 * time.Second)
		}
		if err := os.WriteFile(path, data, 0755); err != nil {
			lastErr = err
			if runtime.GOOS == "windows" && isSharingViolation(err) {
				terminateProcessByPath(path)
				continue
			}
			return err
		}
		return nil
	}
	return lastErr
}

func terminateProcessByPath(path string) {
	name := filepath.Base(path)
	cmd := exec.Command("taskkill", "/F", "/IM", name, "/T")
	if err := cmd.Run(); err == nil {
		golog.Infof("runner: ensured no running %s processes before update", name)
	}
}

func isSharingViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "being used by another process") ||
		strings.Contains(msg, "sharing violation")
}
