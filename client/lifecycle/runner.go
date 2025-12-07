package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kataras/golog"
)

// UpdateError represents an error during update with rollback capability
type UpdateError struct {
	Phase   string
	Err     error
	CanRoll bool
}

func (e *UpdateError) Error() string {
	return fmt.Sprintf("update failed at %s: %v", e.Phase, e.Err)
}

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
			if err := r.performUpdate(); err != nil {
				golog.Errorf("runner: update failed: %v", err)
				return err
			}
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

	case RunModeUIOnly:
		// UI-only mode: no WebSocket connection, Session 0 service handles communication
		golog.Info("runner: Mode = UI_ONLY (UI in user session, no WebSocket connection)")
		golog.Info("runner: Session 0 service maintains server connection, this process handles UI only")
		// Start desktop bridge for handling IPC from Session 0
		if runtime.GOOS == "windows" {
			return RunUIOnlyMode()
		}
		// Non-Windows: just block
		select {}

	case RunModeNoop:
		// No-op mode: service is already running, just exit silently
		golog.Info("runner: Mode = NOOP (service already running, exiting)")
		return nil

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

// performUpdate handles the complete update process with proper synchronization,
// service re-registration, and rollback capability.
func (r *Runner) performUpdate() error {
	golog.Info("runner: service already installed, performing update")

	selfPath, err := os.Executable()
	if err != nil {
		golog.Errorf("runner: failed to get executable path: %v", err)
		return &UpdateError{Phase: "get_executable", Err: err}
	}
	golog.Infof("runner: updating from %s", selfPath)

	installPath := r.installer.GetInstallPath()
	golog.Infof("runner: target install path: %s", installPath)

	// Acquire update mutex to prevent concurrent updates
	golog.Info("runner: acquiring update mutex")
	release, err := acquireUpdateMutex(30 * time.Second)
	if err != nil {
		golog.Errorf("runner: failed to acquire update mutex: %v", err)
		return &UpdateError{Phase: "acquire_mutex", Err: err}
	}
	defer release()
	golog.Info("runner: update mutex acquired")

	// Create backup of current binary for rollback
	backupPath := installPath + ".backup"
	var hasBackup bool
	if _, err := os.Stat(installPath); err == nil {
		golog.Info("runner: creating backup of current binary")
		if backupErr := copyFileAtomic(installPath, backupPath); backupErr != nil {
			golog.Warnf("runner: backup creation failed (continuing): %v", backupErr)
		} else {
			hasBackup = true
			golog.Infof("runner: backup created at %s", backupPath)
		}
	}

	serviceRegistrationRemoved := false

	// Rollback helper
	rollback := func() {
		if hasBackup {
			golog.Warn("runner: attempting rollback from backup")
			if rbErr := copyFileAtomic(backupPath, installPath); rbErr != nil {
				golog.Errorf("runner: rollback failed: %v", rbErr)
			} else {
				golog.Info("runner: rollback successful")
			}
		}
	}

	// Restore helper reinstalls/starts the prior service registration if cleanup removed it
	restoreService := func() {
		if !serviceRegistrationRemoved {
			return
		}
		golog.Info("runner: restoring service registration after failed update")
		if err := r.svcCtrl.Install(); err != nil {
			golog.Errorf("runner: failed to restore service registration: %v", err)
			return
		}
		serviceRegistrationRemoved = false
		if err := r.svcCtrl.Start(); err != nil {
			golog.Warnf("runner: restored service registration but start failed: %v", err)
		} else {
			golog.Info("runner: restored service registration and restarted service")
		}
	}

	// Temporarily disable persistence to allow service to stop
	golog.Info("runner: disabling persistence")
	DisablePersistence(installPath)

	// Stop the service
	golog.Info("runner: stopping service")
	if err := r.svcCtrl.Stop(); err != nil {
		golog.Warnf("runner: service stop returned error (may be okay): %v", err)
	}

	// Wait for service to actually stop using proper state polling
	golog.Info("runner: waiting for service to stop")
	if wsc, ok := r.svcCtrl.(*WindowsServiceController); ok {
		waitForServiceState(wsc, "stopped", 15*time.Second)
	} else {
		// Fallback for non-Windows or other implementations
		time.Sleep(3 * time.Second)
	}

	// Best-effort cleanup of watchdog/run keys/stray processes to prevent respawn during update
	// Note: cleanOldInstall() uninstalls the service, so we must re-register it later
	if wi, ok := r.installer.(*WindowsInstaller); ok {
		golog.Info("runner: cleaning old installation")
		if result := wi.cleanOldInstall(); result != nil && result.ServiceUninstalled {
			serviceRegistrationRemoved = true
		}
	}

	// Read new binary
	golog.Info("runner: reading new binary")
	selfBytes, err := os.ReadFile(selfPath)
	if err != nil {
		golog.Errorf("runner: failed to read new binary: %v", err)
		EnablePersistence(installPath)
		restoreService()
		return &UpdateError{Phase: "read_binary", Err: err}
	}
	golog.Infof("runner: read %d bytes from new binary", len(selfBytes))

	// Overwrite the installed binary
	golog.Infof("runner: writing to %s", installPath)
	if err := writeBinaryWithRetry(installPath, selfBytes); err != nil {
		golog.Errorf("runner: failed to write binary: %v", err)
		rollback()
		EnablePersistence(installPath)
		restoreService()
		return &UpdateError{Phase: "write_binary", Err: err, CanRoll: hasBackup}
	}
	golog.Info("runner: binary updated successfully")

	// Copy support DLLs if any exist alongside the new binary
	golog.Info("runner: copying support DLLs")
	CopySupportDLLs(filepath.Dir(selfPath), filepath.Dir(installPath))

	// Re-register the service if cleanOldInstall removed it
	if serviceRegistrationRemoved {
		golog.Info("runner: ensuring service registration after cleanup")
		if err := r.svcCtrl.Install(); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "already exists") || strings.Contains(errStr, "already installed") {
				golog.Warn("runner: service already registered, continuing")
				serviceRegistrationRemoved = false
			} else {
				golog.Errorf("runner: service install failed: %v", err)
				rollback()
				EnablePersistence(installPath)
				restoreService()
				return &UpdateError{Phase: "reinstall_service", Err: err, CanRoll: hasBackup}
			}
		} else {
			golog.Info("runner: service registration refreshed")
			serviceRegistrationRemoved = false
		}
	}

	// Re-enable persistence
	golog.Info("runner: re-enabling persistence")
	EnablePersistence(installPath)

	// Restart the service
	golog.Info("runner: starting service")
	if err := r.svcCtrl.Start(); err != nil {
		golog.Errorf("runner: failed to start service: %v", err)
		// Try one more time after a brief delay
		time.Sleep(2 * time.Second)
		if retryErr := r.svcCtrl.Start(); retryErr != nil {
			golog.Errorf("runner: service start retry also failed: %v", retryErr)
			return &UpdateError{Phase: "start_service", Err: err}
		}
		golog.Info("runner: service started on retry")
	}

	// Cleanup backup after successful update (delayed)
	if hasBackup {
		go func() {
			time.Sleep(5 * time.Minute)
			os.Remove(backupPath)
			golog.Debug("runner: removed update backup")
		}()
	}

	// Schedule deletion of the updater binary if different from install target
	if selfPath != installPath {
		scheduleSelfDelete(selfPath)
	}

	golog.Info("runner: update completed successfully")
	return nil
}

// copyFileAtomic copies a file atomically using temp file and rename
func copyFileAtomic(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create temp file in same directory for atomic rename
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".tmp_")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	// Copy contents
	srcInfo, err := srcFile.Stat()
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := srcFile.Read(buf)
		if n > 0 {
			if _, writeErr := tmpFile.Write(buf[:n]); writeErr != nil {
				tmpFile.Close()
				os.Remove(tmpPath)
				return writeErr
			}
		}
		if readErr != nil {
			break
		}
	}

	// Sync and close
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	tmpFile.Close()

	// Set permissions
	os.Chmod(tmpPath, srcInfo.Mode())

	// Atomic rename
	if err := os.Rename(tmpPath, dst); err != nil {
		os.Remove(tmpPath)
		return err
	}

	return nil
}

type supportDLLDescriptor struct {
	Name   string
	SHA256 string
}

var trustedSupportDLLs = []supportDLLDescriptor{
	{Name: "libopus-0.dll", SHA256: "6304b7fe8cf3a307080e43a6aed12b8d5fa506563793a2ebe3fe0c698770f9d9"},
	{Name: "libopusfile-0.dll", SHA256: "4d4e7eec10982fc8d6f6ef58175f9a80a09582a30b966371f26c16b640571660"},
	{Name: "libportaudio.dll", SHA256: "868ff31c6d8341cbbc330ec103393f7e38d82553a8df44a8e513662245e3af29"},
	{Name: "libogg-0.dll", SHA256: "5513d25e3e9fcb4ac195ec8bcfbd82402bcecb2b3bdbb256a7eedd4ed886a87d"},
}

// CopySupportDLLs copies known support DLLs from srcDir to dstDir after verifying their hashes.
func CopySupportDLLs(srcDir, dstDir string) {
	if srcDir == "" || dstDir == "" {
		return
	}

	srcDir = filepath.Clean(srcDir)
	dstDir = filepath.Clean(dstDir)

	for _, dll := range trustedSupportDLLs {
		srcPath := filepath.Join(srcDir, dll.Name)
		info, err := os.Stat(srcPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				golog.Warnf("runner: unable to stat support DLL %s: %v", dll.Name, err)
			}
			continue
		}
		if info.IsDir() {
			continue
		}

		hash, err := fileSHA256Hex(srcPath)
		if err != nil {
			golog.Warnf("runner: failed to hash support DLL %s: %v", dll.Name, err)
			continue
		}
		if !strings.EqualFold(hash, dll.SHA256) {
			golog.Warnf("runner: skipped support DLL %s due to hash mismatch (have %s, want %s)", dll.Name, hash, dll.SHA256)
			continue
		}

		dstPath := filepath.Join(dstDir, dll.Name)
		if srcPath == dstPath {
			continue
		}
		if err := copyFileAtomic(srcPath, dstPath); err != nil {
			golog.Warnf("runner: failed to copy support DLL %s: %v", dll.Name, err)
			continue
		}
		golog.Infof("runner: deployed support DLL %s", dll.Name)
	}
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
