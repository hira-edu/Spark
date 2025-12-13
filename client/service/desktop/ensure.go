package desktop

import (
	"sync"
	"time"
)

// BridgeEnsureFunc is set by the Windows service layer to (re)launch the UI bridge
// in a given session when the Session 0 relay can't connect.
type BridgeEnsureFunc func(sessionID uint32, reason string)

var (
	bridgeEnsureMu sync.RWMutex
	bridgeEnsureFn BridgeEnsureFunc
)

// SetBridgeEnsureFunc registers a hook used by Session 0 code paths to request
// that the UI bridge process is started/restarted for a session.
func SetBridgeEnsureFunc(fn BridgeEnsureFunc) {
	bridgeEnsureMu.Lock()
	bridgeEnsureFn = fn
	bridgeEnsureMu.Unlock()
}

// EnsureBridge requests that the UI bridge for sessionID is running.
// A sessionID of 0 means "refresh/scan sessions".
func EnsureBridge(sessionID uint32, reason string) {
	bridgeEnsureMu.RLock()
	fn := bridgeEnsureFn
	bridgeEnsureMu.RUnlock()
	if fn == nil {
		return
	}
	fn(sessionID, reason)
}

// WaitForActiveSession waits until the service layer sets a non-zero active user
// session ID, or returns 0 on timeout.
func WaitForActiveSession(timeout time.Duration) uint32 {
	deadline := time.Now().Add(timeout)
	for {
		sessionID := GetActiveSessionID()
		if sessionID != 0 {
			return sessionID
		}
		if time.Now().After(deadline) {
			return 0
		}
		time.Sleep(200 * time.Millisecond)
	}
}

