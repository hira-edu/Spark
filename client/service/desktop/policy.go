//go:build windows

package desktop

import (
	"sync"
	"time"

	"Spark/client/service/desktop/hookbridge"
	"Spark/client/service/input"
)

// policyManager tracks per-desktop-session policy metadata.
type policyManager struct {
	sync.RWMutex
	sessions map[string]*sessionPolicyState
	native   nativePolicyState
}

type sessionPolicyState struct {
	Policy    *hookbridge.Policy
	CreatedAt time.Time
	UpdatedAt time.Time
}

type nativePolicyState struct {
	ForceInput   bool
	ForceCapture bool
	UpdatedAt    time.Time
}

func newPolicyManager() *policyManager {
	return &policyManager{
		sessions: make(map[string]*sessionPolicyState),
	}
}

func (pm *policyManager) register(sessionID string, policy *hookbridge.Policy) {
	if pm == nil || sessionID == "" || policy == nil {
		return
	}
	pm.Lock()
	if existing, ok := pm.sessions[sessionID]; ok && existing != nil && existing.Policy != nil {
		_ = hookbridge.ReleasePolicy(existing.Policy.ConnectionID)
	}
	pm.sessions[sessionID] = &sessionPolicyState{
		Policy:    policy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	pm.Unlock()
}

func (pm *policyManager) unregister(sessionID string) {
	if pm == nil || sessionID == "" {
		return
	}
	pm.Lock()
	state := pm.sessions[sessionID]
	delete(pm.sessions, sessionID)
	pm.Unlock()
	if state != nil && state.Policy != nil {
		_ = hookbridge.ReleasePolicy(state.Policy.ConnectionID)
	}
}

func (pm *policyManager) clear() {
	if pm == nil {
		return
	}
	pm.Lock()
	old := pm.sessions
	pm.sessions = make(map[string]*sessionPolicyState)
	pm.Unlock()
	for _, state := range old {
		if state != nil && state.Policy != nil {
			_ = hookbridge.ReleasePolicy(state.Policy.ConnectionID)
		}
	}
}

func (pm *policyManager) touch(sessionID string) {
	if pm == nil || sessionID == "" {
		return
	}
	pm.Lock()
	if state, ok := pm.sessions[sessionID]; ok && state != nil {
		state.UpdatedAt = time.Now()
	}
	pm.Unlock()
}

func (pm *policyManager) describe(sessionID string) map[string]any {
	pointerEnabled := input.PointerEnabled()
	keyboardEnabled := input.KeyboardEnabled()
	state := map[string]any{
		"inputEnabled":    pointerEnabled || keyboardEnabled,
		"pointerEnabled":  pointerEnabled,
		"keyboardEnabled": keyboardEnabled,
		"forceInput":      false,
		"forceCapture":    false,
		"connectionId":    sessionID,
		"sessionId":       uint32(0),
		"policyCreated":   int64(0),
		"policyUpdated":   int64(0),
	}
	if pm == nil || sessionID == "" {
		return state
	}
	pm.RLock()
	entry := pm.sessions[sessionID]
	native := pm.native
	pm.RUnlock()
	var requested *hookbridge.Policy
	if entry != nil {
		requested = entry.Policy
		state["policyCreated"] = entry.CreatedAt.UnixMilli()
		state["policyUpdated"] = entry.UpdatedAt.UnixMilli()
	}
	if requested != nil {
		state["requestedForceInput"] = requested.ForceInput
		state["requestedForceCapture"] = requested.ForceCapture
		if len(requested.ConnectionID) > 0 {
			state["connectionId"] = requested.ConnectionID
		}
		if requested.SessionID != 0 {
			state["sessionId"] = requested.SessionID
		}
	}
	state["forceInput"] = native.ForceInput
	state["forceCapture"] = native.ForceCapture
	if !native.UpdatedAt.IsZero() {
		state["nativePolicyUpdated"] = native.UpdatedAt.UnixMilli()
	}
	return state
}

func (pm *policyManager) updateNative(forceInput, forceCapture bool) bool {
	if pm == nil {
		return false
	}
	pm.Lock()
	changed := pm.native.ForceInput != forceInput || pm.native.ForceCapture != forceCapture
	if changed {
		pm.native.ForceInput = forceInput
		pm.native.ForceCapture = forceCapture
		pm.native.UpdatedAt = time.Now()
	}
	pm.Unlock()
	return changed
}

func (pm *policyManager) sessionIDs() []string {
	if pm == nil {
		return nil
	}
	pm.RLock()
	ids := make([]string, 0, len(pm.sessions))
	for id := range pm.sessions {
		ids = append(ids, id)
	}
	pm.RUnlock()
	return ids
}

func (pm *policyManager) applyOverrides(sessionID string, forceInput, forceCapture *bool) bool {
	if pm == nil || sessionID == "" {
		return false
	}
	pm.Lock()
	entry := pm.sessions[sessionID]
	if entry == nil || entry.Policy == nil {
		pm.Unlock()
		return false
	}
	changed := false
	if forceInput != nil && entry.Policy.ForceInput != *forceInput {
		entry.Policy.ForceInput = *forceInput
		changed = true
	}
	if forceCapture != nil && entry.Policy.ForceCapture != *forceCapture {
		entry.Policy.ForceCapture = *forceCapture
		changed = true
	}
	var copyPolicy hookbridge.Policy
	if changed {
		entry.UpdatedAt = time.Now()
		copyPolicy = *entry.Policy
	}
	pm.Unlock()
	if changed {
		if err := hookbridge.ApplyPolicy(copyPolicy); err != nil {
			hookBridgeLogger.Warnf("hookbridge apply policy failed: %v", err)
		}
	}
	return changed
}
