package desktop

import (
	"sync"
	"time"

	"Spark/client/service/desktop/hookbridge"
)

// policyManager tracks per-desktop-session policy metadata.
type policyManager struct {
	sync.RWMutex
	sessions map[string]*sessionPolicyState
}

type sessionPolicyState struct {
	Policy    *hookbridge.Policy
	CreatedAt time.Time
	UpdatedAt time.Time
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

func (pm *policyManager) describe(sessionID string) map[string]any {
	if pm == nil || sessionID == "" {
		return nil
	}
	pm.RLock()
	state := pm.sessions[sessionID]
	pm.RUnlock()
	if state == nil || state.Policy == nil {
		return nil
	}
	policy := state.Policy
	return map[string]any{
		"inputEnabled":  false,
		"forceInput":    policy.ForceInput,
		"forceCapture":  policy.ForceCapture,
		"connectionId":  policy.ConnectionID,
		"sessionId":     policy.SessionID,
		"policyCreated": state.CreatedAt.UnixMilli(),
		"policyUpdated": state.UpdatedAt.UnixMilli(),
	}
}
