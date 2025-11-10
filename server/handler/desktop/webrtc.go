package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
)

var errInvalidSignal = errors.New("invalid WebRTC signal payload")

type webRTCSignalKind string

const (
	signalOffer     webRTCSignalKind = "offer"
	signalAnswer    webRTCSignalKind = "answer"
	signalCandidate webRTCSignalKind = "candidate"
)

type webrtcSessionState struct {
	Desktop               string
	LastOfferAt           time.Time
	LastAnswerAt          time.Time
	LastCandidate         time.Time
	BrowserReady          bool
	AgentReady            bool
	ExpiresAt             time.Time
	QueuedAgentCandidates []map[string]any
}

type webrtcController struct {
	mu       sync.Mutex
	sessions map[string]*webrtcSessionState
	ttl      time.Duration
}

func newWebRTCController(ttl time.Duration) *webrtcController {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &webrtcController{
		sessions: make(map[string]*webrtcSessionState),
		ttl:      ttl,
	}
}

func (c *webrtcController) touch(desktop string) *webrtcSessionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	return c.touchLocked(desktop)
}

func (c *webrtcController) touchLocked(desktop string) *webrtcSessionState {
	state, ok := c.sessions[desktop]
	if !ok {
		state = &webrtcSessionState{Desktop: desktop}
		c.sessions[desktop] = state
	}
	state.ExpiresAt = time.Now().Add(c.ttl)
	return state
}

func (c *webrtcController) recordOffer(desktop string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	state := c.touchLocked(desktop)
	state.LastOfferAt = time.Now()
	state.BrowserReady = false
	state.AgentReady = false
	state.QueuedAgentCandidates = nil
}

func (c *webrtcController) recordAnswer(desktop string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	state := c.touchLocked(desktop)
	state.LastAnswerAt = time.Now()
	state.AgentReady = true
}

func (c *webrtcController) recordCandidate(desktop string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	state := c.touchLocked(desktop)
	state.LastCandidate = time.Now()
}

func (c *webrtcController) markBrowserReady(desktop string) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	state := c.touchLocked(desktop)
	state.BrowserReady = true
	queued := state.QueuedAgentCandidates
	state.QueuedAgentCandidates = nil
	return queued
}

func (c *webrtcController) snapshot(desktop string) webrtcSessionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	if state, ok := c.sessions[desktop]; ok {
		return *state
	}
	return webrtcSessionState{Desktop: desktop}
}

func (c *webrtcController) queueAgentCandidate(desktop string, candidate map[string]any) bool {
	if candidate == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(time.Now())
	state := c.touchLocked(desktop)
	if state.BrowserReady {
		return false
	}
	state.QueuedAgentCandidates = append(state.QueuedAgentCandidates, candidate)
	return true
}

func (c *webrtcController) remove(desktop string) {
	if c == nil || desktop == "" {
		return
	}
	c.mu.Lock()
	delete(c.sessions, desktop)
	c.mu.Unlock()
}

func normalizeBrowserSignal(kind webRTCSignalKind, payload map[string]any) (map[string]any, error) {
	switch kind {
	case signalOffer, signalAnswer:
		return normalizeSDP(kind, payload)
	case signalCandidate:
		return normalizeCandidate(payload)
	default:
		return nil, fmt.Errorf("%w: unsupported kind %q", errInvalidSignal, kind)
	}
}

func normalizeAgentSignal(kind webRTCSignalKind, payload map[string]any) (map[string]any, error) {
	// Agent feeds us the same kinds. Reuse browser sanitizers for now.
	return normalizeBrowserSignal(kind, payload)
}

func normalizeSDP(kind webRTCSignalKind, payload map[string]any) (map[string]any, error) {
	if payload == nil {
		return nil, fmt.Errorf("%w: missing SDP payload", errInvalidSignal)
	}
	rawSDP, _ := payload[`sdp`].(string)
	if strings.TrimSpace(rawSDP) == "" {
		return nil, fmt.Errorf("%w: empty SDP", errInvalidSignal)
	}
	descType, err := toSDPType(string(kind))
	if err != nil {
		return nil, err
	}
	desc := webrtc.SessionDescription{
		Type: descType,
		SDP:  rawSDP,
	}
	encoded, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}
	var normalized webrtc.SessionDescription
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return nil, err
	}
	return map[string]any{
		`type`: normalized.Type.String(),
		`sdp`:  normalized.SDP,
	}, nil
}

func normalizeCandidate(payload map[string]any) (map[string]any, error) {
	if payload == nil {
		return nil, fmt.Errorf("%w: missing ICE payload", errInvalidSignal)
	}
	rawCandidate, _ := payload[`candidate`].(string)
	if strings.TrimSpace(rawCandidate) == "" {
		return nil, fmt.Errorf("%w: empty ICE candidate", errInvalidSignal)
	}
	init := webrtc.ICECandidateInit{
		Candidate: rawCandidate,
	}
	if mid, ok := payload[`sdpMid`].(string); ok && mid != "" {
		init.SDPMid = &mid
	}
	if mle, ok := payload[`sdpMLineIndex`].(float64); ok {
		val := uint16(mle)
		init.SDPMLineIndex = &val
	}
	encoded, err := json.Marshal(init)
	if err != nil {
		return nil, err
	}
	var normalized webrtc.ICECandidateInit
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return nil, err
	}
	result := map[string]any{
		`candidate`: normalized.Candidate,
	}
	if normalized.SDPMid != nil {
		result[`sdpMid`] = *normalized.SDPMid
	}
	if normalized.SDPMLineIndex != nil {
		result[`sdpMLineIndex`] = *normalized.SDPMLineIndex
	}
	return result, nil
}

func toSDPType(kind string) (webrtc.SDPType, error) {
	switch strings.ToLower(kind) {
	case `offer`:
		return webrtc.SDPTypeOffer, nil
	case `answer`:
		return webrtc.SDPTypeAnswer, nil
	case `pranswer`:
		return webrtc.SDPTypePranswer, nil
	case `rollback`:
		return webrtc.SDPTypeRollback, nil
	default:
		return webrtc.SDPTypeOffer, fmt.Errorf("%w: unknown SDP type %q", errInvalidSignal, kind)
	}
}

func toSignalKind(kind any) (webRTCSignalKind, error) {
	if kind == nil {
		return "", fmt.Errorf("%w: missing kind", errInvalidSignal)
	}
	switch v := kind.(type) {
	case string:
		k := webRTCSignalKind(strings.ToLower(v))
		switch k {
		case signalOffer, signalAnswer, signalCandidate:
			return k, nil
		default:
			return "", fmt.Errorf("%w: unsupported kind %q", errInvalidSignal, v)
		}
	default:
		return "", fmt.Errorf("%w: invalid kind type %T", errInvalidSignal, kind)
	}
}

func mapFromAny(value any) (map[string]any, bool) {
	if value == nil {
		return nil, false
	}
	if m, ok := value.(map[string]any); ok {
		return m, true
	}
	return nil, false
}

func (c *webrtcController) cleanupLocked(now time.Time) {
	for key, state := range c.sessions {
		if now.After(state.ExpiresAt) {
			delete(c.sessions, key)
		}
	}
}
