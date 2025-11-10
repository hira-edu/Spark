package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/pion/webrtc/v3"
)

var errInvalidSignal = errors.New("invalid WebRTC signal payload")

type webRTCSignalKind string

const (
	signalOffer     webRTCSignalKind = "offer"
	signalAnswer    webRTCSignalKind = "answer"
	signalCandidate webRTCSignalKind = "candidate"
)

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
