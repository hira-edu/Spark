package desktop

import (
	"Spark/client/common"
	"Spark/modules"
	"errors"
	"os"
	"reflect"
	"strings"

	"github.com/kataras/golog"
	"github.com/pion/webrtc/v4"
)

const (
	maxSDPLength       = 1 << 15 // 32 KiB
	maxCandidateLength = 4096
)

var errWebRTCUnsupported = errors.New(`${i18n|DESKTOP.UNSUPPORTED_PLATFORM}`)

func HandleWebRTCOffer(pack modules.Packet) (map[string]any, error) {
	if !isWebRTCEnabled() {
		return nil, errWebRTCUnsupported
	}
	if pack.Data == nil {
		return nil, errInputInvalid
	}
	sdp, ok := pack.GetData(`sdp`, reflect.String)
	if !ok || len(sdp.(string)) == 0 || len(sdp.(string)) > maxSDPLength {
		return nil, errInputInvalid
	}
	// Validate SDP format
	sdpStr := sdp.(string)
	if !isValidSDP(sdpStr) {
		return nil, errInputInvalid
	}
	sdpType := webrtc.SDPTypeOffer
	if t, ok := pack.GetData(`type`, reflect.String); ok {
		if parsed, err := parseSDPType(t.(string)); err == nil {
			sdpType = parsed
		}
	}
	desktopID, ok := pack.GetData(`desktop`, reflect.String)
	if !ok {
		return nil, errInputInvalid
	}
	sess, ok := sessions.Get(desktopID.(string))
	if !ok {
		return nil, errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	// Hold lock for entire session modification to prevent TOCTOU race
	sess.lock.Lock()
	defer sess.lock.Unlock()

	// Check escape flag under lock
	if sess.escape {
		return nil, errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	// Reset any existing RTC session
	if sess.rtc != nil {
		sess.rtc.close()
		sess.rtc = nil
	}

	// Get configured codec from environment
	codec := VPXCodec(strings.ToLower(strings.TrimSpace(os.Getenv(envWebRTCCodec))))
	if codec == "" {
		codec = VPXCodecVP8
	}

	// Capture session reference for callbacks
	sessRef := sess
	desktopIDStr := desktopID.(string)
	rtc, err := NewDesktopWebRTC(WebRTCConfig{
		Codec: codec,
		OnState: func(state webrtc.PeerConnectionState) {
			if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
				sessRef.lock.Lock()
				if sessRef.rtc != nil {
					sessRef.rtc.close()
					sessRef.rtc = nil
				}
				sessRef.lock.Unlock()
			}
		},
		OnICE: func(c *webrtc.ICECandidate) {
			notifyICE(desktopIDStr, c)
		},
		OnInputData: func(data []byte) {
			if err := handleRTCInput(desktopIDStr, data); err != nil {
				golog.Warnf("rtc input handling failed: %v", err)
			}
		},
	})
	if err != nil {
		return nil, err
	}

	if err := rtc.SetRemoteDescription(webrtc.SessionDescription{
		Type: sdpType,
		SDP:  sdpStr,
	}); err != nil {
		rtc.Close()
		return nil, err
	}
	answer, err := rtc.CreateAnswer()
	if err != nil {
		rtc.Close()
		return nil, err
	}

	rtcSess, err := newRTCSession(desktopIDStr, rtc)
	if err != nil {
		rtc.Close()
		return nil, err
	}
	sess.rtc = rtcSess

	return map[string]any{
		`sdp`:  answer.SDP,
		`type`: answer.Type.String(),
	}, nil
}

func HandleWebRTCAnswer(pack modules.Packet) error {
	if !isWebRTCEnabled() {
		return errWebRTCUnsupported
	}
	if pack.Data == nil {
		return errInputInvalid
	}
	sdp, ok := pack.GetData(`sdp`, reflect.String)
	if !ok || len(sdp.(string)) == 0 || len(sdp.(string)) > maxSDPLength {
		return errInputInvalid
	}
	sdpStr := sdp.(string)
	if !isValidSDP(sdpStr) {
		return errInputInvalid
	}
	sdpType := webrtc.SDPTypeAnswer
	if t, ok := pack.GetData(`type`, reflect.String); ok {
		if parsed, err := parseSDPType(t.(string)); err == nil {
			sdpType = parsed
		}
	}
	desktopID, ok := pack.GetData(`desktop`, reflect.String)
	if !ok {
		return errInputInvalid
	}
	sess, ok := sessions.Get(desktopID.(string))
	if !ok {
		return errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	sess.lock.Lock()
	defer sess.lock.Unlock()

	if sess.escape || sess.rtc == nil {
		return errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}
	return sess.rtc.rtc.SetRemoteDescription(webrtc.SessionDescription{
		Type: sdpType,
		SDP:  sdpStr,
	})
}

func HandleWebRTCIce(pack modules.Packet) error {
	if !isWebRTCEnabled() {
		return errWebRTCUnsupported
	}
	if pack.Data == nil {
		return errInputInvalid
	}
	candidate, ok := pack.GetData(`candidate`, reflect.String)
	if !ok || len(candidate.(string)) == 0 || len(candidate.(string)) > maxCandidateLength {
		return errInputInvalid
	}
	candidateStr := candidate.(string)
	// Validate ICE candidate format
	if !isValidICECandidate(candidateStr) {
		return errInputInvalid
	}
	desktopID, ok := pack.GetData(`desktop`, reflect.String)
	if !ok {
		return errInputInvalid
	}
	sess, ok := sessions.Get(desktopID.(string))
	if !ok {
		return errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	sess.lock.Lock()
	defer sess.lock.Unlock()

	if sess.escape || sess.rtc == nil {
		return errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	init := webrtc.ICECandidateInit{
		Candidate: candidateStr,
	}
	if mid, ok := pack.GetData(`sdpMid`, reflect.String); ok {
		midStr := mid.(string)
		init.SDPMid = &midStr
	}
	// Support both mLine and sdpMLineIndex for compatibility
	if line, ok := pack.GetData(`mLine`, reflect.Float64); ok {
		val := uint16(line.(float64))
		init.SDPMLineIndex = &val
	} else if line, ok := pack.GetData(`sdpMLineIndex`, reflect.Float64); ok {
		val := uint16(line.(float64))
		init.SDPMLineIndex = &val
	}
	return sess.rtc.rtc.AddICECandidate(init)
}

func notifyICE(desktopID string, c *webrtc.ICECandidate) {
	if c == nil || len(desktopID) == 0 || common.WSConn == nil {
		return
	}
	json := c.ToJSON()
	// Use DESKTOP_WEBRTC_ICE for consistency with server handlers
	_ = common.WSConn.SendPack(modules.Packet{
		Act: `DESKTOP_WEBRTC_ICE`,
		Data: map[string]any{
			`desktop`:   desktopID,
			`candidate`: json.Candidate,
			`sdpMid`:    json.SDPMid,
			`mLine`:     json.SDPMLineIndex, // Use consistent field name
			`role`:      `device`,
		},
	})
}

func parseSDPType(t string) (webrtc.SDPType, error) {
	switch strings.ToLower(t) {
	case "offer":
		return webrtc.SDPTypeOffer, nil
	case "answer":
		return webrtc.SDPTypeAnswer, nil
	case "pranswer":
		return webrtc.SDPTypePranswer, nil
	default:
		return webrtc.SDPType(0), errInputInvalid
	}
}

// isValidSDP performs basic validation on SDP format
func isValidSDP(sdp string) bool {
	if sdp == "" {
		return false
	}
	// SDP must contain version line and at least one media section
	return strings.Contains(sdp, "v=") && strings.Contains(sdp, "m=")
}

// isValidICECandidate performs basic validation on ICE candidate format
func isValidICECandidate(candidate string) bool {
	if candidate == "" {
		return true // Empty candidate signals end-of-candidates
	}
	// ICE candidates contain space-separated components and type info
	return strings.Contains(candidate, " ") &&
		(strings.HasPrefix(candidate, "candidate:") || strings.Contains(candidate, "typ "))
}
