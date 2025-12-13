package desktop

import (
	"Rocket/client/common"
	"Rocket/modules"
	"errors"
	"os"
	"reflect"
	"runtime"
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
	if sess.escape.Load() {
		return nil, errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	// Reset any existing RTC session
	if sess.rtc != nil {
		sess.rtc.close()
		sess.rtc = nil
	}

	// Get configured codec from environment (default to H.264 on Windows 10+).
	codec := WebRTCCodec(strings.ToLower(strings.TrimSpace(os.Getenv(envWebRTCCodec))))
	if codec == "" {
		if runtime.GOOS == "windows" {
			codec = WebRTCCodecH264
		} else {
			codec = WebRTCCodecVP8
		}
	}

	// Capture session reference for callbacks
	sessRef := sess
	desktopIDStr := desktopID.(string)
	iceServers := parseICEServers(pack.Data)
	rtc, err := NewDesktopWebRTC(WebRTCConfig{
		Configuration: webrtc.Configuration{ICEServers: iceServers},
		Codec:         codec,
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
		OnKeyFrame: func() {
			sessRef.lock.Lock()
			rtcSess := sessRef.rtc
			sessRef.lock.Unlock()
			if rtcSess != nil {
				rtcSess.requestKeyFrame()
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

	rtcSess, err := newRTCSession(desktopIDStr, rtc, codec)
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

	if sess.escape.Load() || sess.rtc == nil {
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

	if sess.escape.Load() || sess.rtc == nil {
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

func parseICEServers(data map[string]any) []webrtc.ICEServer {
	if data == nil {
		return nil
	}
	raw, ok := data["ice_servers"]
	if !ok || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil
	}

	servers := make([]webrtc.ICEServer, 0, len(list))

	// Hard safety caps to avoid abusive payload sizes.
	const maxServers = 8
	const maxURLs = 16
	const maxURLLen = 512

	for _, item := range list {
		if len(servers) >= maxServers {
			break
		}
		m, ok := item.(map[string]any)
		if !ok || m == nil {
			continue
		}

		var urls []string
		switch v := m["urls"].(type) {
		case string:
			u := strings.TrimSpace(v)
			if u != "" && len(u) <= maxURLLen {
				urls = append(urls, u)
			}
		case []any:
			for _, rawURL := range v {
				if len(urls) >= maxURLs {
					break
				}
				s, ok := rawURL.(string)
				if !ok {
					continue
				}
				s = strings.TrimSpace(s)
				if s == "" || len(s) > maxURLLen {
					continue
				}
				urls = append(urls, s)
			}
		case []string:
			for _, s := range v {
				if len(urls) >= maxURLs {
					break
				}
				s = strings.TrimSpace(s)
				if s == "" || len(s) > maxURLLen {
					continue
				}
				urls = append(urls, s)
			}
		}

		if len(urls) == 0 {
			continue
		}

		server := webrtc.ICEServer{URLs: urls}
		if username, ok := m["username"].(string); ok {
			server.Username = username
		}
		if credential, ok := m["credential"].(string); ok {
			server.Credential = credential
		}
		servers = append(servers, server)
	}

	return servers
}
