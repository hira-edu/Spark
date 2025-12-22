package desktop

import (
	"Rocket/client/ipc"
	"Rocket/modules"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kataras/golog"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
)

const (
	maxSDPLength       = 1 << 15 // 32 KiB
	maxCandidateLength = 4096
)

var errWebRTCUnsupported = errors.New(`${i18n|DESKTOP.UNSUPPORTED_PLATFORM}`)
var ErrWebRTCForwarded = errors.New("webrtc forwarded to bridge")
var localICELogCount atomic.Uint64
var remoteICELogCount atomic.Uint64

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
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopPacket); forwarded {
		if err != nil {
			return nil, err
		}
		return nil, ErrWebRTCForwarded
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

	// File-based debug logging for WebRTC signaling
	signalingLog := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		fmt.Print(msg)
		if f, err := os.OpenFile("logs/webrtc_signaling.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, "[%s] %s", time.Now().Format("15:04:05.000"), msg)
			f.Close()
		}
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

	// Get configured codec from environment, defaulting based on pipeline support.
	codec := WebRTCCodec(strings.ToLower(strings.TrimSpace(os.Getenv(envWebRTCCodec))))
	if codec == "" {
		if isWindowsSinglePipeline() {
			codec = WebRTCCodecH264
		} else if runtime.GOOS == "windows" {
			if isVPXAvailable() {
				codec = WebRTCCodecVP8
			} else {
				codec = WebRTCCodecH264
			}
		} else {
			codec = WebRTCCodecVP8
		}
	}
	if isWindowsSinglePipeline() {
		codec = WebRTCCodecH264
	}

	var h264Sel h264FmtpSelection
	if codec == WebRTCCodecH264 {
		var selErr error
		h264Sel, selErr = selectH264FmtpFromOffer(sdpStr)
		if selErr != nil {
			return nil, fmt.Errorf("h264 negotiation failed: %w", selErr)
		}
	}

	// Capture session reference for callbacks
	sessRef := sess
	desktopIDStr := desktopID.(string)
	var ownedRTC atomic.Pointer[DesktopWebRTC]
	iceServers := parseICEServers(pack.Data)
	rtc, err := NewDesktopWebRTC(WebRTCConfig{
		Configuration: webrtc.Configuration{ICEServers: iceServers},
		Codec:         codec,
		VideoFmtpLine: h264Sel.FmtpLine,
		OnState: func(state webrtc.PeerConnectionState) {
			signalingLog("[SIGNALING] PC state=%s\n", state.String())
			if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
				// Guard against stale callbacks from a previous PeerConnection/offer.
				// Only clear the current session if it still belongs to this DesktopWebRTC instance.
				current := ownedRTC.Load()
				sessRef.lock.Lock()
				if sessRef.rtc != nil && sessRef.rtc.rtc == current {
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
	ownedRTC.Store(rtc)
	rtc.onICEStateChange = func(state webrtc.ICEConnectionState) {
		signalingLog("[SIGNALING] ICE state=%s\n", state.String())
	}
	rtc.onSignalingChange = func(state webrtc.SignalingState) {
		signalingLog("[SIGNALING] signaling state=%s\n", state.String())
	}

	if err := rtc.SetRemoteDescription(webrtc.SessionDescription{
		Type: sdpType,
		SDP:  sdpStr,
	}); err != nil {
		rtc.Close()
		return nil, err
	}

	// Bind video track AFTER SetRemoteDescription so we can match the browser's
	// recvonly transceiver. This is critical for the browser's ontrack to fire.
	sender, err := rtc.BindVideoTrack()
	if err != nil {
		rtc.Close()
		return nil, fmt.Errorf("failed to bind video track: %w", err)
	}

	if codec == WebRTCCodecH264 && h264Sel.FmtpLine != "" {
		signalingLog("[SIGNALING] H264 fmtp selected: %s profile=0x%02x constraint=0x%02x level=0x%02x\n",
			h264Sel.FmtpLine, h264Sel.ProfileID, h264Sel.Constraint, h264Sel.LevelID)
	}
	signalingLog("[SIGNALING] BindVideoTrack succeeded, proceeding to CreateAnswer\n")

	// Setup RTCP reader to detect keyframe requests (PLI/FIR) from the browser.
	// This goroutine drains RTCP packets and invokes OnKeyFrame when needed.
	onKeyFrameCb := func() {
		sessRef.lock.Lock()
		rtcSess := sessRef.rtc
		sessRef.lock.Unlock()
		if rtcSess != nil {
			rtcSess.requestKeyFrame()
		}
	}
	go func() {
		for {
			pkts, _, err := sender.ReadRTCP()
			if err != nil {
				return
			}
			needKeyframe := false
			for _, pkt := range pkts {
				switch p := pkt.(type) {
				case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
					needKeyframe = true
				case *rtcp.ReceiverEstimatedMaximumBitrate:
					// REMB packet - update adaptive quality manager with receiver's bandwidth estimate
					// This is the most reliable signal for network congestion
					sessRef.lock.Lock()
					if sessRef.rtc != nil && sessRef.rtc.qualityManager != nil {
						sessRef.rtc.qualityManager.UpdateREMB(int64(p.Bitrate))
					}
					sessRef.lock.Unlock()
				case *rtcp.ReceiverReport:
					// Extract packet loss from receiver reports for quality adaptation
					sessRef.lock.Lock()
					if sessRef.rtc != nil && sessRef.rtc.qualityManager != nil {
						for _, rr := range p.Reports {
							// FractionLost is 0-255 (0-100% loss)
							lossPercent := float64(rr.FractionLost) / 255.0 * 100.0
							if lossPercent > 0 {
								// Update with loss info (RTT comes from elsewhere)
								sessRef.rtc.qualityManager.UpdateNetworkMetrics(
									sessRef.rtc.qualityManager.rttMs.Load(),
									lossPercent,
									sessRef.rtc.qualityManager.queueDepthBytes.Load(),
								)
							}
						}
					}
					sessRef.lock.Unlock()
				}
				if needKeyframe {
					break
				}
			}
			if needKeyframe {
				onKeyFrameCb()
			}
		}
	}()

	signalingLog("[SIGNALING] Calling CreateAnswer...\n")
	answer, err := rtc.CreateAnswer()
	if err != nil {
		signalingLog("[SIGNALING] CreateAnswer FAILED: %v\n", err)
		rtc.Close()
		return nil, err
	}
	signalingLog("[SIGNALING] CreateAnswer succeeded, SDP type=%s\n", answer.Type.String())
	if videoLines := extractVideoSDPLines(answer.SDP); videoLines != "" {
		signalingLog("[SIGNALING] Answer SDP (video):\n%s\n", videoLines)
	}

	signalingLog("[SIGNALING] Calling newRTCSession...\n")
	rtcSess, err := newRTCSession(desktopIDStr, rtc, codec, h264Sel)
	if err != nil {
		signalingLog("[SIGNALING] newRTCSession FAILED: %v\n", err)
		rtc.Close()
		return nil, err
	}
	signalingLog("[SIGNALING] newRTCSession succeeded\n")
	closingSess := rtcSess
	rtcSess.onClosed = func() {
		sessRef.lock.Lock()
		if sessRef.rtc == closingSess {
			sessRef.rtc = nil
		}
		sessRef.lock.Unlock()
	}
	sess.rtc = rtcSess
	signalingLog("[SIGNALING] sess.rtc assigned, desktopID=%s codec=%s\n", desktopIDStr, string(codec))

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
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopPacket); forwarded {
		if err != nil {
			return err
		}
		return ErrWebRTCForwarded
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
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopPacket); forwarded {
		if err != nil {
			return err
		}
		return ErrWebRTCForwarded
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

	count := remoteICELogCount.Add(1)
	if count <= 5 || count%50 == 0 {
		preview := candidateStr
		if len(preview) > 120 {
			preview = preview[:120] + "..."
		}
		sessionLog("[SIGNALING] remote ICE candidate #%d: %s\n", count, preview)
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
	if err := sess.rtc.rtc.AddICECandidate(init); err != nil {
		sessionLog("[SIGNALING] AddICECandidate failed: %v\n", err)
		return err
	}
	return nil
}

func notifyICE(desktopID string, c *webrtc.ICECandidate) {
	if c == nil || len(desktopID) == 0 {
		return
	}

	// Look up the session so we can route through WS (service mode) or IPC (bridge mode).
	sess, ok := sessions.Get(desktopID)
	if !ok || sess == nil || sess.escape.Load() {
		return
	}

	json := c.ToJSON()
	candidate := strings.TrimSpace(json.Candidate)
	if candidate == "" || len(candidate) > maxCandidateLength {
		return
	}

	count := localICELogCount.Add(1)
	if count <= 5 || count%50 == 0 {
		preview := candidate
		if len(preview) > 120 {
			preview = preview[:120] + "..."
		}
		sessionLog("[SIGNALING] local ICE candidate #%d: %s\n", count, preview)
	}

	// Deliver ICE candidates back to the browser via the server desktop event (Event=desktop uuid).
	sendDesktopPacket(modules.Packet{
		Act:   `DESKTOP_WEBRTC_ICE`,
		Event: sess.event,
		Code:  0,
		Data: map[string]any{
			`desktop`:   desktopID,
			`candidate`: candidate,
			`sdpMid`:    json.SDPMid,
			`mLine`:     json.SDPMLineIndex,
			`role`:      `device`,
		},
	}, sess.rawEvent)
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

func extractVideoSDPLines(sdpStr string) string {
	if sdpStr == "" {
		return ""
	}
	lines := strings.Split(sdpStr, "\n")
	inVideo := false
	out := make([]string, 0, 8)
	for _, raw := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "m=") {
			inVideo = strings.HasPrefix(line, "m=video")
			if inVideo {
				out = append(out, line)
			}
			continue
		}
		if !inVideo {
			continue
		}
		if strings.HasPrefix(line, "a=rtpmap") || strings.HasPrefix(line, "a=fmtp") || strings.HasPrefix(line, "a=rtcp-fb") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
