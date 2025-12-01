package audio

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/server/handler/utility"
	"Rocket/utils"
	"Rocket/utils/melody"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type audio struct {
	uuid       string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
}

var audioSessions = melody.New()

const (
	maxSDPLength       = 1 << 15
	maxCandidateLength = 4096
)

func init() {
	audioSessions.Config.MaxMessageSize = common.MaxMessageSize
	audioSessions.HandleConnect(onAudioConnect)
	audioSessions.HandleMessage(onAudioMessage)
	audioSessions.HandleMessageBinary(onAudioMessage)
	audioSessions.HandleDisconnect(onAudioDisconnect)
	go utility.WSHealthCheck(audioSessions, sendPack)
}

// InitAudio handles audio websocket handshake event
func InitAudio(ctx *gin.Context) {
	tr := otel.Tracer("rocket-server/audio")
	ctxSpan, span := tr.Start(ctx.Request.Context(), "audio.handshake")
	defer span.End()
	ctx.Request = ctx.Request.WithContext(ctxSpan)

	start := time.Now()
	logAbort := func(status int, reason string, extra map[string]any) {
		if extra == nil {
			extra = map[string]any{}
		}
		extra[`path`] = ctx.Request.URL.String()
		extra[`ua`] = ctx.Request.UserAgent()
		extra[`latency_ms`] = time.Since(start).Milliseconds()
		common.Warn(ctx, `AUDIO_HANDSHAKE`, `fail`, reason, extra)
		ctx.AbortWithStatus(status)
	}

	if !ctx.IsWebsocket() {
		logAbort(http.StatusBadRequest, `not websocket`, nil)
		return
	}

	// Validate WebSocket origin to prevent CSWSH attacks
	if !validateWebSocketOrigin(ctx) {
		logAbort(http.StatusForbidden, `invalid websocket origin`, map[string]any{
			`origin`: ctx.GetHeader(`Origin`),
		})
		return
	}

	secretStr, ok := ctx.GetQuery(`secret`)
	if !ok || len(secretStr) != 32 {
		logAbort(http.StatusBadRequest, `missing secret`, map[string]any{
			`secretLen`: len(secretStr),
		})
		return
	}
	secret, err := hex.DecodeString(secretStr)
	if err != nil {
		logAbort(http.StatusBadRequest, `secret decode failed`, map[string]any{
			`error`: err.Error(),
		})
		return
	}
	device, ok := ctx.GetQuery(`device`)
	if !ok {
		logAbort(http.StatusBadRequest, `missing device`, nil)
		return
	}
	if _, ok := common.CheckDevice(device, ``); !ok {
		logAbort(http.StatusBadRequest, `device not found`, map[string]any{
			`device`: device,
		})
		span.RecordError(fmt.Errorf("device not found"))
		span.SetStatus(codes.Error, "device not found")
		return
	}

	audioSessions.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Secret`:   secret,
		`Device`:   device,
		`LastPack`: utils.Unix,
	})

	common.Info(ctx, `AUDIO_HANDSHAKE`, `success`, ``, map[string]any{
		`device`:     device,
		`secret_len`: len(secret),
		`latency_ms`: time.Since(start).Milliseconds(),
	})
	span.SetAttributes(
		attribute.String("audio.device", device),
		attribute.Int("audio.secret_len", len(secret)),
		attribute.Int64("latency_ms", time.Since(start).Milliseconds()),
		attribute.String("origin", ctx.GetHeader(`Origin`)),
	)
}

// audioEventWrapper returns an eventCallback function that will
// be called when device needs to send a packet to browser
func audioEventWrapper(audio *audio) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			data := *pack.Data[`data`].(*[]byte)
			if data[5] == 00 || data[5] == 01 || data[5] == 02 {
				audio.srcConn.WriteBinary(data)
				return
			}

			if data[5] != 05 {
				return
			}
			data = data[8:]
			data = utility.SimpleDecrypt(data, device)
			if utils.JSON.Unmarshal(data, &pack) != nil {
				return
			}
		}

		switch pack.Act {
		case `AUDIO_INIT`:
			if pack.Code != 0 {
				msg := `${i18n|AUDIO.CREATE_SESSION_FAILED}`
				if len(pack.Msg) > 0 {
					msg += `: ` + pack.Msg
				} else {
					msg += `${i18n|COMMON.UNKNOWN_ERROR}`
				}
				sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, audio.srcConn)
				common.RemoveEvent(audio.uuid)
				audio.srcConn.Close()
				common.Warn(audio.srcConn, `AUDIO_INIT`, `fail`, msg, map[string]any{
					`deviceConn`: audio.deviceConn,
				})
			} else {
				common.Info(audio.srcConn, `AUDIO_INIT`, `success`, ``, map[string]any{
					`deviceConn`: audio.deviceConn,
				})
			}
		case `AUDIO_QUIT`:
			msg := `${i18n|AUDIO.SESSION_CLOSED}`
			if len(pack.Msg) > 0 {
				msg = pack.Msg
			}
			sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, audio.srcConn)
			common.RemoveEvent(audio.uuid)
			audio.srcConn.Close()
			common.Info(audio.srcConn, `AUDIO_QUIT`, `success`, ``, map[string]any{
				`deviceConn`: audio.deviceConn,
			})
		case `AUDIO_LIST`:
			// Return available audio devices list
			sendPack(pack, audio.srcConn)
		case `AUDIO_WEBRTC_OFFER`, `AUDIO_WEBRTC_ANSWER`, `AUDIO_WEBRTC_ICE`:
			sendPack(pack, audio.srcConn)
		}
	}
}

func onAudioConnect(session *melody.Session) {
	clientIP := `unknown`
	if addr, ok := session.Get(`Address`); ok {
		clientIP = addr.(string)
	}

	device, ok := session.Get(`Device`)
	if !ok {
		common.Warn(session, `AUDIO_CONN`, `fail`, `no device ID in session`, map[string]any{
			`from`: clientIP,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|AUDIO.CREATE_SESSION_FAILED}`}, session)
		session.Close()
		return
	}
	deviceID := device.(string)

	connUUID, ok := common.CheckDevice(deviceID, ``)
	if !ok {
		common.Warn(session, `AUDIO_CONN`, `fail`, `device not found`, map[string]any{
			`from`:     clientIP,
			`deviceID`: deviceID[:16] + `...`,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}
	deviceConn, ok := common.Melody.GetSessionByUUID(connUUID)
	if !ok {
		common.Warn(session, `AUDIO_CONN`, `fail`, `device connection not found`, map[string]any{
			`from`:     clientIP,
			`deviceID`: deviceID[:16] + `...`,
			`connUUID`: connUUID[:8] + `...`,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}

	audioUUID := utils.GetStrUUID()
	audio := &audio{
		uuid:       audioUUID,
		device:     deviceID,
		srcConn:    session,
		deviceConn: deviceConn,
	}
	session.Set(`Audio`, audio)
	common.AddEvent(audioEventWrapper(audio), connUUID, audioUUID)
	common.SendPack(modules.Packet{Act: `AUDIO_INIT`, Data: gin.H{
		`audio`: audioUUID,
	}, Event: audioUUID}, deviceConn)

	// Get device info for logging
	deviceInfo := map[string]any{
		`uuid`:     audioUUID[:8] + `...`,
		`deviceID`: deviceID[:16] + `...`,
	}
	if dev, ok := common.Devices.Get(connUUID); ok {
		deviceInfo[`name`] = dev.Hostname
		deviceInfo[`ip`] = dev.WAN
	}

	common.Info(audio.srcConn, `AUDIO_CONN`, `success`, ``, map[string]any{
		`from`:   clientIP,
		`target`: deviceInfo,
	})
}

func onAudioMessage(session *melody.Session, data []byte) {
	var pack modules.Packet
	val, ok := session.Get(`Audio`)
	if !ok {
		common.Warn(session, `AUDIO_MSG`, `fail`, `no audio session`, nil)
		return
	}
	audio := val.(*audio)

	service, op, isBinary := utils.CheckBinaryPack(data)
	if !isBinary || service != 23 {
		common.Warn(session, `AUDIO_MSG`, `fail`, `invalid binary pack`, map[string]any{
			`audio`:    audio.uuid[:8] + `...`,
			`service`:  service,
			`isBinary`: isBinary,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	if op != 05 {
		common.Warn(session, `AUDIO_MSG`, `fail`, `invalid op code`, map[string]any{
			`audio`: audio.uuid[:8] + `...`,
			`op`:    op,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	data = utility.SimpleDecrypt(data[8:], session)
	if utils.JSON.Unmarshal(data, &pack) != nil {
		common.Warn(session, `AUDIO_MSG`, `fail`, `JSON unmarshal failed`, map[string]any{
			`audio`: audio.uuid[:8] + `...`,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	session.Set(`LastPack`, utils.Unix)

	switch pack.Act {
	case `AUDIO_PING`:
		common.SendPack(modules.Packet{Act: `AUDIO_PING`, Data: gin.H{
			`audio`: audio.uuid,
		}, Event: audio.uuid}, audio.deviceConn)
		return
	case `AUDIO_KILL`:
		common.Info(audio.srcConn, `AUDIO_KILL`, `success`, ``, map[string]any{
			`deviceConn`: audio.deviceConn,
		})
		common.SendPack(modules.Packet{Act: `AUDIO_KILL`, Data: gin.H{
			`audio`: audio.uuid,
		}, Event: audio.uuid}, audio.deviceConn)
		return
	case `AUDIO_LIST`:
		// Request list of available audio devices
		common.SendPack(modules.Packet{Act: `AUDIO_LIST`, Data: gin.H{
			`audio`: audio.uuid,
		}, Event: audio.uuid}, audio.deviceConn)
		return
	case `AUDIO_START`:
		// Start audio streaming
		if pack.Data != nil {
			deviceID, _ := pack.Data[`device`]
			mode, _ := pack.Data[`mode`] // "input" or "output"
			common.SendPack(modules.Packet{
				Act: `AUDIO_START`,
				Data: gin.H{
					`device`: deviceID,
					`mode`:   mode,
					`audio`:  audio.uuid,
				},
				Event: audio.uuid,
			}, audio.deviceConn)
		}
		return
	case `AUDIO_STOP`:
		// Stop audio streaming
		common.SendPack(modules.Packet{Act: `AUDIO_STOP`, Data: gin.H{
			`audio`: audio.uuid,
		}, Event: audio.uuid}, audio.deviceConn)
		return
	case `AUDIO_WEBRTC_OFFER`, `AUDIO_WEBRTC_ANSWER`:
		if payload, ok := normalizeSDP(pack.Data); ok {
			payload[`audio`] = audio.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: audio.uuid}, audio.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `AUDIO_WEBRTC_ICE`:
		if payload, ok := normalizeCandidate(pack.Data); ok {
			payload[`audio`] = audio.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: audio.uuid}, audio.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	}
	session.Close()
}

func onAudioDisconnect(session *melody.Session) {
	common.Info(session, `AUDIO_CLOSE`, `success`, ``, nil)
	val, ok := session.Get(`Audio`)
	if !ok {
		return
	}
	audio, ok := val.(*audio)
	if !ok {
		return
	}
	common.SendPack(modules.Packet{Act: `AUDIO_KILL`, Data: gin.H{
		`audio`: audio.uuid,
	}, Event: audio.uuid}, audio.deviceConn)
	common.RemoveEvent(audio.uuid)
	session.Set(`Audio`, nil)
	audio = nil
}

func sendPack(pack modules.Packet, session *melody.Session) bool {
	if session == nil {
		return false
	}
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return false
	}
	data = utility.SimpleEncrypt(data, session)
	err = session.WriteBinary(append([]byte{34, 22, 19, 17, 23, 05}, data...))
	return err == nil
}

func CloseSessionsByDevice(deviceID string) {
	var queue []*melody.Session
	audioSessions.IterSessions(func(_ string, session *melody.Session) bool {
		val, ok := session.Get(`Audio`)
		if !ok {
			return true
		}
		audio, ok := val.(*audio)
		if !ok {
			return true
		}
		if audio.device == deviceID {
			sendPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|AUDIO.SESSION_CLOSED}`}, audio.srcConn)
			queue = append(queue, session)
			return false
		}
		return true
	})
	for _, session := range queue {
		session.Close()
	}
}

func normalizeSDP(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	sdp, ok := data[`sdp`].(string)
	if !ok || len(sdp) == 0 || len(sdp) > maxSDPLength {
		return nil, false
	}
	// Validate SDP format
	if !isValidSDP(sdp) {
		return nil, false
	}
	t, ok := data[`type`].(string)
	if !ok || len(t) == 0 {
		return nil, false
	}
	payload := gin.H{
		`sdp`:  sdp,
		`type`: t,
	}
	if role, ok := data[`role`].(string); ok {
		payload[`role`] = role
	}
	if retry, ok := data[`retry`].(float64); ok {
		payload[`retry`] = retry
	}
	return payload, true
}

// isValidSDP performs basic validation on SDP format
func isValidSDP(sdp string) bool {
	if sdp == "" {
		return false
	}
	// SDP must contain version line and at least one media section
	return strings.Contains(sdp, "v=") && strings.Contains(sdp, "m=")
}

func normalizeCandidate(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	candidate, ok := data[`candidate`].(string)
	if !ok || len(candidate) == 0 || len(candidate) > maxCandidateLength {
		return nil, false
	}
	// Validate ICE candidate format
	if !isValidICECandidate(candidate) {
		return nil, false
	}
	payload := gin.H{
		`candidate`: candidate,
	}
	if mid, ok := data[`sdpMid`].(string); ok {
		payload[`sdpMid`] = mid
	}
	// Support both mLine and sdpMLineIndex for compatibility
	if idx, ok := data[`mLine`].(float64); ok {
		payload[`mLine`] = idx
	} else if idx, ok := data[`sdpMLineIndex`].(float64); ok {
		payload[`mLine`] = idx
	}
	if role, ok := data[`role`].(string); ok {
		payload[`role`] = role
	}
	if retry, ok := data[`retry`].(float64); ok {
		payload[`retry`] = retry
	}
	return payload, true
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

// validateWebSocketOrigin checks the Origin header to prevent Cross-Site WebSocket Hijacking
func validateWebSocketOrigin(ctx *gin.Context) bool {
	origin := ctx.GetHeader("Origin")
	if origin == "" {
		// No Origin header - allow (non-browser clients)
		return true
	}

	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}

	requestHost := ctx.Request.Host
	// Strip port from both for comparison
	requestHostWithoutPort := strings.Split(requestHost, ":")[0]
	originHostWithoutPort := strings.Split(originURL.Host, ":")[0]

	// Same host is always allowed
	if originHostWithoutPort == requestHostWithoutPort {
		return true
	}

	// Allow localhost variants to connect to each other
	if isLocalhost(originHostWithoutPort) && isLocalhost(requestHostWithoutPort) {
		return true
	}

	return false
}

// isLocalhost checks if a host is a localhost variant
func isLocalhost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	default:
		return false
	}
}
