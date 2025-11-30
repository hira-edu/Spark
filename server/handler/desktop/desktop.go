package desktop

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"Spark/modules"
	"Spark/server/common"
	"Spark/server/handler/utility"
	"Spark/utils"
	"Spark/utils/melody"

	"github.com/gin-gonic/gin"
)

type desktop struct {
	uuid       string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
}

var desktopSessions = melody.New()

const maxDesktopInputBatch = 32
const (
	maxSDPLength       = 1 << 15
	maxCandidateLength = 4096
)

func init() {
	desktopSessions.Config.MaxMessageSize = common.MaxMessageSize
	desktopSessions.HandleConnect(onDesktopConnect)
	desktopSessions.HandleMessage(onDesktopMessage)
	desktopSessions.HandleMessageBinary(onDesktopMessage)
	desktopSessions.HandleDisconnect(onDesktopDisconnect)
	go utility.WSHealthCheck(desktopSessions, sendPack)
}

// InitDesktop handles desktop websocket handshake event
func InitDesktop(ctx *gin.Context) {
	if !ctx.IsWebsocket() {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Validate WebSocket origin to prevent CSWSH attacks
	if !validateWebSocketOrigin(ctx) {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	secretStr, ok := ctx.GetQuery(`secret`)
	if !ok || len(secretStr) != 32 {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	secret, err := hex.DecodeString(secretStr)
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	device, ok := ctx.GetQuery(`device`)
	if !ok {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if _, ok := common.CheckDevice(device, ``); !ok {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	desktopSessions.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Secret`:   secret,
		`Device`:   device,
		`LastPack`: utils.Unix,
	})
}

// desktopEventWrapper returns a eventCallback function that will
// be called when device need to send a packet to browser
func desktopEventWrapper(desktop *desktop) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			data := *pack.Data[`data`].(*[]byte)
			if data[5] == 00 || data[5] == 01 || data[5] == 02 {
				desktop.srcConn.WriteBinary(data)
				return
			}

			if data[5] != 03 {
				return
			}
			data = data[8:]
			data = utility.SimpleDecrypt(data, device)
			if utils.JSON.Unmarshal(data, &pack) != nil {
				return
			}
		}

		switch pack.Act {
		case `DESKTOP_INIT`:
			if pack.Code != 0 {
				msg := `${i18n|DESKTOP.CREATE_SESSION_FAILED}`
				if len(pack.Msg) > 0 {
					msg += `: ` + pack.Msg
				} else {
					msg += `${i18n|COMMON.UNKNOWN_ERROR}`
				}
				sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, desktop.srcConn)
				common.RemoveEvent(desktop.uuid)
				desktop.srcConn.Close()
				common.Warn(desktop.srcConn, `DESKTOP_INIT`, `fail`, msg, map[string]any{
					`deviceConn`: desktop.deviceConn,
				})
			} else {
				common.Info(desktop.srcConn, `DESKTOP_INIT`, `success`, ``, map[string]any{
					`deviceConn`: desktop.deviceConn,
				})
			}
		case `DESKTOP_QUIT`:
			msg := `${i18n|DESKTOP.SESSION_CLOSED}`
			if len(pack.Msg) > 0 {
				msg = pack.Msg
			}
			sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, desktop.srcConn)
			common.RemoveEvent(desktop.uuid)
			desktop.srcConn.Close()
			common.Info(desktop.srcConn, `DESKTOP_QUIT`, `success`, ``, map[string]any{
				`deviceConn`: desktop.deviceConn,
			})
		case `DESKTOP_INPUT`:
			if pack.Code != 0 {
				sendPack(pack, desktop.srcConn)
			}
		case `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`, `DESKTOP_WEBRTC_ICE`:
			sendPack(pack, desktop.srcConn)
		}
	}
}

func onDesktopConnect(session *melody.Session) {
	device, ok := session.Get(`Device`)
	if !ok {
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|DESKTOP.CREATE_SESSION_FAILED}`}, session)
		session.Close()
		return
	}
	connUUID, ok := common.CheckDevice(device.(string), ``)
	if !ok {
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}
	deviceConn, ok := common.Melody.GetSessionByUUID(connUUID)
	if !ok {
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}
	desktopUUID := utils.GetStrUUID()
	desktop := &desktop{
		uuid:       desktopUUID,
		device:     device.(string),
		srcConn:    session,
		deviceConn: deviceConn,
	}
	session.Set(`Desktop`, desktop)
	common.AddEvent(desktopEventWrapper(desktop), connUUID, desktopUUID)
	common.SendPack(modules.Packet{Act: `DESKTOP_INIT`, Data: gin.H{
		`desktop`: desktopUUID,
	}, Event: desktopUUID}, deviceConn)
	common.Info(desktop.srcConn, `DESKTOP_CONN`, `success`, ``, map[string]any{
		`deviceConn`: desktop.deviceConn,
	})
}

func onDesktopMessage(session *melody.Session, data []byte) {
	var pack modules.Packet
	val, ok := session.Get(`Desktop`)
	if !ok {
		return
	}
	desktop := val.(*desktop)

	service, op, isBinary := utils.CheckBinaryPack(data)
	if !isBinary || service != 20 {
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	if op != 03 {
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	data = utility.SimpleDecrypt(data[8:], session)
	if utils.JSON.Unmarshal(data, &pack) != nil {
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	session.Set(`LastPack`, utils.Unix)

	switch pack.Act {
	case `DESKTOP_PING`:
		common.SendPack(modules.Packet{Act: `DESKTOP_PING`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_KILL`:
		common.Info(desktop.srcConn, `DESKTOP_KILL`, `success`, ``, map[string]any{
			`deviceConn`: desktop.deviceConn,
		})
		common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_SHOT`:
		common.SendPack(modules.Packet{Act: `DESKTOP_SHOT`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_INPUT`:
		events, ok := normalizeInputEvents(pack.Data)
		if !ok {
			common.Warn(desktop.srcConn, `DESKTOP_INPUT`, `fail`, `invalid events payload`, map[string]any{
				`desktop`: desktop.uuid,
			})
			return
		}
		if len(events) == 0 {
			return
		}

		common.SendPack(modules.Packet{
			Act: `DESKTOP_INPUT`,
			Data: gin.H{
				`events`:  events,
				`desktop`: desktop.uuid,
			},
			Event: desktop.uuid,
		}, desktop.deviceConn)
		return
	case `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`:
		if payload, ok := normalizeSDP(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_WEBRTC_ICE`:
		if payload, ok := normalizeCandidate(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	}
	session.Close()
}

func onDesktopDisconnect(session *melody.Session) {
	common.Info(session, `DESKTOP_CLOSE`, `success`, ``, nil)
	val, ok := session.Get(`Desktop`)
	if !ok {
		return
	}
	desktop, ok := val.(*desktop)
	if !ok {
		return
	}
	common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
		`desktop`: desktop.uuid,
	}, Event: desktop.uuid}, desktop.deviceConn)
	common.RemoveEvent(desktop.uuid)
	session.Set(`Desktop`, nil)
	desktop = nil
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
	err = session.WriteBinary(append([]byte{34, 22, 19, 17, 20, 03}, data...))
	return err == nil
}

func CloseSessionsByDevice(deviceID string) {
	var queue []*melody.Session
	desktopSessions.IterSessions(func(_ string, session *melody.Session) bool {
		val, ok := session.Get(`Desktop`)
		if !ok {
			return true
		}
		desktop, ok := val.(*desktop)
		if !ok {
			return true
		}
		if desktop.device == deviceID {
			sendPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|DESKTOP.SESSION_CLOSED}`}, desktop.srcConn)
			queue = append(queue, session)
			return false
		}
		return true
	})
	for _, session := range queue {
		session.Close()
	}
}

func normalizeInputEvents(data map[string]any) ([]any, bool) {
	if data == nil {
		return nil, false
	}

	rawEvents, ok := data[`events`]
	if !ok {
		return nil, false
	}

	switch events := rawEvents.(type) {
	case []any:
		if len(events) > maxDesktopInputBatch {
			return events[:maxDesktopInputBatch], true
		}
		return events, true
	default:
		return nil, false
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
