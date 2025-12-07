package webcam

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"Rocket/modules"
	"Rocket/server/cluster"
	"Rocket/server/common"
	"Rocket/server/handler/utility"
	"Rocket/utils"
	"Rocket/utils/melody"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type webcam struct {
	uuid       string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
}

var webcamSessions = melody.New()

const (
	maxSDPLength       = 1 << 15
	maxCandidateLength = 4096
)

func init() {
	webcamSessions.Config.MaxMessageSize = common.MaxMessageSize
	webcamSessions.HandleConnect(onWebcamConnect)
	webcamSessions.HandleMessage(onWebcamMessage)
	webcamSessions.HandleMessageBinary(onWebcamMessage)
	webcamSessions.HandleDisconnect(onWebcamDisconnect)
	go utility.WSHealthCheck(webcamSessions, sendPack)
}

// InitWebcam handles webcam websocket handshake event
func InitWebcam(ctx *gin.Context) {
	tr := otel.Tracer("rocket-server/webcam")
	ctxSpan, span := tr.Start(ctx.Request.Context(), "webcam.handshake")
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
		common.Warn(ctx, `WEBCAM_HANDSHAKE`, `fail`, reason, extra)
		ctx.AbortWithStatus(status)
	}

	if !ctx.IsWebsocket() {
		logAbort(http.StatusBadRequest, `not websocket`, nil)
		return
	}

	// Validate WebSocket origin to prevent CSWSH attacks
	if !utility.ValidateWebSocketOrigin(ctx, false) {
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
	if cluster.RedirectIfNeeded(ctx, device) {
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

	webcamSessions.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Secret`:   secret,
		`Device`:   device,
		`LastPack`: utils.Unix,
	})

	common.Info(ctx, `WEBCAM_HANDSHAKE`, `success`, ``, map[string]any{
		`device`:     device,
		`secret_len`: len(secret),
		`latency_ms`: time.Since(start).Milliseconds(),
	})
	span.SetAttributes(
		attribute.String("webcam.device", device),
		attribute.Int("webcam.secret_len", len(secret)),
		attribute.Int64("latency_ms", time.Since(start).Milliseconds()),
		attribute.String("origin", ctx.GetHeader(`Origin`)),
	)
}

// webcamEventWrapper returns an eventCallback function that will
// be called when device needs to send a packet to browser
func webcamEventWrapper(webcam *webcam) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			data := *pack.Data[`data`].(*[]byte)
			if utility.IsFrameOp(data[5]) {
				webcam.srcConn.WriteBinary(data)
				return
			}

			if data[5] != utility.BinaryOpWebcamControl {
				return
			}
			// Binary protocol header is 24 bytes: magic(4) + service(1) + op(1) + event(16) + length(2)
			data = data[24:]
			data = utility.SimpleDecrypt(data, device)
			if utils.JSON.Unmarshal(data, &pack) != nil {
				return
			}
		}

		switch pack.Act {
		case `WEBCAM_INIT`:
			if pack.Code != 0 {
				msg := `${i18n|WEBCAM.CREATE_SESSION_FAILED}`
				if len(pack.Msg) > 0 {
					msg += `: ` + pack.Msg
				} else {
					msg += `${i18n|COMMON.UNKNOWN_ERROR}`
				}
				sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, webcam.srcConn)
				common.RemoveEvent(webcam.uuid)
				webcam.srcConn.Close()
				common.Warn(webcam.srcConn, `WEBCAM_INIT`, `fail`, msg, map[string]any{
					`deviceConn`: webcam.deviceConn,
				})
			} else {
				common.Info(webcam.srcConn, `WEBCAM_INIT`, `success`, ``, map[string]any{
					`deviceConn`: webcam.deviceConn,
				})
			}
		case `WEBCAM_QUIT`:
			msg := `${i18n|WEBCAM.SESSION_CLOSED}`
			if len(pack.Msg) > 0 {
				msg = pack.Msg
			}
			sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, webcam.srcConn)
			common.RemoveEvent(webcam.uuid)
			webcam.srcConn.Close()
			common.Info(webcam.srcConn, `WEBCAM_QUIT`, `success`, ``, map[string]any{
				`deviceConn`: webcam.deviceConn,
			})
		case `WEBCAM_LIST`:
			// Return available cameras list
			sendPack(pack, webcam.srcConn)
		case `WEBCAM_WEBRTC_OFFER`, `WEBCAM_WEBRTC_ANSWER`, `WEBCAM_WEBRTC_ICE`:
			sendPack(pack, webcam.srcConn)
		}
	}
}

func onWebcamConnect(session *melody.Session) {
	clientIP := `unknown`
	if addr, ok := session.Get(`Address`); ok {
		clientIP = addr.(string)
	}

	device, ok := session.Get(`Device`)
	if !ok {
		common.Warn(session, `WEBCAM_CONN`, `fail`, `no device ID in session`, map[string]any{
			`from`: clientIP,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|WEBCAM.CREATE_SESSION_FAILED}`}, session)
		session.Close()
		return
	}
	deviceID := device.(string)

	connUUID, ok := common.CheckDevice(deviceID, ``)
	if !ok {
		common.Warn(session, `WEBCAM_CONN`, `fail`, `device not found`, map[string]any{
			`from`:     clientIP,
			`deviceID`: deviceID[:16] + `...`,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}
	deviceConn, ok := common.Melody.GetSessionByUUID(connUUID)
	if !ok {
		common.Warn(session, `WEBCAM_CONN`, `fail`, `device connection not found`, map[string]any{
			`from`:     clientIP,
			`deviceID`: deviceID[:16] + `...`,
			`connUUID`: connUUID[:8] + `...`,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}

	webcamUUID := utils.GetStrUUID()
	webcam := &webcam{
		uuid:       webcamUUID,
		device:     deviceID,
		srcConn:    session,
		deviceConn: deviceConn,
	}
	session.Set(`Webcam`, webcam)
	common.AddEvent(webcamEventWrapper(webcam), connUUID, webcamUUID)
	common.SendPack(modules.Packet{Act: `WEBCAM_INIT`, Data: gin.H{
		`webcam`: webcamUUID,
	}, Event: webcamUUID}, deviceConn)

	// Get device info for logging
	deviceInfo := map[string]any{
		`uuid`:     webcamUUID[:8] + `...`,
		`deviceID`: deviceID[:16] + `...`,
	}
	if dev, ok := common.Devices.Get(connUUID); ok {
		deviceInfo[`name`] = dev.Hostname
		deviceInfo[`ip`] = dev.WAN
	}

	common.Info(webcam.srcConn, `WEBCAM_CONN`, `success`, ``, map[string]any{
		`from`:   clientIP,
		`target`: deviceInfo,
	})
}

func onWebcamMessage(session *melody.Session, data []byte) {
	var pack modules.Packet
	val, ok := session.Get(`Webcam`)
	if !ok {
		common.Warn(session, `WEBCAM_MSG`, `fail`, `no webcam session`, nil)
		return
	}
	webcam := val.(*webcam)

	service, op, isBinary := utils.CheckBinaryPack(data)
	if !isBinary || service != 22 {
		common.Warn(session, `WEBCAM_MSG`, `fail`, `invalid binary pack`, map[string]any{
			`webcam`:   webcam.uuid[:8] + `...`,
			`service`:  service,
			`isBinary`: isBinary,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	if op != 04 {
		common.Warn(session, `WEBCAM_MSG`, `fail`, `invalid op code`, map[string]any{
			`webcam`: webcam.uuid[:8] + `...`,
			`op`:     op,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	data = utility.SimpleDecrypt(data[8:], session)
	if utils.JSON.Unmarshal(data, &pack) != nil {
		common.Warn(session, `WEBCAM_MSG`, `fail`, `JSON unmarshal failed`, map[string]any{
			`webcam`: webcam.uuid[:8] + `...`,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	session.Set(`LastPack`, utils.Unix)

	switch pack.Act {
	case `WEBCAM_PING`:
		common.SendPack(modules.Packet{Act: `WEBCAM_PING`, Data: gin.H{
			`webcam`: webcam.uuid,
		}, Event: webcam.uuid}, webcam.deviceConn)
		return
	case `WEBCAM_KILL`:
		common.Info(webcam.srcConn, `WEBCAM_KILL`, `success`, ``, map[string]any{
			`deviceConn`: webcam.deviceConn,
		})
		common.SendPack(modules.Packet{Act: `WEBCAM_KILL`, Data: gin.H{
			`webcam`: webcam.uuid,
		}, Event: webcam.uuid}, webcam.deviceConn)
		return
	case `WEBCAM_LIST`:
		// Request list of available cameras
		common.SendPack(modules.Packet{Act: `WEBCAM_LIST`, Data: gin.H{
			`webcam`: webcam.uuid,
		}, Event: webcam.uuid}, webcam.deviceConn)
		return
	case `WEBCAM_START`:
		// Start webcam streaming
		if pack.Data != nil {
			cameraID, _ := pack.Data[`camera`]
			common.SendPack(modules.Packet{
				Act: `WEBCAM_START`,
				Data: gin.H{
					`camera`: cameraID,
					`webcam`: webcam.uuid,
				},
				Event: webcam.uuid,
			}, webcam.deviceConn)
		}
		return
	case `WEBCAM_STOP`:
		// Stop webcam streaming
		common.SendPack(modules.Packet{Act: `WEBCAM_STOP`, Data: gin.H{
			`webcam`: webcam.uuid,
		}, Event: webcam.uuid}, webcam.deviceConn)
		return
	case `WEBCAM_WEBRTC_OFFER`, `WEBCAM_WEBRTC_ANSWER`:
		if payload, ok := normalizeSDP(pack.Data); ok {
			payload[`webcam`] = webcam.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: webcam.uuid}, webcam.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `WEBCAM_WEBRTC_ICE`:
		if payload, ok := normalizeCandidate(pack.Data); ok {
			payload[`webcam`] = webcam.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: webcam.uuid}, webcam.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	}
	session.Close()
}

func onWebcamDisconnect(session *melody.Session) {
	common.Info(session, `WEBCAM_CLOSE`, `success`, ``, nil)
	val, ok := session.Get(`Webcam`)
	if !ok {
		return
	}
	webcam, ok := val.(*webcam)
	if !ok {
		return
	}
	common.SendPack(modules.Packet{Act: `WEBCAM_KILL`, Data: gin.H{
		`webcam`: webcam.uuid,
	}, Event: webcam.uuid}, webcam.deviceConn)
	common.RemoveEvent(webcam.uuid)
	session.Set(`Webcam`, nil)
	webcam = nil
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
	err = session.WriteBinary(append([]byte{34, 22, 19, 17, 22, 04}, data...))
	return err == nil
}

func CloseSessionsByDevice(deviceID string) {
	var queue []*melody.Session
	webcamSessions.IterSessions(func(_ string, session *melody.Session) bool {
		val, ok := session.Get(`Webcam`)
		if !ok {
			return true
		}
		webcam, ok := val.(*webcam)
		if !ok {
			return true
		}
		if webcam.device == deviceID {
			sendPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|WEBCAM.SESSION_CLOSED}`}, webcam.srcConn)
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
