package desktop

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"Rocket/modules"
	"Rocket/server/cluster"
	"Rocket/server/common"
	servercfg "Rocket/server/config"
	"Rocket/server/handler/utility"
	"Rocket/server/storage"
	"Rocket/utils"
	"Rocket/utils/melody"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	maxClipboardBytes  = 64 * 1024
	maxFileDropEntries = 5
	maxFileNameLength  = 255
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
	tr := otel.Tracer("rocket-server/desktop")
	ctxSpan, span := tr.Start(ctx.Request.Context(), "desktop.handshake")
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
		common.Warn(ctx, `DESKTOP_HANDSHAKE`, `fail`, reason, extra)
		ctx.AbortWithStatus(status)
	}

	if !ctx.IsWebsocket() {
		logAbort(http.StatusBadRequest, `not websocket`, nil)
		return
	}

	common.Info(ctx, `DESKTOP_HANDSHAKE`, `start`, ``, map[string]any{
		`remote`: common.GetRemoteAddr(ctx),
		`origin`: ctx.GetHeader(`Origin`),
		`path`:   ctx.Request.URL.String(),
	})

	// Validate WebSocket origin to prevent CSWSH attacks
	if !validateWebSocketOrigin(ctx) {
		logAbort(http.StatusForbidden, `invalid websocket origin`, map[string]any{
			`origin`: ctx.GetHeader(`Origin`),
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

	desktopSessions.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Device`:   device,
		`LastPack`: utils.Unix,
	})

	common.Info(ctx, `DESKTOP_HANDSHAKE`, `success`, ``, map[string]any{
		`device`:     device,
		`latency_ms`: time.Since(start).Milliseconds(),
	})
	span.SetAttributes(
		attribute.String("desktop.device", device),
		attribute.Int64("latency_ms", time.Since(start).Milliseconds()),
		attribute.String("origin", ctx.GetHeader(`Origin`)),
	)
}

// desktopEventWrapper returns a eventCallback function that will
// be called when device need to send a packet to browser
func desktopEventWrapper(desktop *desktop) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		common.Info(nil, `[SERVER_DESKTOP_EVENT]`, ``, `Device sent packet for desktop session`, map[string]any{
			`act`:          pack.Act,
			`desktop_uuid`: desktop.uuid[:8] + `...`,
			`has_data`:     pack.Data != nil,
		})

		// Extend leases on any device→browser traffic (best effort)
		if storage.IsMongoEnabled() {
			go func(sessID, deviceID string) {
				ctx, cancel := storage.WithTimeout(context.Background())
				defer cancel()
				if mgr := cluster.Current(); mgr != nil {
					mgr.HeartbeatSession(ctx, sessID)
				} else {
					_ = storage.HeartbeatSession(ctx, sessID, sessionLeaseTTL())
				}
				_ = storage.UpsertDevice(ctx, deviceID, common.GetControllerID(), sessionLeaseTTL(), nil, "")
			}(desktop.uuid, desktop.device)
		}

		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			common.Info(nil, `[SERVER_DESKTOP_RAW_DATA]`, ``, `Device sent raw desktop data`, map[string]any{
				`desktop_uuid`: desktop.uuid[:8] + `...`,
			})
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
			common.Info(nil, `[SERVER_DESKTOP_INIT_RESPONSE]`, ``, `Received DESKTOP_INIT response from device`, map[string]any{
				`code`:         pack.Code,
				`desktop_uuid`: desktop.uuid[:8] + `...`,
				`has_data`:     pack.Data != nil,
			})

			if pack.Code != 0 {
				msg := `${i18n|DESKTOP.CREATE_SESSION_FAILED}`
				if len(pack.Msg) > 0 {
					msg += `: ` + pack.Msg
				} else {
					msg += `${i18n|COMMON.UNKNOWN_ERROR}`
				}
				common.Warn(desktop.srcConn, `[SERVER_DESKTOP_INIT_FAILED]`, ``, `Device returned error for DESKTOP_INIT`, map[string]any{
					`error`:        pack.Msg,
					`desktop_uuid`: desktop.uuid[:8] + `...`,
				})
				sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, desktop.srcConn)
				common.RemoveEvent(desktop.uuid)
				desktop.srcConn.Close()
				common.Warn(desktop.srcConn, `DESKTOP_INIT`, `fail`, msg, map[string]any{
					`deviceConn`: desktop.deviceConn,
				})
			} else {
				common.Info(desktop.srcConn, `[SERVER_DESKTOP_INIT_SUCCESS]`, ``, `Device initialized desktop successfully`, map[string]any{
					`desktop_uuid`: desktop.uuid[:8] + `...`,
					`display_data`: pack.Data,
				})
				common.Info(desktop.srcConn, `DESKTOP_INIT`, `success`, ``, map[string]any{
					`deviceConn`: desktop.deviceConn,
				})

				// Persist session start (best effort)
				if storage.IsMongoEnabled() {
					go func(sessID, deviceID, controllerID string) {
						ctx, cancel := storage.WithTimeout(context.Background())
						defer cancel()
						if mgr := cluster.Current(); mgr != nil {
							mgr.StartSession(ctx, sessID, deviceID, "", "desktop")
						} else {
							_ = storage.StartSession(ctx, sessID, deviceID, "", "desktop", controllerID, sessionLeaseTTL())
						}
					}(desktop.uuid, desktop.device, common.GetControllerID())
				}
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

			// Persist session closure (best effort)
			if storage.IsMongoEnabled() {
				go func(sessID string) {
					ctx, cancel := storage.WithTimeout(context.Background())
					defer cancel()
					if mgr := cluster.Current(); mgr != nil {
						mgr.CloseSession(ctx, sessID, `client_quit`)
					} else {
						_ = storage.CloseSession(ctx, sessID)
					}
				}(desktop.uuid)
			}
		case `DESKTOP_INPUT`:
			if pack.Code != 0 {
				sendPack(pack, desktop.srcConn)
			}
		case `CURSOR_UPDATE`:
			// Relay cursor metadata to browser unchanged
			sendPack(pack, desktop.srcConn)
		case `DESKTOP_CLIPBOARD`, `DESKTOP_AUDIO`, `DESKTOP_FILE_DROP`:
			if pack.Code != 0 {
				sendPack(pack, desktop.srcConn)
			}
		case `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`, `DESKTOP_WEBRTC_ICE`:
			sendPack(pack, desktop.srcConn)
		}
	}
}

func onDesktopConnect(session *melody.Session) {
	clientIP := `unknown`
	if addr, ok := session.Get(`Address`); ok {
		clientIP = addr.(string)
	}

	common.Info(session, `[SERVER_DESKTOP_CONNECT_START]`, ``, `Browser connected to desktop WebSocket`, map[string]any{
		`from`:         clientIP,
		`session_uuid`: session.UUID[:8] + `...`,
	})

	device, ok := session.Get(`Device`)
	if !ok {
		common.Warn(session, `DESKTOP_CONN`, `fail`, `no device ID in session`, map[string]any{
			`from`: clientIP,
		})
		common.Warn(session, `[SERVER_DESKTOP_NO_DEVICE]`, ``, `Device ID missing in session`, nil)
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|DESKTOP.CREATE_SESSION_FAILED}`}, session)
		session.Close()
		return
	}
	deviceID := device.(string)

	common.Info(session, `[SERVER_DESKTOP_DEVICE_LOOKUP]`, ``, `Looking up device connection`, map[string]any{
		`device_id`: deviceID[:16] + `...`,
	})

	connUUID, ok := common.CheckDevice(deviceID, ``)
	if !ok {
		common.Warn(session, `DESKTOP_CONN`, `fail`, `device not found`, map[string]any{
			`from`:     clientIP,
			`deviceID`: deviceID[:16] + `...`,
		})
		common.Warn(session, `[SERVER_DESKTOP_DEVICE_NOT_FOUND]`, ``, `Device not in online devices map`, map[string]any{
			`device_id`: deviceID[:16] + `...`,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}

	common.Info(session, `[SERVER_DESKTOP_DEVICE_FOUND]`, ``, `Device found, getting WebSocket session`, map[string]any{
		`conn_uuid`: connUUID[:8] + `...`,
	})

	deviceConn, ok := common.Melody.GetSessionByUUID(connUUID)
	if !ok {
		common.Warn(session, `DESKTOP_CONN`, `fail`, `device connection not found`, map[string]any{
			`from`:     clientIP,
			`deviceID`: deviceID[:16] + `...`,
			`connUUID`: connUUID[:8] + `...`,
		})
		common.Warn(session, `[SERVER_DESKTOP_WS_NOT_FOUND]`, ``, `Device WebSocket session not found in Melody`, map[string]any{
			`conn_uuid`: connUUID[:8] + `...`,
		})
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}

	common.Info(session, `[SERVER_DESKTOP_WS_FOUND]`, ``, `Device WebSocket session found`, map[string]any{
		`conn_uuid`: connUUID[:8] + `...`,
	})

	desktopUUID := utils.GetStrUUID()
	desktop := &desktop{
		uuid:       desktopUUID,
		device:     deviceID,
		srcConn:    session,
		deviceConn: deviceConn,
	}
	session.Set(`Desktop`, desktop)

	common.Info(session, `[SERVER_DESKTOP_SESSION_CREATED]`, ``, `Desktop session created`, map[string]any{
		`desktop_uuid`: desktopUUID[:8] + `...`,
		`device_id`:    deviceID[:16] + `...`,
	})

	common.AddEvent(desktopEventWrapper(desktop), connUUID, desktopUUID)

	common.Info(session, `[SERVER_DESKTOP_SENDING_INIT]`, ``, `Sending DESKTOP_INIT to device`, map[string]any{
		`desktop_uuid`: desktopUUID[:8] + `...`,
		`conn_uuid`:    connUUID[:8] + `...`,
	})

	if !common.SendPack(modules.Packet{Act: `DESKTOP_INIT`, Data: gin.H{
		`desktop`: desktopUUID,
	}, Event: desktopUUID}, deviceConn) {
		common.Warn(session, `[SERVER_DESKTOP_INIT_SEND_FAILED]`, ``, `Failed to send DESKTOP_INIT to device`, map[string]any{
			`desktop_uuid`: desktopUUID[:8] + `...`,
		})
	} else {
		common.Info(session, `[SERVER_DESKTOP_INIT_SENT]`, ``, `DESKTOP_INIT sent to device successfully`, map[string]any{
			`desktop_uuid`: desktopUUID[:8] + `...`,
		})
	}

	// Persist device record with controller lease (best effort)
	if storage.IsMongoEnabled() {
		go func() {
			ctx, cancel := storage.WithTimeout(context.Background())
			defer cancel()
			_ = storage.UpsertDevice(ctx, deviceID, common.GetControllerID(), sessionLeaseTTL(), map[string]any{
				"clientIP": clientIP,
			}, "")
		}()
	}

	// Get device info for logging
	deviceInfo := map[string]any{
		`uuid`:     desktopUUID[:8] + `...`,
		`deviceID`: deviceID[:16] + `...`,
	}
	if dev, ok := common.Devices.Get(connUUID); ok {
		deviceInfo[`name`] = dev.Hostname
		deviceInfo[`ip`] = dev.WAN
	}

	common.Info(desktop.srcConn, `DESKTOP_CONN`, `success`, ``, map[string]any{
		`from`:   clientIP,
		`target`: deviceInfo,
	})
}

func onDesktopMessage(session *melody.Session, data []byte) {
	common.Info(session, `[SERVER_DESKTOP_MSG_FROM_BROWSER]`, ``, `Received message from browser`, map[string]any{
		`data_len`: len(data),
	})

	var pack modules.Packet
	val, ok := session.Get(`Desktop`)
	if !ok {
		common.Warn(session, `DESKTOP_MSG`, `fail`, `no desktop session`, nil)
		common.Warn(session, `[SERVER_DESKTOP_NO_SESSION]`, ``, `Desktop session not found in Melody session`, nil)
		return
	}
	desktop := val.(*desktop)

	common.Info(session, `[SERVER_DESKTOP_CHECKING_PROTOCOL]`, ``, `Checking binary protocol`, map[string]any{
		`data_len`: len(data),
	})

	service, op, isBinary := utils.CheckBinaryPack(data)
	if !isBinary || service != 20 {
		common.Warn(session, `DESKTOP_MSG`, `fail`, `invalid binary pack`, map[string]any{
			`desktop`:  desktop.uuid[:8] + `...`,
			`service`:  service,
			`isBinary`: isBinary,
		})
		common.Warn(session, `[SERVER_DESKTOP_INVALID_PROTOCOL]`, ``, `Message not in expected binary format`, map[string]any{
			`service`:   service,
			`is_binary`: isBinary,
			`data_len`:  len(data),
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	common.Info(session, `[SERVER_DESKTOP_PROTOCOL_VALID]`, ``, `Binary protocol validated`, map[string]interface{}{
		`service`: service,
		`op`:      op,
	})
	if op != 03 {
		common.Warn(session, `DESKTOP_MSG`, `fail`, `invalid op code`, map[string]any{
			`desktop`: desktop.uuid[:8] + `...`,
			`op`:      op,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	data = utility.SimpleDecrypt(data[8:], session)
	if utils.JSON.Unmarshal(data, &pack) != nil {
		common.Warn(session, `DESKTOP_MSG`, `fail`, `JSON unmarshal failed`, map[string]any{
			`desktop`: desktop.uuid[:8] + `...`,
		})
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	session.Set(`LastPack`, utils.Unix)

	common.Info(session, `[SERVER_DESKTOP_ACTION_DISPATCH]`, ``, `Dispatching desktop action to device`, map[string]any{
		`act`:          pack.Act,
		`desktop_uuid`: desktop.uuid[:8] + `...`,
	})

	switch pack.Act {
	case `DESKTOP_PING`:
		common.Info(session, `[SERVER_DESKTOP_PING]`, ``, `Relaying DESKTOP_PING to device`, nil)
		common.SendPack(modules.Packet{Act: `DESKTOP_PING`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		if storage.IsMongoEnabled() {
			go func(sessID string) {
				ctx, cancel := storage.WithTimeout(context.Background())
				defer cancel()
				if mgr := cluster.Current(); mgr != nil {
					mgr.HeartbeatSession(ctx, sessID)
				} else {
					_ = storage.HeartbeatSession(ctx, sessID, sessionLeaseTTL())
				}
			}(desktop.uuid)
		}
		return
	case `DESKTOP_KILL`:
		common.Info(desktop.srcConn, `DESKTOP_KILL`, `success`, ``, map[string]any{
			`deviceConn`: desktop.deviceConn,
		})
		common.Info(session, `[SERVER_DESKTOP_KILL]`, ``, `Sending DESKTOP_KILL to device`, nil)
		common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_SHOT`:
		common.Info(session, `[SERVER_DESKTOP_SHOT]`, ``, `Requesting desktop screenshot from device`, nil)
		common.SendPack(modules.Packet{Act: `DESKTOP_SHOT`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_INPUT`:
		common.Info(session, `[SERVER_DESKTOP_INPUT]`, ``, `Relaying desktop input to device`, map[string]any{
			`has_events`: pack.Data != nil && pack.Data[`events`] != nil,
		})
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
	case `DESKTOP_CONFIG`:
		payload, ok := normalizeConfig(pack.Data)
		if !ok {
			sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
			return
		}
		payload[`desktop`] = desktop.uuid
		common.Info(session, `[SERVER_DESKTOP_CONFIG]`, ``, `Relaying desktop configuration to device`, payload)
		common.SendPack(modules.Packet{Act: `DESKTOP_CONFIG`, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_CLIPBOARD`:
		if payload, ok := normalizeClipboard(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_FILE_DROP`:
		if payload, ok := normalizeFileDrop(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_AUDIO`:
		if payload, ok := normalizeAudioControl(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
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
	common.Info(session, `[SERVER_DESKTOP_DISCONNECT]`, ``, `Browser disconnected from desktop session`, nil)
	common.Info(session, `DESKTOP_CLOSE`, `success`, ``, nil)

	val, ok := session.Get(`Desktop`)
	if !ok {
		common.Info(session, `[SERVER_DESKTOP_NO_SESSION_ON_DISCONNECT]`, ``, `No desktop session to clean up`, nil)
		return
	}
	desktop, ok := val.(*desktop)
	if !ok {
		common.Warn(session, `[SERVER_DESKTOP_INVALID_SESSION_TYPE]`, ``, `Invalid desktop session type`, nil)
		return
	}

	common.Info(session, `[SERVER_DESKTOP_CLEANUP]`, ``, `Cleaning up desktop session`, map[string]any{
		`desktop_uuid`: desktop.uuid[:8] + `...`,
		`device_id`:    desktop.device[:16] + `...`,
	})

	if !common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
		`desktop`: desktop.uuid,
	}, Event: desktop.uuid}, desktop.deviceConn) {
		common.Warn(session, `[SERVER_DESKTOP_KILL_FAILED]`, ``, `Failed to send DESKTOP_KILL to device`, nil)
	} else {
		common.Info(session, `[SERVER_DESKTOP_KILL_SENT]`, ``, `DESKTOP_KILL sent to device`, nil)
	}

	common.RemoveEvent(desktop.uuid)
	session.Set(`Desktop`, nil)

	if storage.IsMongoEnabled() {
		go func(deviceID string) {
			ctx, cancel := storage.WithTimeout(context.Background())
			defer cancel()
			_ = storage.MarkDeviceOffline(ctx, deviceID)
		}(desktop.device)
	}

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

func sessionLeaseTTL() time.Duration {
	if servercfg.Config.Cluster != nil && servercfg.Config.Cluster.SessionLeaseSeconds > 0 {
		return time.Duration(servercfg.Config.Cluster.SessionLeaseSeconds) * time.Second
	}
	return 3 * time.Minute
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

func normalizeClipboard(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	text, ok := data[`text`].(string)
	if !ok || len(text) == 0 {
		return nil, false
	}
	if len(text) > maxClipboardBytes {
		text = text[:maxClipboardBytes]
	}
	payload := gin.H{`text`: text}
	if mime, ok := data[`mime`].(string); ok && len(mime) > 0 {
		payload[`mime`] = strings.ToLower(mime)
	}
	return payload, true
}

func normalizeFileDrop(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	rawFiles, ok := data[`files`]
	if !ok {
		return nil, false
	}
	list, ok := rawFiles.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}

	files := make([]gin.H, 0, len(list))
	for _, item := range list {
		if len(files) >= maxFileDropEntries {
			break
		}
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m[`name`].(string)
		if len(name) > maxFileNameLength {
			name = name[:maxFileNameLength]
		}
		size := int64(0)
		switch v := m[`size`].(type) {
		case float64:
			size = int64(v)
		case int64:
			size = v
		case int:
			size = int64(v)
		}
		if len(name) == 0 && size <= 0 {
			continue
		}
		file := gin.H{`name`: name}
		if size > 0 {
			file[`size`] = size
		}
		if mime, ok := m[`type`].(string); ok && len(mime) > 0 {
			file[`type`] = mime
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return nil, false
	}
	return gin.H{`files`: files}, true
}

func normalizeAudioControl(data map[string]any) (gin.H, bool) {
	if data == nil {
		return gin.H{}, true
	}
	payload := gin.H{}
	if muted, ok := data[`muted`].(bool); ok {
		payload[`muted`] = muted
	}
	if op, ok := data[`op`].(string); ok && len(op) > 0 {
		payload[`op`] = strings.ToLower(op)
	}
	if mode, ok := data[`mode`].(string); ok && len(mode) > 0 {
		payload[`mode`] = strings.ToLower(mode)
	}
	return payload, true
}

func normalizeConfig(data map[string]any) (gin.H, bool) {
	if data == nil {
		return gin.H{}, true
	}

	payload := gin.H{}

	if fps, ok := coerceNumber(data[`fps`]); ok {
		payload[`fps`] = fps
	}
	if quality, ok := coerceNumber(data[`quality`]); ok {
		payload[`quality`] = quality
	}

	// Accept both "monitor" and "display" keys; map to monitor for the device
	if monitor, ok := coerceNumber(data[`monitor`]); ok {
		payload[`monitor`] = monitor
	} else if display, ok := coerceNumber(data[`display`]); ok {
		payload[`monitor`] = display
	}

	if codec, ok := data[`codec`].(string); ok && len(codec) > 0 {
		payload[`codec`] = strings.ToLower(strings.TrimSpace(codec))
	}
	if allow, ok := data[`allowControl`].(bool); ok {
		payload[`allowControl`] = allow
	}

	// Allow empty payloads; the device will perform stricter validation
	return payload, true
}

func coerceNumber(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case float32:
		return int64(n), true
	}
	return 0, false
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
