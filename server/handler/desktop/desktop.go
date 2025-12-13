package desktop

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
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
	"go.opentelemetry.io/otel/trace"
)

type desktop struct {
	uuid       string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
	frameCount uint64 // diagnostic counter for frame relay monitoring
}

var desktopSessions = melody.New()
var frameRelayStats struct {
	forwarded atomic.Uint64
	failures  atomic.Uint64
	lastLog   atomic.Int64
}
var desktopTelemetry struct {
	handshakeAttempts  atomic.Uint64
	handshakeSuccesses atomic.Uint64
	handshakeFailures  atomic.Uint64
	heartbeatSuccesses atomic.Uint64
	heartbeatFailures  atomic.Uint64
	policyViolations   atomic.Uint64
}
var desktopTelemetryLastLog atomic.Int64

const (
	desktopTelemetryLogInterval = int64(60) // seconds
	frameRelayLogInterval       = int64(30) // seconds
)

// desktopCounterSnapshot returns a point-in-time copy of telemetry counters.
func desktopCounterSnapshot() map[string]uint64 {
	return map[string]uint64{
		"handshake_attempts":  desktopTelemetry.handshakeAttempts.Load(),
		"handshake_successes": desktopTelemetry.handshakeSuccesses.Load(),
		"handshake_failures":  desktopTelemetry.handshakeFailures.Load(),
		"heartbeat_successes": desktopTelemetry.heartbeatSuccesses.Load(),
		"heartbeat_failures":  desktopTelemetry.heartbeatFailures.Load(),
		"policy_violations":   desktopTelemetry.policyViolations.Load(),
		"frames_forwarded":    frameRelayStats.forwarded.Load(),
		"frame_failures":      frameRelayStats.failures.Load(),
	}
}

func traceAttributes(values map[string]any) []attribute.KeyValue {
	if len(values) == 0 {
		return nil
	}
	attrs := make([]attribute.KeyValue, 0, len(values))
	for k, v := range values {
		switch val := v.(type) {
		case string:
			attrs = append(attrs, attribute.String(k, val))
		case fmt.Stringer:
			attrs = append(attrs, attribute.String(k, val.String()))
		case bool:
			attrs = append(attrs, attribute.Bool(k, val))
		case int:
			attrs = append(attrs, attribute.Int(k, val))
		case int64:
			attrs = append(attrs, attribute.Int64(k, val))
		case uint64:
			attrs = append(attrs, attribute.Int64(k, int64(val)))
		case float64:
			attrs = append(attrs, attribute.Float64(k, val))
		default:
			attrs = append(attrs, attribute.String(k, fmt.Sprintf("%v", v)))
		}
	}
	return attrs
}

func recordDesktopHandshakeAttempt() {
	desktopTelemetry.handshakeAttempts.Add(1)
}

func recordDesktopHandshakeSuccess() {
	desktopTelemetry.handshakeSuccesses.Add(1)
	logDesktopTelemetrySnapshot("handshake_success")
}

func recordDesktopHandshakeFailure() {
	desktopTelemetry.handshakeFailures.Add(1)
	logDesktopTelemetrySnapshot("handshake_failure")
}

func recordDesktopHeartbeatSuccess() {
	desktopTelemetry.heartbeatSuccesses.Add(1)
	logDesktopTelemetrySnapshot("heartbeat_success")
}

func recordDesktopHeartbeatFailure() {
	desktopTelemetry.heartbeatFailures.Add(1)
	logDesktopTelemetrySnapshot("heartbeat_failure")
}

func recordDesktopPolicyViolation() {
	desktopTelemetry.policyViolations.Add(1)
	logDesktopTelemetrySnapshot("policy_violation")
}

func recordDesktopFrameRelayFailure(desktopUUID string, frameSize int) {
	frameRelayStats.failures.Add(1)
	logFrameRelaySnapshot("write_error", desktopUUID, frameSize)
}

func logDesktopTelemetrySnapshot(trigger string) {
	now := time.Now().Unix()
	last := desktopTelemetryLastLog.Load()
	if trigger != "policy_violation" && now-last < desktopTelemetryLogInterval {
		return
	}
	if !desktopTelemetryLastLog.CompareAndSwap(last, now) {
		return
	}

	forwarded := frameRelayStats.forwarded.Load()
	failed := frameRelayStats.failures.Load()
	totalFrames := forwarded + failed
	deliveryRate := float64(100)
	if totalFrames > 0 {
		deliveryRate = float64(forwarded) / float64(totalFrames) * 100
	}

	common.Info(nil, `[SERVER_DESKTOP_METRICS]`, ``, `Desktop telemetry snapshot`, map[string]any{
		`trigger`:             trigger,
		`handshake_attempts`:  desktopTelemetry.handshakeAttempts.Load(),
		`handshake_successes`: desktopTelemetry.handshakeSuccesses.Load(),
		`handshake_failures`:  desktopTelemetry.handshakeFailures.Load(),
		`heartbeat_successes`: desktopTelemetry.heartbeatSuccesses.Load(),
		`heartbeat_failures`:  desktopTelemetry.heartbeatFailures.Load(),
		`policy_violations`:   desktopTelemetry.policyViolations.Load(),
		`frames_forwarded`:    forwarded,
		`frames_failed`:       failed,
		`delivery_rate`:       deliveryRate,
	})
}

func logFrameRelaySnapshot(trigger, desktopUUID string, frameSize int) {
	now := time.Now().Unix()
	last := frameRelayStats.lastLog.Load()
	if trigger != "write_error" && now-last < frameRelayLogInterval {
		return
	}
	if !frameRelayStats.lastLog.CompareAndSwap(last, now) {
		return
	}

	forwarded := frameRelayStats.forwarded.Load()
	failed := frameRelayStats.failures.Load()
	total := forwarded + failed
	deliveryRate := float64(100)
	if total > 0 {
		deliveryRate = float64(forwarded) / float64(total) * 100
	}

	common.Info(nil, `[SERVER_FRAME_RELAY_SUMMARY]`, ``, `Frame relay snapshot`, map[string]any{
		`trigger`:       trigger,
		`desktop_uuid`:  desktopUUID,
		`frame_size`:    frameSize,
		`frames_sent`:   forwarded,
		`frames_failed`: failed,
		`delivery_rate`: deliveryRate,
	})
	logDesktopTelemetrySnapshot("frame_relay")
}

// Session control key for view-only enforcement
const sessionAllowControlKey = `DesktopAllowControl`

// Payload limits are now centralized in utility/limits.go
// See: REMOTE_DESKTOP_PIPELINE_AUDIT.md - Payload Constant Centralization

func init() {
	desktopSessions.Config.MaxMessageSize = common.MaxMessageSize
	// Extended timeouts for desktop streaming stability:
	// - PongWait: 120s (up from 60s default) to handle network jitter
	// - WriteWait: 30s (up from 10s) for large frame writes
	// - PingPeriod: 90s (3/4 of PongWait) per WebSocket best practices
	desktopSessions.Config.PongWait = 120 * time.Second
	desktopSessions.Config.WriteWait = 30 * time.Second
	desktopSessions.Config.PingPeriod = 90 * time.Second
	// Disable permessage-deflate compression (RFC 7692).
	// Desktop payloads are already compressed (JPEG/etc); RFC 7692 adds CPU + latency.
	desktopSessions.EnableCompress(false)
	desktopSessions.HandleConnect(onDesktopConnect)
	desktopSessions.HandleMessage(onDesktopMessage)
	desktopSessions.HandleMessageBinary(onDesktopMessage)
	desktopSessions.HandleDisconnect(onDesktopDisconnect)
	// Capture WebSocket close codes for debugging connection issues
	desktopSessions.HandleClose(func(session *melody.Session, code int, text string) error {
		// Store close info for onDesktopDisconnect to log
		session.Set(`CloseCode`, code)
		session.Set(`CloseText`, text)
		common.Info(session, `[SERVER_DESKTOP_WS_CLOSE]`, ``, `WebSocket close frame received`, map[string]any{
			`close_code`: code,
			`close_text`: text,
		})
		return nil
	})
	go utility.WSHealthCheck(desktopSessions, sendPack)
}

// InitDesktop handles desktop websocket handshake event
func InitDesktop(ctx *gin.Context) {
	tr := otel.Tracer("rocket-server/desktop")
	ctxSpan, span := tr.Start(ctx.Request.Context(), "desktop.handshake")
	defer span.End()
	ctx.Request = ctx.Request.WithContext(ctxSpan)

	start := time.Now()
	recordDesktopHandshakeAttempt()
	logAbort := func(status int, reason string, extra map[string]any) {
		if extra == nil {
			extra = map[string]any{}
		}
		extra[`path`] = ctx.Request.URL.String()
		extra[`ua`] = ctx.Request.UserAgent()
		extra[`latency_ms`] = time.Since(start).Milliseconds()
		span.RecordError(errors.New(reason))
		span.SetStatus(codes.Error, reason)
		span.AddEvent("desktop.handshake.abort", trace.WithAttributes(traceAttributes(extra)...))
		common.Warn(ctx, `DESKTOP_HANDSHAKE`, `fail`, reason, extra)
		ctx.AbortWithStatus(status)
		recordDesktopHandshakeFailure()
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
	if !utility.ValidateWebSocketOrigin(ctx, false) {
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

	span.AddEvent("desktop.handshake.accepted", trace.WithAttributes(attribute.String("device", device)))
	span.SetStatus(codes.Ok, "accepted")

	common.Info(ctx, `DESKTOP_HANDSHAKE`, `success`, ``, map[string]any{
		`device`:     device,
		`latency_ms`: time.Since(start).Milliseconds(),
	})
	recordDesktopHandshakeSuccess()
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
				defer func() {
					if r := recover(); r != nil {
						common.Warn(nil, `DESKTOP_HEARTBEAT`, `panic`, `heartbeat goroutine panicked`, map[string]any{
							`session_id`: sessID,
							`device_id`:  deviceID,
							`panic`:      r,
						})
					}
				}()
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
			data := *pack.Data[`data`].(*[]byte)
			if utility.IsFrameOp(data[5]) {
				// Frame data - track and forward to browser
				desktop.frameCount++
				if err := desktop.srcConn.WriteBinary(data); err != nil {
					common.Warn(nil, `[FRAME_RELAY_ERROR]`, ``, `Failed to write frame to browser`, map[string]any{
						`desktop_uuid`: desktop.uuid[:8] + `...`,
						`error`:        err.Error(),
						`frame_count`:  desktop.frameCount,
						`data_size`:    len(data),
					})
					recordDesktopFrameRelayFailure(desktop.uuid, len(data))
				} else {
					frameRelayStats.forwarded.Add(1)
					// Log every 100th frame for monitoring
					if desktop.frameCount%100 == 0 {
						common.Info(nil, `[FRAME_RELAY_STATS]`, ``, `Frame relay statistics`, map[string]any{
							`desktop_uuid`: desktop.uuid[:8] + `...`,
							`frame_count`:  desktop.frameCount,
							`data_size`:    len(data),
						})
					}
				}
				return
			}

			if data[5] != utility.BinaryOpDesktopControl {
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
		case `DESKTOP_INIT`:
			common.Info(nil, `[SERVER_DESKTOP_INIT_RESPONSE]`, ``, `Received DESKTOP_INIT response from device`, map[string]any{
				`code`:         pack.Code,
				`desktop_uuid`: desktop.uuid[:8] + `...`,
				`has_data`:     pack.Data != nil,
			})
		case `DESKTOP_METRICS`:
			handleDesktopMetricsPacket(desktop, pack)

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

				// Forward DESKTOP_INIT to browser with resolution data so canvas can be sized
				// BEFORE any frame data arrives. This prevents rendering on wrong-sized canvas.
				sendPack(modules.Packet{Act: `DESKTOP_INIT`, Code: 0, Data: pack.Data}, desktop.srcConn)

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
		case `DESKTOP_PONG`:
			// Relay device-originated PONG back to browser for latency measurement
			payload := gin.H{`source`: `device`}
			for k, v := range pack.Data {
				payload[k] = v
			}
			sendPack(modules.Packet{Act: `DESKTOP_PONG`, Code: 0, Data: payload}, desktop.srcConn)
		case `DESKTOP_STATS`:
			payload := gin.H{
				`desktop_uuid`: desktop.uuid,
				`device_id`:    desktop.device,
			}
			for k, v := range pack.Data {
				payload[k] = v
			}

			common.Info(nil, `[SERVER_DESKTOP_STATS]`, ``, `Desktop session metrics snapshot received`, payload)
			sendPack(modules.Packet{Act: `DESKTOP_STATS`, Code: 0, Data: payload}, desktop.srcConn)
		case `DESKTOP_INPUT`:
			if pack.Code != 0 {
				sendPack(pack, desktop.srcConn)
			}
		case `CURSOR_UPDATE`:
			// Validate and relay cursor metadata to browser
			if validated, ok := normalizeCursor(pack.Data); ok {
				sendPack(modules.Packet{Act: `CURSOR_UPDATE`, Data: validated}, desktop.srcConn)
			}
		case `DESKTOP_CLIPBOARD`, `DESKTOP_AUDIO`, `DESKTOP_FILE_DROP`:
			if pack.Code != 0 {
				sendPack(pack, desktop.srcConn)
			}
		case `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`, `DESKTOP_WEBRTC_ICE`:
			sendPack(pack, desktop.srcConn)
		}
	}
}

func handleDesktopMetricsPacket(desktop *desktop, pack modules.Packet) {
	if pack.Data == nil {
		common.Warn(nil, `[SERVER_DESKTOP_METRICS_INVALID]`, ``, `Desktop metrics payload missing data`, map[string]any{
			`desktop_uuid`: desktop.uuid[:8] + `...`,
		})
		return
	}

	raw, err := utils.JSON.Marshal(pack.Data)
	if err != nil {
		common.Warn(nil, `[SERVER_DESKTOP_METRICS_MARSHAL_ERROR]`, ``, `Failed to marshal desktop metrics payload`, map[string]any{
			`desktop_uuid`: desktop.uuid[:8] + `...`,
			`error`:        err.Error(),
		})
		return
	}

	payload := struct {
		Sessions    []DesktopSessionMetrics `json:"sessions"`
		GeneratedAt int64                   `json:"generated_at"`
	}{}

	if err := utils.JSON.Unmarshal(raw, &payload); err != nil {
		common.Warn(nil, `[SERVER_DESKTOP_METRICS_DECODE_FAILED]`, ``, `Failed to decode desktop metrics payload`, map[string]any{
			`desktop_uuid`: desktop.uuid[:8] + `...`,
			`error`:        err.Error(),
		})
		return
	}

	if payload.GeneratedAt == 0 {
		payload.GeneratedAt = time.Now().Unix()
	}

	envelope := DesktopMetricsEnvelope{
		DeviceID:    desktop.device,
		DesktopUUID: desktop.uuid,
		GeneratedAt: payload.GeneratedAt,
		Sessions:    payload.Sessions,
	}
	storeDesktopMetrics(envelope)

	common.Info(nil, `[SERVER_DESKTOP_METRICS]`, ``, `Desktop metrics snapshot stored`, map[string]any{
		`desktop_uuid`: desktop.uuid[:8] + `...`,
		`device`:       desktop.device,
		`sessions`:     len(payload.Sessions),
		`generated_at`: payload.GeneratedAt,
	})
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
	session.Set(sessionAllowControlKey, true)

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
		`desktop`:      desktopUUID,
		`allowControl`: allowControlEnabled(session),
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
		// Forward ping to device for keep-alive
		if ok := common.SendPack(modules.Packet{Act: `DESKTOP_PING`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn); !ok {
			common.Warn(session, `[SERVER_DESKTOP_PING]`, `fail`, `failed to forward ping to device`, map[string]any{
				`desktop_uuid`: desktop.uuid[:8] + `...`,
			})
			recordDesktopHeartbeatFailure()
		} else {
			recordDesktopHeartbeatSuccess()
		}

		// Send quick ACK so browser knows server link is alive (tagged as server source)
		sendPack(modules.Packet{Act: `DESKTOP_PONG`, Data: gin.H{
			`source`: `server`,
		}}, session)

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
	case `DESKTOP_BROWSER_STATS`:
		statsPayload := utility.CollectBrowserStats(pack.Data)
		statsPayload[`desktop_uuid`] = desktop.uuid[:8] + `...`
		statsPayload[`device_id`] = desktop.device[:16] + `...`
		common.Info(session, `[SERVER_DESKTOP_BROWSER_STATS]`, ``, `Browser telemetry snapshot`, statsPayload)
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
		if allow, ok := pack.Data[`allowControl`].(bool); ok {
			setAllowControlFlag(session, allow)
		}
		if !allowControlEnabled(session) {
			blockControlAction(session, desktop, pack.Act)
			return
		}
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

		allowControl := allowControlEnabled(session)
		common.SendPack(modules.Packet{
			Act: `DESKTOP_INPUT`,
			Data: gin.H{
				`events`:       events,
				`desktop`:      desktop.uuid,
				`allowControl`: allowControl,
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
		if allowVal, exists := payload[`allowControl`].(bool); exists {
			setAllowControlFlag(session, allowVal)
		}
		payload[`desktop`] = desktop.uuid
		common.Info(session, `[SERVER_DESKTOP_CONFIG]`, ``, `Relaying desktop configuration to device`, payload)
		common.SendPack(modules.Packet{Act: `DESKTOP_CONFIG`, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_CLIPBOARD`:
		if !allowControlEnabled(session) {
			blockControlAction(session, desktop, pack.Act)
			return
		}
		if payload, ok := normalizeClipboard(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_FILE_DROP`:
		if !allowControlEnabled(session) {
			blockControlAction(session, desktop, pack.Act)
			return
		}
		if payload, ok := normalizeFileDrop(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_AUDIO`:
		if !allowControlEnabled(session) {
			blockControlAction(session, desktop, pack.Act)
			return
		}
		if payload, ok := normalizeAudioControl(pack.Data); ok {
			payload[`desktop`] = desktop.uuid
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_WEBRTC_OFFER`:
		if payload, ok := normalizeSDP(pack.Data); ok {
			payload[`desktop`] = desktop.uuid

			// Provide ICE/TURN config to the device so it can gather relay candidates even
			// when the desktop agent isn't configured via env vars.
			if servercfg.Config.WebRTC != nil {
				cfg := servercfg.Config.WebRTC
				identifier := "device"
				if len(desktop.device) >= 8 {
					identifier = "device:" + desktop.device[:8]
				}
				payload[`ice_servers`] = utility.BuildICEServers(
					cfg.Stun,
					cfg.Turn,
					cfg.TurnSecret,
					identifier,
					cfg.TurnCredentialTTL,
				)
			}

			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktop.uuid}, desktop.deviceConn)
			return
		}
		sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	case `DESKTOP_WEBRTC_ANSWER`:
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
	common.Warn(session, `[SERVER_DESKTOP_UNKNOWN_ACTION]`, ``, `Unknown desktop action from browser`, map[string]any{
		`act`:          pack.Act,
		`desktop_uuid`: desktop.uuid[:8] + `...`,
	})
	sendPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
	return
}

func onDesktopDisconnect(session *melody.Session) {
	// Collect diagnostic info for disconnect analysis
	closeCode := 0
	closeText := ""
	if code, ok := session.Get(`CloseCode`); ok {
		closeCode, _ = code.(int)
	}
	if text, ok := session.Get(`CloseText`); ok {
		closeText, _ = text.(string)
	}

	common.Info(session, `[SERVER_DESKTOP_DISCONNECT]`, ``, `Browser disconnected from desktop session`, map[string]any{
		`close_code`: closeCode,
		`close_text`: closeText,
	})
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
		`frame_count`:  desktop.frameCount,
		`close_code`:   closeCode,
		`close_text`:   closeText,
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

func setAllowControlFlag(session *melody.Session, allowed bool) {
	if session == nil {
		return
	}
	prev := allowControlEnabled(session)
	session.Set(sessionAllowControlKey, allowed)
	if prev == allowed {
		return
	}

	if val, ok := session.Get(`Desktop`); ok {
		if desktop, ok := val.(*desktop); ok {
			common.Info(session, `[SERVER_DESKTOP_POLICY]`, ``, `allowControl updated`, map[string]any{
				`desktop_uuid`: desktop.uuid[:8] + `...`,
				`previous`:     prev,
				`current`:      allowed,
			})
			if !allowed {
				recordDesktopPolicyViolation()
			}
		}
	}
}

func allowControlEnabled(session *melody.Session) bool {
	if session == nil {
		return true
	}
	val, ok := session.Get(sessionAllowControlKey)
	if !ok {
		return true
	}
	allowed, ok := val.(bool)
	if !ok {
		return true
	}
	return allowed
}

func blockControlAction(session *melody.Session, desktop *desktop, act string) {
	common.Warn(session, `[SERVER_DESKTOP_POLICY]`, `fail`, `control action blocked`, map[string]any{
		`desktop_uuid`: desktop.uuid[:8] + `...`,
		`action`:       act,
	})
	sendPack(modules.Packet{Act: act, Code: 1, Msg: `${i18n|SHARE.VIEW_ONLY}`}, session)
	recordDesktopPolicyViolation()
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
		if len(events) > utility.MaxDesktopInputBatch {
			return events[:utility.MaxDesktopInputBatch], true
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
	if !ok || len(sdp) == 0 || len(sdp) > utility.MaxSDPLength {
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
	if !ok || len(candidate) == 0 || len(candidate) > utility.MaxCandidateLength {
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
	if len(text) > utility.MaxClipboardBytes {
		text = text[:utility.MaxClipboardBytes]
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
		if len(files) >= utility.MaxFileDropEntries {
			break
		}
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m[`name`].(string)
		if len(name) > utility.MaxFileNameLength {
			name = name[:utility.MaxFileNameLength]
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

// normalizeCursor validates and sanitizes cursor update data.
// Enforces maximum dimensions and data size to prevent memory abuse.
func normalizeCursor(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}

	// Validate dimensions
	width, wOk := coerceNumber(data[`width`])
	height, hOk := coerceNumber(data[`height`])
	if !wOk || !hOk || width <= 0 || height <= 0 {
		return nil, false
	}
	if width > utility.MaxCursorWidth || height > utility.MaxCursorHeight {
		return nil, false
	}

	// Validate base64 data size
	dataStr, ok := data[`data`].(string)
	if ok && len(dataStr) > utility.MaxCursorDataSize {
		return nil, false
	}

	// Build validated payload
	payload := gin.H{
		`width`:  width,
		`height`: height,
	}

	// Copy safe numeric fields
	if x, ok := coerceNumber(data[`x`]); ok {
		payload[`x`] = x
	}
	if y, ok := coerceNumber(data[`y`]); ok {
		payload[`y`] = y
	}
	if hotX, ok := coerceNumber(data[`hotX`]); ok {
		payload[`hotX`] = hotX
	}
	if hotY, ok := coerceNumber(data[`hotY`]); ok {
		payload[`hotY`] = hotY
	}
	if hash, ok := coerceNumber(data[`hash`]); ok {
		payload[`hash`] = hash
	}

	// Copy boolean/string fields
	if visible, ok := data[`visible`].(bool); ok {
		payload[`visible`] = visible
	}
	if format, ok := data[`format`].(string); ok && len(format) > 0 && len(format) < 32 {
		payload[`format`] = format
	}
	if len(dataStr) > 0 {
		payload[`data`] = dataStr
	}

	return payload, true
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
	if transport, ok := data[`transport`].(string); ok && len(transport) > 0 {
		payload[`transport`] = strings.ToLower(strings.TrimSpace(transport))
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
