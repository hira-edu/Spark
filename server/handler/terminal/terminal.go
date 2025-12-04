package terminal

import (
	"Rocket/modules"
	"Rocket/server/cluster"
	"Rocket/server/common"
	servercfg "Rocket/server/config"
	"Rocket/server/handler/utility"
	"Rocket/server/storage"
	"Rocket/utils"
	"Rocket/utils/melody"
	"context"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"net/http"
	"reflect"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type terminal struct {
	uuid       string
	device     string
	session    *melody.Session
	deviceConn *melody.Session
}

var terminalSessions = melody.New()

func init() {
	terminalSessions.Config.MaxMessageSize = common.MaxMessageSize
	terminalSessions.HandleConnect(onTerminalConnect)
	terminalSessions.HandleMessage(onTerminalMessage)
	terminalSessions.HandleMessageBinary(onTerminalMessage)
	terminalSessions.HandleDisconnect(onTerminalDisconnect)
	go utility.WSHealthCheck(terminalSessions, sendPack)
}

// InitTerminal handles terminal websocket handshake event
func InitTerminal(ctx *gin.Context) {
	tr := otel.Tracer("rocket-server/terminal")
	ctxSpan, span := tr.Start(ctx.Request.Context(), "terminal.handshake")
	defer span.End()
	ctx.Request = ctx.Request.WithContext(ctxSpan)
	start := time.Now()

	common.Info(ctx, `TERMINAL_HANDSHAKE`, ``, `start`, map[string]any{
		`from`: ctx.ClientIP(),
	})

	if !ctx.IsWebsocket() {
		common.Warn(ctx, `TERMINAL_HANDSHAKE`, `fail`, `not websocket`, nil)
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "not websocket")
		return
	}
	secretStr, ok := ctx.GetQuery(`secret`)
	if !ok || len(secretStr) != 32 {
		common.Warn(ctx, `TERMINAL_HANDSHAKE`, `fail`, `invalid secret`, map[string]any{
			`secretLen`: len(secretStr),
		})
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "missing secret")
		return
	}
	secret, err := hex.DecodeString(secretStr)
	if err != nil {
		common.Warn(ctx, `TERMINAL_HANDSHAKE`, `fail`, `secret decode failed`, map[string]any{
			`error`: err.Error(),
		})
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.RecordError(err)
		span.SetStatus(codes.Error, "secret decode failed")
		return
	}
	device, ok := ctx.GetQuery(`device`)
	if !ok {
		common.Warn(ctx, `TERMINAL_HANDSHAKE`, `fail`, `missing device`, nil)
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "missing device")
		return
	}
	if cluster.RedirectIfNeeded(ctx, device) {
		common.Info(ctx, `TERMINAL_HANDSHAKE`, ``, `redirected`, map[string]any{
			`device`: device,
		})
		return
	}
	if _, ok := common.CheckDevice(device, ``); !ok {
		common.Warn(ctx, `TERMINAL_HANDSHAKE`, `fail`, `device not found`, map[string]any{
			`device`: device,
		})
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "device not found")
		return
	}

	terminalSessions.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Secret`:   secret,
		`Device`:   device,
		`LastPack`: utils.Unix,
	})

	span.SetAttributes(
		attribute.String("terminal.device", device),
		attribute.Int("terminal.secret_len", len(secret)),
		attribute.Int64("latency_ms", time.Since(start).Milliseconds()),
	)
}

// terminalEventWrapper returns a eventCallback function that will
// be called when device need to send a packet to browser
func terminalEventWrapper(terminal *terminal) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			data := *pack.Data[`data`].(*[]byte)
			common.Info(nil, `TERMINAL_RAW_DATA`, ``, ``, map[string]any{
				`dataLen`: len(data),
				`op`:      data[5],
			})
			if data[5] == utility.BinaryOpTerminalStream {
				terminal.session.WriteBinary(data)
				return
			}

			if data[5] != utility.BinaryOpTerminalJSON {
				common.Warn(nil, `TERMINAL_RAW_DATA`, ``, `unexpected op code`, map[string]any{
					`op`: data[5],
				})
				return
			}
			// Binary protocol header is 24 bytes: magic(4) + service(1) + op(1) + event(16) + length(2)
			// JSON payload starts at byte 24
			data = data[24:]
			data = utility.SimpleDecrypt(data, device)
			if utils.JSON.Unmarshal(data, &pack) != nil {
				common.Warn(nil, `TERMINAL_RAW_DATA`, ``, `JSON parse failed`, nil)
				return
			}
		}

		switch pack.Act {
		case `TERMINAL_INIT`:
			if pack.Code != 0 {
				msg := `${i18n|TERMINAL.CREATE_SESSION_FAILED}`
				if len(pack.Msg) > 0 {
					msg += `: ` + pack.Msg
				} else {
					msg += `${i18n|COMMON.UNKNOWN_ERROR}`
				}
				sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, terminal.session)
				common.RemoveEvent(terminal.uuid)
				terminal.session.Close()
				common.Warn(terminal.session, `TERMINAL_INIT`, `fail`, msg, map[string]any{
					`deviceConn`: terminal.deviceConn,
				})
			} else {
				common.Info(terminal.session, `TERMINAL_INIT`, `success`, ``, map[string]any{
					`deviceConn`: terminal.deviceConn,
				})
			}
		case `TERMINAL_QUIT`:
			msg := `${i18n|TERMINAL.SESSION_CLOSED}`
			if len(pack.Msg) > 0 {
				msg = pack.Msg
			}
			sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, terminal.session)
			common.RemoveEvent(terminal.uuid)
			terminal.session.Close()
			common.Info(terminal.session, `TERMINAL_QUIT`, ``, msg, map[string]any{
				`deviceConn`: terminal.deviceConn,
			})
		case `TERMINAL_OUTPUT`:
			if pack.Data == nil {
				return
			}
			if output, ok := pack.Data[`output`]; ok {
				sendPack(modules.Packet{Act: `TERMINAL_OUTPUT`, Data: gin.H{
					`output`: output,
				}}, terminal.session)
			}
		}
	}
}

func onTerminalConnect(session *melody.Session) {
	device, ok := session.Get(`Device`)
	if !ok {
		sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|TERMINAL.CREATE_SESSION_FAILED}`}, session)
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
	uuid := utils.GetStrUUID()
	terminal := &terminal{
		uuid:       uuid,
		device:     device.(string),
		session:    session,
		deviceConn: deviceConn,
	}
	session.Set(`Terminal`, terminal)
	common.AddEvent(terminalEventWrapper(terminal), connUUID, uuid)

	if storage.IsMongoEnabled() {
		go func(sessID, deviceID string) {
			ctx, cancel := storage.WithTimeout(context.Background())
			defer cancel()
			if mgr := cluster.Current(); mgr != nil {
				mgr.StartSession(ctx, sessID, deviceID, "", "terminal")
			} else {
				_ = storage.StartSession(ctx, sessID, deviceID, "", "terminal", common.GetControllerID(), sessionLeaseTTL())
			}
		}(uuid, terminal.device)
	}

	common.SendPack(modules.Packet{Act: `TERMINAL_INIT`, Data: gin.H{
		`terminal`: uuid,
	}, Event: uuid}, deviceConn)
	common.Info(terminal.session, `TERMINAL_CONN`, `success`, ``, map[string]any{
		`deviceConn`: terminal.deviceConn,
	})
}

func onTerminalMessage(session *melody.Session, data []byte) {
	var pack modules.Packet
	val, ok := session.Get(`Terminal`)
	if !ok {
		return
	}
	terminal := val.(*terminal)

	service, op, isBinary := utils.CheckBinaryPack(data)
	if !isBinary {
		sendPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	// Handle raw terminal input/output (service 21, op 00)
	if service == 21 && op == 00 {
		session.Set(`LastPack`, utils.Unix)
		rawEvent, _ := hex.DecodeString(terminal.uuid)
		data = append(data, rawEvent...)
		copy(data[22:], data[6:])
		copy(data[6:], rawEvent)
		terminal.deviceConn.WriteBinary(data)
		return
	}

	// Handle encrypted JSON commands (service 20 or 21, op 01 or 03)
	if !((service == 20 && op == 03) || (service == 21 && op == 01)) {
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
	case `TERMINAL_INPUT`:
		if pack.Data == nil {
			return
		}
		if input, ok := pack.GetData(`input`, reflect.String); ok {
			rawInput, _ := hex.DecodeString(input.(string))
			common.Info(terminal.session, `TERMINAL_INPUT`, ``, ``, map[string]any{
				`deviceConn`: terminal.deviceConn,
				`input`:      utils.BytesToString(rawInput),
			})
			common.SendPack(modules.Packet{Act: `TERMINAL_INPUT`, Data: gin.H{
				`input`:    input,
				`terminal`: terminal.uuid,
			}, Event: terminal.uuid}, terminal.deviceConn)
		}
		return
	case `TERMINAL_RESIZE`:
		if pack.Data == nil {
			return
		}
		if cols, ok := pack.Data[`cols`]; ok {
			if rows, ok := pack.Data[`rows`]; ok {
				common.SendPack(modules.Packet{Act: `TERMINAL_RESIZE`, Data: gin.H{
					`cols`:     cols,
					`rows`:     rows,
					`terminal`: terminal.uuid,
				}, Event: terminal.uuid}, terminal.deviceConn)
			}
		}
		return
	case `TERMINAL_KILL`:
		common.Info(terminal.session, `TERMINAL_KILL`, `success`, ``, map[string]any{
			`deviceConn`: terminal.deviceConn,
		})
		common.SendPack(modules.Packet{Act: `TERMINAL_KILL`, Data: gin.H{
			`terminal`: terminal.uuid,
		}, Event: terminal.uuid}, terminal.deviceConn)
		return
	case `PING`:
		common.SendPack(modules.Packet{Act: `TERMINAL_PING`, Data: gin.H{
			`terminal`: terminal.uuid,
		}, Event: terminal.uuid}, terminal.deviceConn)
		if storage.IsMongoEnabled() {
			go func(sessID string) {
				ctx, cancel := storage.WithTimeout(context.Background())
				defer cancel()
				if mgr := cluster.Current(); mgr != nil {
					mgr.HeartbeatSession(ctx, sessID)
				} else {
					_ = storage.HeartbeatSession(ctx, sessID, sessionLeaseTTL())
				}
			}(terminal.uuid)
		}
		return
	}
	session.Close()
}

func onTerminalDisconnect(session *melody.Session) {
	common.Info(session, `TERMINAL_CLOSE`, `success`, ``, nil)
	val, ok := session.Get(`Terminal`)
	if !ok {
		return
	}
	terminal, ok := val.(*terminal)
	if !ok {
		return
	}
	common.SendPack(modules.Packet{Act: `TERMINAL_KILL`, Data: gin.H{
		`terminal`: terminal.uuid,
	}, Event: terminal.uuid}, terminal.deviceConn)
	common.RemoveEvent(terminal.uuid)
	if storage.IsMongoEnabled() {
		go func(sessID string) {
			ctx, cancel := storage.WithTimeout(context.Background())
			defer cancel()
			if mgr := cluster.Current(); mgr != nil {
				mgr.CloseSession(ctx, sessID, `client_quit`)
			} else {
				_ = storage.CloseSession(ctx, sessID)
			}
		}(terminal.uuid)
	}
	session.Set(`Terminal`, nil)
	terminal = nil
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
	err = session.WriteBinary(data)
	return err == nil
}

func CloseSessionsByDevice(deviceID string) {
	var queue []*melody.Session
	terminalSessions.IterSessions(func(_ string, session *melody.Session) bool {
		val, ok := session.Get(`Terminal`)
		if !ok {
			return true
		}
		terminal, ok := val.(*terminal)
		if !ok {
			return true
		}
		if terminal.device == deviceID {
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
