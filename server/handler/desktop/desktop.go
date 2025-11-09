package desktop

import (
	"Spark/modules"
	"Spark/server/common"
	"Spark/server/handler/utility"
	"Spark/utils"
	"Spark/utils/melody"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"math"
	"net/http"
	"reflect"
)

type desktop struct {
	uuid       string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
	caps       map[string]any
	metrics    map[string]any
}

var desktopSessions = melody.New()

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
		case `DESKTOP_CAPS`:
			desktop.caps = pack.Data
			sendPack(modules.Packet{Act: `DESKTOP_CAPS`, Data: pack.Data}, desktop.srcConn)
			common.Info(desktop.srcConn, `DESKTOP_CAPS`, ``, ``, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`caps`:       pack.Data,
			})
		case `DESKTOP_METRICS`:
			derived := logDesktopMetrics(pack, desktop)
			if derived == nil {
				derived = pack.Data
			}
			desktop.metrics = derived
			sendPack(modules.Packet{Act: `DESKTOP_METRICS`, Data: derived}, desktop.srcConn)
		case `DESKTOP_MONITORS`:
			sendPack(modules.Packet{Act: `DESKTOP_MONITORS`, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_SET_MONITOR`:
			sendPack(modules.Packet{Act: `DESKTOP_SET_MONITOR`, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_SET_QUALITY`:
			sendPack(modules.Packet{Act: `DESKTOP_SET_QUALITY`, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_INPUT`:
			// Currently no echo back to browser.
		case `DESKTOP_CLIPBOARD_DATA`:
			sendPack(modules.Packet{Act: `DESKTOP_CLIPBOARD_DATA`, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_CLIPBOARD_RESULT`:
			sendPack(modules.Packet{Act: `DESKTOP_CLIPBOARD_RESULT`, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		}
	}
}

func logDesktopMetrics(pack modules.Packet, desktop *desktop) map[string]any {
	if desktop == nil || pack.Data == nil {
		return nil
	}
	frames, okFrames := metricFloat(pack.Data[`frames`])
	bytesVal, okBytes := metricFloat(pack.Data[`bytes`])
	intervalMs, okInterval := metricFloat(pack.Data[`intervalMs`])
	if !(okFrames && okBytes && okInterval) || intervalMs <= 0 {
		return nil
	}
	intervalSeconds := intervalMs / 1000
	if intervalSeconds <= 0 {
		return nil
	}
	fps := frames / intervalSeconds
	bandwidth := bytesVal / intervalSeconds
	blocks, _ := metricFloat(pack.Data[`blocks`])
	queueHigh, _ := metricFloat(pack.Data[`queueHighWater`])
	queueDrops, _ := metricFloat(pack.Data[`queueDrops`])
	encoderErrors, _ := metricFloat(pack.Data[`encoderErrors`])
	timestamp, _ := metricFloat(pack.Data[`timestamp`])
	var lastError string
	if v, ok := pack.Data[`lastError`].(string); ok {
		lastError = v
	}
	avgBlocks := 0.0
	if frames > 0 && blocks > 0 {
		avgBlocks = blocks / frames
	}
	metrics := map[string]any{
		`desktop`:               desktop.uuid,
		`device`:                desktop.device,
		`fps`:                   math.Round(fps*100) / 100,
		`bandwidth_bytes_per_s`: math.Round(bandwidth*100) / 100,
		`queue_high_water`:      int(queueHigh),
		`queue_drops`:           int(queueDrops),
		`encoder_errors`:        int(encoderErrors),
		`avg_blocks_per_frame`:  math.Round(avgBlocks*100) / 100,
		`frames`:                int(frames),
		`interval_ms`:           intervalMs,
		`bytes_interval`:        bytesVal,
	}
	if timestamp > 0 {
		metrics[`timestamp`] = timestamp
	}
	if len(lastError) > 0 {
		metrics[`last_error`] = lastError
	}
	common.Info(desktop.srcConn, `DESKTOP_METRICS`, ``, ``, metrics)
	uiMetrics := map[string]any{
		`fps`:                  math.Round(fps*100) / 100,
		`bandwidthBytesPerSec`: math.Round(bandwidth*100) / 100,
		`frames`:               int(frames),
		`blocks`:               int(blocks),
		`queueHighWater`:       int(queueHigh),
		`queueDrops`:           int(queueDrops),
		`encoderErrors`:        int(encoderErrors),
		`intervalMs`:           intervalMs,
		`bytesInterval`:        bytesVal,
	}
	if timestamp > 0 {
		uiMetrics[`timestamp`] = timestamp
	}
	if len(lastError) > 0 {
		uiMetrics[`lastError`] = lastError
	}
	return uiMetrics
}

func metricFloat(val any) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
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
	case `DESKTOP_MONITORS`:
		common.SendPack(modules.Packet{Act: `DESKTOP_MONITORS`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_SET_MONITOR`:
		idx, ok := pack.GetData(`index`, reflect.Float64)
		if !ok {
			sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
			return
		}
		common.SendPack(modules.Packet{Act: `DESKTOP_SET_MONITOR`, Data: gin.H{
			`desktop`: desktop.uuid,
			`index`:   idx,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_SET_QUALITY`:
		key, ok := pack.GetData(`preset`, reflect.String)
		if !ok {
			sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
			return
		}
		common.SendPack(modules.Packet{Act: `DESKTOP_SET_QUALITY`, Data: gin.H{
			`desktop`: desktop.uuid,
			`preset`:  key,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_CLIPBOARD_PUSH`:
		text, ok := pack.GetData(`text`, reflect.String)
		if !ok {
			sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
			return
		}
		common.SendPack(modules.Packet{Act: `DESKTOP_CLIPBOARD_PUSH`, Data: gin.H{
			`desktop`: desktop.uuid,
			`text`:    text,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_CLIPBOARD_PULL`:
		common.SendPack(modules.Packet{Act: `DESKTOP_CLIPBOARD_PULL`, Data: gin.H{
			`desktop`: desktop.uuid,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_INPUT`:
		common.SendPack(modules.Packet{Act: `DESKTOP_INPUT`, Data: gin.H{
			`desktop`: desktop.uuid,
			`payload`: pack.Data[`payload`],
		}, Event: desktop.uuid}, desktop.deviceConn)
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
