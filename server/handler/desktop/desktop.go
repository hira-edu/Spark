package desktop

import (
	"Spark/modules"
	"Spark/server/common"
	"Spark/server/handler/utility"
	"Spark/utils"
	"Spark/utils/melody"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"math"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"
)

type desktop struct {
	uuid          string
	device        string
	srcConn       *melody.Session
	deviceConn    *melody.Session
	caps          map[string]any
	metrics       map[string]any
	inputLimiter  *rateLimiter
	inputStats    inputStats
	inputJournal  []inputDigest
	hotkeyLimiter *rateLimiter
}

const (
	inputRateLimitPerWindow = 600
	inputRateWindow         = time.Second
	inputAuditInterval      = 5 * time.Second
	inputJournalLimit       = 500
	hotkeyLimitPerWindow    = 3
	hotkeyRateWindow        = 10 * time.Second
)

var desktopSessions = melody.New()
var webrtcSessions = newWebRTCController(5 * time.Minute)

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
			flushInputJournal(desktop)
			sendPack(modules.Packet{Act: `QUIT`, Msg: msg}, desktop.srcConn)
			common.RemoveEvent(desktop.uuid)
			desktop.srcConn.Close()
			common.Info(desktop.srcConn, `DESKTOP_QUIT`, `success`, ``, map[string]any{
				`deviceConn`: desktop.deviceConn,
			})
		case `DESKTOP_CAPS`:
			desktop.caps = enrichDesktopWebRTCCaps(desktop.uuid, pack.Data)
			sendPack(modules.Packet{Act: `DESKTOP_CAPS`, Event: pack.Event, Data: desktop.caps}, desktop.srcConn)
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
			sendPack(modules.Packet{Act: `DESKTOP_METRICS`, Event: pack.Event, Data: derived}, desktop.srcConn)
		case `DESKTOP_POLICY`:
			if desktop.caps == nil {
				desktop.caps = map[string]any{}
			}
			if pack.Data != nil {
				desktop.caps[`policy`] = pack.Data
			}
			sendPack(modules.Packet{Act: `DESKTOP_POLICY`, Event: pack.Event, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_POLICY_ALERT`:
			logPolicyAlert(desktop, pack)
			sendPack(modules.Packet{Act: `DESKTOP_POLICY_ALERT`, Event: pack.Event, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_POLICY_FORCE`:
			sendPack(modules.Packet{Act: `DESKTOP_POLICY_FORCE`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_WEBRTC_SIGNAL`:
			handleAgentWebRTCSignal(desktop, pack)
		case `DESKTOP_MONITORS`:
			sendPack(modules.Packet{Act: `DESKTOP_MONITORS`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_SET_MONITOR`:
			sendPack(modules.Packet{Act: `DESKTOP_SET_MONITOR`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_SET_QUALITY`:
			sendPack(modules.Packet{Act: `DESKTOP_SET_QUALITY`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
		case `DESKTOP_INPUT`:
			// Currently no echo back to browser.
		case `DESKTOP_CLIPBOARD_DATA`:
			sendPack(modules.Packet{Act: `DESKTOP_CLIPBOARD_DATA`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
			common.Info(desktop.srcConn, `DESKTOP_CLIPBOARD`, `pull`, pack.Msg, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`desktop`:    desktop.uuid,
				`timestamp`:  pack.Data[`timestamp`],
			})
		case `DESKTOP_CLIPBOARD_RESULT`:
			sendPack(modules.Packet{Act: `DESKTOP_CLIPBOARD_RESULT`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
			direction, _ := pack.Data[`direction`].(string)
			common.Info(desktop.srcConn, `DESKTOP_CLIPBOARD`, direction, pack.Msg, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`desktop`:    desktop.uuid,
				`timestamp`:  pack.Data[`timestamp`],
			})
		case `DESKTOP_SECURE_HOTKEY`:
			sendPack(modules.Packet{Act: `DESKTOP_SECURE_HOTKEY`, Event: pack.Event, Code: pack.Code, Msg: pack.Msg, Data: pack.Data}, desktop.srcConn)
			common.Info(desktop.srcConn, `DESKTOP_SECURE_HOTKEY`, `result`, pack.Msg, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`desktop`:    desktop.uuid,
				`sequence`:   pack.Data[`sequence`],
				`code`:       pack.Code,
			})
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
	if rawWebRTC, ok := mapFromAny(pack.Data[`webrtc`]); ok {
		if derived := deriveWebRTCMetrics(rawWebRTC); len(derived) > 0 {
			metrics[`webrtc`] = derived
			uiMetrics[`webrtc`] = derived
		}
	}
	return uiMetrics
}

func deriveWebRTCMetrics(raw map[string]any) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	intervalMs, ok := metricFloat(raw[`intervalMs`])
	if !ok || intervalMs <= 0 {
		intervalMs = 1000
	}
	intervalSeconds := intervalMs / 1000
	if intervalSeconds <= 0 {
		intervalSeconds = 1
	}
	dataBytes, _ := metricFloat(raw[`dataBytes`])
	videoBytes, _ := metricFloat(raw[`videoBytes`])
	videoFrames, _ := metricFloat(raw[`videoFrames`])
	videoKeyframes, _ := metricFloat(raw[`videoKeyframes`])
	dataDrops, _ := metricFloat(raw[`dataDrops`])
	videoDrops, _ := metricFloat(raw[`videoDrops`])
	videoFps := 0.0
	if videoFrames > 0 {
		videoFps = videoFrames / intervalSeconds
	}
	metrics := map[string]any{
		`intervalMs`:                intervalMs,
		`timestamp`:                 raw[`timestamp`],
		`state`:                     raw[`state`],
		`dataBytes`:                 int(dataBytes),
		`videoBytes`:                int(videoBytes),
		`videoFrames`:               int(videoFrames),
		`videoKeyframes`:            int(videoKeyframes),
		`dataDrops`:                 int(dataDrops),
		`videoDrops`:                int(videoDrops),
		`dataBandwidthBytesPerSec`:  math.Round((dataBytes/intervalSeconds)*100) / 100,
		`videoBandwidthBytesPerSec`: math.Round((videoBytes/intervalSeconds)*100) / 100,
		`videoFps`:                  math.Round(videoFps*100) / 100,
	}
	if lastErr, ok := raw[`lastError`].(string); ok && lastErr != "" {
		metrics[`lastError`] = lastErr
	}
	return metrics
}

func logPolicyAlert(desktop *desktop, pack modules.Packet) {
	if desktop == nil {
		return
	}
	payload := map[string]any{}
	if pack.Data != nil {
		payload = pack.Data
	}
	args := map[string]any{
		`deviceConn`: desktop.deviceConn,
		`desktop`:    desktop.uuid,
		`device`:     desktop.device,
	}
	for _, key := range []string{`func`, `pid`, `session`, `user`, `sid`, `source`, `detail`, `timestamp`, `category`, `severity`} {
		if val, ok := payload[key]; ok && val != nil {
			args[key] = val
		}
	}
	if pack.Event != "" {
		args[`eventId`] = pack.Event
	}
	common.Warn(desktop.srcConn, `DESKTOP_POLICY_ALERT`, `umh`, pack.Msg, args)
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

type rateLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	count       int
	windowStart time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:       limit,
		window:      window,
		windowStart: time.Now(),
	}
}

func (r *rateLimiter) Allow() bool {
	if r == nil || r.limit <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.windowStart) >= r.window {
		r.windowStart = now
		r.count = 0
	}
	if r.count >= r.limit {
		return false
	}
	r.count++
	return true
}

type inputStats struct {
	mu        sync.Mutex
	mouse     uint64
	keyboard  uint64
	blocked   uint64
	lastFlush time.Time
}

func newInputStats() inputStats {
	return inputStats{
		lastFlush: time.Now(),
	}
}

func (s *inputStats) record(kind string) (mouse uint64, keyboard uint64, flush bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == "keyboard" {
		s.keyboard++
	} else {
		s.mouse++
	}
	if time.Since(s.lastFlush) >= inputAuditInterval && (s.mouse > 0 || s.keyboard > 0) {
		mouse = s.mouse
		keyboard = s.keyboard
		s.mouse = 0
		s.keyboard = 0
		s.lastFlush = time.Now()
		flush = true
	}
	return
}

func (s *inputStats) recordBlocked() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocked++
	return s.blocked
}

func detectInputKind(payload any) string {
	body, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	if val, ok := body[`type`].(string); ok {
		return strings.ToLower(val)
	}
	return ""
}

type inputDigest struct {
	Hash      string `json:"hash"`
	Type      string `json:"type"`
	Timestamp int64  `json:"ts"`
}

func (d *desktop) recordInputDigest(entry inputDigest) {
	if d == nil {
		return
	}
	d.inputJournal = append(d.inputJournal, entry)
	if len(d.inputJournal) > inputJournalLimit {
		d.inputJournal = d.inputJournal[len(d.inputJournal)-inputJournalLimit:]
	}
}

func newInputDigest(kind string, payload any) *inputDigest {
	if payload == nil {
		return nil
	}
	data, err := utils.JSON.Marshal(payload)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	return &inputDigest{
		Hash:      hex.EncodeToString(sum[:]),
		Type:      kind,
		Timestamp: time.Now().UnixMilli(),
	}
}

func flushInputJournal(desktop *desktop) {
	if desktop == nil || len(desktop.inputJournal) == 0 {
		return
	}
	common.Info(desktop.srcConn, `DESKTOP_INPUT_JOURNAL`, ``, ``, map[string]any{
		`deviceConn`: desktop.deviceConn,
		`entries`:    desktop.inputJournal,
	})
	desktop.inputJournal = nil
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
		uuid:          desktopUUID,
		device:        device.(string),
		srcConn:       session,
		deviceConn:    deviceConn,
		inputLimiter:  newRateLimiter(inputRateLimitPerWindow, inputRateWindow),
		inputStats:    newInputStats(),
		hotkeyLimiter: newRateLimiter(hotkeyLimitPerWindow, hotkeyRateWindow),
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
	case `DESKTOP_SECURE_HOTKEY`:
		seq, ok := pack.GetData(`sequence`, reflect.String)
		if !ok {
			sendPack(modules.Packet{Act: `DESKTOP_SECURE_HOTKEY`, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
			return
		}
		if desktop.hotkeyLimiter != nil && !desktop.hotkeyLimiter.Allow() {
			common.Warn(desktop.srcConn, `DESKTOP_SECURE_HOTKEY`, `rate_limit`, `${i18n|DESKTOP.SECURE_HOTKEY_RATE_LIMIT}`, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`sequence`:   seq,
			})
			sendPack(modules.Packet{Act: `DESKTOP_SECURE_HOTKEY`, Code: 1, Msg: `${i18n|DESKTOP.SECURE_HOTKEY_RATE_LIMIT}`}, session)
			return
		}
		common.SendPack(modules.Packet{Act: `DESKTOP_SECURE_HOTKEY`, Data: gin.H{
			`desktop`:  desktop.uuid,
			`sequence`: seq,
		}, Event: desktop.uuid}, desktop.deviceConn)
		common.Info(desktop.srcConn, `DESKTOP_SECURE_HOTKEY`, `forward`, ``, map[string]any{
			`deviceConn`: desktop.deviceConn,
			`sequence`:   seq,
		})
		return
	case `DESKTOP_CONTROL`:
		enabled, ok := pack.GetData(`enabled`, reflect.Bool)
		if !ok {
			return
		}
		common.SendPack(modules.Packet{Act: `DESKTOP_CONTROL`, Data: gin.H{
			`desktop`: desktop.uuid,
			`enabled`: enabled,
		}, Event: desktop.uuid}, desktop.deviceConn)
		common.Info(desktop.srcConn, `DESKTOP_CONTROL`, `state`, ``, map[string]any{
			`deviceConn`: desktop.deviceConn,
			`desktop`:    desktop.uuid,
			`enabled`:    enabled,
		})
		return
	case `DESKTOP_INPUT`:
		payload := pack.Data[`payload`]
		kind := detectInputKind(payload)
		if desktop.inputLimiter != nil && !desktop.inputLimiter.Allow() {
			blocked := desktop.inputStats.recordBlocked()
			common.Warn(desktop.srcConn, `DESKTOP_INPUT`, `rate_limit`, `${i18n|DESKTOP.INPUT_RATE_LIMIT}`, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`type`:       kind,
				`blocked`:    blocked,
			})
			sendPack(modules.Packet{Act: `WARN`, Msg: `${i18n|DESKTOP.INPUT_RATE_LIMIT}`}, session)
			return
		}
		if digest := newInputDigest(kind, payload); digest != nil {
			desktop.recordInputDigest(*digest)
		}
		if mouse, keyboard, flush := desktop.inputStats.record(kind); flush {
			common.Info(desktop.srcConn, `DESKTOP_INPUT`, `summary`, ``, map[string]any{
				`deviceConn`: desktop.deviceConn,
				`mouse`:      mouse,
				`keyboard`:   keyboard,
			})
		}
		common.SendPack(modules.Packet{Act: `DESKTOP_INPUT`, Data: gin.H{
			`desktop`: desktop.uuid,
			`payload`: payload,
		}, Event: desktop.uuid}, desktop.deviceConn)
		return
	case `DESKTOP_WEBRTC_SIGNAL`:
		handleBrowserWebRTCSignal(desktop, pack)
		return
	case `DESKTOP_POLICY_FORCE`:
		common.SendPack(modules.Packet{Act: `DESKTOP_POLICY_FORCE`, Data: gin.H{
			`desktop`:      desktop.uuid,
			`forceInput`:   pack.Data[`forceInput`],
			`forceCapture`: pack.Data[`forceCapture`],
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
	flushInputJournal(desktop)
	common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
		`desktop`: desktop.uuid,
	}, Event: desktop.uuid}, desktop.deviceConn)
	common.RemoveEvent(desktop.uuid)
	webrtcSessions.remove(desktop.uuid)
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

func handleBrowserWebRTCSignal(desktop *desktop, pack modules.Packet) {
	if desktop == nil {
		return
	}
	kind, err := toSignalKind(pack.Data[`kind`])
	if err != nil {
		sendWebRTCSignalError(desktop, "browser_kind", err.Error())
		return
	}
	if kind == signalOffer && !desktopSupportsWebRTC(desktop) {
		sendWebRTCUnsupported(desktop, "remote device has not advertised WebRTC support")
		common.Warn(desktop.srcConn, `DESKTOP_WEBRTC_SIGNAL`, `unsupported`, `device missing WebRTC capability`, map[string]any{
			`desktop`: desktop.uuid,
		})
		return
	}
	payload, ok := mapFromAny(pack.Data[`payload`])
	if !ok {
		sendWebRTCSignalError(desktop, "browser_payload", `${i18n|COMMON.INVALID_PARAMETER}`)
		return
	}
	normalized, err := normalizeBrowserSignal(kind, payload)
	if err != nil {
		sendWebRTCSignalError(desktop, "browser_normalize", err.Error())
		return
	}
	if desktop.deviceConn == nil {
		sendWebRTCSignalError(desktop, "agent_unavailable", `${i18n|DESKTOP.SESSION_CLOSED}`)
		return
	}
	if kind == signalOffer {
		webrtcSessions.recordOffer(desktop.uuid)
	}
	common.Info(desktop.srcConn, `DESKTOP_WEBRTC_SIGNAL`, `browser_forward`, ``, map[string]any{
		`deviceConn`: desktop.deviceConn,
		`desktop`:    desktop.uuid,
		`kind`:       string(kind),
	})
	state := webrtcSessions.snapshot(desktop.uuid)
	common.SendPack(modules.Packet{
		Act:   `DESKTOP_WEBRTC_SIGNAL`,
		Event: desktop.uuid,
		Data: gin.H{
			`desktop`: desktop.uuid,
			`kind`:    string(kind),
			`payload`: normalized,
			`origin`:  `browser`,
		},
	}, desktop.deviceConn)
	sendWebRTCState(desktop, "browser_"+string(kind), state)
}

func handleAgentWebRTCSignal(desktop *desktop, pack modules.Packet) {
	if desktop == nil {
		return
	}
	if pack.Code != 0 {
		stage := "agent_error"
		if pack.Msg == "" {
			pack.Msg = `${i18n|COMMON.UNKNOWN_ERROR}`
		}
		sendWebRTCSignalError(desktop, stage, pack.Msg)
		return
	}
	kind, err := toSignalKind(pack.Data[`kind`])
	if err != nil {
		sendWebRTCSignalError(desktop, "agent_kind", err.Error())
		return
	}
	payload, ok := mapFromAny(pack.Data[`payload`])
	if !ok {
		sendWebRTCSignalError(desktop, "agent_payload", `${i18n|COMMON.INVALID_PARAMETER}`)
		return
	}
	normalized, err := normalizeAgentSignal(kind, payload)
	if err != nil {
		sendWebRTCSignalError(desktop, "agent_normalize", err.Error())
		return
	}
	stage := "agent_" + string(kind)
	deliver := true
	switch kind {
	case signalAnswer:
		webrtcSessions.recordAnswer(desktop.uuid)
	case signalCandidate:
		webrtcSessions.recordCandidate(desktop.uuid)
		if webrtcSessions.queueAgentCandidate(desktop.uuid, normalized) {
			deliver = false
			stage = "agent_candidate_queued"
		}
	}
	if deliver {
		sendPack(modules.Packet{
			Act:  `DESKTOP_WEBRTC_SIGNAL`,
			Code: 0,
			Data: map[string]any{
				`kind`:    string(kind),
				`payload`: normalized,
			},
		}, desktop.srcConn)
	}
	if kind == signalAnswer {
		queued := webrtcSessions.markBrowserReady(desktop.uuid)
		for _, candidate := range queued {
			sendPack(modules.Packet{
				Act:  `DESKTOP_WEBRTC_SIGNAL`,
				Code: 0,
				Data: map[string]any{
					`kind`:    string(signalCandidate),
					`payload`: candidate,
				},
			}, desktop.srcConn)
		}
	}
	state := webrtcSessions.snapshot(desktop.uuid)
	sendWebRTCState(desktop, stage, state)
}

func sendWebRTCState(desktop *desktop, stage string, state webrtcSessionState) {
	if desktop == nil || desktop.srcConn == nil {
		return
	}
	payload := map[string]any{
		"desktop":       desktop.uuid,
		"stage":         stage,
		"browserReady":  state.BrowserReady,
		"agentReady":    state.AgentReady,
		"lastOfferAt":   state.LastOfferAt.UnixMilli(),
		"lastAnswerAt":  state.LastAnswerAt.UnixMilli(),
		"lastCandidate": state.LastCandidate.UnixMilli(),
	}
	common.Info(desktop.srcConn, `DESKTOP_WEBRTC_STATE`, stage, ``, payload)
	common.SendPack(modules.Packet{
		Act:  "DESKTOP_WEBRTC_STATE",
		Code: 0,
		Data: payload,
	}, desktop.srcConn)
}

func desktopSupportsWebRTC(desktop *desktop) bool {
	if desktop == nil {
		return false
	}
	caps := desktop.caps
	if caps == nil {
		return false
	}
	transports := toStringSlice(caps[`transports`])
	supportsTransport := false
	for _, transport := range transports {
		if strings.EqualFold(transport, "webrtc") {
			supportsTransport = true
			break
		}
	}
	webrtcCaps, _ := caps[`webrtc`].(map[string]any)
	if !supportsTransport {
		if webrtcCaps == nil {
			return false
		}
		if enabled, ok := webrtcCaps[`enabled`].(bool); ok {
			return enabled
		}
		return true
	}
	if webrtcCaps != nil {
		if enabled, ok := webrtcCaps[`enabled`].(bool); ok {
			return enabled
		}
	}
	return true
}

func toStringSlice(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		result := make([]string, 0, len(v))
		for _, entry := range v {
			if entry == nil {
				continue
			}
			result = append(result, fmt.Sprintf("%v", entry))
		}
		return result
	default:
		if s, ok := raw.(string); ok && s != "" {
			return []string{s}
		}
	}
	return nil
}

func sendWebRTCUnsupported(desktop *desktop, message string) {
	if desktop == nil || desktop.srcConn == nil {
		return
	}
	payload := map[string]any{
		`status`: "unsupported",
	}
	if message != "" {
		payload[`message`] = message
	}
	sendPack(modules.Packet{
		Act:  `DESKTOP_WEBRTC_SIGNAL`,
		Code: 0,
		Data: payload,
	}, desktop.srcConn)
	sendTransportFallback(desktop, "browser_offer_unsupported", message)
}

func sendWebRTCSignalError(desktop *desktop, stage, message string) {
	if desktop == nil || desktop.srcConn == nil {
		return
	}
	if message == "" {
		message = `${i18n|COMMON.UNKNOWN_ERROR}`
	}
	sendPack(modules.Packet{
		Act:  `DESKTOP_WEBRTC_SIGNAL`,
		Code: 1,
		Msg:  message,
	}, desktop.srcConn)
	sendTransportFallback(desktop, stage, message)
}

func sendTransportFallback(desktop *desktop, stage, reason string) {
	if desktop == nil || desktop.srcConn == nil {
		return
	}
	payload := map[string]any{
		`desktop`: desktop.uuid,
	}
	if stage != "" {
		payload[`stage`] = stage
	}
	if reason != "" {
		payload[`reason`] = reason
	}
	sendPack(modules.Packet{
		Act:   `DESKTOP_TRANSPORT_FALLBACK`,
		Event: desktop.uuid,
		Data:  payload,
	}, desktop.srcConn)
	common.Warn(desktop.srcConn, `DESKTOP_TRANSPORT_FALLBACK`, `webrtc`, reason, map[string]any{
		`desktop`: desktop.uuid,
		`stage`:   stage,
	})
	webrtcSessions.remove(desktop.uuid)
}
