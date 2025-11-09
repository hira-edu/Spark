//go:build windows

package desktop

import (
	"Spark/client/common"
	"Spark/client/config"
	"Spark/client/internal/winsession"
	"Spark/client/service/desktop/hookbridge"
	"Spark/client/service/input"
	"Spark/modules"
	"Spark/utils"
	"Spark/utils/cmap"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/kataras/golog"
	"github.com/kbinani/screenshot"
	"image"
	"image/jpeg"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type session struct {
	lastPack int64
	rawEvent []byte
	event    string
	escape   bool
	channel  chan message
	lock     *sync.Mutex
	metrics  *sessionMetrics
}
type message struct {
	t     int
	info  string
	frame *[]*[]byte
}

type capturePreset struct {
	Key         string
	Label       string
	JPEGQuality int
	FPS         int
}

type sessionMetrics struct {
	sync.Mutex
	frames         uint64
	bytes          uint64
	blocks         uint64
	queueDrops     uint64
	queueHighWater int
	encoderErrors  uint64
	lastError      string
	intervalStart  time.Time
}

type metricsSnapshot struct {
	frames         uint64
	bytes          uint64
	blocks         uint64
	queueDrops     uint64
	queueHighWater int
	encoderErrors  uint64
	lastError      string
	interval       time.Duration
}

// frame packet format:
// +---------+---------+----------+-------------+----------+---------+---------+---------+---------+-------+
// | magic   | op code | event id | body length | img type | x       | y       | width   | height  | image |
// +---------+---------+----------+-------------+----------+---------+---------+---------+---------+-------+
// | 5 bytes | 1 byte  | 16 bytes | 2 bytes     | 2 bytes  | 2 bytes | 2 bytes | 2 bytes | 2 bytes | -     |
// +---------+---------+----------+-------------+----------+---------+---------+---------+---------+-------+

// magic:
// []byte{34, 22, 19, 17, 20}

// op code:
// 00: first part of a frame, device -> browser
// 01: rest parts of a frame, device -> browser
// 02: set resolution of every frame, device -> browser
// 03: JSON string, server -> browser

// img type:
// 0: raw image
// 1: compressed image (jpeg)

const compress = 1
const fpsLimit = 24
const blockSize = 96
const frameBuffer = 3
const imageQuality = 70
const metricsInterval = 5 * time.Second
const capabilitySchemaVersion = "2024.05"

var displayIndex uint = 0

var lock = &sync.Mutex{}
var working = false
var sessions = cmap.New[*session]()
var prevDesktop *image.RGBA
var displayBounds image.Rectangle
var errNoImage = errors.New(`DESKTOP.NO_IMAGE_YET`)
var hookBridgeLogger = golog.Child("[desktop-hookbridge]")
var hookBridgeOnce sync.Once
var hookBridgeErr error
var agentSessionInfo winsession.Info
var sessionPolicies = newPolicyManager()
var pointerLimiter struct {
	sync.Mutex
	lastMove time.Time
}
var clipboardLimiter struct {
	sync.Mutex
	lastPush time.Time
	lastPull time.Time
}

const (
	minPointerInterval = 4 * time.Millisecond
	clipboardCooldown  = 500 * time.Millisecond
)

var (
	capturePresetLock sync.RWMutex
	currentPreset     capturePreset
	presetOrder       = []string{`balanced`, `sharp`, `bandwidth`}
	presetCatalog     = map[string]capturePreset{
		`balanced`: {
			Key:         `balanced`,
			Label:       `Balanced`,
			JPEGQuality: 70,
			FPS:         24,
		},
		`sharp`: {
			Key:         `sharp`,
			Label:       `High Fidelity`,
			JPEGQuality: 82,
			FPS:         24,
		},
		`bandwidth`: {
			Key:         `bandwidth`,
			Label:       `Bandwidth Saver`,
			JPEGQuality: 60,
			FPS:         18,
		},
	}
)

func init() {
	initCapturePreset()
	if runtime.GOOS != "windows" {
		return
	}
	if info, err := winsession.QueryCurrentProcess(); err == nil {
		agentSessionInfo = info
	} else {
		hookBridgeLogger.Debugf("winsession metadata unavailable: %v", err)
	}
}

func newSessionMetrics() *sessionMetrics {
	return &sessionMetrics{
		intervalStart: time.Now(),
	}
}

func enumerateDisplays() []map[string]any {
	total := screenshot.NumActiveDisplays()
	if total <= 0 {
		return nil
	}
	monitors := make([]map[string]any, 0, total)
	for i := 0; i < total; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		monitors = append(monitors, map[string]any{
			"index":     i,
			"width":     bounds.Dx(),
			"height":    bounds.Dy(),
			"isPrimary": i == 0,
		})
	}
	return monitors
}

func changeDisplay(index uint) error {
	total := screenshot.NumActiveDisplays()
	if total == 0 {
		return fmt.Errorf("desktop: no active displays detected")
	}
	if int(index) >= total {
		return fmt.Errorf("desktop: invalid display index %d (max %d)", index, total-1)
	}
	bounds := screenshot.GetDisplayBounds(int(index))
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		return fmt.Errorf("desktop: display %d has zero bounds", index)
	}
	lock.Lock()
	displayIndex = index
	displayBounds = bounds
	prevDesktop = nil
	lock.Unlock()
	broadcastResolution()
	return nil
}

func broadcastResolution() {
	sessions.IterCb(func(uuid string, desktop *session) bool {
		desktop.lock.Lock()
		defer desktop.lock.Unlock()
		if desktop.escape {
			return true
		}
		select {
		case desktop.channel <- message{t: 2}:
		default:
		}
		return true
	})
}

func getDisplayConfig() (uint, image.Rectangle) {
	lock.Lock()
	defer lock.Unlock()
	return displayIndex, displayBounds
}

func initCapturePreset() {
	capturePresetLock.Lock()
	defer capturePresetLock.Unlock()
	currentPreset = presetCatalog[`balanced`]
}

func snapshotCapturePreset() capturePreset {
	capturePresetLock.RLock()
	defer capturePresetLock.RUnlock()
	return currentPreset
}

func listCapturePresets() []map[string]any {
	capturePresetLock.RLock()
	defer capturePresetLock.RUnlock()
	list := make([]map[string]any, 0, len(presetOrder))
	for _, key := range presetOrder {
		if preset, ok := presetCatalog[key]; ok {
			list = append(list, map[string]any{
				`key`:         preset.Key,
				`label`:       preset.Label,
				`jpegQuality`: preset.JPEGQuality,
				`fps`:         preset.FPS,
			})
		}
	}
	return list
}

func applyCapturePreset(key string) (capturePreset, error) {
	capturePresetLock.Lock()
	defer capturePresetLock.Unlock()
	preset, ok := presetCatalog[key]
	if !ok {
		return currentPreset, fmt.Errorf("desktop: unknown quality preset %s", key)
	}
	currentPreset = preset
	return currentPreset, nil
}

func (m *sessionMetrics) recordFrame(size int, blocks int, depth int) {
	if m == nil {
		return
	}
	m.Lock()
	m.frames++
	if size > 0 {
		m.bytes += uint64(size)
	}
	if blocks > 0 {
		m.blocks += uint64(blocks)
	}
	if depth > m.queueHighWater {
		m.queueHighWater = depth
	}
	m.Unlock()
}

func (m *sessionMetrics) recordDrop() {
	if m == nil {
		return
	}
	m.Lock()
	m.queueDrops++
	m.Unlock()
}

func (m *sessionMetrics) recordError(err error) {
	if m == nil || err == nil {
		return
	}
	m.Lock()
	m.encoderErrors++
	m.lastError = err.Error()
	m.Unlock()
}

func (m *sessionMetrics) snapshot() (metricsSnapshot, bool) {
	if m == nil {
		return metricsSnapshot{}, false
	}
	m.Lock()
	defer m.Unlock()
	interval := time.Since(m.intervalStart)
	if interval <= 0 {
		interval = metricsInterval
	}
	if interval < metricsInterval && m.frames == 0 && m.queueDrops == 0 && m.encoderErrors == 0 {
		return metricsSnapshot{}, false
	}
	shot := metricsSnapshot{
		frames:         m.frames,
		bytes:          m.bytes,
		blocks:         m.blocks,
		queueDrops:     m.queueDrops,
		queueHighWater: m.queueHighWater,
		encoderErrors:  m.encoderErrors,
		lastError:      m.lastError,
		interval:       interval,
	}
	m.frames = 0
	m.bytes = 0
	m.blocks = 0
	m.queueDrops = 0
	m.queueHighWater = 0
	m.encoderErrors = 0
	m.lastError = ``
	m.intervalStart = time.Now()
	return shot, true
}

func buildDesktopCapabilities(connectionID string) map[string]any {
	primary, fallbacks, multiMonitor := detectCaptureStack()
	fallbackCopy := make([]string, len(fallbacks))
	copy(fallbackCopy, fallbacks)
	preset := snapshotCapturePreset()
	caps := map[string]any{
		"version":   capabilitySchemaVersion,
		"timestamp": time.Now().UnixMilli(),
		"agent": map[string]any{
			"os":     runtime.GOOS,
			"arch":   runtime.GOARCH,
			"commit": config.Commit,
		},
		"transports": []string{"ws-diff"},
		"capture": map[string]any{
			"primary":      primary,
			"fallbacks":    fallbackCopy,
			"blockSize":    blockSize,
			"fpsCap":       fpsLimit,
			"imageQuality": imageQuality,
			"multiMonitor": multiMonitor,
			"displayIndex": displayIndex,
			"dimensions": map[string]int{
				"width":  displayBounds.Dx(),
				"height": displayBounds.Dy(),
			},
		},
		"encoders": []map[string]any{
			{
				"name":     "jpeg-software",
				"type":     "software-jpeg",
				"quality":  imageQuality,
				"lossless": false,
			},
		},
		"features": []string{"diff-jpeg:v1", "metrics:v1", "input:v1"},
	}
	caps["input"] = map[string]any{
		"pointer": map[string]any{
			"enabled": input.PointerEnabled(),
		},
		"keyboard": map[string]any{
			"enabled": input.KeyboardEnabled(),
		},
		"clipboard": map[string]any{
			"enabled": input.ClipboardSupported(),
		},
	}
	if meta := buildSessionMetadata(); meta != nil {
		caps["session"] = meta
	}
	if monitors := enumerateDisplays(); len(monitors) > 0 {
		caps["monitors"] = monitors
		caps["selectedMonitor"] = int(displayIndex)
	}
	caps["quality"] = map[string]any{
		`selected`:    preset.Key,
		`presets`:     listCapturePresets(),
		`jpegQuality`: preset.JPEGQuality,
		`fps`:         preset.FPS,
	}
	policy := map[string]any{
		"inputEnabled":  false,
		"forceInput":    false,
		"forceCapture":  false,
		"connectionId":  connectionID,
		"policyCreated": 0,
		"policyUpdated": 0,
	}
	if state := sessionPolicies.describe(connectionID); len(state) > 0 {
		policy = state
	}
	caps["policy"] = policy
	return caps
}

func buildSessionMetadata() map[string]any {
	if agentSessionInfo.SessionID == 0 && agentSessionInfo.SID == "" && agentSessionInfo.User == "" {
		return nil
	}
	meta := map[string]any{}
	if agentSessionInfo.SessionID != 0 {
		meta["id"] = agentSessionInfo.SessionID
	}
	if agentSessionInfo.User != "" {
		meta["user"] = agentSessionInfo.User
	}
	if agentSessionInfo.SID != "" {
		meta["sid"] = agentSessionInfo.SID
	}
	return meta
}

func ensureHookBridge() {
	hookBridgeOnce.Do(func() {
		cfg := hookbridge.Config{
			EnableByDefault: os.Getenv("SPARK_EXPERIMENTAL_UMH") == "1",
			Log:             hookBridgeLogger,
		}
		hookBridgeErr = hookbridge.Init(cfg, hookbridgeTelemetrySink)
		if hookBridgeErr != nil {
			hookBridgeLogger.Debugf("hookbridge init skipped: %v", hookBridgeErr)
		}
	})
}

func hookbridgeTelemetrySink(evt hookbridge.Event) {
	hookBridgeLogger.Debugf("hookbridge event kind=%s pid=%d session=%d", evt.Kind, evt.PID, evt.SessionID)
}

func registerSessionPolicy(uuid string) {
	if !hookbridge.Enabled() || uuid == "" {
		return
	}
	policy := &hookbridge.Policy{
		PID:          uint32(os.Getpid()),
		SessionID:    agentSessionInfo.SessionID,
		ConnectionID: uuid,
		Timestamp:    time.Now(),
	}
	sessionPolicies.register(uuid, policy)
	if err := hookbridge.ApplyPolicy(*policy); err != nil {
		hookBridgeLogger.Debugf("hookbridge apply policy failed: %v", err)
	}
}

func unregisterSessionPolicy(uuid string) {
	if uuid == "" {
		return
	}
	sessionPolicies.unregister(uuid)
	// TODO: send explicit release signal when native bridge supports it
}

func clearSessionPolicies() {
	sessionPolicies.clear()
}

func detectCaptureStack() (string, []string, bool) {
	multiMonitor := screenshot.NumActiveDisplays() > 1
	switch runtime.GOOS {
	case "windows":
		return "dxgi", []string{"gdi"}, multiMonitor
	default:
		return "screenshot", []string{}, multiMonitor
	}
}

func sendDesktopCaps(desktop *session) {
	if desktop == nil || common.WSConn == nil {
		return
	}
	_ = common.WSConn.SendPack(modules.Packet{
		Act:   `DESKTOP_CAPS`,
		Event: desktop.event,
		Data:  buildDesktopCapabilities(desktop.event),
	})
}

func init() {
	ensureHookBridge()
	go healthCheck()
}

func worker() {
	runtime.LockOSThread()
	lock.Lock()
	if working {
		lock.Unlock()
		runtime.UnlockOSThread()
		return
	}
	working = true
	lock.Unlock()

	var (
		numErrors int
		screen    Screen
		img       *image.RGBA
		err       error
		delay     time.Duration
	)
	activeDisplay, activeBounds := getDisplayConfig()
	screen.Init(activeDisplay, activeBounds)
	for working {
		if sessions.Count() == 0 {
			break
		}
		cfg := snapshotCapturePreset()
		if cfg.FPS <= 0 {
			cfg.FPS = 24
		}
		delay = time.Second / time.Duration(cfg.FPS)
		nextDisplay, nextBounds := getDisplayConfig()
		if activeDisplay != nextDisplay || !activeBounds.Eq(nextBounds) {
			screen.Release()
			activeDisplay = nextDisplay
			activeBounds = nextBounds
			prevDesktop = nil
			screen.Init(activeDisplay, activeBounds)
			continue
		}
		img, err = screen.Capture()
		if err != nil {
			if err == errNoImage {
				<-time.After(delay)
				continue
			}
			recordEncoderError(err)
			numErrors++
			if numErrors > 10 {
				break
			}
		} else {
			numErrors = 0
			diff := imageCompare(img, prevDesktop, compress, cfg)
			if diff != nil && len(diff) > 0 {
				prevDesktop = img
				sendImageDiff(diff)
			}
			<-time.After(delay)
		}
	}
	img = nil
	prevDesktop = nil
	if numErrors > 10 {
		quitAllDesktop(err.Error())
	}
	lock.Lock()
	working = false
	lock.Unlock()
	screen.Release()
	runtime.UnlockOSThread()
	go runtime.GC()
}

func sendImageDiff(diff []*[]byte) {
	if len(diff) == 0 {
		return
	}
	frameBytes := framePayloadSize(diff)
	frameBlocks := len(diff)
	sessions.IterCb(func(uuid string, desktop *session) bool {
		var (
			recordDrop  bool
			recordFrame bool
			queueDepth  int
		)
		desktop.lock.Lock()
		if !desktop.escape {
			if len(desktop.channel) >= frameBuffer {
				select {
				case <-desktop.channel:
				default:
				}
				recordDrop = true
			}
			desktop.channel <- message{t: 0, frame: &diff}
			recordFrame = true
			queueDepth = len(desktop.channel)
		}
		desktop.lock.Unlock()
		if desktop.metrics != nil {
			if recordDrop {
				desktop.metrics.recordDrop()
			}
			if recordFrame {
				desktop.metrics.recordFrame(frameBytes, frameBlocks, queueDepth)
			}
		}
		return true
	})
}

func framePayloadSize(diff []*[]byte) int {
	total := 0
	for _, block := range diff {
		if block == nil || *block == nil {
			continue
		}
		total += len(*block)
	}
	return total
}

func recordEncoderError(err error) {
	if err == nil {
		return
	}
	sessions.IterCb(func(_ string, desktop *session) bool {
		if desktop.metrics != nil {
			desktop.metrics.recordError(err)
		}
		return true
	})
}

func quitAllDesktop(info string) {
	keys := make([]string, 0)
	sessions.IterCb(func(uuid string, desktop *session) bool {
		keys = append(keys, uuid)
		desktop.escape = true
		desktop.channel <- message{t: 1, info: info}
		return true
	})
	sessions.Clear()
	clearSessionPolicies()
	lock.Lock()
	working = false
	lock.Unlock()
}

func imageCompare(img, prev *image.RGBA, compress int, cfg capturePreset) []*[]byte {
	result := make([]*[]byte, 0)
	if prev == nil {
		return splitFullImage(img, compress, cfg)
	}
	quality := cfg.JPEGQuality
	diff := getDiff(img, prev)
	if diff == nil {
		return result
	}
	for _, rect := range diff {
		block := getImageBlock(img, rect, compress, quality)
		block = makeImageBlock(block, rect, compress)
		result = append(result, &block)
	}
	return result
}

func splitFullImage(img *image.RGBA, compress int, cfg capturePreset) []*[]byte {
	if img == nil {
		return nil
	}
	quality := cfg.JPEGQuality
	result := make([]*[]byte, 0)
	rect := img.Rect
	imgWidth := rect.Dx()
	imgHeight := rect.Dy()
	for y := rect.Min.Y; y < rect.Max.Y; y += blockSize {
		height := utils.If(y+blockSize > imgHeight, imgHeight-y, blockSize)
		for x := rect.Min.X; x < rect.Max.X; x += blockSize {
			width := utils.If(x+blockSize > imgWidth, imgWidth-x, blockSize)
			blockRect := image.Rect(x, y, x+width, y+height)
			block := getImageBlock(img, blockRect, compress, quality)
			block = makeImageBlock(block, blockRect, compress)
			result = append(result, &block)
		}
	}
	return result
}

func getImageBlock(img *image.RGBA, rect image.Rectangle, compress int, quality int) []byte {
	width := rect.Dx()
	height := rect.Dy()
	buf := make([]byte, width*height*4)
	bufPos := 0
	imgPos := img.PixOffset(rect.Min.X, rect.Min.Y)
	for y := 0; y < height; y++ {
		copy(buf[bufPos:bufPos+width*4], img.Pix[imgPos:imgPos+width*4])
		bufPos += width * 4
		imgPos += img.Stride
	}
	switch compress {
	case 0:
		return buf
	case 1:
		subImg := &image.RGBA{
			Pix:    buf,
			Stride: width * 4,
			Rect:   image.Rect(0, 0, width, height),
		}
		writer := &bytes.Buffer{}
		if quality <= 0 {
			quality = 70
		}
		jpeg.Encode(writer, subImg, &jpeg.Options{Quality: quality})
		return writer.Bytes()
	}
	return nil
}

func makeImageBlock(block []byte, rect image.Rectangle, compress int) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(block)+10))
	binary.BigEndian.PutUint16(buf[2:4], uint16(compress))
	binary.BigEndian.PutUint16(buf[4:6], uint16(rect.Min.X))
	binary.BigEndian.PutUint16(buf[6:8], uint16(rect.Min.Y))
	binary.BigEndian.PutUint16(buf[8:10], uint16(rect.Size().X))
	binary.BigEndian.PutUint16(buf[10:12], uint16(rect.Size().Y))
	buf = append(buf, block...)
	return buf
}

func getDiff(img, prev *image.RGBA) []image.Rectangle {
	imgWidth := img.Rect.Dx()
	imgHeight := img.Rect.Dy()
	result := make([]image.Rectangle, 0)
	for y := 0; y < imgHeight; y += blockSize * 2 {
		height := utils.If(y+blockSize > imgHeight, imgHeight-y, blockSize)
		for x := 0; x < imgWidth; x += blockSize {
			width := utils.If(x+blockSize > imgWidth, imgWidth-x, blockSize)
			rect := image.Rect(x, y, x+width, y+height)
			if isDiff(img, prev, rect) {
				result = append(result, rect)
			}
		}
	}
	for y := blockSize; y < imgHeight; y += blockSize * 2 {
		height := utils.If(y+blockSize > imgHeight, imgHeight-y, blockSize)
		for x := 0; x < imgWidth; x += blockSize {
			width := utils.If(x+blockSize > imgWidth, imgWidth-x, blockSize)
			rect := image.Rect(x, y, x+width, y+height)
			if isDiff(img, prev, rect) {
				result = append(result, rect)
			}
		}
	}
	return result
}

func isDiff(img, prev *image.RGBA, rect image.Rectangle) bool {
	imgHeader := (*reflect.SliceHeader)(unsafe.Pointer(&img.Pix))
	prevHeader := (*reflect.SliceHeader)(unsafe.Pointer(&prev.Pix))
	imgPtr := imgHeader.Data
	prevPtr := prevHeader.Data
	imgWidth := img.Rect.Dx()
	rectWidth := rect.Dx()

	end := 0
	if rect.Max.Y == 0 {
		end = rect.Max.X * 4
	} else {
		end = (rect.Max.Y*imgWidth - imgWidth + rect.Max.X) * 4
	}
	if imgHeader.Len < end || prevHeader.Len < end {
		return true
	}
	for y := rect.Min.Y; y < rect.Max.Y; y += 2 {
		cursor := uintptr((y*imgWidth + rect.Min.X) * 4)
		for x := 0; x < rectWidth; x += 4 {
			if *(*uint64)(unsafe.Pointer(imgPtr + cursor)) != *(*uint64)(unsafe.Pointer(prevPtr + cursor)) {
				return true
			}
			cursor += 16
		}
	}
	return false
}

func InitDesktop(pack modules.Packet) error {
	var uuid string
	ensureHookBridge()
	rawEvent, err := hex.DecodeString(pack.Event)
	if err != nil {
		return err
	}
	if val, ok := pack.GetData(`desktop`, reflect.String); !ok {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	} else {
		uuid = val.(string)
	}
	desktop := &session{
		event:    pack.Event,
		rawEvent: rawEvent,
		lastPack: utils.Unix,
		escape:   false,
		channel:  make(chan message, 5),
		lock:     &sync.Mutex{},
		metrics:  newSessionMetrics(),
	}
	{
		if screenshot.NumActiveDisplays() == 0 {
			if err := errors.New(`${i18n|DESKTOP.NO_DISPLAY_FOUND}`); err != nil {
				close(desktop.channel)
				data, _ := utils.JSON.Marshal(modules.Packet{Act: `DESKTOP_QUIT`, Msg: err.Error()})
				data = utils.XOR(data, common.WSConn.GetSecret())
				common.WSConn.SendRawData(desktop.rawEvent, data, 20, 03)
				return err
			}
		}
		if err := changeDisplay(displayIndex); err != nil {
			close(desktop.channel)
			data, _ := utils.JSON.Marshal(modules.Packet{Act: `DESKTOP_QUIT`, Msg: err.Error()})
			data = utils.XOR(data, common.WSConn.GetSecret())
			common.WSConn.SendRawData(desktop.rawEvent, data, 20, 03)
			return err
		}
		desktop.channel <- message{t: 2}
	}
	sendDesktopCaps(desktop)
	registerSessionPolicy(uuid)
	go handleDesktop(pack, uuid, desktop)
	go monitorDesktopMetrics(desktop)
	if !working {
		sessions.Set(uuid, desktop)
		go worker()
	} else {
		cfg := snapshotCapturePreset()
		img := splitFullImage(prevDesktop, compress, cfg)
		desktop.lock.Lock()
		desktop.channel <- message{t: 0, frame: &img}
		desktop.lock.Unlock()
		sessions.Set(uuid, desktop)
	}
	return nil
}

func PingDesktop(pack modules.Packet) {
	var uuid string
	var desktop *session
	if val, ok := pack.GetData(`desktop`, reflect.String); !ok {
		return
	} else {
		uuid = val.(string)
	}
	desktop, ok := sessions.Get(uuid)
	if !ok {
		return
	}
	desktop.lastPack = utils.Unix
}

func KillDesktop(pack modules.Packet) {
	var uuid string
	if val, ok := pack.GetData(`desktop`, reflect.String); !ok {
		return
	} else {
		uuid = val.(string)
	}
	desktop, ok := sessions.Get(uuid)
	if !ok {
		return
	}
	sessions.Remove(uuid)
	unregisterSessionPolicy(uuid)
	data, _ := utils.JSON.Marshal(modules.Packet{Act: `DESKTOP_QUIT`, Msg: `${i18n|DESKTOP.SESSION_CLOSED}`})
	data = utils.XOR(data, common.WSConn.GetSecret())
	common.WSConn.SendRawData(desktop.rawEvent, data, 20, 03)
	desktop.lock.Lock()
	desktop.escape = true
	desktop.rawEvent = nil
	desktop.lock.Unlock()
}

func GetDesktop(pack modules.Packet) {
	var uuid string
	var desktop *session
	if val, ok := pack.GetData(`desktop`, reflect.String); !ok {
		return
	} else {
		uuid = val.(string)
	}
	desktop, ok := sessions.Get(uuid)
	if !ok {
		return
	}
	if !desktop.escape {
		lock.Lock()
		cfg := snapshotCapturePreset()
		img := splitFullImage(prevDesktop, compress, cfg)
		lock.Unlock()
		desktop.lock.Lock()
		desktop.channel <- message{t: 0, frame: &img}
		desktop.lock.Unlock()
	}
}

func ListMonitors(pack modules.Packet) {
	data := map[string]any{
		`monitors`:  enumerateDisplays(),
		`selected`:  int(displayIndex),
		`timestamp`: time.Now().UnixMilli(),
	}
	if common.WSConn == nil {
		return
	}
	_ = common.WSConn.SendPack(modules.Packet{
		Act:   `DESKTOP_MONITORS`,
		Event: pack.Event,
		Data:  data,
	})
}

func SetMonitor(pack modules.Packet) {
	val, ok := pack.GetData(`index`, reflect.Float64)
	if !ok {
		return
	}
	requested := uint(val.(float64))
	err := changeDisplay(requested)
	if err != nil {
		hookBridgeLogger.Debugf("failed to change display: %v", err)
	}
	if common.WSConn == nil {
		return
	}
	resp := modules.Packet{
		Act:   `DESKTOP_SET_MONITOR`,
		Event: pack.Event,
		Data: map[string]any{
			`index`:     requested,
			`selected`:  int(displayIndex),
			`monitors`:  enumerateDisplays(),
			`timestamp`: time.Now().UnixMilli(),
		},
	}
	if err != nil {
		resp.Code = 1
		resp.Msg = err.Error()
	}
	_ = common.WSConn.SendPack(resp)
}

func SetQuality(pack modules.Packet) {
	if common.WSConn == nil {
		return
	}
	val, ok := pack.GetData(`preset`, reflect.String)
	if !ok {
		return
	}
	preset, err := applyCapturePreset(val.(string))
	resp := modules.Packet{
		Act:   `DESKTOP_SET_QUALITY`,
		Event: pack.Event,
		Data: map[string]any{
			`selected`:    preset.Key,
			`presets`:     listCapturePresets(),
			`jpegQuality`: preset.JPEGQuality,
			`fps`:         preset.FPS,
		},
	}
	if err != nil {
		resp.Code = 1
		resp.Msg = err.Error()
	}
	_ = common.WSConn.SendPack(resp)
}

func HandleDesktopInput(pack modules.Packet) {
	payload, ok := pack.Data[`payload`]
	if !ok {
		return
	}
	body, ok := payload.(map[string]any)
	if !ok {
		return
	}
	evtType, _ := body[`type`].(string)
	switch strings.ToLower(evtType) {
	case `mouse`:
		if !input.PointerEnabled() {
			return
		}
		evt := input.PointerEvent{}
		if val, ok := body[`action`].(string); ok {
			evt.Action = val
		}
		if val, ok := body[`button`].(float64); ok {
			evt.Button = int(val)
		}
		if val, ok := body[`deltaY`].(float64); ok {
			evt.DeltaY = int(val)
		}
		if val, ok := body[`x`].(float64); ok {
			evt.X = int(val)
		}
		if val, ok := body[`y`].(float64); ok {
			evt.Y = int(val)
		}
		if len(evt.Action) == 0 {
			return
		}
		if evt.Action == `move` {
			if !allowPointerMove() {
				return
			}
		}
		if err := input.SendPointerEvent(evt); err != nil {
			hookBridgeLogger.Debugf("desktop pointer injection failed: %v", err)
		}
	case `keyboard`:
		if !input.KeyboardEnabled() {
			return
		}
		evt := input.KeyboardEvent{}
		if val, ok := body[`action`].(string); ok {
			evt.Action = val
		}
		if val, ok := body[`key`].(string); ok {
			evt.Key = val
		}
		if val, ok := body[`code`].(string); ok {
			evt.Code = val
		}
		if val, ok := body[`keyCode`].(float64); ok {
			evt.KeyCode = int(val)
		}
		if val, ok := body[`location`].(float64); ok {
			evt.Location = int(val)
		}
		evt.Alt = boolFromAny(body[`altKey`])
		evt.Ctrl = boolFromAny(body[`ctrlKey`])
		evt.Shift = boolFromAny(body[`shiftKey`])
		evt.Meta = boolFromAny(body[`metaKey`])
		evt.Repeat = boolFromAny(body[`repeat`])
		if len(evt.Action) == 0 {
			return
		}
		if err := input.SendKeyboardEvent(evt); err != nil {
			hookBridgeLogger.Debugf("desktop keyboard injection failed: %v", err)
		}
	default:
		return
	}
}

func SetQuality(pack modules.Packet) {
	key, ok := pack.GetData(`preset`, reflect.String)
	if !ok {
		sendQualityResponse(1, `${i18n|COMMON.INVALID_PARAMETER}`, nil)
		return
	}
	preset, err := applyCapturePreset(key.(string))
	payload := map[string]any{
		`selected`:    preset.Key,
		`presets`:     listCapturePresets(),
		`jpegQuality`: preset.JPEGQuality,
		`fps`:         preset.FPS,
		`timestamp`:   time.Now().UnixMilli(),
	}
	if err != nil {
		sendQualityResponse(1, err.Error(), payload)
		return
	}
	sendQualityResponse(0, ``, payload)
}

func sendQualityResponse(code int, msg string, data map[string]any) {
	if common.WSConn == nil {
		return
	}
	resp := modules.Packet{
		Act:  `DESKTOP_SET_QUALITY`,
		Code: code,
		Msg:  msg,
		Data: data,
	}
	_ = common.WSConn.SendPack(resp)
}

func ClipboardPush(pack modules.Packet) {
	if !input.ClipboardSupported() {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, `${i18n|DESKTOP.CLIPBOARD_UNSUPPORTED}`, nil)
		return
	}
	text, ok := pack.GetData(`text`, reflect.String)
	if !ok {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, `${i18n|COMMON.INVALID_PARAMETER}`, nil)
		return
	}
	if !allowClipboardOp(true) {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, `${i18n|DESKTOP.CLIPBOARD_RATE_LIMIT}`, nil)
		return
	}
	err := input.WriteClipboardText(text.(string))
	if err != nil {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, err.Error(), nil)
	} else {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 0, ``, map[string]any{
			`direction`: `push`,
			`timestamp`: time.Now().UnixMilli(),
		})
	}
}

func ClipboardPull(pack modules.Packet) {
	if !input.ClipboardSupported() {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, `${i18n|DESKTOP.CLIPBOARD_UNSUPPORTED}`, nil)
		return
	}
	if !allowClipboardOp(false) {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, `${i18n|DESKTOP.CLIPBOARD_RATE_LIMIT}`, nil)
		return
	}
	text, err := input.ReadClipboardText()
	if err != nil {
		sendClipboardResponse(`DESKTOP_CLIPBOARD_RESULT`, 1, err.Error(), nil)
		return
	}
	sendClipboardResponse(`DESKTOP_CLIPBOARD_DATA`, 0, ``, map[string]any{
		`text`:      text,
		`timestamp`: time.Now().UnixMilli(),
	})
}

func sendClipboardResponse(act string, code int, msg string, data map[string]any) {
	if common.WSConn == nil {
		return
	}
	resp := modules.Packet{
		Act:  act,
		Code: code,
		Msg:  msg,
		Data: data,
	}
	_ = common.WSConn.SendPack(resp)
}

func monitorDesktopMetrics(desktop *session) {
	ticker := time.NewTicker(metricsInterval)
	defer ticker.Stop()
	for range ticker.C {
		if desktop == nil || desktop.escape {
			return
		}
		snap, ok := desktop.metrics.snapshot()
		if !ok {
			continue
		}
		payload := map[string]any{
			`desktop`:        desktop.event,
			`frames`:         int64(snap.frames),
			`bytes`:          int64(snap.bytes),
			`blocks`:         int64(snap.blocks),
			`queueHighWater`: snap.queueHighWater,
			`queueDrops`:     int64(snap.queueDrops),
			`intervalMs`:     snap.interval.Milliseconds(),
			`encoderErrors`:  int64(snap.encoderErrors),
			`timestamp`:      time.Now().UnixMilli(),
		}
		if len(snap.lastError) > 0 {
			payload[`lastError`] = snap.lastError
		}
		if common.WSConn == nil {
			continue
		}
		_ = common.WSConn.SendPack(modules.Packet{
			Act:   `DESKTOP_METRICS`,
			Event: desktop.event,
			Data:  payload,
		})
	}
}

func handleDesktop(pack modules.Packet, uuid string, desktop *session) {
	for !desktop.escape {
		select {
		case msg, ok := <-desktop.channel:
			// send error info
			if msg.t == 1 || !ok {
				data, _ := utils.JSON.Marshal(modules.Packet{Act: `DESKTOP_QUIT`, Msg: msg.info})
				data = utils.XOR(data, common.WSConn.GetSecret())
				common.WSConn.SendRawData(desktop.rawEvent, data, 20, 03)
				desktop.escape = true
				sessions.Remove(uuid)
				unregisterSessionPolicy(uuid)
				break
			}
			// send image
			if msg.t == 0 {
				buf := append([]byte{34, 22, 19, 17, 20, 00}, desktop.rawEvent...)
				for _, slice := range *msg.frame {
					if len(buf)+len(*slice) >= common.MaxMessageSize {
						if common.WSConn.SendData(buf) != nil {
							break
						}
						buf = append([]byte{34, 22, 19, 17, 20, 01}, desktop.rawEvent...)
					}
					buf = append(buf, *slice...)
				}
				common.WSConn.SendData(buf)
				buf = nil
				continue
			}
			// set resolution
			if msg.t == 2 {
				buf := append([]byte{34, 22, 19, 17, 20, 02}, desktop.rawEvent...)
				data := make([]byte, 6)
				binary.BigEndian.PutUint16(data[:2], 4)
				binary.BigEndian.PutUint16(data[2:4], uint16(displayBounds.Dx()))
				binary.BigEndian.PutUint16(data[4:6], uint16(displayBounds.Dy()))
				buf = append(buf, data...)
				common.WSConn.SendData(buf)
				continue
			}
		case <-time.After(7 * time.Second):
			continue
		}
	}
}

func healthCheck() {
	const MaxInterval = 30
	for now := range time.NewTicker(30 * time.Second).C {
		timestamp := now.Unix()
		// stores sessions to be disconnected
		keys := make([]string, 0)
		sessions.IterCb(func(uuid string, desktop *session) bool {
			if timestamp-desktop.lastPack > MaxInterval {
				keys = append(keys, uuid)
			}
			return true
		})
		for _, key := range keys {
			unregisterSessionPolicy(key)
		}
		sessions.Remove(keys...)
	}
}

func boolFromAny(val any) bool {
	if b, ok := val.(bool); ok {
		return b
	}
	return false
}

func allowPointerMove() bool {
	pointerLimiter.Lock()
	defer pointerLimiter.Unlock()
	if time.Since(pointerLimiter.lastMove) < minPointerInterval {
		return false
	}
	pointerLimiter.lastMove = time.Now()
	return true
}

func allowClipboardOp(isPush bool) bool {
	clipboardLimiter.Lock()
	defer clipboardLimiter.Unlock()
	now := time.Now()
	if isPush {
		if now.Sub(clipboardLimiter.lastPush) < clipboardCooldown {
			return false
		}
		clipboardLimiter.lastPush = now
	} else {
		if now.Sub(clipboardLimiter.lastPull) < clipboardCooldown {
			return false
		}
		clipboardLimiter.lastPull = now
	}
	return true
}
