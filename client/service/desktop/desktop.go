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
	"fmt"
	"github.com/kbinani/screenshot"
	"image"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type session struct {
	lastPack  int64 // atomic
	rawEvent  []byte
	event     string
	escape    atomic.Bool
	channel   chan message
	closeOnce sync.Once
	lock      *sync.Mutex
	rtc       *rtcSession
	// Per-session control flag (view-only support)
	allowControl atomic.Bool

	// Backpressure metrics (atomic for thread-safety)
	framesDropped    atomic.Uint64 // Total frames dropped due to backpressure
	framesDelivered  atomic.Uint64 // Total frames successfully delivered
	channelHighWater atomic.Uint64 // Peak channel utilization
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

// Frame protocol constants (legacy, now use Codec interface)
const (
	compressRaw  = 0 // Raw RGBA image
	compressJPEG = 1 // JPEG compressed image
)

// Screen capture settings
const (
	fpsDefault   = 24 // Default frames per second
	blockSize    = 96 // Pixel block size for delta encoding
	frameBuffer  = 3  // Max queued frames before dropping
	imageQuality = 40 // JPEG quality (0-100) - used for default codec (lower default to reduce bandwidth)
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

// Active codec configuration (set via SetCodec)
// Default: JPEG for compatibility
var compress = compressJPEG

var lock = &sync.RWMutex{}
var working int32 // atomic: 1 if worker running, 0 otherwise
var sessions = cmap.New[*session]()
var prevDesktop atomic.Value   // Stores *image.RGBA - eliminates race condition
var displayBounds atomic.Value // Stores image.Rectangle - eliminates race condition
var errNoImage = errors.New(`DESKTOP.NO_IMAGE_YET`)
var errNoActiveSession = errors.New(`DESKTOP.NO_ACTIVE_SESSION`)
var adaptiveQualityManager = NewAdaptiveQualityManager() // Global adaptive quality controller
var lastRTTMs atomic.Int64                               // Optional RTT estimator for adaptive quality

// UpdateRTT ingests RTT measurements (milliseconds) for adaptive quality tuning.
func UpdateRTT(rttMs int64) {
	if rttMs <= 0 {
		return
	}
	lastRTTMs.Store(rttMs)
	if adaptiveQualityManager != nil {
		adaptiveQualityManager.UpdateNetworkMetrics(rttMs, 0, pendingFrameBytes.Load())
		adaptiveQualityManager.Adapt()
	}
}

func clampFPSValue(fps int32) int32 {
	if fps < 12 {
		return 12
	}
	if fps > 60 {
		return 60
	}
	return fps
}

func clampQualityValue(quality int32) int32 {
	if quality < 1 {
		return 1
	}
	if quality > 100 {
		return 100
	}
	return quality
}

func clampMonitorValue(monitor int32) int32 {
	if monitor < 0 {
		return 0
	}
	numDisplays := screenshot.NumActiveDisplays()
	if numDisplays <= 0 {
		return monitor
	}
	if int(monitor) >= numDisplays {
		return int32(numDisplays - 1)
	}
	return monitor
}

func getDisplayBoundsForMonitor(monitor int32) (image.Rectangle, error) {
	numDisplays := screenshot.NumActiveDisplays()
	if numDisplays <= 0 {
		return image.Rectangle{}, errors.New("no active displays")
	}
	idx := clampMonitorValue(monitor)
	if int(idx) >= numDisplays {
		return image.Rectangle{}, fmt.Errorf("monitor index %d out of range (max %d)", idx, numDisplays-1)
	}
	bounds := screenshot.GetDisplayBounds(int(idx))
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		return image.Rectangle{}, fmt.Errorf("invalid bounds for monitor %d", idx)
	}
	return bounds, nil
}

// enumerateDisplays builds a snapshot of active monitors for UI/state sync.
func enumerateDisplays() []map[string]int {
	total := screenshot.NumActiveDisplays()
	if total <= 0 {
		return nil
	}

	out := make([]map[string]int, 0, total)
	for i := 0; i < total; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		out = append(out, map[string]int{
			"index":  i,
			"x":      bounds.Min.X,
			"y":      bounds.Min.Y,
			"width":  bounds.Dx(),
			"height": bounds.Dy(),
		})
	}
	return out
}

// Buffer pools for zero-allocation image processing
var (
	// Block buffer pool: reusable byte slices for block extraction
	// Pool key: buffer size (width * height * 4)
	// Max block size: 96*96*4 = 36,864 bytes
	blockBufferPool = sync.Pool{
		New: func() interface{} {
			// Allocate max block size buffer
			buf := make([]byte, blockSize*blockSize*4)
			return &buf
		},
	}

	// JPEG encode buffer pool: reusable bytes.Buffer for JPEG encoding
	jpegBufferPool = sync.Pool{
		New: func() interface{} {
			return &bytes.Buffer{}
		},
	}

	// Header buffer pool: reusable 12-byte headers for block metadata
	headerBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 12)
			return &buf
		},
	}

	// Chunk buffer pool: reusable buffers for message chunking
	// Pre-allocate MaxMessageSize to avoid growth
	chunkBufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 0, common.MaxMessageSize)
			return &buf
		},
	}

	// Pool statistics for monitoring
	poolStats struct {
		blockBufferGets  atomic.Uint64
		blockBufferPuts  atomic.Uint64
		jpegBufferGets   atomic.Uint64
		jpegBufferPuts   atomic.Uint64
		headerBufferGets atomic.Uint64
		headerBufferPuts atomic.Uint64
		chunkBufferGets  atomic.Uint64
		chunkBufferPuts  atomic.Uint64
		allocations      atomic.Uint64 // New allocations (pool misses)
	}

	// Chunking statistics
	chunkStats struct {
		totalChunks      atomic.Uint64
		totalBlocks      atomic.Uint64
		totalBytes       atomic.Uint64
		multiChunkFrames atomic.Uint64 // Frames requiring >1 chunk
		maxChunksInFrame atomic.Uint64
	}

	// Global backpressure statistics (aggregated across all sessions)
	backpressureStats struct {
		totalFramesDropped   atomic.Uint64 // Total frames dropped across all sessions
		totalFramesDelivered atomic.Uint64 // Total frames delivered across all sessions
		sessionsWithDrops    atomic.Uint64 // Count of sessions that experienced drops
		peakUtilization      atomic.Uint64 // Peak channel utilization % (0-100)
	}
)

// Backpressure management for frame sending
var pendingFrameBytes atomic.Int64       // Tracks approximate pending data
const maxPendingFrameBytes = 1024 * 1024 // 1MB threshold

// sendDesktopData writes desktop binary data either to the WebSocket (Session 0) or over IPC (user session bridge).
// Implements backpressure by tracking pending writes per VNC/RDP best practices.
// Respects WebSocket MaxMessageSize by chunking large frames (2025 best practice).
func sendDesktopData(buf []byte) {
	if common.WSConn != nil {
		// Backpressure check: Drop frames if too many pending writes
		// This prevents memory explosion when network is slower than capture rate
		// Best practice from VNC/RDP implementations and WebSocket streaming guides
		pending := pendingFrameBytes.Load()
		queueBytes := pending + int64(len(buf))

		if adaptiveQualityManager != nil {
			adaptiveQualityManager.UpdateNetworkMetrics(lastRTTMs.Load(), 0, queueBytes)
			adaptiveQualityManager.Adapt()
		}

		if queueBytes > maxPendingFrameBytes {
			// Drop this frame - video streaming is lossy anyway
			telemetry.LogStructured("WARN", "desktop: dropping frame due to backpressure", map[string]interface{}{
				"pending_bytes": pending,
				"queued_bytes":  queueBytes,
				"frame_size":    len(buf),
			})
			return
		}

		// MTU/MaxMessageSize awareness for WebSocket (2025 best practice):
		// - WebSocket is TCP-based, so no UDP MTU limits apply
		// - However, servers often set MaxMessageSize (default 1MB in many implementations)
		// - Large frames should be chunked to respect server limits
		// - Chunking also improves latency (don't wait for huge frame to encode/send)
		//
		// Chunking strategy:
		// - Frames < 256KB: send as single message (most common case)
		// - Frames >= 256KB: split into 256KB chunks with fragment headers
		// - Server reassembles fragments using fragment ID and sequence numbers
		const wsMaxChunkSize = MaxWSChunkSize // 256 KB from mtu_fragmentation.go

		if len(buf) > wsMaxChunkSize {
			// Fragment large frame
			fragments, err := FragmentFrame(buf, wsMaxChunkSize)
			if err != nil {
				telemetry.LogStructured("ERROR", "desktop: frame fragmentation failed", map[string]interface{}{
					"error":      err.Error(),
					"frame_size": len(buf),
				})
				return
			}

			// Track pending data for all fragments
			pendingFrameBytes.Add(int64(len(buf)))

			// Send fragments asynchronously
			go func(frags [][]byte, totalSize int) {
				defer pendingFrameBytes.Add(-int64(totalSize))
				for i, frag := range frags {
					if err := common.WSConn.SendData(frag); err != nil {
						telemetry.LogStructured("ERROR", "desktop: failed to send frame fragment", map[string]interface{}{
							"error":           err.Error(),
							"fragment":        i + 1,
							"total_fragments": len(frags),
						})
						return // Stop sending remaining fragments on error
					}
				}
			}(fragments, len(buf))
			return
		}

		// Small frame - send directly without fragmentation
		// Track pending data
		pendingFrameBytes.Add(int64(len(buf)))

		// Send asynchronously to not block capture thread
		go func(data []byte) {
			defer pendingFrameBytes.Add(-int64(len(data)))
			if err := common.WSConn.SendData(data); err != nil {
				telemetry.LogStructured("ERROR", "desktop: failed to send frame over WS", map[string]interface{}{
					"error": err.Error(),
					"size":  len(data),
				})
			}
			telemetry.LogStructured("DEBUG", "desktop: sent frame over WS", map[string]interface{}{
				"size": len(data),
			})
		}(buf)
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

	// DIAGNOSTIC: Log all desktop packet sends to trace the flow
	hasData := pack.Data != nil && len(pack.Data) > 0
	eventPreview := pack.Event
	if len(eventPreview) > 16 {
		eventPreview = eventPreview[:16] + "..."
	}
	telemetry.LogStructured("DEBUG", "sendDesktopPacket called", map[string]interface{}{
		"act":            pack.Act,
		"code":           pack.Code,
		"has_data":       hasData,
		"event":          eventPreview,
		"ws_conn_set":    common.WSConn != nil,
		"is_bridge_mode": IsBridgeMode(),
		"is_session0":    IsSession0Mode(),
	})

	if common.WSConn != nil {
		// For init acknowledgements, use the standard encrypted pack pathway.
		if pack.Act == "DESKTOP_INIT" {
			telemetry.LogStructured("INFO", "desktop: sending DESKTOP_INIT via SendPack (encrypted JSON)", map[string]interface{}{
				"has_display_data": pack.Data != nil,
				"is_session0":      IsSession0Mode(),
			})
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
	eventPreview = pack.Event
	if len(eventPreview) > 16 {
		eventPreview = eventPreview[:16] + "..."
	}
	telemetry.LogStructured("INFO", "desktop: sending packet via IPC to Session 0", map[string]interface{}{
		"act":      pack.Act,
		"code":     pack.Code,
		"has_data": pack.Data != nil,
		"event":    eventPreview,
	})
	if ok := SendPacketViaIPC(pack); !ok {
		telemetry.LogStructured("WARN", "desktop: IPC control send failed", map[string]interface{}{
			"act":         pack.Act,
			"bridge_mode": IsBridgeMode(),
		})
	} else {
		telemetry.LogStructured("INFO", "desktop: packet sent successfully via IPC", map[string]interface{}{
			"act": pack.Act,
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
	case ipc.MsgTypeDesktopPacket:
		return true, relay.SendPacket(pack)
	default:
		return true, errors.New("unsupported relay message type")
	}
}

func init() {
	// Start with a reasonable RTT estimate to seed adaptive quality
	lastRTTMs.Store(50)
	go healthCheck()
}

// startCaptureWorker launches the capture worker if not already running.
// Returns true when the worker was started (CAS success).
func startCaptureWorker() bool {
	if !atomic.CompareAndSwapInt32(&working, 0, 1) {
		return false
	}
	go worker()
	return true
}

func worker() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	defer atomic.StoreInt32(&working, 0)

	var (
		numErrors       int
		numConsecutive  int // Consecutive errors for circuit breaker
		screen          Screen
		img             *image.RGBA
		err             error
		lastSuccessTime time.Time

		// Performance metrics for delta detection
		frameCount         uint64
		fullFrameCount     uint64
		deltaFrameCount    uint64
		identicalCount     uint64
		totalBlocksSent    uint64
		totalBlocksSkipped uint64

		// Resolution change tracking
		currentBounds     image.Rectangle
		resolutionChanges uint64
	)

	// Initialize monitor selection and bounds
	activeMonitor := clampMonitorValue(configMonitor.Load())
	if currentBounds, err = getDisplayBoundsForMonitor(activeMonitor); err != nil {
		telemetry.LogStructured("ERROR", "worker: failed to load display bounds", map[string]interface{}{
			"monitor": activeMonitor,
			"error":   err.Error(),
		})
		return
	}
	displayBounds.Store(currentBounds)

	screen.Init(uint(activeMonitor), currentBounds)
	defer screen.Release()

	// FIXED: Use ticker for precise frame timing (Issue #1)
	currentFPS := clampFPSValue(configFPS.Load())
	frameDuration := time.Second / time.Duration(currentFPS)
	ticker := time.NewTicker(frameDuration)
	defer ticker.Stop()

	lastSuccessTime = time.Now()
	noSessionCheckTicker := time.NewTicker(time.Second)
	defer noSessionCheckTicker.Stop()

	telemetry.LogStructured("INFO", "desktop worker started", map[string]interface{}{
		"fps":      currentFPS,
		"monitor":  activeMonitor,
		"width":    currentBounds.Dx(),
		"height":   currentBounds.Dy(),
		"duration": frameDuration.String(),
	})

	for atomic.LoadInt32(&working) == 1 {
		select {
		case <-noSessionCheckTicker.C:
			// Periodic check: exit if no sessions for extended period
			if sessions.Count() == 0 {
				telemetry.LogStructured("INFO", "worker: no active sessions, exiting", nil)
				return
			}

		case tickTime := <-ticker.C:
			// Skip if no active sessions (but don't exit immediately)
			if sessions.Count() == 0 {
				continue
			}

			// Apply runtime FPS changes without restarting worker
			if updatedFPS := clampFPSValue(configFPS.Load()); updatedFPS != currentFPS {
				currentFPS = updatedFPS
				frameDuration = time.Second / time.Duration(currentFPS)
				ticker.Reset(frameDuration)
				telemetry.LogStructured("INFO", "worker: fps updated", map[string]interface{}{
					"fps":      currentFPS,
					"duration": frameDuration.String(),
				})
			}

			// Monitor switch support: reinitialize screen on monitor changes
			if desiredMonitor := clampMonitorValue(configMonitor.Load()); desiredMonitor != activeMonitor {
				screen.Release()

				newBounds, boundsErr := getDisplayBoundsForMonitor(desiredMonitor)
				if boundsErr != nil {
					telemetry.LogStructured("ERROR", "worker: monitor switch failed, reverting", map[string]interface{}{
						"from":  activeMonitor,
						"to":    desiredMonitor,
						"error": boundsErr.Error(),
					})
					// Re-initialize previous monitor to keep capture alive
					screen.Init(uint(activeMonitor), currentBounds)
					continue
				}

				activeMonitor = desiredMonitor
				currentBounds = newBounds
				displayBounds.Store(newBounds)

				// Clear previous frame to force full-frame sync on new monitor
				prevDesktop.Store((*image.RGBA)(nil))

				screen.Init(uint(activeMonitor), currentBounds)

				// Broadcast resolution change before next frame
				broadcastResolutionChange(currentBounds)

				telemetry.LogStructured("INFO", "worker: monitor switched", map[string]interface{}{
					"monitor": activeMonitor,
					"width":   currentBounds.Dx(),
					"height":  currentBounds.Dy(),
				})

				// Skip this tick to keep cadence after re-init
				continue
			}

			// Capture frame
			img, err = screen.Capture()

			if err != nil {
				if err == errNoImage {
					// FIXED: On ErrNoImageYet, maintain cadence and continue (Issue #4)
					// No error counting - this is expected when screen is idle
					time.Sleep(10 * time.Millisecond)
					continue
				}

				// Real error occurred
				numErrors++
				numConsecutive++

				telemetry.LogStructured("WARN", "worker: capture error", map[string]interface{}{
					"error":       err.Error(),
					"num_errors":  numErrors,
					"consecutive": numConsecutive,
				})

				// Circuit breaker: 10 consecutive errors = fatal
				if numConsecutive > 10 {
					telemetry.LogStructured("ERROR", "worker: too many consecutive errors, shutting down", map[string]interface{}{
						"error": err.Error(),
					})
					quitAllDesktop(err.Error())
					return
				}

				// FIXED: On error, reset ticker to last success time (Issue #4)
				timeSinceSuccess := time.Since(lastSuccessTime)
				if timeSinceSuccess < frameDuration {
					// Still within expected frame time, just skip this frame
					continue
				}

				// Been too long, try to resync to target cadence
				ticker.Reset(frameDuration)
				continue
			}

			// Success! Reset error counters
			numConsecutive = 0
			lastSuccessTime = tickTime
			frameCount++

			// RESOLUTION CHANGE DETECTION: Check if screen bounds changed
			newBounds := img.Rect
			if newBounds != currentBounds {
				resolutionChanges++
				oldBounds := currentBounds
				currentBounds = newBounds

				// Update atomic displayBounds for other components
				displayBounds.Store(newBounds)

				telemetry.LogStructured("INFO", "desktop: resolution changed", map[string]interface{}{
					"old_width":  oldBounds.Dx(),
					"old_height": oldBounds.Dy(),
					"new_width":  newBounds.Dx(),
					"new_height": newBounds.Dy(),
					"change_num": resolutionChanges,
				})

				// Force full frame resync by clearing previous frame
				prevDesktop.Store((*image.RGBA)(nil))

				// Broadcast resolution change to ALL sessions BEFORE next frame
				broadcastResolutionChange(newBounds)
			}

			// FIXED: Use atomic.Value to eliminate prevDesktop race (Issue #2)
			prevVal := prevDesktop.Load()
			var prev *image.RGBA
			if prevVal != nil {
				prev = prevVal.(*image.RGBA)
			}

			// Delta detection with performance tracking
			diff := imageCompare(img, prev, compress)

			// Track metrics for performance monitoring
			if prev == nil {
				fullFrameCount++
			} else if len(diff) == 0 {
				identicalCount++
			} else {
				deltaFrameCount++
				totalBlocksSent += uint64(len(diff))

				// Estimate skipped blocks (for 1920x1080: ~20x12 = 240 blocks total)
				bounds := img.Rect
				totalBlocks := ((bounds.Dx() + blockSize - 1) / blockSize) * ((bounds.Dy() + blockSize - 1) / blockSize)
				totalBlocksSkipped += uint64(totalBlocks - len(diff))
			}

			// Log performance metrics every 300 frames (~12 seconds at 24fps)
			if frameCount%300 == 0 {
				compressionRatio := float64(0)
				if totalBlocksSent > 0 {
					compressionRatio = float64(totalBlocksSkipped) / float64(totalBlocksSent+totalBlocksSkipped) * 100
				}

				// Calculate buffer pool efficiency
				blockGets := poolStats.blockBufferGets.Load()
				blockPuts := poolStats.blockBufferPuts.Load()
				jpegGets := poolStats.jpegBufferGets.Load()
				jpegPuts := poolStats.jpegBufferPuts.Load()
				headerGets := poolStats.headerBufferGets.Load()
				headerPuts := poolStats.headerBufferPuts.Load()

				poolEfficiency := float64(0)
				totalGets := blockGets + jpegGets + headerGets
				totalPuts := blockPuts + jpegPuts + headerPuts
				if totalGets > 0 {
					poolEfficiency = float64(totalPuts) / float64(totalGets) * 100
				}

				// Get codec stats
				codecStatsMap := GetCodecStats()

				// Get chunking stats
				totalChunks := chunkStats.totalChunks.Load()
				totalChunkBlocks := chunkStats.totalBlocks.Load()
				totalChunkBytes := chunkStats.totalBytes.Load()
				multiChunkFrames := chunkStats.multiChunkFrames.Load()
				maxChunks := chunkStats.maxChunksInFrame.Load()
				chunkGets := poolStats.chunkBufferGets.Load()
				chunkPuts := poolStats.chunkBufferPuts.Load()

				avgChunkSize := uint64(0)
				avgBlocksPerChunk := float64(0)
				if totalChunks > 0 {
					avgChunkSize = totalChunkBytes / totalChunks
					avgBlocksPerChunk = float64(totalChunkBlocks) / float64(totalChunks)
				}

				// Get backpressure stats
				totalDropped := backpressureStats.totalFramesDropped.Load()
				totalDelivered := backpressureStats.totalFramesDelivered.Load()
				sessionsWithDrops := backpressureStats.sessionsWithDrops.Load()
				peakUtil := backpressureStats.peakUtilization.Load()

				globalDeliveryRate := float64(100.0)
				if totalDropped+totalDelivered > 0 {
					globalDeliveryRate = float64(totalDelivered) / float64(totalDropped+totalDelivered) * 100
				}

				telemetry.LogStructured("INFO", "desktop: performance metrics", map[string]interface{}{
					// Delta detection
					"frames_total":      frameCount,
					"frames_full":       fullFrameCount,
					"frames_delta":      deltaFrameCount,
					"frames_identical":  identicalCount,
					"blocks_sent":       totalBlocksSent,
					"blocks_skipped":    totalBlocksSkipped,
					"compression_ratio": compressionRatio,

					// Resolution tracking
					"resolution_changes": resolutionChanges,
					"current_width":      currentBounds.Dx(),
					"current_height":     currentBounds.Dy(),

					// Codec metrics
					"codec_active":        codecStatsMap["active_codec"],
					"codec_type":          codecStatsMap["codec_type"],
					"codec_quality":       codecStatsMap["codec_quality"],
					"codec_hardware":      codecStatsMap["hardware_accel"],
					"codec_encode_count":  codecStatsMap["encode_count"],
					"codec_encoded_bytes": codecStatsMap["encoded_bytes"],
					"codec_errors":        codecStatsMap["encode_errors"],
					"codec_switches":      codecStatsMap["codec_switches"],

					// Chunking metrics
					"chunk_total_chunks":        totalChunks,
					"chunk_total_blocks":        totalChunkBlocks,
					"chunk_total_bytes":         totalChunkBytes,
					"chunk_multi_chunk_frames":  multiChunkFrames,
					"chunk_max_chunks_in_frame": maxChunks,
					"chunk_avg_size":            avgChunkSize,
					"chunk_avg_blocks":          avgBlocksPerChunk,

					// Backpressure metrics
					"backpressure_frames_dropped":    totalDropped,
					"backpressure_frames_delivered":  totalDelivered,
					"backpressure_sessions_affected": sessionsWithDrops,
					"backpressure_peak_utilization":  peakUtil,
					"backpressure_delivery_rate":     globalDeliveryRate,

					// Buffer pool metrics
					"pool_block_gets":  blockGets,
					"pool_block_puts":  blockPuts,
					"pool_jpeg_gets":   jpegGets,
					"pool_jpeg_puts":   jpegPuts,
					"pool_header_gets": headerGets,
					"pool_header_puts": headerPuts,
					"pool_chunk_gets":  chunkGets,
					"pool_chunk_puts":  chunkPuts,
					"pool_efficiency":  poolEfficiency,

					// Adaptive quality metrics
					"aqm_jpeg_quality":   adaptiveQualityManager.GetCurrentJPEGQuality(),
					"aqm_bitrate_bps":    adaptiveQualityManager.GetCurrentBitrate(),
					"aqm_max_frame_size": adaptiveQualityManager.GetMaxFrameSize(),
				})
			}

			if diff != nil && len(diff) > 0 {
				// Store new frame atomically
				prevDesktop.Store(img)
				sendImageDiff(diff)
			}

			// Broadcast to WebRTC sessions
			broadcastRTC(img, frameDuration)
		}
	}

	// Cleanup
	prevDesktop.Store((*image.RGBA)(nil))

	// Final performance report
	compressionRatio := float64(0)
	if totalBlocksSent > 0 {
		compressionRatio = float64(totalBlocksSkipped) / float64(totalBlocksSent+totalBlocksSkipped) * 100
	}

	// Buffer pool final stats
	blockGets := poolStats.blockBufferGets.Load()
	blockPuts := poolStats.blockBufferPuts.Load()
	jpegGets := poolStats.jpegBufferGets.Load()
	jpegPuts := poolStats.jpegBufferPuts.Load()
	headerGets := poolStats.headerBufferGets.Load()
	headerPuts := poolStats.headerBufferPuts.Load()

	poolEfficiency := float64(0)
	totalGets := blockGets + jpegGets + headerGets
	totalPuts := blockPuts + jpegPuts + headerPuts
	if totalGets > 0 {
		poolEfficiency = float64(totalPuts) / float64(totalGets) * 100
	}

	// Get final chunking stats
	finalTotalChunks := chunkStats.totalChunks.Load()
	finalTotalChunkBlocks := chunkStats.totalBlocks.Load()
	finalTotalChunkBytes := chunkStats.totalBytes.Load()
	finalMultiChunkFrames := chunkStats.multiChunkFrames.Load()
	finalMaxChunks := chunkStats.maxChunksInFrame.Load()

	finalAvgChunkSize := uint64(0)
	finalAvgBlocksPerChunk := float64(0)
	if finalTotalChunks > 0 {
		finalAvgChunkSize = finalTotalChunkBytes / finalTotalChunks
		finalAvgBlocksPerChunk = float64(finalTotalChunkBlocks) / float64(finalTotalChunks)
	}

	telemetry.LogStructured("INFO", "desktop worker stopped - final statistics", map[string]interface{}{
		// Error tracking
		"total_errors": numErrors,

		// Delta detection metrics
		"frames_total":      frameCount,
		"frames_full":       fullFrameCount,
		"frames_delta":      deltaFrameCount,
		"frames_identical":  identicalCount,
		"blocks_sent":       totalBlocksSent,
		"blocks_skipped":    totalBlocksSkipped,
		"compression_ratio": compressionRatio,
		"avg_blocks_per_frame": func() float64 {
			if deltaFrameCount > 0 {
				return float64(totalBlocksSent) / float64(deltaFrameCount)
			}
			return 0
		}(),

		// Resolution change metrics
		"resolution_changes": resolutionChanges,
		"final_width":        currentBounds.Dx(),
		"final_height":       currentBounds.Dy(),

		// Chunking metrics
		"chunk_total_chunks":       finalTotalChunks,
		"chunk_total_blocks":       finalTotalChunkBlocks,
		"chunk_total_bytes":        finalTotalChunkBytes,
		"chunk_multi_chunk_frames": finalMultiChunkFrames,
		"chunk_max_chunks":         finalMaxChunks,
		"chunk_avg_size":           finalAvgChunkSize,
		"chunk_avg_blocks":         finalAvgBlocksPerChunk,

		// Backpressure metrics
		"backpressure_frames_dropped":    backpressureStats.totalFramesDropped.Load(),
		"backpressure_frames_delivered":  backpressureStats.totalFramesDelivered.Load(),
		"backpressure_sessions_affected": backpressureStats.sessionsWithDrops.Load(),
		"backpressure_peak_utilization":  backpressureStats.peakUtilization.Load(),
		"backpressure_global_delivery_rate": func() float64 {
			dropped := backpressureStats.totalFramesDropped.Load()
			delivered := backpressureStats.totalFramesDelivered.Load()
			total := dropped + delivered
			if total > 0 {
				return float64(delivered) / float64(total) * 100
			}
			return 100.0
		}(),

		// Buffer pool metrics
		"pool_total_gets":     totalGets,
		"pool_total_puts":     totalPuts,
		"pool_block_gets":     blockGets,
		"pool_block_puts":     blockPuts,
		"pool_jpeg_gets":      jpegGets,
		"pool_jpeg_puts":      jpegPuts,
		"pool_header_gets":    headerGets,
		"pool_header_puts":    headerPuts,
		"pool_chunk_gets":     poolStats.chunkBufferGets.Load(),
		"pool_chunk_puts":     poolStats.chunkBufferPuts.Load(),
		"pool_efficiency":     poolEfficiency,
		"pool_leaked_buffers": totalGets - totalPuts,
	})
}

// GetSessionBackpressureStats returns backpressure statistics for a specific session.
// Useful for monitoring individual client health.
func GetSessionBackpressureStats(uuid string) map[string]interface{} {
	session, ok := sessions.Get(uuid)
	if !ok {
		return map[string]interface{}{
			"error": "session not found",
		}
	}

	session.lock.Lock()
	channelLen := 0
	channelCap := 0
	if session.channel != nil {
		channelLen = len(session.channel)
		channelCap = cap(session.channel)
	}
	session.lock.Unlock()

	dropped := session.framesDropped.Load()
	delivered := session.framesDelivered.Load()
	total := dropped + delivered
	deliveryRate := float64(100.0)
	if total > 0 {
		deliveryRate = float64(delivered) / float64(total) * 100
	}

	utilization := float64(0)
	if channelCap > 0 {
		utilization = float64(channelLen) / float64(channelCap) * 100
	}

	return map[string]interface{}{
		"uuid":                uuid,
		"channel_len":         channelLen,
		"channel_cap":         channelCap,
		"channel_utilization": utilization,
		"high_water_mark":     session.channelHighWater.Load(),
		"frames_dropped":      dropped,
		"frames_delivered":    delivered,
		"delivery_rate":       deliveryRate,
		"is_healthy":          deliveryRate > 95.0 && utilization < 80.0,
	}
}

// broadcastResolutionChange sends resolution change notification to ALL active sessions.
// This must be called BEFORE sending the next frame after a resolution change.
//
// Resolution change protocol:
// 1. Detect bounds change after capture
// 2. Broadcast resolution packet to all sessions (this function)
// 3. Clear prevDesktop to force full frame
// 4. Send full frame with new resolution
//
// This ensures clients receive resolution update before any frame data with new dimensions.
// packFrameIntoChunks efficiently packs block data into chunks under MaxMessageSize.
// Implements optimized metadata packing with zero-copy techniques where possible.
//
// Message format:
// ┌─────────┬──────────┬──────────┬─────────────────────────────────┐
// │ magic   │ opcode   │ event ID │ blocks (until MaxMessageSize)   │
// │ 5 bytes │ 1 byte   │ 16 bytes │ variable                         │
// └─────────┴──────────┴──────────┴─────────────────────────────────┘
//
// Block format (from makeImageBlock):
// ┌─────────┬──────┬─────┬─────┬───────┬────────┬──────────┐
// │ len     │ type │ x   │ y   │ width │ height │ data     │
// │ 2 bytes │ 2 B  │ 2 B │ 2 B │ 2 B   │ 2 B    │ len-10 B │
// └─────────┴──────┴─────┴─────┴───────┴────────┴──────────┘
//
// Optimization strategy:
// 1. Pre-allocate chunk buffer with header (22 bytes overhead)
// 2. Aggregate blocks until approaching MaxMessageSize
// 3. Send chunk when next block would exceed limit
// 4. Use pooled buffers for chunk building (future)
//
// Performance:
// - Typical frame: 10 blocks → 1 chunk (no splitting)
// - Large frame: 240 blocks → 3-4 chunks
// - Overhead per chunk: 22 bytes (magic + opcode + eventID)
func packFrameIntoChunks(rawEvent []byte, blocks *[]*[]byte) {
	if blocks == nil || len(*blocks) == 0 {
		return
	}

	const (
		headerSize   = 22  // magic(5) + opcode(1) + eventID(16)
		safetyMargin = 128 // Leave room to avoid exact boundary
	)

	numBlocks := len(*blocks)

	// Statistics for this frame
	var (
		chunksCreated  int
		totalBytesSent int
		totalFrameSize = headerSize
	)

	for _, blockPtr := range *blocks {
		if blockPtr != nil {
			totalFrameSize += len(*blockPtr)
		}
	}

	if adaptiveQualityManager != nil {
		queueEstimate := pendingFrameBytes.Load() + int64(totalFrameSize)
		adaptiveQualityManager.UpdateNetworkMetrics(lastRTTMs.Load(), 0, queueEstimate)
		adaptiveQualityManager.Adapt()
	}

	// Enforce transport and adaptive frame size ceilings
	if adaptiveQualityManager != nil && adaptiveQualityManager.ShouldDropFrame(int64(totalFrameSize)) {
		backpressureStats.totalFramesDropped.Add(1)
		telemetry.LogStructured("WARN", "packFrameIntoChunks: dropping frame over adaptive budget", map[string]interface{}{
			"frame_size": totalFrameSize,
			"max_size":   adaptiveQualityManager.GetMaxFrameSize(),
			"blocks":     numBlocks,
		})
		return
	}
	if int64(totalFrameSize) > int64(DefaultWSMaxMessageSize) {
		backpressureStats.totalFramesDropped.Add(1)
		telemetry.LogStructured("WARN", "packFrameIntoChunks: dropping frame over transport limit", map[string]interface{}{
			"frame_size": totalFrameSize,
			"limit":      DefaultWSMaxMessageSize,
			"blocks":     numBlocks,
		})
		return
	}

	// Get chunk buffer from pool (OPTIMIZED: reuse allocation)
	poolStats.chunkBufferGets.Add(1)
	chunkPtr := chunkBufferPool.Get().(*[]byte)
	chunk := (*chunkPtr)[:0] // Reset length, keep capacity

	// Build first chunk header with opFirstFrame
	chunk = append(chunk, magicBytes...)
	chunk = append(chunk, opFirstFrame)
	chunk = append(chunk, rawEvent...)
	chunkStartSize := len(chunk) // Save header size (22 bytes)

	for _, blockPtr := range *blocks {
		if blockPtr == nil {
			continue
		}

		block := *blockPtr
		blockLen := len(block)

		// Check if adding this block would exceed MaxMessageSize
		// Use safety margin to ensure we never exceed hard limit
		if len(chunk)+blockLen >= common.MaxMessageSize-safetyMargin {
			// Send current chunk (if it has blocks)
			if len(chunk) > chunkStartSize {
				// Copy chunk data before sending (chunk buffer will be reused)
				chunkCopy := make([]byte, len(chunk))
				copy(chunkCopy, chunk)
				sendDesktopData(chunkCopy)

				chunksCreated++
				totalBytesSent += len(chunk)

				// Update multi-chunk stats
				if chunksCreated == 1 {
					chunkStats.multiChunkFrames.Add(1)
				}
			}

			// Reset chunk with opRestFrame header
			chunk = (*chunkPtr)[:0] // Reset to empty, keep capacity
			chunk = append(chunk, magicBytes...)
			chunk = append(chunk, opRestFrame)
			chunk = append(chunk, rawEvent...)
			chunkStartSize = len(chunk)
		}

		// Add block to current chunk (zero-copy append)
		chunk = append(chunk, block...)
	}

	// Send final chunk (if it has any blocks)
	if len(chunk) > chunkStartSize {
		// Copy chunk data before sending
		chunkCopy := make([]byte, len(chunk))
		copy(chunkCopy, chunk)
		sendDesktopData(chunkCopy)

		chunksCreated++
		totalBytesSent += len(chunk)
	}

	// Return chunk buffer to pool
	chunkBufferPool.Put(chunkPtr)
	poolStats.chunkBufferPuts.Add(1)

	// Update chunking statistics
	chunkStats.totalChunks.Add(uint64(chunksCreated))
	chunkStats.totalBlocks.Add(uint64(numBlocks))
	chunkStats.totalBytes.Add(uint64(totalBytesSent))

	if uint64(chunksCreated) > chunkStats.maxChunksInFrame.Load() {
		chunkStats.maxChunksInFrame.Store(uint64(chunksCreated))
	}

	// Log multi-chunk frames (debug)
	if chunksCreated > 1 {
		telemetry.LogStructured("DEBUG", "packFrameIntoChunks: multi-chunk frame", map[string]interface{}{
			"chunks_created": chunksCreated,
			"total_blocks":   numBlocks,
			"total_bytes":    totalBytesSent,
			"avg_chunk_size": totalBytesSent / chunksCreated,
		})
	}
}

func broadcastResolutionChange(newBounds image.Rectangle) {
	telemetry.LogStructured("INFO", "desktop: broadcasting resolution change", map[string]interface{}{
		"width":           newBounds.Dx(),
		"height":          newBounds.Dy(),
		"active_sessions": sessions.Count(),
	})

	sessions.IterCb(func(uuid string, desktop *session) bool {
		if desktop.escape.Load() {
			return true
		}

		desktop.lock.Lock()
		defer desktop.lock.Unlock()

		if desktop.channel == nil {
			return true
		}

		// Send resolution change message (type 2)
		// This takes priority over frame data
		select {
		case desktop.channel <- message{t: 2}:
			telemetry.LogStructured("DEBUG", "desktop: resolution sent to session", map[string]interface{}{
				"uuid":   uuid,
				"width":  newBounds.Dx(),
				"height": newBounds.Dy(),
			})
		default:
			// Channel full - drop oldest frame and try again
			select {
			case <-desktop.channel:
				// Dropped old frame, try sending resolution again
				select {
				case desktop.channel <- message{t: 2}:
				default:
					// Still couldn't send, will retry on next frame
					telemetry.LogStructured("WARN", "desktop: resolution packet dropped", map[string]interface{}{
						"uuid": uuid,
					})
				}
			default:
			}
		}
		return true
	})
}

// sendImageDiff delivers frame data to all active sessions with backpressure management.
//
// Backpressure strategy (per-session):
// 1. Check channel utilization (len vs cap)
// 2. If near capacity (≥80%): drop oldest frame
// 3. Try non-blocking send
// 4. If still full: drop current frame, increment metric
// 5. NEVER block capture goroutine
//
// This ensures:
// - Capture continues at 24 FPS regardless of slow clients
// - Slow clients get degraded service (frame drops) vs global degradation
// - Fast clients unaffected by slow clients
// - Memory bounded (channel size limit)
func sendImageDiff(diff []*[]byte) {
	sessions.IterCb(func(uuid string, desktop *session) bool {
		if desktop.escape.Load() {
			return true
		}

		desktop.lock.Lock()
		defer desktop.lock.Unlock()

		if desktop.channel == nil {
			return true
		}

		// BACKPRESSURE: Monitor channel utilization
		channelLen := len(desktop.channel)
		channelCap := cap(desktop.channel)
		utilization := float64(channelLen) / float64(channelCap)
		utilizationPct := uint64(utilization * 100)

		// Track peak channel utilization (per-session)
		if uint64(channelLen) > desktop.channelHighWater.Load() {
			desktop.channelHighWater.Store(uint64(channelLen))
		}

		// Track peak utilization (global)
		if utilizationPct > backpressureStats.peakUtilization.Load() {
			backpressureStats.peakUtilization.Store(utilizationPct)
		}

		// BACKPRESSURE: If channel is ≥80% full, drop oldest frame
		// This creates headroom for new frames and prevents blocking
		// VNC/RDP best practice: always keep channel below 80% to avoid stalls
		if utilization >= 0.8 && channelLen > 0 {
			select {
			case oldFrame := <-desktop.channel:
				// Successfully dropped oldest frame
				desktop.framesDropped.Add(1)
				backpressureStats.totalFramesDropped.Add(1)

				// Log if dropping data frames (not resolution/error messages)
				if oldFrame.t == 0 {
					telemetry.LogStructured("DEBUG", "backpressure: dropped oldest frame", map[string]interface{}{
						"uuid":        uuid,
						"channel_len": channelLen,
						"utilization": utilizationPct,
						"frame_type":  "data",
					})
				}
			default:
				// Channel empty between check and read (rare race, harmless)
			}
		}

		// Try non-blocking send (NEVER block capture goroutine)
		select {
		case desktop.channel <- message{t: 0, frame: &diff}:
			// Success! Frame delivered
			desktop.framesDelivered.Add(1)
			backpressureStats.totalFramesDelivered.Add(1)

		default:
			// Channel still full after drop attempt
			// Drop current frame (don't block capture goroutine)
			desktop.framesDropped.Add(1)
			backpressureStats.totalFramesDropped.Add(1)

			// Track sessions with drops (for alerting)
			if desktop.framesDropped.Load() == 1 {
				// First drop for this session
				backpressureStats.sessionsWithDrops.Add(1)
			}

			telemetry.LogStructured("WARN", "backpressure: dropped current frame", map[string]interface{}{
				"uuid":              uuid,
				"channel_len":       len(desktop.channel),
				"channel_cap":       channelCap,
				"session_dropped":   desktop.framesDropped.Load(),
				"session_delivered": desktop.framesDelivered.Load(),
				"delivery_rate": func() float64 {
					dropped := desktop.framesDropped.Load()
					delivered := desktop.framesDelivered.Load()
					total := dropped + delivered
					if total > 0 {
						return float64(delivered) / float64(total) * 100
					}
					return 100.0
				}(),
			})
		}

		// Feed adaptive quality manager with loss + queue depth metrics.
		// Treat desktop channel drops as a loss signal to downshift quality when the client is struggling.
		if adaptiveQualityManager != nil {
			dropped := desktop.framesDropped.Load()
			delivered := desktop.framesDelivered.Load()
			total := dropped + delivered
			lossPct := float64(0)
			if total > 0 {
				lossPct = (float64(dropped) / float64(total)) * 100
			}
			adaptiveQualityManager.UpdateNetworkMetrics(
				lastRTTMs.Load(),
				lossPct,
				pendingFrameBytes.Load(),
			)
			adaptiveQualityManager.Adapt()
		}

		return true
	})
}

// quitSession gracefully closes a single session with proper error path.
// Implements robust cleanup:
// 1. Enqueue QUIT message with reason
// 2. Close RTC session if exists
// 3. Close channel via sync.Once (prevents double-close)
// 4. Remove from session map
//
// This is the canonical error path for all session terminations.
func quitSession(uuid string, desktop *session, reason string) {
	if desktop == nil {
		return
	}

	// Stop cursor capture loop (safe no-op on non-Windows)
	StopCursorCapture()

	// Mark session as closing
	desktop.escape.Store(true)

	desktop.lock.Lock()
	rawEvent := desktop.rawEvent
	event := desktop.event

	// Step 1: Close RTC session (if exists)
	if desktop.rtc != nil {
		desktop.rtc.close()
		desktop.rtc = nil
		telemetry.LogStructured("DEBUG", "quitSession: RTC closed", map[string]interface{}{
			"uuid": uuid,
		})
	}

	// Step 2: Try to enqueue QUIT message (best effort)
	if desktop.channel != nil {
		select {
		case desktop.channel <- message{t: 1, info: reason}:
			// QUIT message enqueued successfully
			telemetry.LogStructured("DEBUG", "quitSession: QUIT enqueued", map[string]interface{}{
				"uuid":   uuid,
				"reason": reason,
			})
		default:
			// Channel full, will close anyway
			telemetry.LogStructured("WARN", "quitSession: QUIT not enqueued (channel full)", map[string]interface{}{
				"uuid": uuid,
			})
		}
	}
	desktop.lock.Unlock()

	// Step 3: Close channel via sync.Once (prevents panic on double-close)
	desktop.closeOnce.Do(func() {
		desktop.lock.Lock()
		if desktop.channel != nil {
			close(desktop.channel)
			desktop.channel = nil
			telemetry.LogStructured("DEBUG", "quitSession: channel closed", map[string]interface{}{
				"uuid": uuid,
			})
		}
		desktop.lock.Unlock()
	})

	// Step 4: Send QUIT packet to server (if possible)
	if rawEvent != nil && event != "" {
		sendDesktopPacket(modules.Packet{
			Act:   "DESKTOP_QUIT",
			Msg:   reason,
			Event: event,
		}, rawEvent)
	}

	// Step 5: Log final session statistics
	dropped := desktop.framesDropped.Load()
	delivered := desktop.framesDelivered.Load()
	total := dropped + delivered
	deliveryRate := float64(100.0)
	if total > 0 {
		deliveryRate = float64(delivered) / float64(total) * 100
	}

	telemetry.LogStructured("INFO", "quitSession: session closed", map[string]interface{}{
		"uuid":             uuid,
		"reason":           reason,
		"frames_dropped":   dropped,
		"frames_delivered": delivered,
		"delivery_rate":    deliveryRate,
		"high_water_mark":  desktop.channelHighWater.Load(),
	})

	// Step 6: Remove from sessions map
	sessions.Remove(uuid)
}

// quitAllDesktop closes all sessions with error message.
// Uses quitSession for each session to ensure proper cleanup.
func quitAllDesktop(info string) {
	telemetry.LogStructured("WARN", "quitAllDesktop: closing all sessions", map[string]interface{}{
		"reason":          info,
		"active_sessions": sessions.Count(),
	})

	keys := make([]string, 0)
	sessionList := make([]*session, 0)

	sessions.IterCb(func(uuid string, desktop *session) bool {
		keys = append(keys, uuid)
		sessionList = append(sessionList, desktop)
		return true
	})

	// Close each session properly
	for i, uuid := range keys {
		quitSession(uuid, sessionList[i], info)
	}

	// Clear map (should already be empty)
	sessions.Clear()

	// Stop worker
	atomic.StoreInt32(&working, 0)
}

// imageCompare performs optimized delta detection with block-level comparison BEFORE encoding.
// This significantly reduces CPU usage by only encoding changed blocks.
//
// Performance optimization based on VNC/RDP best practices:
// 1. First frame: full-frame path (no previous frame to compare)
// 2. Subsequent frames: block-level delta detection
// 3. Short-circuit: identical blocks are skipped entirely (no encoding)
// 4. Resync: automatically handles resolution changes via nil prev
func imageCompare(img, prev *image.RGBA, compress int) []*[]byte {
	// Full-frame path: first frame or resync (no previous frame)
	if prev == nil {
		telemetry.LogStructured("DEBUG", "imageCompare: full-frame path (first frame or resync)", map[string]interface{}{
			"width":  img.Rect.Dx(),
			"height": img.Rect.Dy(),
		})
		return splitFullImage(img, compress)
	}

	// Delta detection: find changed blocks at block granularity
	diff := getDiff(img, prev)
	if diff == nil || len(diff) == 0 {
		// Short-circuit: entire frame is identical, return empty result
		return make([]*[]byte, 0)
	}

	result := make([]*[]byte, 0, len(diff))

	// Encode only the changed blocks
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
	rect := img.Rect
	imgWidth := rect.Dx()
	imgHeight := rect.Dy()
	blocksX := (imgWidth + blockSize - 1) / blockSize
	blocksY := (imgHeight + blockSize - 1) / blockSize
	result := make([]*[]byte, 0, blocksX*blocksY)
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

// getImageBlock extracts a block from the source image with color space and stride normalization.
// Uses selectable codec system for flexible compression (raw RGBA, JPEG, WebP, etc.)
//
// Color space normalization:
// - Input: RGBA (Go standard, may have non-standard stride)
// - Output: RGBA with normalized stride (width * 4)
// - Rect: Always (0, 0, width, height) for consistency
//
// Codec selection:
// - Raw RGBA: LAN/low latency (no compression, ~36KB per block)
// - JPEG: Balanced (CPU encoding, ~2-8KB per block)
// - WebP: WAN optimization (better compression, ~1-5KB per block)
// - VP8/VP9/H.264: Hardware encoding when available (future)
//
// Performance optimization:
// - Reuses buffers from sync.Pool (zero allocations after warmup)
// - Copies data row-by-row to handle non-standard strides
// - Uses codec interface for flexible encoding
func getImageBlock(img *image.RGBA, rect image.Rectangle, codecType int) []byte {
	width := rect.Dx()
	height := rect.Dy()
	blockBytes := width * height * 4

	// Get buffer from pool (reuse existing allocation)
	poolStats.blockBufferGets.Add(1)
	bufPtr := blockBufferPool.Get().(*[]byte)
	defer func() {
		blockBufferPool.Put(bufPtr)
		poolStats.blockBufferPuts.Add(1)
	}()

	buf := (*bufPtr)[:blockBytes] // Slice to actual size needed

	// Extract block with stride normalization
	// Input stride: img.Stride (may not equal width*4)
	// Output stride: width*4 (normalized)
	bufPos := 0
	imgPos := img.PixOffset(rect.Min.X, rect.Min.Y)

	for y := 0; y < height; y++ {
		// Copy one row at a time, handling stride differences
		copy(buf[bufPos:bufPos+width*4], img.Pix[imgPos:imgPos+width*4])
		bufPos += width * 4  // Normalized stride
		imgPos += img.Stride // Source stride (may differ)
	}

	// Create normalized RGBA image wrapper (zero-copy)
	normalizedImg := &image.RGBA{
		Pix:    buf,
		Stride: width * 4,                       // Normalized stride
		Rect:   image.Rect(0, 0, width, height), // Normalized rect (0,0 origin)
	}

	// Use active codec for encoding
	codec := GetCodec()
	encoded, err := codec.Encode(normalizedImg)
	if err != nil {
		telemetry.LogStructured("ERROR", "getImageBlock: codec encode failed", map[string]interface{}{
			"codec":  codec.Name(),
			"error":  err.Error(),
			"width":  width,
			"height": height,
		})

		// Fallback to raw RGBA on error
		result := make([]byte, blockBytes)
		copy(result, buf)
		return result
	}

	return encoded
}

// makeImageBlock prepends block metadata header to image data.
// Uses buffer pool for header to avoid small allocations.
//
// Header format (12 bytes):
// - [0:2]   uint16 body length (len(block) + 10)
// - [2:4]   uint16 codec type (0=raw, 1=JPEG, 2=WebP, 4=VP8, 5=VP9, 6=H.264)
// - [4:6]   uint16 X position
// - [6:8]   uint16 Y position
// - [8:10]  uint16 width
// - [10:12] uint16 height
//
// Performance: Reuses 12-byte header buffer from pool
func makeImageBlock(block []byte, rect image.Rectangle, codecType int) []byte {
	// Get header buffer from pool
	poolStats.headerBufferGets.Add(1)
	headerPtr := headerBufferPool.Get().(*[]byte)
	header := *headerPtr

	// Get active codec type (may differ from compress parameter for backwards compat)
	codec := GetCodec()
	actualCodecType := codec.Type()

	// Build header with actual codec type
	binary.BigEndian.PutUint16(header[0:2], uint16(len(block)+10))
	binary.BigEndian.PutUint16(header[2:4], uint16(actualCodecType))
	binary.BigEndian.PutUint16(header[4:6], uint16(rect.Min.X))
	binary.BigEndian.PutUint16(header[6:8], uint16(rect.Min.Y))
	binary.BigEndian.PutUint16(header[8:10], uint16(rect.Size().X))
	binary.BigEndian.PutUint16(header[10:12], uint16(rect.Size().Y))

	// Combine header + block data
	result := make([]byte, 12+len(block))
	copy(result[:12], header)
	copy(result[12:], block)

	// Return header buffer to pool
	headerBufferPool.Put(headerPtr)
	poolStats.headerBufferPuts.Add(1)

	return result
}

// getDiff performs block-level delta detection with checkboard pattern scanning.
// This is optimized for typical desktop usage patterns where changes are localized.
//
// Scanning pattern (checkboard to detect motion):
// - Pass 1: Even rows (y += blockSize * 2)
// - Pass 2: Odd rows (y += blockSize * 2, starting at blockSize)
//
// Performance characteristics:
// - Best case (no changes): O(blocks) with early uint64 comparison
// - Worst case (all changed): O(blocks) + encoding overhead
// - Typical case (few changes): O(blocks) with most blocks short-circuited
func getDiff(img, prev *image.RGBA) []image.Rectangle {
	// Safety check: resolution must match
	if img.Rect != prev.Rect {
		// Resolution changed, force full frame resync
		return nil // Will trigger full-frame path in imageCompare
	}

	imgWidth := img.Rect.Dx()
	imgHeight := img.Rect.Dy()
	result := make([]image.Rectangle, 0, 64) // Pre-allocate for typical case

	// Pass 1: Even rows (checkboard pattern)
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

	// Pass 2: Odd rows (checkboard pattern)
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

// isDiff performs fast block-level comparison using unsafe pointer arithmetic.
// Returns true if the block has changed, false if identical.
//
// Optimization strategy:
// - Compare 8 bytes (1x uint64) at a time for balance of speed and accuracy
// - Early return on first difference (short-circuit)
// - Check every row to catch thin changes (clocks, text cursors, notifications)
// - Stride by 2 pixels (x += 2) = 8 bytes per iteration
//
// Performance: ~2-3 CPU cycles per 8-byte comparison on modern CPUs
// Typical 96x96 block: 96*96*4 = 36,864 bytes → ~4,608 comparisons → ~14,000 cycles (~4µs)
// Trade-off: 2x slower than aggressive sampling, but catches all UI updates reliably
func isDiff(img, prev *image.RGBA, rect image.Rectangle) bool {
	// Safety checks
	if img == nil || prev == nil {
		return true
	}
	if img.Rect != prev.Rect {
		return true
	}

	imgHeader := (*reflect.SliceHeader)(unsafe.Pointer(&img.Pix))
	prevHeader := (*reflect.SliceHeader)(unsafe.Pointer(&prev.Pix))

	// Ensure slices are valid
	if imgHeader.Len != prevHeader.Len || imgHeader.Len == 0 {
		return true
	}

	imgPtr := imgHeader.Data
	prevPtr := prevHeader.Data
	imgWidth := img.Rect.Dx()
	rectWidth := rect.Dx()

	// Bounds checking for the rectangle
	end := 0
	if rect.Max.Y == 0 {
		end = rect.Max.X * 4
	} else {
		end = (rect.Max.Y*imgWidth - imgWidth + rect.Max.X) * 4
	}
	if imgHeader.Len < end || prevHeader.Len < end {
		return true
	}

	// Fast comparison: 8 bytes (1x uint64) at a time with early termination.
	// Check every row to catch thin changes (e.g., cursor/text) that can be missed when skipping rows.
	// Check every 2 pixels to reliably detect small UI updates like clock digits.
	for y := rect.Min.Y; y < rect.Max.Y; y++ {
		cursor := uintptr((y*imgWidth + rect.Min.X) * 4)

		// Compare 8 bytes per iteration (2 RGBA pixels = 8 bytes)
		for x := 0; x < rectWidth; x += 2 {
			// Bounds check: ensure 8 bytes available
			if int(cursor)+8 > imgHeader.Len || int(cursor)+8 > prevHeader.Len {
				// Not enough data left, compare remaining bytes safely
				remaining := imgHeader.Len - int(cursor)
				if remaining > 0 && remaining < 8 {
					// Compare byte-by-byte for remainder
					for i := 0; i < remaining; i++ {
						imgByte := *(*byte)(unsafe.Pointer(imgPtr + cursor + uintptr(i)))
						prevByte := *(*byte)(unsafe.Pointer(prevPtr + cursor + uintptr(i)))
						if imgByte != prevByte {
							return true // Early termination: difference found
						}
					}
				}
				break
			}

			// Fast path: compare 1x uint64 (8 bytes) at once
			imgVal := *(*uint64)(unsafe.Pointer(imgPtr + cursor))
			prevVal := *(*uint64)(unsafe.Pointer(prevPtr + cursor))
			if imgVal != prevVal {
				return true // Early termination: difference found
			}

			cursor += 8
		}
	}

	// No differences found - block is identical
	return false
}

func InitDesktop(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopInit); forwarded {
		return err
	}

	telemetry.LogStructured("INFO", "desktop: init start", map[string]interface{}{
		"event":       pack.Event,
		"has_data":    pack.Data != nil,
		"is_session0": IsSession0Mode(),
	})

	var uuid string
	rawEvent, err := hex.DecodeString(pack.Event)
	if err != nil {
		return err
	}
	if len(rawEvent) != 16 {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}
	if val, ok := pack.GetData(`desktop`, reflect.String); !ok {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	} else {
		uuid = val.(string)
	}
	if uuid == `` {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}

	// Apply optional initialization parameters (monitor/fps/quality/codec)
	if val, ok := pack.GetData(`monitor`, reflect.Float64); ok {
		configMonitor.Store(clampMonitorValue(int32(val.(float64))))
	}
	if val, ok := pack.GetData(`fps`, reflect.Float64); ok {
		configFPS.Store(clampFPSValue(int32(val.(float64))))
	}
	if val, ok := pack.GetData(`quality`, reflect.Float64); ok {
		configQuality.Store(clampQualityValue(int32(val.(float64))))
		// Refresh JPEG codec quality if active
		if _, ok := GetCodec().(*JPEGCodec); ok {
			newCodec := NewJPEGCodec(int(configQuality.Load()))
			if adaptiveQualityManager != nil {
				newCodec.EnableAdaptiveQuality(adaptiveQualityManager)
			}
			SetCodec(newCodec)
		}
	}
	if val, ok := pack.GetData(`codec`, reflect.String); ok {
		switch strings.ToLower(val.(string)) {
		case "raw", "rgba":
			SetCodec(NewRawCodec())
		case "webp":
			SetCodec(NewWebPCodec(int(configQuality.Load())))
		default:
			jpeg := NewJPEGCodec(int(configQuality.Load()))
			if adaptiveQualityManager != nil {
				jpeg.EnableAdaptiveQuality(adaptiveQualityManager)
			}
			SetCodec(jpeg)
		}
	}

	desktop := &session{
		event:    pack.Event,
		rawEvent: rawEvent,
		channel:  make(chan message, 5),
		lock:     &sync.Mutex{},
	}
	desktop.allowControl.Store(true)
	atomic.StoreInt64(&desktop.lastPack, utils.Unix)

	// FIXED: Get and store display bounds atomically (Issue #3)
	activeMonitor := clampMonitorValue(configMonitor.Load())
	bounds, boundsErr := getDisplayBoundsForMonitor(activeMonitor)
	if boundsErr != nil || bounds.Dx() == 0 || bounds.Dy() == 0 {
		close(desktop.channel)
		sendDesktopPacket(modules.Packet{Act: `DESKTOP_QUIT`, Msg: `${i18n|DESKTOP.NO_DISPLAY_FOUND}`, Event: pack.Event}, desktop.rawEvent)
		if boundsErr != nil {
			return boundsErr
		}
		return errors.New(`${i18n|DESKTOP.NO_DISPLAY_FOUND}`)
	}
	telemetry.LogStructured("INFO", "desktop: display bounds resolved", map[string]interface{}{
		"width":   bounds.Dx(),
		"height":  bounds.Dy(),
		"monitor": activeMonitor,
	})
	configMonitor.Store(activeMonitor)
	displayBounds.Store(bounds) // Atomic store - no race condition

	// Send DESKTOP_INIT acknowledgment to server
	sendDesktopPacket(modules.Packet{
		Act:   `DESKTOP_INIT`,
		Code:  0,
		Event: pack.Event,
		Data: map[string]interface{}{
			"width":    bounds.Dx(),
			"height":   bounds.Dy(),
			"monitor":  activeMonitor,
			"monitors": enumerateDisplays(),
		},
	}, desktop.rawEvent)
	telemetry.LogStructured("INFO", "desktop: init ack sent", map[string]interface{}{
		"desktop_uuid": uuid,
		"event":        pack.Event,
	})

	// Add session to map BEFORE starting goroutines to avoid race conditions
	sessions.Set(uuid, desktop)

	// Start capture worker (worker guards itself with CAS to avoid duplicates)
	startCaptureWorker()

	// Send initial frame if worker is already running
	if atomic.LoadInt32(&working) == 1 {
		prevVal := prevDesktop.Load()
		if prevVal != nil {
			prev := prevVal.(*image.RGBA)
			img := splitFullImage(prev, compress)
			if img != nil {
				desktop.lock.Lock()
				select {
				case desktop.channel <- message{t: 0, frame: &img}:
				default:
					// Channel full, skip initial frame
				}
				desktop.lock.Unlock()
			}
		}
	}

	// Send resolution message and start handler
	desktop.lock.Lock()
	select {
	case desktop.channel <- message{t: 2}:
	default:
		// Channel full, skip resolution (will be sent later)
	}
	desktop.lock.Unlock()

	// Start cursor capture loop (Windows only)
	StartCursorCapture(rawEvent)

	go handleDesktop(pack, uuid, desktop)
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
	atomic.StoreInt64(&desktop.lastPack, utils.Unix)
}

// KillDesktop gracefully terminates a desktop session.
// Uses canonical quitSession error path for proper cleanup.
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

	// Stop cursor capture
	StopCursorCapture()

	// Use canonical error path for proper cleanup
	quitSession(uuid, desktop, "${i18n|DESKTOP.SESSION_CLOSED}")
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

	if desktop.escape.Load() {
		return
	}

	// FIXED: Use atomic.Value for prevDesktop (Issue #2)
	prevVal := prevDesktop.Load()
	if prevVal == nil {
		return
	}
	prev := prevVal.(*image.RGBA)

	img := splitFullImage(prev, compress)
	if img == nil {
		return
	}

	desktop.lock.Lock()
	defer desktop.lock.Unlock()

	if desktop.channel != nil {
		select {
		case desktop.channel <- message{t: 0, frame: &img}:
		default:
			// Channel full, skip screenshot
		}
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

	for !desktop.escape.Load() {
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
				desktop.escape.Store(true)
				return
			}
			// send image
			if msg.t == 0 {
				desktop.lock.Lock()
				rawEvent := desktop.rawEvent
				desktop.lock.Unlock()

				// OPTIMIZED METADATA PACKING & CHUNKING
				// Protocol: [magic(5)][opcode(1)][eventID(16)][blocks...]
				// Each block: [len(2)][type(2)][x(2)][y(2)][w(2)][h(2)][data(len-10)]
				// Chunks must stay under MaxMessageSize (65KB)

				packFrameIntoChunks(rawEvent, msg.frame)
				continue
			}
			// set resolution
			if msg.t == 2 {
				desktop.lock.Lock()
				rawEvent := desktop.rawEvent
				desktop.lock.Unlock()

				// FIXED: Use atomic.Value for displayBounds (Issue #3)
				boundsVal := displayBounds.Load()
				if boundsVal == nil {
					continue
				}
				bounds := boundsVal.(image.Rectangle)

				buf := append(append(magicBytes, opResolution), rawEvent...)
				data := make([]byte, 6)
				binary.BigEndian.PutUint16(data[:2], 4)
				binary.BigEndian.PutUint16(data[2:4], uint16(bounds.Dx()))
				binary.BigEndian.PutUint16(data[4:6], uint16(bounds.Dy()))
				buf = append(buf, data...)
				sendDesktopData(buf)
				telemetry.LogStructured("DEBUG", "desktop: sent resolution update", map[string]interface{}{
					"desktop": uuid,
					"width":   bounds.Dx(),
					"height":  bounds.Dy(),
				})
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
			lastPack := atomic.LoadInt64(&desktop.lastPack)
			if timestamp-lastPack > MaxInterval {
				desktop.lock.Lock()
				if desktop.rtc != nil {
					desktop.rtc.close()
					desktop.rtc = nil
				}
				desktop.lock.Unlock()
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
