package desktop

import (
	"Rocket/modules"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"math"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kataras/golog"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	xdraw "golang.org/x/image/draw"
)

const (
	envWebRTCEnabled   = "SPARK_WEBRTC_ENABLED"
	envWebRTCFPS       = "SPARK_WEBRTC_MAX_FPS"
	envWebRTCBitrate   = "SPARK_WEBRTC_MAX_BITRATE"
	envWebRTCCodec     = "SPARK_WEBRTC_CODEC"
	envWebRTCMaxWidth  = "SPARK_WEBRTC_MAX_WIDTH"
	envWebRTCMaxHeight = "SPARK_WEBRTC_MAX_HEIGHT"
	// envWebRTCFrameQueue controls the size of the encode/send queue used by the WebRTC session.
	// Larger queues absorb transient encoder/network jitter but can increase latency under load.
	// Perf/latency harnesses typically set this to 1 to prefer dropping stale frames.
	envWebRTCFrameQueue = "SPARK_WEBRTC_FRAME_QUEUE"
	webRTCDefaultFPS    = 30
	webRTCDefaultCodec  = string(WebRTCCodecVP8)
	webRTCDefaultBR     = 2_500_000
	webRTCDefaultMaxW   = 1920
	webRTCDefaultMaxH   = 1080
	maxInputPayload     = 1 << 16
)

// adaptiveQualityEncoder is implemented by encoders that can react to network conditions.
type adaptiveQualityEncoder interface {
	EnableAdaptiveQuality(aqm *AdaptiveQualityManager)
}

type rtcSession struct {
	desktopID      string
	rtc            *DesktopWebRTC
	encoder        WebRTCEncoder
	targetFrameNs  int64
	lastSent       int64
	codec          WebRTCCodec
	bitrate        int
	maxWidth       int
	maxHeight      int
	scaleBuf       *image.RGBA
	webcamStop     func()
	audioStop      func()
	h264ProfileID  uint8
	h264Constraint uint8
	h264LevelID    uint8

	frameCh chan rtcFrameRequest
	stopCh  chan struct{}
	stopped atomic.Bool

	onClosed func()

	// Adaptive quality management (REMB-driven bitrate adaptation)
	qualityManager *AdaptiveQualityManager

	// GPU fallback warning tracking (avoid log spam)
	gpuFallbackWarned atomic.Bool

	// Debug counters
	enqueueCount atomic.Int64
	sendCount    atomic.Int64

	encodeErrorLogged atomic.Bool
	sendErrorLogged   atomic.Bool

	// Codec fallback tracking
	consecutiveEncodeErrors atomic.Int32
	codecFallbackTriggered  atomic.Bool
}

type rtcFrameRequest struct {
	frame    *CaptureFrame
	duration time.Duration
}

func isWebRTCEnabled() bool {
	if isWindowsSinglePipeline() {
		return true
	}
	val := strings.TrimSpace(os.Getenv(envWebRTCEnabled))
	if val == "" {
		return true
	}
	switch strings.ToLower(val) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func isWebRTCWebcamEnabled() bool {
	if isWindowsSinglePipeline() {
		return false
	}
	val := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_WEBCAM"))
	if val == "" {
		return true
	}
	switch strings.ToLower(val) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func isWebRTCAudioEnabled() bool {
	if isWindowsSinglePipeline() {
		return false
	}
	val := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_AUDIO"))
	if val == "" {
		return true
	}
	switch strings.ToLower(val) {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func parseEnvInt(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	if v, err := strconv.Atoi(raw); err == nil && v > 0 {
		return v
	}
	return def
}

func parseEnvOptionalInt(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 {
		return def
	}
	return v
}

// sessionLog writes to the WebRTC signaling debug log
func sessionLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Print(msg)
	if f, err := os.OpenFile("logs/webrtc_signaling.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		fmt.Fprintf(f, "[%s] %s", time.Now().Format("15:04:05.000"), msg)
		f.Close()
	}
}

func newRTCSession(desktopID string, rtc *DesktopWebRTC, codec WebRTCCodec, h264Sel h264FmtpSelection) (*rtcSession, error) {
	sessionLog("[SESSION] newRTCSession starting, desktopID=%s, requestedCodec=%s\n", desktopID, string(codec))
	codec = WebRTCCodecH264
	bitrate := parseEnvInt(envWebRTCBitrate, webRTCDefaultBR)
	fps := parseEnvInt(envWebRTCFPS, webRTCDefaultFPS)
	if fps <= 0 {
		fps = webRTCDefaultFPS
	}

	maxWidth := parseEnvOptionalInt(envWebRTCMaxWidth, webRTCDefaultMaxW)
	maxHeight := parseEnvOptionalInt(envWebRTCMaxHeight, webRTCDefaultMaxH)
	queueSize := parseEnvInt(envWebRTCFrameQueue, 30)
	if queueSize < 1 {
		queueSize = 1
	}
	if queueSize > 120 {
		queueSize = 120
	}

	sessionLog("[SESSION] Calling NewWebRTCEncoder codec=%s bitrate=%d\n", string(codec), bitrate)
	encoder, actualCodec, err := NewWebRTCEncoder(codec, WebRTCEncoderConfig{
		BitRate:          bitrate,
		KeyFrameInterval: 60,
		H264ProfileID:    h264Sel.ProfileID,
		H264Constraint:   h264Sel.Constraint,
		H264LevelID:      h264Sel.LevelID,
	})
	if err != nil {
		sessionLog("[SESSION] NewWebRTCEncoder FAILED: %v\n", err)
		return nil, err
	}
	sessionLog("[SESSION] NewWebRTCEncoder succeeded, actualCodec=%s\n", string(actualCodec))
	// Attach adaptive quality manager for bitrate enforcement when available.
	if adaptiveQualityManager != nil {
		if enc, ok := encoder.(adaptiveQualityEncoder); ok {
			enc.EnableAdaptiveQuality(adaptiveQualityManager)
		}
	}
	var webcamStop func()
	var audioStop func()

	// Create per-session quality manager for REMB-driven adaptation
	// This allows each session to adapt independently based on its network conditions
	sessionQualityManager := NewAdaptiveQualityManager()

	sess := &rtcSession{
		desktopID:      desktopID,
		rtc:            rtc,
		encoder:        encoder,
		targetFrameNs:  int64(time.Second / time.Duration(fps)),
		codec:          actualCodec,
		bitrate:        bitrate,
		maxWidth:       maxWidth,
		maxHeight:      maxHeight,
		h264ProfileID:  h264Sel.ProfileID,
		h264Constraint: h264Sel.Constraint,
		h264LevelID:    h264Sel.LevelID,
		// Default queue size is aligned with Sunshine's proven 30-slot encode session queue.
		// Override via SPARK_WEBRTC_FRAME_QUEUE for perf/low-latency runs.
		frameCh:        make(chan rtcFrameRequest, queueSize),
		stopCh:         make(chan struct{}),
		webcamStop:     webcamStop,
		audioStop:      audioStop,
		qualityManager: sessionQualityManager,
	}
	sess.start()
	return sess, nil
}

func (r *rtcSession) start() {
	if r == nil || r.stopped.Load() {
		return
	}
	go r.run()
}

func (r *rtcSession) close() {
	if r == nil {
		return
	}
	if r.stopped.CompareAndSwap(false, true) {
		close(r.stopCh)
		// Best-effort drain queued frames.
		for {
			select {
			case req := <-r.frameCh:
				if req.frame != nil {
					req.frame.Close()
				}
			default:
				goto drained
			}
		}
	drained:
		if r.onClosed != nil {
			go r.onClosed()
		}
	}
	if r.webcamStop != nil {
		r.webcamStop()
	}
	if r.audioStop != nil {
		r.audioStop()
	}
	if r.encoder != nil {
		r.encoder.Close()
	}
	if r.rtc != nil {
		r.rtc.Close()
	}
}

type frameEncoder interface {
	EncodeFrame(frame *CaptureFrame, duration time.Duration) (media.Sample, error)
}

func (r *rtcSession) enqueue(frame *CaptureFrame, duration time.Duration) {
	if r == nil || frame == nil {
		if frame != nil {
			frame.Close()
		}
		return
	}
	if r.stopped.Load() {
		frame.Close()
		return
	}

	cnt := r.enqueueCount.Add(1)
	if cnt <= 5 || cnt%300 == 0 {
		hasGPU := frame.GPU != nil
		hasImg := frame.Image != nil
		fmt.Printf("[DEBUG_RTC] enqueue frame=%d hasGPU=%v hasImg=%v codec=%s\n",
			cnt, hasGPU, hasImg, string(r.codec))
	}

	req := rtcFrameRequest{frame: frame, duration: duration}

	defer func() {
		if recover() != nil {
			frame.Close()
		}
	}()

	select {
	case r.frameCh <- req:
		return
	default:
		// Queue full: drop oldest, keep newest.
		select {
		case old := <-r.frameCh:
			if old.frame != nil {
				old.frame.Close()
			}
		default:
		}
		select {
		case r.frameCh <- req:
		default:
			frame.Close()
		}
	}
}

func (r *rtcSession) run() {
	for {
		select {
		case <-r.stopCh:
			return
		case req := <-r.frameCh:
			r.sendQueued(req)
		}
	}
}

func (r *rtcSession) sendQueued(req rtcFrameRequest) {
	if r == nil || r.encoder == nil || r.rtc == nil || req.frame == nil {
		if req.frame != nil {
			req.frame.Close()
		}
		return
	}
	defer req.frame.Close()

	connState := r.rtc.ConnectionState()
	if connState == webrtc.PeerConnectionStateFailed || connState == webrtc.PeerConnectionStateClosed {
		return
	}
	iceState := r.rtc.ICEConnectionState()

	startNs := time.Now().UnixNano()
	last := atomic.LoadInt64(&r.lastSent)
	if last != 0 && startNs-last < r.targetFrameNs {
		return
	}

	cnt := r.sendCount.Add(1)
	if connState != webrtc.PeerConnectionStateConnected {
		if cnt <= 5 || cnt%300 == 0 {
			sessionLog("[SESSION] sendQueued: peer not connected (state=%s ice=%s), continuing\n",
				connState.String(), iceState.String())
		}
	}

	duration := req.duration
	if duration <= 0 {
		duration = time.Second / 30
	}

	if isWindowsSinglePipeline() {
		if req.frame.GPU == nil || req.frame.GPU.Backend != "dxgi_nv12" {
			r.logGPUFallbackWarningOnce()
			return
		}
		enc, ok := r.encoder.(frameEncoder)
		if !ok {
			if r.encodeErrorLogged.CompareAndSwap(false, true) {
				sessionLog("[SESSION] EncodeFrame unavailable in single-pipeline mode\n")
			}
			r.close()
			return
		}
		if cnt <= 5 || cnt%300 == 0 {
			sessionLog("[SESSION] frame=%d calling EncodeFrame (GPU-only)\n", cnt)
		}
		sample, err := enc.EncodeFrame(req.frame, duration)
		if err != nil {
			// Track consecutive encode errors for potential codec fallback
			errCount := r.consecutiveEncodeErrors.Add(1)

			if errors.Is(err, ErrWebRTCEncoderTimeout) {
				if cnt <= 5 || cnt%300 == 0 {
					sessionLog("[SESSION] frame=%d ErrWebRTCEncoderTimeout (dropped, single-pipeline)\n", cnt)
				}
				// Timeout errors don't close session but may trigger fallback
				// Reduced threshold since encoder now has internal recovery at 3 errors
				if errCount >= 5 && r.codecFallbackTriggered.CompareAndSwap(false, true) {
					golog.Warnf("[WEBRTC_ENCODE] codec fallback recommended: %d consecutive timeouts, codec=%s", errCount, string(r.codec))
					// TODO: Implement actual codec switch to VP8/VP9 when H.264 consistently fails
					// For now, log and reduce quality via adaptive quality manager
					if r.qualityManager != nil {
						r.qualityManager.UpdateNetworkMetrics(500, 10.0, 1024*1024) // Force quality downgrade
					}
				}
				return
			}
			if r.encodeErrorLogged.CompareAndSwap(false, true) {
				sessionLog("[SESSION] EncodeFrame failed: %v\n", err)
			}
			golog.Warnf("[WEBRTC_ENCODE] GPU encode failed error=%s codec=%s consecutiveErrors=%d", err.Error(), string(r.codec), errCount)

			// After 5 consecutive hard errors, close session
			if errCount >= 5 {
				r.close()
			}
			return
		}
		// Reset error counter on successful encode
		r.consecutiveEncodeErrors.Store(0)
		if len(sample.Data) == 0 {
			if cnt <= 5 || cnt%300 == 0 {
				sessionLog("[SESSION] frame=%d empty sample (encoder warmup)\n", cnt)
			}
			return
		}
		sendDuration := sample.Duration
		if sendDuration <= 0 {
			sendDuration = duration
		}
		if cnt <= 5 || cnt%300 == 0 {
			sessionLog("[SESSION] frame=%d sending %d bytes via RTP\n", cnt, len(sample.Data))
		}
		if err := r.rtc.SendFrame(sample.Data, sendDuration); err != nil {
			state := r.rtc.ConnectionState()
			if state == webrtc.PeerConnectionStateConnected {
				if r.sendErrorLogged.CompareAndSwap(false, true) {
					sessionLog("[SESSION] SendFrame failed (gpu=true): %v\n", err)
				}
				golog.Warnf("[WEBRTC_SEND] SendFrame failed error=%s codec=%s gpu=true", err.Error(), string(r.codec))
				r.close()
			}
			return
		}
		if cnt <= 5 || cnt%300 == 0 {
			sessionLog("[SESSION] frame=%d sent successfully\n", cnt)
		}
		atomic.StoreInt64(&r.lastSent, startNs)
		return
	}

	// Prefer GPU path when available.
	if req.frame.GPU != nil {
		if enc, ok := r.encoder.(frameEncoder); ok {
			if cnt <= 5 || cnt%300 == 0 {
				fmt.Printf("[DEBUG_RTC] sendQueued frame=%d calling EncodeFrame (GPU path)\n", cnt)
			}
			sample, err := enc.EncodeFrame(req.frame, duration)
			if err != nil {
				if errors.Is(err, ErrWebRTCEncoderTimeout) {
					// Treat as a dropped frame (e.g., encoder buffering / no output ready yet).
					if cnt <= 5 || cnt%300 == 0 {
						sessionLog("[SESSION] frame=%d ErrWebRTCEncoderTimeout (dropped)\n", cnt)
					}
					return
				}
				if r.encodeErrorLogged.CompareAndSwap(false, true) {
					sessionLog("[SESSION] EncodeFrame failed: %v\n", err)
				}
				golog.Warnf("[WEBRTC_ENCODE] GPU encode failed error=%s codec=%s", err.Error(), string(r.codec))
				r.close()
				return
			}
			if len(sample.Data) == 0 {
				// Encoder produced no output (common for hardware encoders warming up).
				// Treat as a dropped frame; do not send empty RTP.
				return
			}
			sendDuration := sample.Duration
			if sendDuration <= 0 {
				sendDuration = duration
			}
			// Send perf metadata BEFORE video frame for accurate latency measurement.
			// This ensures the browser has the capture timestamp before it renders the frame.
			if req.frame.CaptureTimeNs > 0 {
				tsMs := req.frame.CaptureTimeNs / 1_000_000
				payload, err := json.Marshal(map[string]any{
					"captureTs": tsMs,
				})
				if err == nil {
					if cnt <= 10 || cnt%100 == 0 {
						sessionLog("[PERF] sending perf metadata: captureTs=%d\n", tsMs)
					}
					r.rtc.SendPerfMetadata(payload)
				}
			}
			if err := r.rtc.SendFrame(sample.Data, sendDuration); err != nil {
				state := r.rtc.ConnectionState()
				if state == webrtc.PeerConnectionStateConnected {
					if r.sendErrorLogged.CompareAndSwap(false, true) {
						sessionLog("[SESSION] SendFrame failed (gpu=true): %v\n", err)
					}
					golog.Warnf("[WEBRTC_SEND] SendFrame failed error=%s codec=%s gpu=true", err.Error(), string(r.codec))
					r.close()
				}
				return
			}
			atomic.StoreInt64(&r.lastSent, startNs)
			return
		}
		// No GPU-capable encoder for this codec - fall back to CPU image if available.
		if req.frame.Image == nil {
			// GPU frame with no CPU fallback and no hardware encoder - cannot encode.
			// Log once per session to avoid log spam.
			r.logGPUFallbackWarningOnce()
			return
		}
		// Fall through to CPU encoding path below using req.frame.Image.
		golog.Debugf("[WEBRTC_ENCODE] GPU encoder unavailable, using CPU fallback codec=%s", string(r.codec))
	}

	img := req.frame.Image
	if img == nil {
		return
	}
	src := img
	if scaled := r.scaleFrame(img); scaled != nil {
		src = scaled
	}

	sample, err := r.encoder.Encode(src, duration)
	if err != nil {
		if errors.Is(err, ErrWebRTCEncoderTimeout) {
			// Treat as a dropped frame (e.g., encoder buffering / no output ready yet).
			return
		}
		if r.encodeErrorLogged.CompareAndSwap(false, true) {
			sessionLog("[SESSION] Encode (cpu) failed: %v\n", err)
		}
		r.close()
		return
	}
	if len(sample.Data) == 0 {
		// Encoder produced no output. Treat as a dropped frame; do not send empty RTP.
		return
	}
	sendDuration := sample.Duration
	if sendDuration <= 0 {
		sendDuration = duration
	}
	// Send perf metadata BEFORE video frame for accurate latency measurement.
	if req.frame.CaptureTimeNs > 0 {
		tsMs := req.frame.CaptureTimeNs / 1_000_000
		payload, err := json.Marshal(map[string]any{
			"captureTs": tsMs,
		})
		if err == nil {
			if cnt <= 10 || cnt%100 == 0 {
				sessionLog("[PERF] sending perf metadata: captureTs=%d\n", tsMs)
			}
			r.rtc.SendPerfMetadata(payload)
		}
	}
	if err := r.rtc.SendFrame(sample.Data, sendDuration); err != nil {
		state := r.rtc.ConnectionState()
		if state == webrtc.PeerConnectionStateConnected {
			if r.sendErrorLogged.CompareAndSwap(false, true) {
				sessionLog("[SESSION] SendFrame failed (gpu=false): %v\n", err)
			}
			golog.Warnf("[WEBRTC_SEND] SendFrame failed error=%s codec=%s gpu=false", err.Error(), string(r.codec))
			r.close()
		}
		return
	}
	atomic.StoreInt64(&r.lastSent, startNs)
}

func (r *rtcSession) scaleFrame(img *image.RGBA) *image.RGBA {
	if r == nil || img == nil {
		return nil
	}
	maxW := r.maxWidth
	maxH := r.maxHeight
	if maxW <= 0 && maxH <= 0 {
		return nil
	}

	b := img.Bounds()
	w := b.Dx()
	h := b.Dy()
	if w <= 0 || h <= 0 {
		return nil
	}

	// No scaling needed.
	if (maxW <= 0 || w <= maxW) && (maxH <= 0 || h <= maxH) {
		return nil
	}

	scaleW := math.Inf(1)
	if maxW > 0 {
		scaleW = float64(maxW) / float64(w)
	}
	scaleH := math.Inf(1)
	if maxH > 0 {
		scaleH = float64(maxH) / float64(h)
	}

	scale := math.Min(scaleW, scaleH)
	if !(scale > 0) || scale >= 1 {
		return nil
	}

	tw := int(math.Round(float64(w) * scale))
	th := int(math.Round(float64(h) * scale))
	if tw < 2 {
		tw = 2
	}
	if th < 2 {
		th = 2
	}
	// NV12/H.264 encoders generally require even dimensions.
	if tw%2 == 1 {
		tw--
	}
	if th%2 == 1 {
		th--
	}
	if tw < 2 || th < 2 {
		return nil
	}

	if r.scaleBuf == nil || r.scaleBuf.Bounds().Dx() != tw || r.scaleBuf.Bounds().Dy() != th {
		r.scaleBuf = image.NewRGBA(image.Rect(0, 0, tw, th))
	}

	xdraw.ApproxBiLinear.Scale(r.scaleBuf, r.scaleBuf.Bounds(), img, b, xdraw.Src, nil)
	return r.scaleBuf
}

type keyFrameRequester interface {
	RequestKeyFrame()
}

func (r *rtcSession) requestKeyFrame() {
	if r == nil || r.encoder == nil {
		return
	}
	if requester, ok := r.encoder.(keyFrameRequester); ok {
		requester.RequestKeyFrame()
	}
}

// logGPUFallbackWarningOnce logs a warning once per session when GPU frames cannot be encoded
// due to missing hardware encoder and no CPU fallback image available.
func (r *rtcSession) logGPUFallbackWarningOnce() {
	if r == nil {
		return
	}
	if r.gpuFallbackWarned.CompareAndSwap(false, true) {
		golog.Warnf("[WEBRTC_ENCODE] GPU frame received but no hardware encoder available and no CPU fallback image; frames will be dropped until CPU fallback is provided codec=%s", string(r.codec))
	}
}

// handleRTCInput parses data channel payloads and forwards to the existing handlers.
// The preferred payload schema matches the WebSocket control plane: {act, data}.
func handleRTCInput(desktopID string, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxInputPayload {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}
	sess, ok := sessions.Get(desktopID)
	if !ok || sess.escape.Load() {
		return errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}

	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return err
	}

	// New schema: {act, data}
	if rawAct, ok := body[`act`]; ok {
		act, ok := rawAct.(string)
		if !ok || act == "" {
			return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
		}

		data := map[string]any{}
		if rawData, ok := body[`data`]; ok {
			if m, ok := rawData.(map[string]any); ok && m != nil {
				data = m
			}
		}
		data[`desktop`] = desktopID

		switch act {
		case `DESKTOP_INPUT`:
			if !sess.allowControl.Load() {
				return errInputUnsupported
			}
			if events, ok := data[`events`].([]any); ok && len(events) > inputBatchLimit {
				data[`events`] = events[:inputBatchLimit]
			}
			// Never trust allowControl toggles from a direct P2P channel.
			data[`allowControl`] = sess.allowControl.Load()
			return HandleInput(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_CONFIG`:
			// Allow view-only sessions to tune QoS, but ignore allowControl toggles.
			delete(data, `allowControl`)
			return HandleConfig(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_CLIPBOARD`:
			if isWindowsSinglePipeline() {
				return errInputUnsupported
			}
			if !sess.allowControl.Load() {
				return errInputUnsupported
			}
			return HandleClipboard(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_FILE_DROP`:
			if isWindowsSinglePipeline() {
				return errInputUnsupported
			}
			if !sess.allowControl.Load() {
				return errInputUnsupported
			}
			return HandleFileDrop(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_AUDIO`:
			if isWindowsSinglePipeline() {
				return errInputUnsupported
			}
			if !sess.allowControl.Load() {
				return errInputUnsupported
			}
			return HandleAudio(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_SHOT`:
			// View-only sessions may still request a fresh full frame for recovery.
			GetDesktop(modules.Packet{Act: act, Event: desktopID, Data: data})
			return nil
		default:
			return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
		}
	}

	// Legacy schema (older clients): {events:[...]}
	events, ok := body[`events`]
	if !ok {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}
	if slice, ok := events.([]any); ok && len(slice) > inputBatchLimit {
		body[`events`] = slice[:inputBatchLimit]
	}
	if !sess.allowControl.Load() {
		return errInputUnsupported
	}
	return HandleInput(modules.Packet{
		Act:   `DESKTOP_INPUT`,
		Event: desktopID,
		Data: map[string]any{
			`desktop`:      desktopID,
			`events`:       body[`events`],
			`allowControl`: sess.allowControl.Load(),
		},
	})
}
