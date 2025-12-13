package desktop

import (
	"Rocket/modules"
	"encoding/json"
	"errors"
	"image"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	xdraw "golang.org/x/image/draw"
)

const (
	envWebRTCEnabled   = "SPARK_WEBRTC_ENABLED"
	envWebRTCFPS       = "SPARK_WEBRTC_MAX_FPS"
	envWebRTCBitrate   = "SPARK_WEBRTC_MAX_BITRATE"
	envWebRTCCodec     = "SPARK_WEBRTC_CODEC"
	envWebRTCMaxWidth  = "SPARK_WEBRTC_MAX_WIDTH"
	envWebRTCMaxHeight = "SPARK_WEBRTC_MAX_HEIGHT"
	webRTCDefaultFPS   = 30
	webRTCDefaultCodec = string(WebRTCCodecVP8)
	webRTCDefaultBR    = 2_500_000
	webRTCDefaultMaxW  = 1920
	webRTCDefaultMaxH  = 1080
	maxInputPayload    = 1 << 16
)

// adaptiveQualityEncoder is implemented by encoders that can react to network conditions.
type adaptiveQualityEncoder interface {
	EnableAdaptiveQuality(aqm *AdaptiveQualityManager)
}

type rtcSession struct {
	desktopID     string
	rtc           *DesktopWebRTC
	encoder       WebRTCEncoder
	targetFrameNs int64
	lastSent      int64
	codec         WebRTCCodec
	bitrate       int
	maxWidth      int
	maxHeight     int
	scaleBuf      *image.RGBA
	webcamStop    func()
	audioStop     func()
}

func isWebRTCEnabled() bool {
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

func newRTCSession(desktopID string, rtc *DesktopWebRTC, codec WebRTCCodec) (*rtcSession, error) {
	if codec == "" {
		envCodec := strings.ToLower(strings.TrimSpace(os.Getenv(envWebRTCCodec)))
		if envCodec != "" {
			codec = WebRTCCodec(envCodec)
		} else if runtime.GOOS == "windows" {
			codec = WebRTCCodecH264
		} else {
			codec = WebRTCCodec(webRTCDefaultCodec)
		}
	}
	bitrate := parseEnvInt(envWebRTCBitrate, webRTCDefaultBR)
	fps := parseEnvInt(envWebRTCFPS, webRTCDefaultFPS)
	if fps <= 0 {
		fps = webRTCDefaultFPS
	}

	maxWidth := parseEnvOptionalInt(envWebRTCMaxWidth, webRTCDefaultMaxW)
	maxHeight := parseEnvOptionalInt(envWebRTCMaxHeight, webRTCDefaultMaxH)

	encoder, actualCodec, err := NewWebRTCEncoder(codec, WebRTCEncoderConfig{
		BitRate:          bitrate,
		KeyFrameInterval: 60,
	})
	if err != nil {
		return nil, err
	}
	// Attach adaptive quality manager for bitrate enforcement when available.
	if adaptiveQualityManager != nil {
		if enc, ok := encoder.(adaptiveQualityEncoder); ok {
			enc.EnableAdaptiveQuality(adaptiveQualityManager)
		}
	}
	var webcamStop func()
	if isWebRTCWebcamEnabled() {
		if stopFn, err := startWebcamTrack(rtc); err == nil {
			webcamStop = stopFn
		}
	}
	var audioStop func()
	if isWebRTCAudioEnabled() {
		if stopFn, err := startAudioTrack(rtc); err == nil {
			audioStop = stopFn
		}
	}
	return &rtcSession{
		desktopID:     desktopID,
		rtc:           rtc,
		encoder:       encoder,
		targetFrameNs: int64(time.Second / time.Duration(fps)),
		codec:         actualCodec,
		bitrate:       bitrate,
		maxWidth:      maxWidth,
		maxHeight:     maxHeight,
		webcamStop:    webcamStop,
		audioStop:     audioStop,
	}, nil
}

func (r *rtcSession) close() {
	if r == nil {
		return
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

func (r *rtcSession) sendFrame(img *image.RGBA, interval time.Duration) error {
	if r == nil || r.encoder == nil || r.rtc == nil || img == nil {
		return nil
	}
	now := time.Now().UnixNano()
	// Use atomic load/store for lastSent to prevent race conditions
	last := atomic.LoadInt64(&r.lastSent)
	if last != 0 && now-last < r.targetFrameNs {
		return nil
	}
	src := img
	if scaled := r.scaleFrame(img); scaled != nil {
		src = scaled
	}

	sample, err := r.encoder.Encode(src, interval)
	if err != nil {
		return err
	}
	if err := r.rtc.SendFrame(sample.Data, sample.Duration); err != nil {
		return err
	}
	atomic.StoreInt64(&r.lastSent, now)
	return nil
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
			if !sess.allowControl.Load() {
				return errInputUnsupported
			}
			return HandleClipboard(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_FILE_DROP`:
			if !sess.allowControl.Load() {
				return errInputUnsupported
			}
			return HandleFileDrop(modules.Packet{Act: act, Event: desktopID, Data: data})
		case `DESKTOP_AUDIO`:
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
