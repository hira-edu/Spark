package desktop

import (
	"Rocket/modules"
	"encoding/json"
	"errors"
	"image"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	envWebRTCEnabled   = "SPARK_WEBRTC_ENABLED"
	envWebRTCFPS       = "SPARK_WEBRTC_MAX_FPS"
	envWebRTCBitrate   = "SPARK_WEBRTC_MAX_BITRATE"
	envWebRTCCodec     = "SPARK_WEBRTC_CODEC"
	webRTCDefaultFPS   = 24
	webRTCDefaultCodec = string(VPXCodecVP8)
	webRTCDefaultBR    = 900000
	maxInputPayload    = 1 << 16
)

// adaptiveQualityEncoder is implemented by encoders that can react to network conditions.
type adaptiveQualityEncoder interface {
	EnableAdaptiveQuality(aqm *AdaptiveQualityManager)
}

type rtcSession struct {
	desktopID     string
	rtc           *DesktopWebRTC
	encoder       VPXEncoder
	targetFrameNs int64
	lastSent      int64
	codec         VPXCodec
	bitrate       int
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

func newRTCSession(desktopID string, rtc *DesktopWebRTC) (*rtcSession, error) {
	codec := VPXCodec(strings.ToLower(strings.TrimSpace(os.Getenv(envWebRTCCodec))))
	if codec == "" {
		codec = VPXCodec(webRTCDefaultCodec)
	}
	bitrate := parseEnvInt(envWebRTCBitrate, webRTCDefaultBR)
	fps := parseEnvInt(envWebRTCFPS, webRTCDefaultFPS)
	if fps <= 0 {
		fps = webRTCDefaultFPS
	}
	encoder, err := NewVPXEncoder(codec, VPXEncoderConfig{
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
		codec:         codec,
		bitrate:       bitrate,
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
	sample, err := r.encoder.Encode(img, interval)
	if err != nil {
		return err
	}
	if err := r.rtc.SendFrame(sample.Data, sample.Duration); err != nil {
		return err
	}
	atomic.StoreInt64(&r.lastSent, now)
	return nil
}

// handleRTCInput parses data channel payloads and forwards to the existing injector.
func handleRTCInput(desktopID string, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxInputPayload {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}
	sess, ok := sessions.Get(desktopID)
	if !ok || sess.escape.Load() {
		return errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	}
	if !sess.allowControl.Load() {
		return errInputUnsupported
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		return err
	}
	events, ok := body[`events`]
	if !ok {
		return errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	}
	if slice, ok := events.([]any); ok && len(slice) > inputBatchLimit {
		body[`events`] = slice[:inputBatchLimit]
	}
	pack := modules.Packet{
		Act: `DESKTOP_INPUT`,
		Data: map[string]any{
			`desktop`:      desktopID,
			`events`:       body[`events`],
			`allowControl`: sess.allowControl.Load(),
		},
	}
	return HandleInput(pack)
}
