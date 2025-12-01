//go:build !mediasrc
// +build !mediasrc

package desktop

import (
	"image"
	"image/color"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

// startWebcamTrack attaches a synthetic webcam track (solid frame) to the WebRTC session.
func startWebcamTrack(rtc *DesktopWebRTC) (func(), error) {
	if rtc == nil {
		return func() {}, nil
	}
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"webcam",
		"rocket-webcam",
	)
	if err != nil {
		return nil, err
	}
	sender, err := rtc.AddTrack(track)
	if err != nil {
		return nil, err
	}

	enc, err := NewVPXEncoder(VPXCodecVP8, VPXEncoderConfig{
		BitRate:          400_000,
		KeyFrameInterval: 60,
	})
	if err != nil {
		return nil, err
	}

	stop := make(chan struct{})
	go func() {
		defer enc.Close()
		defer sender.Stop()
		img := image.NewRGBA(image.Rect(0, 0, 320, 240))
		fill(img, color.RGBA{R: 32, G: 32, B: 32, A: 255})
		ticker := time.NewTicker(time.Second / 5) // ~5 fps
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sample, err := enc.Encode(img, time.Second/5)
				if err == nil {
					_ = track.WriteSample(sample)
				}
			case <-stop:
				return
			}
		}
	}()

	return func() { close(stop) }, nil
}

// startAudioTrack attaches a PCMU silence track to the WebRTC session.
func startAudioTrack(rtc *DesktopWebRTC) (func(), error) {
	if rtc == nil {
		return func() {}, nil
	}
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypePCMU, ClockRate: 8000, Channels: 1},
		"audio",
		"rocket-audio",
	)
	if err != nil {
		return nil, err
	}
	sender, err := rtc.AddTrack(track)
	if err != nil {
		return nil, err
	}

	stop := make(chan struct{})
	go func() {
		defer sender.Stop()
		silence := make([]byte, 160) // 20ms @8kHz PCMU
		for i := range silence {
			silence[i] = 0xFF
		}
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = track.WriteSample(media.Sample{
					Data:     silence,
					Duration: 20 * time.Millisecond,
				})
			case <-stop:
				return
			}
		}
	}()

	return func() { close(stop) }, nil
}

func fill(img *image.RGBA, c color.RGBA) {
	buf := img.Pix
	for i := 0; i < len(buf); i += 4 {
		buf[i] = c.R
		buf[i+1] = c.G
		buf[i+2] = c.B
		buf[i+3] = c.A
	}
}
