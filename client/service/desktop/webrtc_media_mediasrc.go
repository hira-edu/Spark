//go:build mediasrc
// +build mediasrc

package desktop

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/mediadevices"
	"github.com/pion/mediadevices/pkg/codec"
	"github.com/pion/mediadevices/pkg/codec/opus"
	"github.com/pion/mediadevices/pkg/codec/vpx"
	"github.com/pion/mediadevices/pkg/prop"
	"github.com/pion/webrtc/v4"
)

// startWebcamTrack captures a real camera using mediadevices (requires platform drivers in the build).
func startWebcamTrack(rtc *DesktopWebRTC) (func(), error) {
	if rtc == nil {
		return func() {}, nil
	}
	vp8, err := vpx.NewVP8Params()
	if err != nil {
		return nil, err
	}
	vp8.BitRate = 800_000
	vp8.KeyFrameInterval = 60
	stream, err := mediadevices.GetUserMedia(mediadevices.MediaStreamConstraints{
		Video: func(c *mediadevices.MediaTrackConstraints) {
			if id := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_VIDEO_DEVICE")); id != "" {
				c.DeviceID = prop.String(id)
			}
			if w := parseIntEnv("SPARK_WEBRTC_VIDEO_WIDTH"); w > 0 {
				c.Width = prop.Int(w)
			}
			if h := parseIntEnv("SPARK_WEBRTC_VIDEO_HEIGHT"); h > 0 {
				c.Height = prop.Int(h)
			}
			if fps := parseIntEnv("SPARK_WEBRTC_VIDEO_FPS"); fps > 0 {
				c.FrameRate = prop.Float(float64(fps))
			} else {
				c.FrameRate = prop.Float(15)
			}
		},
		Codec: []codec.Matcher{
			&codec.VideoMatcher{Video: &vp8.Params.Codec, Score: 10},
		},
	})
	if err != nil {
		return nil, err
	}
	videos := stream.GetVideoTracks()
	if len(videos) == 0 {
		stream.Close()
		return func() {}, nil
	}
	if _, err := rtc.peer.AddTransceiverFromTrack(videos[0], webrtc.RtpTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream.Close, nil
}

// startAudioTrack captures microphone audio using mediadevices (requires platform drivers in the build).
func startAudioTrack(rtc *DesktopWebRTC) (func(), error) {
	if rtc == nil {
		return func() {}, nil
	}
	opusParams, err := opus.NewParams()
	if err != nil {
		return nil, err
	}
	opusParams.BitRate = 48_000
	stream, err := mediadevices.GetUserMedia(mediadevices.MediaStreamConstraints{
		Audio: func(c *mediadevices.MediaTrackConstraints) {
			if id := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_AUDIO_DEVICE")); id != "" {
				c.DeviceID = prop.String(id)
			}
			c.ChannelCount = prop.Int(1)
			c.SampleRate = prop.Int(48000)
		},
		Codec: []codec.Matcher{
			&codec.AudioMatcher{Audio: &opusParams.Codec, Score: 10},
		},
	})
	if err != nil {
		return nil, err
	}
	audios := stream.GetAudioTracks()
	if len(audios) == 0 {
		stream.Close()
		return func() {}, nil
	}
	if _, err := rtc.peer.AddTransceiverFromTrack(audios[0], webrtc.RtpTransceiverInit{Direction: webrtc.RTPTransceiverDirectionSendonly}); err != nil {
		stream.Close()
		return nil, err
	}
	return func() {
		time.Sleep(30 * time.Millisecond)
		stream.Close()
	}, nil
}

func parseIntEnv(name string) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	if v, err := strconv.Atoi(raw); err == nil && v > 0 {
		return v
	}
	return 0
}
