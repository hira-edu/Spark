//go:build mediasrc
// +build mediasrc

package desktop

import (
	"time"

	"github.com/pion/mediadevices"
	"github.com/pion/mediadevices/pkg/codec"
	"github.com/pion/mediadevices/pkg/codec/opus"
	"github.com/pion/mediadevices/pkg/codec/vpx"
	"github.com/pion/mediadevices/pkg/prop"
	"github.com/pion/webrtc/v4"
)

// Media capture using mediadevices (requires platform drivers, cgo).
// Import drivers for the target OS (e.g., avfoundation on macOS).
import (
	_ "github.com/pion/mediadevices/pkg/driver/avfoundation"
	_ "github.com/pion/mediadevices/pkg/driver/videotest"
)

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
			c.Width = prop.Int(640)
			c.Height = prop.Int(480)
			c.FrameRate = prop.Float(15)
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
			c.SampleRate = prop.Int(48000)
			c.ChannelCount = prop.Int(1)
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
		// give a small delay to flush buffered audio
		time.Sleep(30 * time.Millisecond)
		stream.Close()
	}, nil
}
