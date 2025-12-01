package desktop

import (
	"errors"
	"image"
	"os"
	"strings"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	envICEList  = "SPARK_WEBRTC_ICE"
	envStunList = "SPARK_WEBRTC_STUN"
	envTurnList = "SPARK_WEBRTC_TURN"
	envTurnUser = "SPARK_WEBRTC_TURN_USERNAME"
	envTurnPass = "SPARK_WEBRTC_TURN_PASSWORD"
)

var defaultICEURLs = []string{
	"stun:stun.l.google.com:19302",
	"stun:stun.cloudflare.com:3478",
}

// ErrVPXUnavailable is returned when the VPX encoder was not built into the binary.
var ErrVPXUnavailable = errors.New("vpx encoder not built (enable cgo, install libvpx, and build with -tags vpx)")

// DesktopWebRTC mirrors the JPEG cadence by emitting samples on a video track and
// reuses the DESKTOP_INPUT data channel for input forwarding.
type DesktopWebRTC struct {
	peer        *webrtc.PeerConnection
	videoTrack  *webrtc.TrackLocalStaticSample
	inputDC     *webrtc.DataChannel
	onState     func(webrtc.PeerConnectionState)
	onICE       func(*webrtc.ICECandidate)
	onInputData func([]byte)
}

type WebRTCConfig struct {
	Configuration webrtc.Configuration
	Codec         VPXCodec // VP8 or VP9, defaults to VP8
	OnState       func(webrtc.PeerConnectionState)
	OnICE         func(*webrtc.ICECandidate)
	OnInputData   func([]byte)
}

type VPXCodec string

const (
	VPXCodecVP8 VPXCodec = "vp8"
	VPXCodecVP9 VPXCodec = "vp9"
)

// VPXEncoderConfig carries optional quality settings for VP8/VP9.
type VPXEncoderConfig struct {
	BitRate          int // bits per second; defaults to ~900kbps when zero
	KeyFrameInterval int // keyframe interval in frames; defaults to 60 when zero
}

// VPXEncoder encodes RGBA frames into WebRTC-ready samples (VP8/VP9).
type VPXEncoder interface {
	Encode(img *image.RGBA, duration time.Duration) (media.Sample, error)
	Close() error
}

// NewDesktopWebRTC builds a peer connection and data channel using the supplied
// config. If no ICEServers are provided, SPARK_WEBRTC_* env vars are applied.
func NewDesktopWebRTC(cfg WebRTCConfig) (*DesktopWebRTC, error) {
	cfg.Configuration = applyICEFromEnv(cfg.Configuration)

	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}
	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		return nil, err
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i))
	pc, err := api.NewPeerConnection(cfg.Configuration)
	if err != nil {
		return nil, err
	}

	// Use configured codec, default to VP8
	mimeType := webrtc.MimeTypeVP8
	if cfg.Codec == VPXCodecVP9 {
		mimeType = webrtc.MimeTypeVP9
	}

	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: mimeType},
		"screen",
		"rocket-desktop",
	)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if _, err = pc.AddTrack(videoTrack); err != nil {
		pc.Close()
		return nil, err
	}

	inputDC, err := pc.CreateDataChannel("desktop-input", nil)
	if err != nil {
		pc.Close()
		return nil, err
	}

	w := &DesktopWebRTC{
		peer:        pc,
		videoTrack:  videoTrack,
		inputDC:     inputDC,
		onState:     cfg.OnState,
		onICE:       cfg.OnICE,
		onInputData: cfg.OnInputData,
	}
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		if cfg.OnICE != nil {
			cfg.OnICE(c)
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if cfg.OnState != nil {
			cfg.OnState(state)
		}
	})
	inputDC.OnMessage(func(msg webrtc.DataChannelMessage) {
		if cfg.OnInputData != nil {
			cfg.OnInputData(msg.Data)
		}
	})
	return w, nil
}

func (w *DesktopWebRTC) CreateOffer() (*webrtc.SessionDescription, error) {
	if w == nil || w.peer == nil {
		return nil, errors.New("webrtc not initialized")
	}
	offer, err := w.peer.CreateOffer(nil)
	if err != nil {
		return nil, err
	}
	if err := w.peer.SetLocalDescription(offer); err != nil {
		return nil, err
	}
	return &offer, nil
}

func (w *DesktopWebRTC) CreateAnswer() (*webrtc.SessionDescription, error) {
	if w == nil || w.peer == nil {
		return nil, errors.New("webrtc not initialized")
	}
	answer, err := w.peer.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}
	if err := w.peer.SetLocalDescription(answer); err != nil {
		return nil, err
	}
	return &answer, nil
}

func (w *DesktopWebRTC) SetRemoteDescription(desc webrtc.SessionDescription) error {
	if w == nil || w.peer == nil {
		return errors.New("webrtc not initialized")
	}
	return w.peer.SetRemoteDescription(desc)
}

func (w *DesktopWebRTC) AddICECandidate(candidate webrtc.ICECandidateInit) error {
	if w == nil || w.peer == nil {
		return errors.New("webrtc not initialized")
	}
	return w.peer.AddICECandidate(candidate)
}

// SendFrame mirrors the JPEG cadence: duration should reflect the capture interval.
func (w *DesktopWebRTC) SendFrame(frame []byte, d time.Duration) error {
	if w == nil || w.videoTrack == nil {
		return errors.New("webrtc not initialized")
	}
	return w.videoTrack.WriteSample(media.Sample{Data: frame, Duration: d})
}

func (w *DesktopWebRTC) SendInput(payload []byte) error {
	if w == nil || w.inputDC == nil {
		return errors.New("webrtc not initialized")
	}
	if w.inputDC.ReadyState() != webrtc.DataChannelStateOpen {
		return errors.New("input channel not open")
	}
	return w.inputDC.Send(payload)
}

// AddTrack allows callers to attach additional media tracks (webcam/audio).
func (w *DesktopWebRTC) AddTrack(track webrtc.TrackLocal) (*webrtc.RTPSender, error) {
	if w == nil || w.peer == nil {
		return nil, errors.New("webrtc not initialized")
	}
	return w.peer.AddTrack(track)
}

func (w *DesktopWebRTC) Close() error {
	if w == nil || w.peer == nil {
		return nil
	}
	return w.peer.Close()
}

// applyICEFromEnv injects ICE servers from env vars when none are present.
func applyICEFromEnv(cfg webrtc.Configuration) webrtc.Configuration {
	if len(cfg.ICEServers) == 0 {
		cfg.ICEServers = loadICEServersFromEnv()
	}
	return cfg
}

// loadICEServersFromEnv reads SPARK_WEBRTC_ICE (url|user|pass), then
// SPARK_WEBRTC_STUN and SPARK_WEBRTC_TURN with optional username/password.
func loadICEServersFromEnv() []webrtc.ICEServer {
	if servers := parseICEOverride(os.Getenv(envICEList)); len(servers) > 0 {
		return servers
	}

	servers := make([]webrtc.ICEServer, 0, 4)
	stunURLs := splitICEList(os.Getenv(envStunList))
	if len(stunURLs) == 0 {
		stunURLs = defaultICEURLs
	}
	for _, url := range stunURLs {
		if url == "" {
			continue
		}
		servers = append(servers, webrtc.ICEServer{URLs: []string{url}})
	}

	turnURLs := splitICEList(os.Getenv(envTurnList))
	if len(turnURLs) == 0 {
		return servers
	}

	username := strings.TrimSpace(os.Getenv(envTurnUser))
	credential := strings.TrimSpace(os.Getenv(envTurnPass))
	for _, url := range turnURLs {
		if url == "" {
			continue
		}
		server := webrtc.ICEServer{URLs: []string{url}}
		if username != "" || credential != "" {
			server.Username = username
			server.Credential = credential
		}
		servers = append(servers, server)
	}
	return servers
}

// parseICEOverride accepts comma/semicolon/whitespace separated entries in the
// form url|username|password so a single env var can define mixed STUN/TURN.
func parseICEOverride(raw string) []webrtc.ICEServer {
	entries := splitICEList(raw)
	servers := make([]webrtc.ICEServer, 0, len(entries))
	for _, entry := range entries {
		parts := strings.SplitN(entry, "|", 3)
		url := strings.TrimSpace(parts[0])
		if url == "" {
			continue
		}
		server := webrtc.ICEServer{URLs: []string{url}}
		if len(parts) > 1 {
			server.Username = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			server.Credential = strings.TrimSpace(parts[2])
		}
		servers = append(servers, server)
	}
	return servers
}

func splitICEList(raw string) []string {
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		switch r {
		case ',', ';', '\n', '\r', '\t':
			return true
		default:
			return false
		}
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}
