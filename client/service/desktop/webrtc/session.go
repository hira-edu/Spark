package webrtc

import (
	"Spark/client/service/desktop/encoder"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
)

// Session wraps a pion PeerConnection plus book-keeping we need for desktop streaming.
type Session struct {
	desktopID string
	eventID   string
	pc        *webrtc.PeerConnection
	sender    signalSender
	createdAt time.Time

	mu     sync.Mutex
	closed bool
	dc     *webrtc.DataChannel
	video  *webrtc.TrackLocalStaticSample
	stats  *transportMetrics
}

var ErrDataChannelUnavailable = errors.New("webrtc: diff data channel unavailable")
var ErrVideoTrackUnavailable = errors.New("webrtc: video track unavailable")

// NewSession constructs a session with the supplied configuration and signal sender.
func NewSession(desktopID, eventID string, cfg webrtc.Configuration, sender signalSender, enableVideo bool) (*Session, error) {
	pc, err := webrtc.NewPeerConnection(cfg)
	if err != nil {
		return nil, err
	}
	session := &Session{
		desktopID: desktopID,
		eventID:   eventID,
		pc:        pc,
		sender:    sender,
		createdAt: time.Now(),
		stats:     newTransportMetrics(),
	}
	// Ensure we advertise video send capability even before media plumbing lands.
	if err := session.prepareTransceivers(); err != nil {
		pc.Close()
		return nil, err
	}
	if err := session.initDataChannel(); err != nil {
		pc.Close()
		return nil, err
	}
	if enableVideo {
		if err := session.initVideoTrack(); err != nil {
			logger.Warnf("webrtc video track unavailable desktop=%s: %v", desktopID, err)
		}
	}
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		payload := map[string]any{
			"candidate": init.Candidate,
		}
		if init.SDPMid != nil {
			payload["sdpMid"] = *init.SDPMid
		}
		if init.SDPMLineIndex != nil {
			payload["sdpMLineIndex"] = *init.SDPMLineIndex
		}
		if err := session.sendSignal(SignalCandidate, payload); err != nil {
			logger.Debugf("failed to emit ICE candidate desktop=%s: %v", desktopID, err)
		}
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		switch state {
		case webrtc.PeerConnectionStateDisconnected, webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
			session.Close()
		}
	})
	return session, nil
}

func (s *Session) prepareTransceivers() error {
	_, err := s.pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendonly,
	})
	return err
}

func (s *Session) initDataChannel() error {
	channel, err := s.pc.CreateDataChannel("spark-diff", nil)
	if err != nil {
		return err
	}
	s.dc = channel
	channel.OnOpen(func() {
		logger.Infof("webrtc data channel open desktop=%s", s.desktopID)
	})
	channel.OnClose(func() {
		logger.Infof("webrtc data channel closed desktop=%s", s.desktopID)
	})
	channel.OnError(func(err error) {
		if err != nil {
			logger.Warnf("webrtc data channel error desktop=%s: %v", s.desktopID, err)
		}
	})
	return nil
}

func (s *Session) initVideoTrack() error {
	if s == nil {
		return fmt.Errorf("nil session")
	}
	track, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{
		MimeType: webrtc.MimeTypeH264,
	}, "spark-video", s.desktopID)
	if err != nil {
		return err
	}
	rtpSender, err := s.pc.AddTrack(track)
	if err != nil {
		return err
	}
	go func() {
		rtcpBuf := make([]byte, 1500)
		for {
			if _, _, rtcpErr := rtpSender.Read(rtcpBuf); rtcpErr != nil {
				return
			}
		}
	}()
	s.video = track
	return nil
}

// AcceptOffer applies the remote SDP offer, generates an answer, and emits it via the sender.
func (s *Session) AcceptOffer(payload map[string]any) error {
	if s == nil {
		return fmt.Errorf("nil session")
	}
	desc, err := decodeSessionDescription(payload)
	if err != nil {
		return err
	}
	if desc.Type != webrtc.SDPTypeOffer {
		return fmt.Errorf("expected offer, got %s", desc.Type.String())
	}
	if err := s.pc.SetRemoteDescription(desc); err != nil {
		return err
	}
	answer, err := s.pc.CreateAnswer(nil)
	if err != nil {
		return err
	}
	gatherComplete := webrtc.GatheringCompletePromise(s.pc)
	if err := s.pc.SetLocalDescription(answer); err != nil {
		return err
	}
	<-gatherComplete
	local := s.pc.LocalDescription()
	if local == nil {
		return fmt.Errorf("missing local description")
	}
	payload = map[string]any{
		"type": local.Type.String(),
		"sdp":  local.SDP,
	}
	return s.sendSignal(SignalAnswer, payload)
}

// AddRemoteCandidate appends an ICE candidate provided by the browser/server.
func (s *Session) AddRemoteCandidate(payload map[string]any) error {
	if s == nil {
		return fmt.Errorf("nil session")
	}
	if payload == nil {
		return fmt.Errorf("missing candidate payload")
	}
	init := webrtc.ICECandidateInit{}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(bytes, &init); err != nil {
		return err
	}
	return s.pc.AddICECandidate(init)
}

// Close tears down the peer connection (idempotent).
func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	pc := s.pc
	if s.dc != nil {
		_ = s.dc.Close()
		s.dc = nil
	}
	s.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (s *Session) sendSignal(kind SignalKind, payload map[string]any) error {
	if s == nil || s.sender == nil {
		return fmt.Errorf("signal sender unavailable")
	}
	return s.sender(kind, payload)
}

// SendDiffFrame transmits a frame over the WebRTC data channel (best-effort).
func (s *Session) SendDiffFrame(payload []byte) error {
	if s == nil {
		return ErrDataChannelUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.dc == nil || s.dc.ReadyState() != webrtc.DataChannelStateOpen {
		return ErrDataChannelUnavailable
	}
	if len(payload) == 0 {
		return nil
	}
	if err := s.dc.Send(payload); err != nil {
		if s.stats != nil {
			s.stats.recordDataDrop(err)
		}
		return err
	}
	if s.stats != nil {
		s.stats.recordDataBytes(len(payload))
	}
	return nil
}

// SendVideoSample writes an encoded video sample to the WebRTC track.
func (s *Session) SendVideoSample(sample encoder.VideoSample) error {
	if s == nil {
		return ErrVideoTrackUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.video == nil {
		return ErrVideoTrackUnavailable
	}
	if len(sample.Data) == 0 {
		return nil
	}
	err := s.video.WriteSample(media.Sample{
		Data:     sample.Data,
		Duration: sample.Duration,
	})
	if err != nil {
		if s.stats != nil {
			s.stats.recordVideoDrop(err)
		}
		return err
	}
	if s.stats != nil {
		s.stats.recordVideoSample(len(sample.Data), sample.Keyframe)
	}
	return nil
}

func decodeSessionDescription(payload map[string]any) (webrtc.SessionDescription, error) {
	if payload == nil {
		return webrtc.SessionDescription{}, fmt.Errorf("missing SDP payload")
	}
	bytes, err := json.Marshal(payload)
	if err != nil {
		return webrtc.SessionDescription{}, err
	}
	var desc webrtc.SessionDescription
	if err := json.Unmarshal(bytes, &desc); err != nil {
		return webrtc.SessionDescription{}, err
	}
	if strings.TrimSpace(desc.SDP) == "" {
		return webrtc.SessionDescription{}, fmt.Errorf("empty SDP")
	}
	return desc, nil
}

type transportMetrics struct {
	sync.Mutex
	dataBytes    uint64
	dataDrops    uint64
	videoBytes   uint64
	videoFrames  uint64
	videoKey     uint64
	videoDrops   uint64
	lastError    string
	intervalBase time.Time
}

type Metrics struct {
	IntervalMs     int64  `json:"intervalMs"`
	Timestamp      int64  `json:"timestamp"`
	State          string `json:"state"`
	DataBytes      uint64 `json:"dataBytes"`
	DataDrops      uint64 `json:"dataDrops"`
	VideoBytes     uint64 `json:"videoBytes"`
	VideoFrames    uint64 `json:"videoFrames"`
	VideoKeyframes uint64 `json:"videoKeyframes"`
	VideoDrops     uint64 `json:"videoDrops"`
	LastError      string `json:"lastError,omitempty"`
}

func newTransportMetrics() *transportMetrics {
	return &transportMetrics{
		intervalBase: time.Now(),
	}
}

func (m *transportMetrics) recordDataBytes(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.Lock()
	m.dataBytes += uint64(n)
	m.Unlock()
}

func (m *transportMetrics) recordVideoSample(size int, keyframe bool) {
	if m == nil || size <= 0 {
		return
	}
	m.Lock()
	m.videoBytes += uint64(size)
	m.videoFrames++
	if keyframe {
		m.videoKey++
	}
	m.Unlock()
}

func (m *transportMetrics) recordDataDrop(err error) {
	if m == nil {
		return
	}
	m.Lock()
	m.dataDrops++
	if err != nil {
		m.lastError = err.Error()
	}
	m.Unlock()
}

func (m *transportMetrics) recordVideoDrop(err error) {
	if m == nil {
		return
	}
	m.Lock()
	m.videoDrops++
	if err != nil {
		m.lastError = err.Error()
	}
	m.Unlock()
}

func (m *transportMetrics) snapshot(state string) (Metrics, bool) {
	if m == nil {
		return Metrics{}, false
	}
	m.Lock()
	defer m.Unlock()
	now := time.Now()
	interval := now.Sub(m.intervalBase)
	if interval <= 0 {
		interval = time.Second
	}
	stats := Metrics{
		IntervalMs:     interval.Milliseconds(),
		Timestamp:      now.UnixMilli(),
		State:          state,
		DataBytes:      m.dataBytes,
		DataDrops:      m.dataDrops,
		VideoBytes:     m.videoBytes,
		VideoFrames:    m.videoFrames,
		VideoKeyframes: m.videoKey,
		VideoDrops:     m.videoDrops,
		LastError:      m.lastError,
	}
	m.dataBytes = 0
	m.dataDrops = 0
	m.videoBytes = 0
	m.videoFrames = 0
	m.videoKey = 0
	m.videoDrops = 0
	m.lastError = ""
	m.intervalBase = now
	hasActivity := stats.DataBytes > 0 ||
		stats.DataDrops > 0 ||
		stats.VideoBytes > 0 ||
		stats.VideoFrames > 0 ||
		stats.VideoDrops > 0 ||
		stats.LastError != ""
	if !hasActivity {
		return stats, false
	}
	return stats, true
}

func (s *Session) snapshotMetrics() (Metrics, bool) {
	if s == nil || s.stats == nil {
		return Metrics{}, false
	}
	state := "closed"
	if s.dc != nil {
		state = s.dc.ReadyState().String()
	} else if s.video != nil {
		state = "video"
	}
	return s.stats.snapshot(state)
}
