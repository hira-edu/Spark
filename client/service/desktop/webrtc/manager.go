package webrtc

import (
	"Spark/client/service/desktop/encoder"
	"encoding/json"
	"fmt"
	"image"
	"os"
	"strings"
	"sync"

	"github.com/kataras/golog"
	"github.com/pion/webrtc/v3"
)

// SignalKind enumerates the WebRTC signal payloads the agent understands.
type SignalKind string

const (
	SignalOffer     SignalKind = "offer"
	SignalAnswer    SignalKind = "answer"
	SignalCandidate SignalKind = "candidate"
)

var logger = golog.Child("[desktop-webrtc]")

type signalSender func(kind SignalKind, payload map[string]any) error

// Manager orchestrates per-desktop WebRTC sessions.
type Manager struct {
	mu        sync.Mutex
	sessions  map[string]*Session
	iceConfig webrtc.Configuration
	video     *videoPipeline
}

var (
	managerOnce sync.Once
	managerInst *Manager
)

// Instance returns the singleton manager.
func Instance() *Manager {
	managerOnce.Do(func() {
		var video *videoPipeline
		if videoStreamingEnabled() && videoEncoderAvailable(defaultVideoEncoderName) {
			video = newVideoPipeline()
		}
		managerInst = &Manager{
			sessions: make(map[string]*Session),
			iceConfig: webrtc.Configuration{
				ICEServers: loadICEServers(),
			},
			video: video,
		}
		if video != nil {
			video.start(managerInst)
		}
	})
	return managerInst
}

// HandleSignal routes signalling messages (offer, candidate) to the correct session.
func (m *Manager) HandleSignal(desktopID, eventID string, kind SignalKind, payload map[string]any, sender signalSender) error {
	if m == nil {
		return fmt.Errorf("webrtc manager not initialized")
	}
	if desktopID == "" {
		return fmt.Errorf("missing desktop id")
	}
	switch kind {
	case SignalOffer:
		return m.handleOffer(desktopID, eventID, payload, sender)
	case SignalCandidate:
		return m.handleCandidate(desktopID, payload)
	default:
		return fmt.Errorf("unsupported WebRTC signal %q", kind)
	}
}

func (m *Manager) handleOffer(desktopID, eventID string, payload map[string]any, sender signalSender) error {
	if sender == nil {
		return fmt.Errorf("missing signal sender")
	}
	session, err := NewSession(desktopID, eventID, m.iceConfig, sender, m.videoEnabled())
	if err != nil {
		return err
	}
	if err := session.AcceptOffer(payload); err != nil {
		session.Close()
		return err
	}
	m.mu.Lock()
	if existing, ok := m.sessions[desktopID]; ok && existing != nil {
		existing.Close()
	}
	m.sessions[desktopID] = session
	m.mu.Unlock()
	logger.Infof("webrtc session established desktop=%s", desktopID)
	return nil
}

func (m *Manager) handleCandidate(desktopID string, payload map[string]any) error {
	m.mu.Lock()
	session := m.sessions[desktopID]
	m.mu.Unlock()
	if session == nil {
		return fmt.Errorf("no active WebRTC session for desktop %s", desktopID)
	}
	return session.AddRemoteCandidate(payload)
}

// CloseSession tears down the session associated with the given desktop.
func (m *Manager) CloseSession(desktopID string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	session := m.sessions[desktopID]
	delete(m.sessions, desktopID)
	m.mu.Unlock()
	if session != nil {
		session.Close()
		logger.Infof("webrtc session closed desktop=%s", desktopID)
	}
}

// CloseAll tears down every active session.
func (m *Manager) CloseAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for key, session := range m.sessions {
		if session != nil {
			sessions = append(sessions, session)
		}
		delete(m.sessions, key)
	}
	m.mu.Unlock()
	for _, session := range sessions {
		session.Close()
	}
}

// SendDiffFrame forwards a diff/JPEG payload over the session data channel.
func (m *Manager) SendDiffFrame(desktopID string, payload []byte) error {
	if m == nil {
		return ErrDataChannelUnavailable
	}
	m.mu.Lock()
	session := m.sessions[desktopID]
	m.mu.Unlock()
	if session == nil {
		return ErrDataChannelUnavailable
	}
	return session.SendDiffFrame(payload)
}

// Configuration exposes the ICE/TURN configuration used by the manager.
func (m *Manager) Configuration() webrtc.Configuration {
	if m == nil {
		return webrtc.Configuration{}
	}
	return m.iceConfig
}

// PublishFrame pushes a captured RGBA frame into the video pipeline.
func (m *Manager) PublishFrame(img *image.RGBA, fps int) {
	if m == nil || m.video == nil {
		return
	}
	m.video.submit(img, fps)
}

func (m *Manager) broadcastVideoSample(sample encoder.VideoSample) {
	if len(sample.Data) == 0 {
		return
	}
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		if session != nil {
			sessions = append(sessions, session)
		}
	}
	m.mu.Unlock()
	for _, session := range sessions {
		if err := session.SendVideoSample(sample); err != nil && err != ErrVideoTrackUnavailable {
			logger.Debugf("webrtc video sample drop desktop=%s: %v", session.desktopID, err)
		}
	}
}

func (m *Manager) videoEnabled() bool {
	return m != nil && m.video != nil
}

func loadICEServers() []webrtc.ICEServer {
	raw := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_ICE"))
	if raw == "" {
		return nil
	}
	var parsed []webrtc.ICEServer
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			return parsed
		} else {
			logger.Warnf("failed to parse SPARK_WEBRTC_ICE JSON: %v", err)
		}
	}
	parts := strings.Split(raw, ",")
	server := webrtc.ICEServer{
		URLs: filterEmpty(parts),
	}
	if user := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_ICE_USERNAME")); user != "" {
		server.Username = user
	}
	if cred := strings.TrimSpace(os.Getenv("SPARK_WEBRTC_ICE_CREDENTIAL")); cred != "" {
		server.Credential = cred
	}
	if len(server.URLs) == 0 {
		return nil
	}
	return []webrtc.ICEServer{server}
}

func filterEmpty(values []string) []string {
	result := make([]string, 0, len(values))
	for _, val := range values {
		val = strings.TrimSpace(val)
		if val != "" {
			result = append(result, val)
		}
	}
	return result
}

func videoStreamingEnabled() bool {
	return strings.EqualFold(os.Getenv("SPARK_EXPERIMENTAL_WEBRTC_ENCODERS"), "1")
}

func videoEncoderAvailable(name string) bool {
	caps := encoder.Instance().Capabilities()
	for _, cap := range caps {
		if strings.EqualFold(cap.Name, name) && !cap.Disabled {
			return true
		}
	}
	return false
}
