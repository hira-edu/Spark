package desktop

import (
	"Rocket/client/telemetry"
	"errors"
	"fmt"
	"image"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

const (
	envICEList      = "SPARK_WEBRTC_ICE"
	envStunList     = "SPARK_WEBRTC_STUN"
	envTurnList     = "SPARK_WEBRTC_TURN"
	envTurnUser     = "SPARK_WEBRTC_TURN_USERNAME"
	envTurnPass     = "SPARK_WEBRTC_TURN_PASSWORD"
	envICETransport = "SPARK_WEBRTC_ICE_TRANSPORT_POLICY" // "all", "relay" (force TURN)
	envNATType      = "SPARK_WEBRTC_NAT_TYPE"             // "symmetric", "cone", "auto"
)

// Default STUN servers - using multiple providers for redundancy (2025 best practice)
var defaultICEURLs = []string{
	// Google STUN (primary, most reliable)
	"stun:stun.l.google.com:19302",
	"stun:stun1.l.google.com:19302",
	// Cloudflare STUN (backup)
	"stun:stun.cloudflare.com:3478",
}

// Default TURN servers with multiple transports for symmetric NAT
// These should be configured via environment variables in production
var defaultTURNServers = []struct {
	urls []string
	note string
}{
	{
		urls: []string{
			"turn:turn.example.com:3478?transport=udp", // UDP (standard, lowest latency)
			"turn:turn.example.com:3478?transport=tcp", // TCP (for UDP-blocked networks)
			"turns:turn.example.com:443?transport=tcp", // TLS (for restrictive firewalls)
		},
		note: "Production TURN servers should be configured via SPARK_WEBRTC_TURN",
	},
}

// ErrVPXUnavailable is returned when the VPX encoder was not built into the binary.
var ErrVPXUnavailable = errors.New("vpx encoder not built (enable cgo, install libvpx, and build with -tags vpx)")
var ErrH264Unavailable = errors.New("h264 encoder not available on this platform")

// DesktopWebRTC mirrors the JPEG cadence by emitting samples on a video track and
// reuses the DESKTOP_INPUT data channel for input forwarding.
type DesktopWebRTC struct {
	peer              *webrtc.PeerConnection
	videoTrack        *webrtc.TrackLocalStaticSample
	inputDC           *webrtc.DataChannel
	onState           func(webrtc.PeerConnectionState)
	onICE             func(*webrtc.ICECandidate)
	onInputData       func([]byte)
	onICEStateChange  func(webrtc.ICEConnectionState)
	onSignalingChange func(webrtc.SignalingState)
	closed            atomic.Bool
	mu                sync.RWMutex // Protects concurrent access to peer, track, and inputDC
}

type WebRTCConfig struct {
	Configuration webrtc.Configuration
	Codec         WebRTCCodec // h264/vp8/vp9 (defaults chosen by caller)
	OnState       func(webrtc.PeerConnectionState)
	OnICE         func(*webrtc.ICECandidate)
	OnInputData   func([]byte)
	OnKeyFrame    func()
}

type WebRTCCodec string

const (
	WebRTCCodecH264 WebRTCCodec = "h264"
	WebRTCCodecVP8  WebRTCCodec = "vp8"
	WebRTCCodecVP9  WebRTCCodec = "vp9"
)

// WebRTCEncoderConfig carries optional quality settings for the selected codec.
type WebRTCEncoderConfig struct {
	BitRate          int // bits per second; defaults to ~900kbps when zero
	KeyFrameInterval int // keyframe interval in frames; defaults to 60 when zero
}

// WebRTCEncoder encodes RGBA frames into WebRTC-ready samples (H.264/VP8/VP9).
type WebRTCEncoder interface {
	Encode(img *image.RGBA, duration time.Duration) (media.Sample, error)
	Close() error
}

// NewDesktopWebRTC builds a peer connection and data channel using the supplied
// config. If no ICEServers are provided, SPARK_WEBRTC_* env vars are applied.
func NewDesktopWebRTC(cfg WebRTCConfig) (*DesktopWebRTC, error) {
	cfg.Configuration = applyICEFromEnv(cfg.Configuration)

	// Setup MediaEngine with VP8/VP9 codecs for video
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}

	// Setup Interceptor Registry for SRTP encryption and RTCP feedback
	// This automatically configures:
	// - SRTP (Secure RTP) with AES-128/256 encryption for media
	// - SRTCP (Secure RTCP) for control packets
	// - NACK (Negative Acknowledgment) for packet loss recovery
	// - TWCC (Transport-Wide Congestion Control) for adaptive bitrate
	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		return nil, err
	}

	// Configure ICE for best browser interoperability:
	// - Enable loopback candidates for same-host (localhost) WebRTC sessions.
	// - Allow querying remote mDNS candidates (Chromium's default behavior).
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryOnly)

	// Create API with MediaEngine and Interceptors
	api := webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(i),
		webrtc.WithSettingEngine(se),
	)

	// Create PeerConnection with ICE servers and security settings
	pc, err := api.NewPeerConnection(cfg.Configuration)
	if err != nil {
		return nil, err
	}

	// Use configured codec, default to VP8
	mimeType := webrtc.MimeTypeVP8
	codecCap := webrtc.RTPCodecCapability{
		MimeType: mimeType,
	}
	switch cfg.Codec {
	case WebRTCCodecVP9:
		mimeType = webrtc.MimeTypeVP9
		codecCap.MimeType = mimeType
	case WebRTCCodecH264:
		mimeType = webrtc.MimeTypeH264
		codecCap = webrtc.RTPCodecCapability{
			MimeType:     mimeType,
			ClockRate:    90000,
			SDPFmtpLine:  "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640028",
			RTCPFeedback: nil, // default interceptors add feedback
		}
	}

	// Create video track with optimized RTP codec capability.
	// NOTE: Don't call AddTrack here - we must wait until SetRemoteDescription
	// processes the browser's offer so we can bind to its recvonly transceiver.
	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		codecCap,
		"screen",
		"rocket-desktop",
	)
	if err != nil {
		pc.Close()
		return nil, err
	}

	w := &DesktopWebRTC{
		peer:        pc,
		videoTrack:  videoTrack,
		onState:     cfg.OnState,
		onICE:       cfg.OnICE,
		onInputData: cfg.OnInputData,
	}
	// ICE Candidate handler - fires when new candidates are discovered
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		if cfg.OnICE != nil {
			cfg.OnICE(c)
		}
	})

	// Connection State handler - monitors overall peer connection health
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if cfg.OnState != nil {
			cfg.OnState(state)
		}
		// Mark as closed when connection is closed or failed
		if state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateFailed {
			w.closed.Store(true)
		}
	})

	// ICE Connection State handler - provides more granular ICE-specific state
	// Critical for detecting network changes and triggering ICE restart
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		if w.onICEStateChange != nil {
			w.onICEStateChange(state)
		}
		// After 30s of no network activity, state becomes Failed
		// This is the trigger point for ICE restart
		if state == webrtc.ICEConnectionStateFailed && cfg.OnState != nil {
			cfg.OnState(webrtc.PeerConnectionStateFailed)
		}
	})

	// Signaling State handler - tracks negotiation progress
	pc.OnSignalingStateChange(func(state webrtc.SignalingState) {
		if w.onSignalingChange != nil {
			w.onSignalingChange(state)
		}
	})

	// ICE Gathering State handler - monitors candidate collection
	pc.OnICEGatheringStateChange(func(state webrtc.ICEGatheringState) {
		// Can be used to show "gathering" status to user
		// States: new, gathering, complete
	})

	// DataChannel negotiation: the offerer (browser) creates the DataChannel so the
	// offer SDP includes an m=application section. As the answerer, we only accept
	// incoming channels via OnDataChannel.
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc == nil {
			return
		}
		label := dc.Label()
		if label != "desktop-input" && label != "desktop-control" {
			return
		}
		w.mu.Lock()
		w.inputDC = dc
		w.mu.Unlock()

		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if cfg.OnInputData != nil {
				cfg.OnInputData(msg.Data)
			}
		})
		dc.OnError(func(err error) {
			if cfg.OnState != nil {
				cfg.OnState(webrtc.PeerConnectionStateFailed)
			}
		})
		dc.OnClose(func() {
			if cfg.OnState != nil {
				cfg.OnState(webrtc.PeerConnectionStateClosed)
			}
			w.mu.Lock()
			if w.inputDC == dc {
				w.inputDC = nil
			}
			w.mu.Unlock()
		})
	})
	return w, nil
}

// BindVideoTrack binds the video track to the peer connection AFTER SetRemoteDescription.
// This is necessary because the browser creates a recvonly transceiver in its offer,
// and we must bind our sendonly track to match that transceiver. Calling AddTrack
// before SetRemoteDescription creates a mismatched transceiver that the browser ignores.
// Returns the RTPSender for RTCP handling (PLI/FIR keyframe requests).
func (w *DesktopWebRTC) BindVideoTrack() (*webrtc.RTPSender, error) {
	if w == nil {
		return nil, errors.New("webrtc not initialized")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.peer == nil {
		return nil, errors.New("peer connection not initialized")
	}
	if w.videoTrack == nil {
		return nil, errors.New("video track not initialized")
	}

	// Log transceiver state for debugging
	transceivers := w.peer.GetTransceivers()
	fmt.Printf("[WebRTC] BindVideoTrack: found %d transceivers\n", len(transceivers))
	for i, t := range transceivers {
		dir := t.Direction()
		kind := t.Kind()
		sender := t.Sender()
		receiver := t.Receiver()
		fmt.Printf("[WebRTC] BindVideoTrack: transceiver[%d] kind=%v dir=%v sender=%v receiver=%v\n",
			i, kind, dir, sender != nil, receiver != nil)
	}

	// After SetRemoteDescription, the browser's recvonly transceiver exists but the
	// sender is nil until we add a track. Use AddTrack which will automatically
	// reuse the existing transceiver that matches the track's codec.
	//
	// Pion's AddTrack behavior after SetRemoteDescription:
	// - If an existing transceiver matches (same codec, direction compatible), reuses it
	// - Creates a sender on that transceiver
	// - The browser's recvonly transceiver becomes sendrecv or sendonly from our side
	fmt.Printf("[WebRTC] BindVideoTrack: calling AddTrack to bind video track\n")
	sender, err := w.peer.AddTrack(w.videoTrack)
	if err != nil {
		fmt.Printf("[WebRTC] BindVideoTrack: AddTrack failed: %v\n", err)
		return nil, err
	}
	fmt.Printf("[WebRTC] BindVideoTrack: AddTrack succeeded, sender=%v\n", sender != nil)

	// Log final transceiver state
	transceivers = w.peer.GetTransceivers()
	fmt.Printf("[WebRTC] BindVideoTrack: after AddTrack, found %d transceivers\n", len(transceivers))
	for i, t := range transceivers {
		dir := t.Direction()
		kind := t.Kind()
		s := t.Sender()
		r := t.Receiver()
		fmt.Printf("[WebRTC] BindVideoTrack: transceiver[%d] kind=%v dir=%v sender=%v receiver=%v\n",
			i, kind, dir, s != nil, r != nil)
	}

	return sender, nil
}

func (w *DesktopWebRTC) CreateOffer() (*webrtc.SessionDescription, error) {
	if w == nil {
		return nil, errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return nil, errors.New("webrtc already closed")
	}
	w.mu.RLock()
	peer := w.peer
	w.mu.RUnlock()
	if peer == nil {
		return nil, errors.New("peer connection not initialized")
	}
	// Wait for ICE gathering complete per WebRTC best practices
	gatherComplete := webrtc.GatheringCompletePromise(peer)
	offer, err := peer.CreateOffer(nil)
	if err != nil {
		return nil, err
	}
	if err := peer.SetLocalDescription(offer); err != nil {
		return nil, err
	}
	// Wait for all ICE candidates to be gathered before returning
	<-gatherComplete
	return peer.LocalDescription(), nil
}

func (w *DesktopWebRTC) CreateAnswer() (*webrtc.SessionDescription, error) {
	if w == nil {
		return nil, errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return nil, errors.New("webrtc already closed")
	}
	w.mu.RLock()
	peer := w.peer
	w.mu.RUnlock()
	if peer == nil {
		return nil, errors.New("peer connection not initialized")
	}
	// Wait for ICE gathering complete per WebRTC best practices
	gatherComplete := webrtc.GatheringCompletePromise(peer)
	answer, err := peer.CreateAnswer(nil)
	if err != nil {
		return nil, err
	}
	if err := peer.SetLocalDescription(answer); err != nil {
		return nil, err
	}
	// Wait for all ICE candidates to be gathered before returning
	<-gatherComplete
	return peer.LocalDescription(), nil
}

func (w *DesktopWebRTC) SetRemoteDescription(desc webrtc.SessionDescription) error {
	if w == nil {
		return errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return errors.New("webrtc already closed")
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.peer == nil {
		return errors.New("peer connection not initialized")
	}
	return w.peer.SetRemoteDescription(desc)
}

func (w *DesktopWebRTC) AddICECandidate(candidate webrtc.ICECandidateInit) error {
	if w == nil {
		return errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return errors.New("webrtc already closed")
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.peer == nil {
		return errors.New("peer connection not initialized")
	}
	return w.peer.AddICECandidate(candidate)
}

// SendFrame mirrors the JPEG cadence: duration should reflect the capture interval.
// SendFrame sends a video frame over RTP with automatic MTU-aware packetization.
// Pion WebRTC automatically fragments frames into RTP packets (max ~1200 bytes per RFC).
// Large frames are split into multiple RTP packets by the RTP packetizer.
// For best performance, keep encoded frames under 256KB to minimize packetization overhead.
func (w *DesktopWebRTC) SendFrame(frame []byte, d time.Duration) error {
	if w == nil {
		return errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return errors.New("webrtc already closed")
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.videoTrack == nil {
		return errors.New("video track not initialized")
	}

	// MTU Awareness (2025 best practice):
	// - Pion WebRTC automatically packetizes frames into ~1200 byte RTP packets
	// - Each RTP packet includes: IP header (20 bytes) + UDP header (8 bytes) + RTP header (12 bytes)
	// - Payload per packet: ~1200 - 12 = ~1188 bytes
	// - Large frames (e.g., 100KB) = ~84 RTP packets
	// - This avoids IP fragmentation which is unreliable on many networks
	//
	// For best performance:
	// - Keep frames under 256KB (already enforced by adaptive quality manager)
	// - Use VP8/VP9 temporal scalability for better packet loss recovery
	// - Monitor packet loss via RTCP feedback (handled by interceptors)

	// Warn if frame is excessively large (may cause burst congestion)
	if len(frame) > 512*1024 {
		// Log warning but don't fail - let RTP packetizer handle it
		// In production, this should trigger quality reduction
		telemetry.LogStructured("WARN", "webrtc: large frame may cause congestion", map[string]interface{}{
			"frame_size_kb":        len(frame) / 1024,
			"rtp_packets_estimate": (len(frame) + 1187) / 1188,
		})
	}

	return w.videoTrack.WriteSample(media.Sample{Data: frame, Duration: d})
}

func (w *DesktopWebRTC) SendInput(payload []byte) error {
	if w == nil {
		return errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return errors.New("webrtc already closed")
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.inputDC == nil {
		return errors.New("input data channel not initialized")
	}
	if w.inputDC.ReadyState() != webrtc.DataChannelStateOpen {
		return errors.New("input channel not open")
	}
	// Check backpressure before sending (WebRTC best practice)
	// Drop input if buffer > 256KB to prevent memory explosion
	const maxBufferedAmount = 256 * 1024
	if w.inputDC.BufferedAmount() > maxBufferedAmount {
		return errors.New("data channel congested, dropping input")
	}
	return w.inputDC.Send(payload)
}

// AddTrack allows callers to attach additional media tracks (webcam/audio).
func (w *DesktopWebRTC) AddTrack(track webrtc.TrackLocal) (*webrtc.RTPSender, error) {
	if w == nil {
		return nil, errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return nil, errors.New("webrtc already closed")
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.peer == nil {
		return nil, errors.New("peer connection not initialized")
	}
	return w.peer.AddTrack(track)
}

func (w *DesktopWebRTC) Close() error {
	if w == nil {
		return nil
	}
	// Use CAS to ensure Close() is called exactly once
	if !w.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.peer != nil {
		return w.peer.Close()
	}
	return nil
}

// RestartICE triggers ICE restart to recover from network changes
// Call this when ICEConnectionState becomes "failed"
// Note: In Pion, you must create a new offer with ICERestart option manually
func (w *DesktopWebRTC) RestartICE() (*webrtc.SessionDescription, error) {
	if w == nil {
		return nil, errors.New("webrtc not initialized")
	}
	if w.closed.Load() {
		return nil, errors.New("webrtc already closed")
	}
	w.mu.RLock()
	peer := w.peer
	w.mu.RUnlock()
	if peer == nil {
		return nil, errors.New("peer connection not initialized")
	}
	// Create new offer with ICERestart option
	gatherComplete := webrtc.GatheringCompletePromise(peer)
	offer, err := peer.CreateOffer(&webrtc.OfferOptions{
		ICERestart: true,
	})
	if err != nil {
		return nil, err
	}
	if err := peer.SetLocalDescription(offer); err != nil {
		return nil, err
	}
	<-gatherComplete
	return peer.LocalDescription(), nil
}

// ConnectionState returns the current peer connection state
func (w *DesktopWebRTC) ConnectionState() webrtc.PeerConnectionState {
	if w == nil || w.closed.Load() {
		return webrtc.PeerConnectionStateClosed
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.peer == nil {
		return webrtc.PeerConnectionStateClosed
	}
	return w.peer.ConnectionState()
}

// ICEConnectionState returns the current ICE connection state
func (w *DesktopWebRTC) ICEConnectionState() webrtc.ICEConnectionState {
	if w == nil || w.closed.Load() {
		return webrtc.ICEConnectionStateClosed
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.peer == nil {
		return webrtc.ICEConnectionStateClosed
	}
	return w.peer.ICEConnectionState()
}

// applyICEFromEnv injects ICE servers from env vars when none are present.
// Also applies ICE transport policy and NAT-aware settings (2025 best practices).
func applyICEFromEnv(cfg webrtc.Configuration) webrtc.Configuration {
	if len(cfg.ICEServers) == 0 {
		cfg.ICEServers = loadICEServersFromEnv()
	}

	// Apply ICE transport policy for symmetric NAT handling
	transportPolicy := strings.ToLower(strings.TrimSpace(os.Getenv(envICETransport)))
	switch transportPolicy {
	case "relay":
		// Force TURN relay (bypass STUN for symmetric NAT)
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	case "all", "":
		// Try all candidates (STUN + TURN) - default
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyAll
	}

	// Detect NAT type and adjust strategy
	natType := strings.ToLower(strings.TrimSpace(os.Getenv(envNATType)))
	if natType == "symmetric" || isSymmetricNATLikely(cfg.ICEServers) {
		// For symmetric NAT: prefer TURN and, if not forced by env, switch to relay-only
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
		cfg.ICEServers = preferTURNServers(cfg.ICEServers)
	}

	// Enable bundle policy (multiplex all media on single transport)
	// Reduces ICE candidates and improves connection time
	if cfg.BundlePolicy == 0 {
		cfg.BundlePolicy = webrtc.BundlePolicyMaxBundle
	}

	// Enable RTCP multiplexing (best practice for bandwidth efficiency)
	if cfg.RTCPMuxPolicy == 0 {
		cfg.RTCPMuxPolicy = webrtc.RTCPMuxPolicyRequire
	}

	return cfg
}

// isSymmetricNATLikely heuristically detects if TURN servers are heavily configured
// which often indicates symmetric NAT environment (corporate networks)
func isSymmetricNATLikely(servers []webrtc.ICEServer) bool {
	turnCount := 0
	stunCount := 0
	for _, server := range servers {
		for _, url := range server.URLs {
			if strings.HasPrefix(url, "turn:") || strings.HasPrefix(url, "turns:") {
				turnCount++
			} else if strings.HasPrefix(url, "stun:") {
				stunCount++
			}
		}
	}
	// If TURN servers outnumber STUN, assume symmetric NAT environment
	return turnCount > stunCount
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

// preferTURNServers moves TURN/TURNS URLs ahead of STUN entries to improve relay preference.
func preferTURNServers(servers []webrtc.ICEServer) []webrtc.ICEServer {
	if len(servers) == 0 {
		return servers
	}

	turn := make([]webrtc.ICEServer, 0, len(servers))
	stun := make([]webrtc.ICEServer, 0, len(servers))
	for _, s := range servers {
		isTurn := false
		for _, url := range s.URLs {
			if strings.HasPrefix(url, "turn:") || strings.HasPrefix(url, "turns:") {
				isTurn = true
				break
			}
		}
		if isTurn {
			turn = append(turn, s)
		} else {
			stun = append(stun, s)
		}
	}
	return append(turn, stun...)
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
