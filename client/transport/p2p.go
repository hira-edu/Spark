package transport

import (
	"Rocket/client/common"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// P2P Metrics - Tracks success rates for P2P vs Relay connections
// ============================================================================

// p2pMetrics tracks P2P connection statistics
type p2pMetrics struct {
	// P2P direct connection stats
	p2pAttempts  uint64
	p2pSuccesses uint64
	p2pFailures  uint64

	// Relay fallback stats
	relayFallbacks uint64
	relaySuccesses uint64
	relayFailures  uint64

	// Timing stats (in milliseconds)
	totalP2PConnectTime   uint64
	totalRelayConnectTime uint64

	// NAT type distribution
	natTypeCounts sync.Map // NATType -> count
}

// P2PMetrics is the global metrics instance
var P2PMetrics = &p2pMetrics{}

// RecordP2PAttempt records a P2P connection attempt
func (m *p2pMetrics) RecordP2PAttempt() {
	atomic.AddUint64(&m.p2pAttempts, 1)
}

// RecordP2PSuccess records a successful P2P connection
func (m *p2pMetrics) RecordP2PSuccess(duration time.Duration) {
	atomic.AddUint64(&m.p2pSuccesses, 1)
	atomic.AddUint64(&m.totalP2PConnectTime, uint64(duration.Milliseconds()))
}

// RecordP2PFailure records a failed P2P connection
func (m *p2pMetrics) RecordP2PFailure() {
	atomic.AddUint64(&m.p2pFailures, 1)
}

// RecordRelayFallback records when relay fallback is triggered
func (m *p2pMetrics) RecordRelayFallback() {
	atomic.AddUint64(&m.relayFallbacks, 1)
}

// RecordRelaySuccess records a successful relay connection
func (m *p2pMetrics) RecordRelaySuccess() {
	atomic.AddUint64(&m.relaySuccesses, 1)
}

// RecordRelayFailure records a failed relay connection
func (m *p2pMetrics) RecordRelayFailure() {
	atomic.AddUint64(&m.relayFailures, 1)
}

// RecordNATType records the detected NAT type
func (m *p2pMetrics) RecordNATType(natType NATType) {
	if val, ok := m.natTypeCounts.Load(natType); ok {
		m.natTypeCounts.Store(natType, val.(uint64)+1)
	} else {
		m.natTypeCounts.Store(natType, uint64(1))
	}
}

// P2PMetricsSnapshot contains a point-in-time snapshot of P2P metrics
type P2PMetricsSnapshot struct {
	P2PAttempts         uint64            `json:"p2p_attempts"`
	P2PSuccesses        uint64            `json:"p2p_successes"`
	P2PFailures         uint64            `json:"p2p_failures"`
	P2PSuccessRate      float64           `json:"p2p_success_rate"`
	RelayFallbacks      uint64            `json:"relay_fallbacks"`
	RelaySuccesses      uint64            `json:"relay_successes"`
	RelayFailures       uint64            `json:"relay_failures"`
	RelaySuccessRate    float64           `json:"relay_success_rate"`
	AvgP2PConnectMs     float64           `json:"avg_p2p_connect_ms"`
	NATTypeDistribution map[string]uint64 `json:"nat_type_distribution"`
}

// Snapshot returns a point-in-time snapshot of metrics
func (m *p2pMetrics) Snapshot() *P2PMetricsSnapshot {
	attempts := atomic.LoadUint64(&m.p2pAttempts)
	successes := atomic.LoadUint64(&m.p2pSuccesses)
	failures := atomic.LoadUint64(&m.p2pFailures)
	relayFallbacks := atomic.LoadUint64(&m.relayFallbacks)
	relaySuccesses := atomic.LoadUint64(&m.relaySuccesses)
	relayFailures := atomic.LoadUint64(&m.relayFailures)
	totalTime := atomic.LoadUint64(&m.totalP2PConnectTime)

	snapshot := &P2PMetricsSnapshot{
		P2PAttempts:         attempts,
		P2PSuccesses:        successes,
		P2PFailures:         failures,
		RelayFallbacks:      relayFallbacks,
		RelaySuccesses:      relaySuccesses,
		RelayFailures:       relayFailures,
		NATTypeDistribution: make(map[string]uint64),
	}

	// Calculate success rates
	if attempts > 0 {
		snapshot.P2PSuccessRate = float64(successes) / float64(attempts) * 100
	}
	if relayFallbacks > 0 {
		snapshot.RelaySuccessRate = float64(relaySuccesses) / float64(relayFallbacks) * 100
	}
	if successes > 0 {
		snapshot.AvgP2PConnectMs = float64(totalTime) / float64(successes)
	}

	// Collect NAT type distribution
	m.natTypeCounts.Range(func(key, value interface{}) bool {
		natType := key.(NATType)
		count := value.(uint64)
		snapshot.NATTypeDistribution[natType.String()] = count
		return true
	})

	return snapshot
}

// Reset clears all metrics (useful for testing)
func (m *p2pMetrics) Reset() {
	atomic.StoreUint64(&m.p2pAttempts, 0)
	atomic.StoreUint64(&m.p2pSuccesses, 0)
	atomic.StoreUint64(&m.p2pFailures, 0)
	atomic.StoreUint64(&m.relayFallbacks, 0)
	atomic.StoreUint64(&m.relaySuccesses, 0)
	atomic.StoreUint64(&m.relayFailures, 0)
	atomic.StoreUint64(&m.totalP2PConnectTime, 0)
	m.natTypeCounts = sync.Map{}
}

// ============================================================================
// P2P Transport Implementation
// ============================================================================

// P2PTransport implements direct peer-to-peer connections using hole punching
// Falls back to relay when direct connection fails
type P2PTransport struct {
	natDetector *NATDetector
	holePuncher *HolePuncher
	client      *http.Client

	mu            sync.Mutex
	connected     bool
	conn          net.Conn
	natInfo       *NATInfo
	defaultConfig *P2PConfig
	defaultTarget string
}

// P2PConfig configures P2P transport behavior
type P2PConfig struct {
	// STUNServers for NAT detection
	STUNServers []string

	// RendezvousURL is the server URL for peer coordination
	RendezvousURL string

	// PeerID is this client's unique identifier
	PeerID string
	// PeerKey authenticates register/request calls
	PeerKey string

	// Token returned from rendezvous registration
	Token string

	// HolePunch configuration
	HolePunch *HolePunchConfig

	// FallbackToRelay enables relay fallback on punch failure
	FallbackToRelay bool

	// RelayServers are URLs for relay fallback
	RelayServers []string

	// RelayConfig optionally overrides the transport.Config used for relay fallback.
	// If nil, defaults are derived from RendezvousURL/RelayServers + token.
	RelayConfig *Config
}

// NewP2PTransport creates a new P2P transport
func NewP2PTransport(defaultCfg *P2PConfig, target string) *P2PTransport {
	return &P2PTransport{
		natDetector: NewNATDetector(nil),
		holePuncher: NewHolePuncher(nil),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		defaultConfig: defaultCfg,
		defaultTarget: target,
	}
}

func (t *P2PTransport) Name() string {
	return "p2p"
}

func (t *P2PTransport) Priority() int {
	return 5 // Highest priority - direct connection is best
}

func (t *P2PTransport) IsAvailable(ctx context.Context) bool {
	if t.defaultConfig == nil || t.defaultTarget == "" {
		return false
	}

	t.applyDetectorConfig(t.defaultConfig)

	// Check if NAT type allows hole punching
	natInfo, err := t.natDetector.DetectWithCache(ctx, 5*time.Minute)
	if err != nil {
		return false
	}

	t.mu.Lock()
	t.natInfo = natInfo
	t.mu.Unlock()

	// P2P is available if NAT allows hole punching
	return natInfo.Type.CanHolePunch()
}

func (t *P2PTransport) Connect(ctx context.Context, config *Config) (*common.Conn, error) {
	p2pCfg, target := t.resolveConfig(config)
	if p2pCfg == nil || target == "" {
		return nil, fmt.Errorf("p2p transport requires target configuration")
	}
	return t.ConnectToPeer(ctx, p2pCfg, target)
}

func (t *P2PTransport) resolveConfig(cfg *Config) (*P2PConfig, string) {
	p2pCfg := t.defaultConfig
	target := t.defaultTarget
	if cfg != nil {
		if cfg.P2PConfig != nil {
			p2pCfg = cfg.P2PConfig
		}
		if cfg.P2PTargetID != "" {
			target = cfg.P2PTargetID
		}
	}
	return p2pCfg, target
}

func (t *P2PTransport) applyDetectorConfig(p2pCfg *P2PConfig) {
	if p2pCfg == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(p2pCfg.STUNServers) > 0 {
		t.natDetector = NewNATDetector(p2pCfg.STUNServers)
	}
	if p2pCfg.HolePunch != nil {
		t.holePuncher = NewHolePuncher(p2pCfg.HolePunch)
	}
}

// ConnectToPeer establishes a direct P2P connection to a peer
func (t *P2PTransport) ConnectToPeer(ctx context.Context, p2pConfig *P2PConfig, targetPeerID string) (*common.Conn, error) {
	t.mu.Lock()
	if t.connected {
		t.mu.Unlock()
		return nil, fmt.Errorf("already connected")
	}
	t.mu.Unlock()

	t.applyDetectorConfig(p2pConfig)

	// Record P2P connection attempt
	P2PMetrics.RecordP2PAttempt()
	startTime := time.Now()

	puncher := t.holePuncher
	if p2pConfig != nil && p2pConfig.HolePunch != nil {
		puncher = NewHolePuncher(p2pConfig.HolePunch)
	}
	if puncher == nil {
		puncher = NewHolePuncher(nil)
	}

	// Step 1: Detect our NAT type and external address
	natInfo, err := t.natDetector.Detect(ctx)
	if err != nil {
		P2PMetrics.RecordP2PFailure()
		return nil, fmt.Errorf("NAT detection failed: %w", err)
	}

	// Record NAT type for metrics
	P2PMetrics.RecordNATType(natInfo.Type)

	t.mu.Lock()
	t.natInfo = natInfo
	t.mu.Unlock()

	// Step 2: Register with rendezvous server
	regResp, err := t.registerWithRendezvous(ctx, p2pConfig, natInfo)
	if err != nil {
		P2PMetrics.RecordP2PFailure()
		return nil, fmt.Errorf("rendezvous registration failed: %w", err)
	}
	if p2pConfig != nil {
		p2pConfig.Token = regResp.Token
	}

	// Step 3: Request peer's endpoint information
	peerInfo, err := t.requestPeerEndpoint(ctx, p2pConfig, targetPeerID, regResp.Token)
	if err != nil {
		P2PMetrics.RecordP2PFailure()
		if p2pConfig.FallbackToRelay {
			return t.connectViaRelay(ctx, p2pConfig, targetPeerID)
		}
		return nil, fmt.Errorf("peer endpoint request failed: %w", err)
	}

	// Step 4: Check if both peers can hole punch
	if !t.canPunchWithPeer(natInfo, peerInfo) {
		P2PMetrics.RecordP2PFailure()
		if p2pConfig.FallbackToRelay {
			return t.connectViaRelay(ctx, p2pConfig, targetPeerID)
		}
		return nil, fmt.Errorf("NAT types incompatible for hole punching")
	}

	// Step 5: Coordinate punch timing via rendezvous
	punchSession, err := t.initiatePunchSession(ctx, p2pConfig, targetPeerID, regResp.Token)
	if err != nil {
		P2PMetrics.RecordP2PFailure()
		if p2pConfig.FallbackToRelay {
			return t.connectViaRelay(ctx, p2pConfig, targetPeerID)
		}
		return nil, fmt.Errorf("punch coordination failed: %w", err)
	}

	if punchSession == nil {
		P2PMetrics.RecordP2PFailure()
		if p2pConfig.FallbackToRelay {
			return t.connectViaRelay(ctx, p2pConfig, targetPeerID)
		}
		return nil, fmt.Errorf("punch coordination unavailable")
	}

	if !punchSession.CanPunch {
		P2PMetrics.RecordP2PFailure()
		if p2pConfig.FallbackToRelay {
			return t.connectViaRelay(ctx, p2pConfig, targetPeerID)
		}
		return nil, fmt.Errorf("rendezvous server indicated relay is required")
	}

	endpoints := peerInfo.Endpoints
	if len(punchSession.TargetEndpoints) > 0 {
		endpoints = punchSession.TargetEndpoints
	}

	// Step 6: Attempt hole punching
	peerAddr, err := t.selectBestEndpoint(endpoints)
	if err != nil {
		P2PMetrics.RecordP2PFailure()
		return nil, err
	}

	var punchResult *HolePunchResult
	if !punchSession.StartTime.IsZero() {
		punchResult, err = puncher.CoordinatedPunch(ctx, peerAddr, punchSession.StartTime)
	} else {
		punchResult, err = puncher.PunchBidirectional(ctx, peerAddr)
	}

	t.reportPunchResult(p2pConfig, punchSession, regResp.Token, punchResult, err)

	if err != nil || punchResult == nil || !punchResult.Success {
		P2PMetrics.RecordP2PFailure()
		if p2pConfig.FallbackToRelay {
			return t.connectViaRelay(ctx, p2pConfig, targetPeerID)
		}
		return nil, fmt.Errorf("hole punch failed: %w", err)
	}

	// Record successful P2P connection
	P2PMetrics.RecordP2PSuccess(time.Since(startTime))

	// Step 6: Wrap raw connection in common.Conn
	t.mu.Lock()
	t.connected = true
	t.conn = punchResult.Conn
	t.mu.Unlock()

	// Create adapter for common.Conn
	adapter := &P2PAdapter{
		conn:      punchResult.Conn,
		transport: t,
	}

	return common.CreateConnFromAdapter(adapter, nil), nil
}

// RendezvousRegisterResponse is the response from registering with rendezvous
type RendezvousRegisterResponse struct {
	Token string `json:"token"`
}

// PeerEndpointInfo contains peer's endpoint information from rendezvous
type PeerEndpointInfo struct {
	PeerID    string              `json:"peer_id"`
	Endpoints []PeerEndpointEntry `json:"endpoints"`
	Metadata  map[string]any      `json:"metadata"`
	LastSeen  time.Time           `json:"last_seen"`
}

// PeerEndpointEntry is a single endpoint advertised by a peer
type PeerEndpointEntry struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// PunchInitiateResponse contains rendezvous punch coordination data
type PunchInitiateResponse struct {
	SessionID       string              `json:"session_id"`
	StartTime       time.Time           `json:"start_time"`
	TargetEndpoints []PeerEndpointEntry `json:"target_endpoints"`
	TargetNATType   string              `json:"target_nat_type"`
	CanPunch        bool                `json:"can_punch"`
	RecommendRelay  bool                `json:"recommend_relay"`
}

type punchExchangePayload struct {
	SessionID string         `json:"session_id"`
	PeerID    string         `json:"peer_id"`
	Token     string         `json:"token"`
	Success   bool           `json:"success"`
	LocalAddr string         `json:"local_addr,omitempty"`
	Error     string         `json:"error,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

func (t *P2PTransport) registerWithRendezvous(ctx context.Context, config *P2PConfig, natInfo *NATInfo) (*RendezvousRegisterResponse, error) {
	endpoints := []map[string]any{
		{
			"protocol": "tcp",
			"host":     natInfo.ExternalIP.String(),
			"port":     natInfo.ExternalPort,
		},
	}

	// Add local endpoint for same-network detection
	if natInfo.LocalIP != nil && !natInfo.LocalIP.Equal(natInfo.ExternalIP) {
		endpoints = append(endpoints, map[string]any{
			"protocol": "tcp-local",
			"host":     natInfo.LocalIP.String(),
			"port":     natInfo.LocalPort,
		})
	}

	payload := map[string]any{
		"peer_id":   config.PeerID,
		"endpoints": endpoints,
		"metadata": map[string]any{
			"nat_type": natInfo.Type.String(),
			"latency":  natInfo.Latency.Milliseconds(),
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		config.RendezvousURL+"/p2p/rendezvous/register",
		nil)
	if err != nil {
		return nil, err
	}
	req.Body = newJSONBody(body)
	req.Header.Set("Content-Type", "application/json")
	if config.PeerID != "" {
		req.Header.Set("UUID", config.PeerID)
	}
	if config.PeerKey != "" {
		req.Header.Set("Key", config.PeerKey)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register failed: %s", resp.Status)
	}

	var result RendezvousRegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (t *P2PTransport) requestPeerEndpoint(ctx context.Context, config *P2PConfig, targetPeerID, token string) (*PeerEndpointInfo, error) {
	payload := map[string]any{
		"peer_id": targetPeerID,
		"token":   token,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		config.RendezvousURL+"/p2p/rendezvous/request",
		nil)
	if err != nil {
		return nil, err
	}
	req.Body = newJSONBody(body)
	req.Header.Set("Content-Type", "application/json")
	if config.PeerID != "" {
		req.Header.Set("UUID", config.PeerID)
	}
	if config.PeerKey != "" {
		req.Header.Set("Key", config.PeerKey)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request peer failed: %s", resp.Status)
	}

	var result PeerEndpointInfo
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (t *P2PTransport) initiatePunchSession(ctx context.Context, config *P2PConfig, targetPeerID, token string) (*PunchInitiateResponse, error) {
	if config == nil {
		return nil, fmt.Errorf("missing P2P configuration")
	}

	payload := map[string]any{
		"initiator_id":    config.PeerID,
		"target_id":       targetPeerID,
		"initiator_token": token,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		config.RendezvousURL+"/p2p/punch/initiate",
		nil)
	if err != nil {
		return nil, err
	}
	req.Body = newJSONBody(body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("initiate punch failed: %s", resp.Status)
	}

	var result PunchInitiateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (t *P2PTransport) reportPunchResult(config *P2PConfig, session *PunchInitiateResponse, token string, result *HolePunchResult, punchErr error) {
	if config == nil || session == nil || session.SessionID == "" || config.PeerID == "" || token == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		t.exchangePunchResult(ctx, config, session.SessionID, config.PeerID, token, result, punchErr)
	}()
}

func (t *P2PTransport) exchangePunchResult(ctx context.Context, config *P2PConfig, sessionID, peerID, token string, result *HolePunchResult, punchErr error) {
	payload := punchExchangePayload{
		SessionID: sessionID,
		PeerID:    peerID,
		Token:     token,
	}

	if result != nil {
		payload.Success = result.Success && punchErr == nil
		if result.LocalAddr != nil {
			payload.LocalAddr = result.LocalAddr.String()
		}
		if payload.Metadata == nil {
			payload.Metadata = make(map[string]any)
		}
		payload.Metadata["attempts"] = result.AttemptCount
		payload.Metadata["duration_ms"] = result.Duration.Milliseconds()
		if result.RemoteAddr != nil {
			payload.Metadata["remote_addr"] = result.RemoteAddr.String()
		}
	} else {
		payload.Success = false
	}

	if punchErr != nil {
		payload.Error = punchErr.Error()
	} else if result != nil && result.Error != nil {
		payload.Error = result.Error.Error()
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST",
		config.RendezvousURL+"/p2p/punch/exchange",
		nil)
	if err != nil {
		return
	}
	req.Body = newJSONBody(body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func (t *P2PTransport) canPunchWithPeer(local *NATInfo, peer *PeerEndpointInfo) bool {
	// Check local NAT type
	if !local.Type.CanHolePunch() {
		return false
	}

	// Check peer's NAT type from metadata
	if peer.Metadata != nil {
		if natTypeStr, ok := peer.Metadata["nat_type"].(string); ok {
			peerNATType := parseNATType(natTypeStr)
			if !peerNATType.CanHolePunch() {
				return false
			}

			// Both symmetric = definitely can't punch
			if local.Type == NATTypeSymmetric && peerNATType == NATTypeSymmetric {
				return false
			}
		}
	}

	return true
}

func parseNATType(s string) NATType {
	switch s {
	case "Open":
		return NATTypeOpen
	case "FullCone":
		return NATTypeFullCone
	case "RestrictedCone":
		return NATTypeRestrictedCone
	case "PortRestricted":
		return NATTypePortRestricted
	case "Symmetric":
		return NATTypeSymmetric
	default:
		return NATTypeUnknown
	}
}

func (t *P2PTransport) selectBestEndpoint(endpoints []PeerEndpointEntry) (*net.TCPAddr, error) {
	// Prefer TCP endpoints
	for _, ep := range endpoints {
		if ep.Protocol == "tcp" || ep.Protocol == "tcp-local" {
			return &net.TCPAddr{
				IP:   net.ParseIP(ep.Host),
				Port: ep.Port,
			}, nil
		}
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints available")
	}

	// Fallback to first endpoint
	ep := endpoints[0]
	return &net.TCPAddr{
		IP:   net.ParseIP(ep.Host),
		Port: ep.Port,
	}, nil
}

func (t *P2PTransport) connectViaRelay(ctx context.Context, config *P2PConfig, targetPeerID string) (*common.Conn, error) {
	// Record relay fallback in metrics
	P2PMetrics.RecordRelayFallback()

	relayCfg := t.buildRelayConfig(config)
	if relayCfg == nil {
		P2PMetrics.RecordRelayFailure()
		return nil, fmt.Errorf("no relay configuration available")
	}

	manager := NewManager(relayCfg)
	conn, usedTransport, err := manager.Connect(ctx)
	if err != nil {
		P2PMetrics.RecordRelayFailure()
		return nil, fmt.Errorf("relay connection failed: %w", err)
	}

	_ = usedTransport // placeholder for future telemetry
	P2PMetrics.RecordRelaySuccess()
	return conn, nil
}

// buildRelayConfig resolves the transport configuration for relay fallback.
func (t *P2PTransport) buildRelayConfig(p2pCfg *P2PConfig) *Config {
	if p2pCfg == nil {
		return nil
	}

	if p2pCfg.RelayConfig != nil {
		cfgCopy := *p2pCfg.RelayConfig
		t.populateRelayDefaults(&cfgCopy, p2pCfg)
		return &cfgCopy
	}

	cfg := &Config{}
	t.populateRelayDefaults(cfg, p2pCfg)
	if cfg.ServerURL == "" {
		return nil
	}
	return cfg
}

func (t *P2PTransport) populateRelayDefaults(cfg *Config, p2pCfg *P2PConfig) {
	if cfg.ServerURL == "" {
		switch {
		case len(p2pCfg.RelayServers) > 0:
			cfg.ServerURL = p2pCfg.RelayServers[0]
		case p2pCfg.RendezvousURL != "":
			cfg.ServerURL = p2pCfg.RendezvousURL
		}
	}
	if cfg.UUID == "" {
		cfg.UUID = p2pCfg.PeerID
	}
	if cfg.Key == "" {
		cfg.Key = p2pCfg.PeerKey
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = 30 * time.Second
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 60 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	if cfg.LongPollTimeout == 0 {
		cfg.LongPollTimeout = 30 * time.Second
	}
	if cfg.LongPollPath == "" {
		cfg.LongPollPath = "/api/longpoll"
	}
	// P2P relay fallbacks use existing WebSocket/LongPoll transports;
	// QUIC is off unless explicitly enabled to avoid UDP blocks on same networks.
}

func (t *P2PTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	t.connected = false
	return nil
}

// GetNATInfo returns the detected NAT information
func (t *P2PTransport) GetNATInfo() *NATInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.natInfo
}

// P2PAdapter implements common.TransportAdapter for P2P connections
type P2PAdapter struct {
	conn      net.Conn
	transport *P2PTransport
	mu        sync.Mutex
}

func (a *P2PAdapter) Write(data []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.conn.Write(data)
	return err
}

func (a *P2PAdapter) Read() ([]byte, error) {
	buf := make([]byte, 65536)
	n, err := a.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (a *P2PAdapter) Close() error {
	return a.transport.Close()
}

func (a *P2PAdapter) SetWriteDeadline(deadline interface{}) error {
	if t, ok := deadline.(time.Time); ok {
		return a.conn.SetWriteDeadline(t)
	}
	return nil
}

func (a *P2PAdapter) IsConnected() bool {
	a.transport.mu.Lock()
	defer a.transport.mu.Unlock()
	return a.transport.connected
}

// TransportSelector decides which transport to use based on NAT analysis
type TransportSelector struct {
	natDetector   *NATDetector
	p2pTransport  *P2PTransport
	fallbackOrder []Transport
}

// NewTransportSelector creates a selector that prefers P2P when possible
func NewTransportSelector(config *Config) *TransportSelector {
	var defaultP2P *P2PConfig
	var defaultTarget string
	if config != nil {
		defaultP2P = config.P2PConfig
		defaultTarget = config.P2PTargetID
	}
	return &TransportSelector{
		natDetector:  NewNATDetector(nil),
		p2pTransport: NewP2PTransport(defaultP2P, defaultTarget),
		fallbackOrder: []Transport{
			NewWebSocketTransport(true),  // WSS
			NewWebSocketTransport(false), // WS
			NewLongPollingTransport(),
		},
	}
}

// SelectTransport analyzes the network and returns the best transport
func (s *TransportSelector) SelectTransport(ctx context.Context) (Transport, *NATInfo, error) {
	// Detect NAT type
	natInfo, err := s.natDetector.Detect(ctx)
	if err != nil {
		// NAT detection failed, use fallback
		return s.fallbackOrder[0], nil, nil
	}

	// If NAT supports hole punching, prefer P2P
	if natInfo.Type.CanHolePunch() {
		return s.p2pTransport, natInfo, nil
	}

	// Symmetric NAT or unknown - use relay transport
	return s.fallbackOrder[0], natInfo, nil
}

// SelectionResult contains the transport selection decision
type SelectionResult struct {
	Transport    Transport
	NATInfo      *NATInfo
	Reason       string
	FallbackUsed bool
}

// SelectWithDetails provides detailed selection reasoning
func (s *TransportSelector) SelectWithDetails(ctx context.Context) (*SelectionResult, error) {
	result := &SelectionResult{}

	natInfo, err := s.natDetector.Detect(ctx)
	if err != nil {
		result.Transport = s.fallbackOrder[0]
		result.Reason = fmt.Sprintf("NAT detection failed: %v", err)
		result.FallbackUsed = true
		return result, nil
	}

	result.NATInfo = natInfo

	if natInfo.Type.CanHolePunch() {
		result.Transport = s.p2pTransport
		result.Reason = fmt.Sprintf("NAT type %s supports hole punching", natInfo.Type)
		return result, nil
	}

	result.Transport = s.fallbackOrder[0]
	result.Reason = fmt.Sprintf("NAT type %s requires relay", natInfo.Type)
	result.FallbackUsed = true
	return result, nil
}

// Helper to create JSON body reader
type jsonBodyReader struct {
	data []byte
	pos  int
}

func newJSONBody(data []byte) *jsonBodyReader {
	return &jsonBodyReader{data: data}
}

func (r *jsonBodyReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *jsonBodyReader) Close() error {
	return nil
}
