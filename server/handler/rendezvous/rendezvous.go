package rendezvous

import (
	"Rocket/server/common"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	peerTTL             = 2 * time.Minute
	cleanupInterval     = 30 * time.Second
	maxEndpointsPerPeer = 4
)

var (
	errPeerNotFound  = errors.New("peer not found")
	errTokenMismatch = errors.New("token mismatch")
	errPeerExpired   = errors.New("peer expired")
)

type PeerEndpoint struct {
	Protocol string `json:"protocol" binding:"required" bson:"protocol"`
	Host     string `json:"host" binding:"required" bson:"host"`
	Port     int    `json:"port" binding:"required" bson:"port"`
}

type PeerRecord struct {
	PeerID    string         `json:"peer_id" bson:"peer_id"`
	Token     string         `json:"token" bson:"token"`
	Endpoints []PeerEndpoint `json:"endpoints" bson:"endpoints"`
	Metadata  map[string]any `json:"metadata,omitempty" bson:"metadata,omitempty"`
	LastSeen  time.Time      `json:"last_seen" bson:"last_seen"`
	CreatedAt time.Time      `json:"created_at" bson:"created_at"`

	// Requester tracks runtime information for auditing; it is not persisted.
	Requester map[string]interface{} `json:"-" bson:"-"`
}

// RegisterDeviceRoutes attaches device-authenticated rendezvous endpoints.
func RegisterDeviceRoutes(router *gin.RouterGroup) {
	router.POST(`/p2p/rendezvous/register`, registerPeerHandler)
	router.POST(`/p2p/rendezvous/heartbeat`, heartbeatHandler)
	router.POST(`/p2p/rendezvous/request`, requestPeerHandler)
	router.DELETE(`/p2p/rendezvous/register`, deletePeerHandler)

	router.POST(`/p2p/punch/initiate`, initiatePunchHandler)
	router.POST(`/p2p/punch/exchange`, exchangePunchHandler)
	router.GET(`/p2p/punch/relay`, getRelayServersHandler)
}

// RegisterAdminRoutes attaches admin-only rendezvous endpoints.
func RegisterAdminRoutes(router *gin.RouterGroup) {
	router.GET(`/p2p/metrics`, getP2PMetricsHandler)
	router.POST(`/p2p/metrics/report`, reportP2PMetricsHandler)
}

type registerPeerRequest struct {
	PeerID    string         `json:"peer_id" binding:"required"`
	Endpoints []PeerEndpoint `json:"endpoints" binding:"required"`
	Metadata  map[string]any `json:"metadata"`
}

type registerPeerResponse struct {
	Token string `json:"token"`
}

func registerPeerHandler(c *gin.Context) {
	store := getPeerStore()
	var req registerPeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}
	peerID, ok := getAuthenticatedPeerID(c)
	if !ok {
		return
	}
	if len(req.Endpoints) == 0 || len(req.Endpoints) > maxEndpointsPerPeer {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid endpoint count`})
		return
	}
	token, err := generateToken(16)
	if err != nil {
		common.Warn(c, `RENDEZVOUS_REGISTER`, `fail`, `token generation failed`, map[string]any{
			`error`: err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{`error`: `token generation failed`})
		return
	}

	now := time.Now()
	record := &PeerRecord{
		PeerID:    peerID,
		Token:     token,
		Endpoints: req.Endpoints,
		Metadata:  req.Metadata,
		LastSeen:  now,
		CreatedAt: now,
	}
	if err := store.Upsert(record); err != nil {
		common.Warn(c, `RENDEZVOUS_REGISTER`, `fail`, `peer upsert failed`, map[string]any{
			`peer_id`: req.PeerID,
			`error`:   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{`error`: `registration failed`})
		return
	}

	common.Info(c, `RENDEZVOUS_REGISTER`, `success`, `peer registered`, map[string]any{
		`peer_id`: peerID,
	})
	c.JSON(http.StatusOK, registerPeerResponse{Token: token})
}

func heartbeatHandler(c *gin.Context) {
	store := getPeerStore()
	var req struct {
		PeerID string `json:"peer_id" binding:"required"`
		Token  string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}
	if peerID, ok := getAuthenticatedPeerID(c); ok {
		req.PeerID = peerID
	} else {
		return
	}
	if err := store.UpdateHeartbeat(req.PeerID, req.Token); err != nil {
		switch {
		case errors.Is(err, errPeerNotFound):
			c.JSON(http.StatusNotFound, gin.H{`error`: err.Error()})
		case errors.Is(err, errTokenMismatch), errors.Is(err, errPeerExpired):
			c.JSON(http.StatusBadRequest, gin.H{`error`: err.Error()})
		default:
			common.Warn(c, `RENDEZVOUS_HEARTBEAT`, `fail`, `heartbeat failed`, map[string]any{
				`peer_id`: req.PeerID,
				`error`:   err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{`error`: `heartbeat failed`})
		}
		return
	}
	c.Status(http.StatusNoContent)
}

func requestPeerHandler(c *gin.Context) {
	store := getPeerStore()
	var req struct {
		PeerID string `json:"peer_id" binding:"required"`
		Token  string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}
	peer, err := store.Lookup(req.PeerID, req.Token)
	if err != nil {
		switch {
		case errors.Is(err, errPeerNotFound), errors.Is(err, errTokenMismatch), errors.Is(err, errPeerExpired):
			c.JSON(http.StatusNotFound, gin.H{`error`: err.Error()})
		default:
			common.Warn(c, `RENDEZVOUS_REQUEST`, `fail`, `lookup failed`, map[string]any{
				`peer_id`: req.PeerID,
				`error`:   err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{`error`: `lookup failed`})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{
		`peer_id`:   peer.PeerID,
		`endpoints`: peer.Endpoints,
		`metadata`:  peer.Metadata,
		`last_seen`: peer.LastSeen.UTC(),
	})
}

func deletePeerHandler(c *gin.Context) {
	store := getPeerStore()
	var req struct {
		PeerID string `json:"peer_id" binding:"required"`
		Token  string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}
	if peerID, ok := getAuthenticatedPeerID(c); ok {
		req.PeerID = peerID
	} else {
		return
	}
	peer, err := store.Lookup(req.PeerID, req.Token)
	if err != nil {
		switch {
		case errors.Is(err, errPeerNotFound), errors.Is(err, errTokenMismatch), errors.Is(err, errPeerExpired):
			c.JSON(http.StatusNotFound, gin.H{`error`: err.Error()})
		default:
			common.Warn(c, `RENDEZVOUS_DEREGISTER`, `fail`, `lookup failed`, map[string]any{
				`peer_id`: req.PeerID,
				`error`:   err.Error(),
			})
			c.JSON(http.StatusInternalServerError, gin.H{`error`: `deregister failed`})
		}
		return
	}
	if err := store.Delete(peer.PeerID); err != nil {
		common.Warn(c, `RENDEZVOUS_DEREGISTER`, `fail`, `delete failed`, map[string]any{
			`peer_id`: peer.PeerID,
			`error`:   err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{`error`: `deregister failed`})
		return
	}
	common.Info(c, `RENDEZVOUS_DEREGISTER`, `success`, `peer deregistered`, map[string]any{
		`peer_id`: peer.PeerID,
	})
	c.Status(http.StatusNoContent)
}

func generateToken(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ============================================================================
// Punch Coordination Handlers (Phase 3 - RustDesk Parity)
// ============================================================================

// PunchSession tracks an in-progress hole punch attempt between two peers
type PunchSession struct {
	SessionID   string         `json:"session_id"`
	InitiatorID string         `json:"initiator_id"`
	TargetID    string         `json:"target_id"`
	StartTime   time.Time      `json:"start_time"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Status      string         `json:"status"` // "pending", "exchanged", "connected", "failed"
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// punchSessionStore manages active punch sessions (in-memory for now)
var (
	punchSessions   = make(map[string]*PunchSession)
	punchSessionsMu sync.RWMutex
	punchTTL        = 30 * time.Second // Punch attempts expire quickly
)

// initiatePunchHandler starts a hole punch attempt
// POST /p2p/punch/initiate
// Body: { "initiator_id": "peer-a", "target_id": "peer-b", "initiator_token": "..." }
func initiatePunchHandler(c *gin.Context) {
	var req struct {
		InitiatorID    string `json:"initiator_id" binding:"required"`
		TargetID       string `json:"target_id" binding:"required"`
		InitiatorToken string `json:"initiator_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}

	store := getPeerStore()

	// Validate initiator's token
	initiator, err := store.Lookup(req.InitiatorID, req.InitiatorToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{`error`: `invalid initiator credentials`})
		return
	}

	// Check target exists (without token - we just need to know they're registered)
	target, err := store.LookupByID(req.TargetID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{`error`: `target peer not found`})
		return
	}

	// Generate session ID and start time
	sessionID, _ := generateToken(16)
	now := time.Now()
	startTime := now.Add(500 * time.Millisecond) // Both peers start in 500ms

	session := &PunchSession{
		SessionID:   sessionID,
		InitiatorID: req.InitiatorID,
		TargetID:    req.TargetID,
		StartTime:   startTime,
		ExpiresAt:   now.Add(punchTTL),
		Status:      "pending",
		Metadata: map[string]any{
			"initiator_nat": initiator.Metadata["nat_type"],
			"target_nat":    target.Metadata["nat_type"],
		},
	}

	punchSessionsMu.Lock()
	punchSessions[sessionID] = session
	punchSessionsMu.Unlock()

	// Check NAT compatibility
	canPunch := canNATsPunch(
		getNATTypeFromMeta(initiator.Metadata),
		getNATTypeFromMeta(target.Metadata),
	)

	common.Info(c, `PUNCH_INITIATE`, `success`, `punch session created`, map[string]any{
		`session_id`:   sessionID,
		`initiator`:    req.InitiatorID,
		`target`:       req.TargetID,
		`can_punch`:    canPunch,
		`start_time`:   startTime.UTC(),
	})

	c.JSON(http.StatusOK, gin.H{
		`session_id`:         sessionID,
		`start_time`:         startTime.UTC(),
		`target_endpoints`:   target.Endpoints,
		`target_nat_type`:    target.Metadata["nat_type"],
		`can_punch`:          canPunch,
		`recommend_relay`:    !canPunch,
	})
}

// exchangePunchHandler allows peers to exchange punch attempt results
// POST /p2p/punch/exchange
// Body: { "session_id": "...", "peer_id": "...", "token": "...", "result": {...} }
func exchangePunchHandler(c *gin.Context) {
	var req struct {
		SessionID string         `json:"session_id" binding:"required"`
		PeerID    string         `json:"peer_id" binding:"required"`
		Token     string         `json:"token" binding:"required"`
		Success   bool           `json:"success"`
		LocalAddr string         `json:"local_addr,omitempty"`
		Error     string         `json:"error,omitempty"`
		Metadata  map[string]any `json:"metadata,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}

	store := getPeerStore()

	// Validate peer's token
	if _, err := store.Lookup(req.PeerID, req.Token); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{`error`: `invalid credentials`})
		return
	}

	punchSessionsMu.Lock()
	session, ok := punchSessions[req.SessionID]
	if !ok {
		punchSessionsMu.Unlock()
		c.JSON(http.StatusNotFound, gin.H{`error`: `session not found`})
		return
	}

	// Verify peer is part of this session
	if req.PeerID != session.InitiatorID && req.PeerID != session.TargetID {
		punchSessionsMu.Unlock()
		c.JSON(http.StatusForbidden, gin.H{`error`: `peer not in session`})
		return
	}

	// Check if session expired
	if time.Now().After(session.ExpiresAt) {
		delete(punchSessions, req.SessionID)
		punchSessionsMu.Unlock()
		c.JSON(http.StatusGone, gin.H{`error`: `session expired`})
		return
	}

	// Update session status
	if req.Success {
		session.Status = "connected"
	} else if session.Status != "connected" {
		session.Status = "exchanged"
	}

	// Store exchange metadata
	if session.Metadata == nil {
		session.Metadata = make(map[string]any)
	}
	session.Metadata[req.PeerID+"_result"] = map[string]any{
		"success":    req.Success,
		"local_addr": req.LocalAddr,
		"error":      req.Error,
		"metadata":   req.Metadata,
	}

	punchSessionsMu.Unlock()

	common.Info(c, `PUNCH_EXCHANGE`, session.Status, `punch result exchanged`, map[string]any{
		`session_id`: req.SessionID,
		`peer_id`:    req.PeerID,
		`success`:    req.Success,
	})

	c.JSON(http.StatusOK, gin.H{
		`status`:  session.Status,
		`success`: req.Success,
	})
}

// getRelayServersHandler returns available relay servers for fallback
// GET /p2p/punch/relay
func getRelayServersHandler(c *gin.Context) {
	// TODO: Load from config or environment
	relayServers := getRelayServers()

	c.JSON(http.StatusOK, gin.H{
		`relay_servers`: relayServers,
		`websocket_url`: "/api/device/ws",
		`longpoll_url`:  "/api/poll",
	})
}

// Helper functions

func getNATTypeFromMeta(meta map[string]any) string {
	if meta == nil {
		return "Unknown"
	}
	if natType, ok := meta["nat_type"].(string); ok {
		return natType
	}
	return "Unknown"
}

func canNATsPunch(natA, natB string) bool {
	// Symmetric + Symmetric = can't punch
	if natA == "Symmetric" && natB == "Symmetric" {
		return false
	}
	// Symmetric + anything else = unlikely but possible
	if natA == "Symmetric" || natB == "Symmetric" {
		return false // Conservative: recommend relay
	}
	// Unknown = can't determine
	if natA == "Unknown" || natB == "Unknown" {
		return true // Optimistic: try punch
	}
	// Cone + Cone = should work
	return true
}

func getRelayServers() []map[string]any {
	// TODO: Load from config
	return []map[string]any{
		{
			"url":      "/api/device/ws",
			"protocol": "websocket",
			"priority": 1,
		},
		{
			"url":      "/api/poll",
			"protocol": "longpoll",
			"priority": 2,
		},
	}
}

// cleanupExpiredPunchSessions removes expired punch sessions
func cleanupExpiredPunchSessions() {
	punchSessionsMu.Lock()
	defer punchSessionsMu.Unlock()

	now := time.Now()
	for id, session := range punchSessions {
		if now.After(session.ExpiresAt) {
			delete(punchSessions, id)
		}
	}
}

// ============================================================================
// P2P Metrics (Phase 7 - Server-side aggregation)
// ============================================================================

// serverP2PMetrics aggregates client-reported P2P metrics
type serverP2PMetrics struct {
	mu sync.RWMutex

	// Aggregated from client reports
	totalP2PAttempts   uint64
	totalP2PSuccesses  uint64
	totalP2PFailures   uint64
	totalRelayFallbacks uint64
	totalRelaySuccesses uint64
	totalRelayFailures  uint64

	// NAT type distribution (from punch initiations)
	natTypeDistribution map[string]uint64

	// Per-peer tracking
	peerMetrics map[string]*peerMetricsEntry
}

type peerMetricsEntry struct {
	PeerID        string    `json:"peer_id"`
	NATType       string    `json:"nat_type"`
	P2PAttempts   uint64    `json:"p2p_attempts"`
	P2PSuccesses  uint64    `json:"p2p_successes"`
	RelayFallbacks uint64   `json:"relay_fallbacks"`
	LastReport    time.Time `json:"last_report"`
}

var p2pServerMetrics = &serverP2PMetrics{
	natTypeDistribution: make(map[string]uint64),
	peerMetrics:         make(map[string]*peerMetricsEntry),
}

// getP2PMetricsHandler returns aggregated P2P metrics
// GET /p2p/metrics
func getP2PMetricsHandler(c *gin.Context) {
	p2pServerMetrics.mu.RLock()
	defer p2pServerMetrics.mu.RUnlock()

	// Calculate success rates
	var p2pSuccessRate, relaySuccessRate float64
	if p2pServerMetrics.totalP2PAttempts > 0 {
		p2pSuccessRate = float64(p2pServerMetrics.totalP2PSuccesses) / float64(p2pServerMetrics.totalP2PAttempts) * 100
	}
	if p2pServerMetrics.totalRelayFallbacks > 0 {
		relaySuccessRate = float64(p2pServerMetrics.totalRelaySuccesses) / float64(p2pServerMetrics.totalRelayFallbacks) * 100
	}

	// Get active punch sessions count
	punchSessionsMu.RLock()
	activePunchSessions := len(punchSessions)
	punchSessionsMu.RUnlock()

	// Get registered peers count
	store := getPeerStore()
	var registeredPeers int
	if ms, ok := store.(*memoryPeerStore); ok {
		ms.mu.RLock()
		registeredPeers = len(ms.peers)
		ms.mu.RUnlock()
	}

	c.JSON(http.StatusOK, gin.H{
		"p2p_attempts":          p2pServerMetrics.totalP2PAttempts,
		"p2p_successes":         p2pServerMetrics.totalP2PSuccesses,
		"p2p_failures":          p2pServerMetrics.totalP2PFailures,
		"p2p_success_rate":      p2pSuccessRate,
		"relay_fallbacks":       p2pServerMetrics.totalRelayFallbacks,
		"relay_successes":       p2pServerMetrics.totalRelaySuccesses,
		"relay_failures":        p2pServerMetrics.totalRelayFailures,
		"relay_success_rate":    relaySuccessRate,
		"nat_type_distribution": p2pServerMetrics.natTypeDistribution,
		"active_punch_sessions": activePunchSessions,
		"registered_peers":      registeredPeers,
	})
}

// reportP2PMetricsHandler allows clients to report their P2P metrics
// POST /p2p/metrics/report
func reportP2PMetricsHandler(c *gin.Context) {
	var req struct {
		PeerID          string `json:"peer_id" binding:"required"`
		Token           string `json:"token" binding:"required"`
		P2PAttempts     uint64 `json:"p2p_attempts"`
		P2PSuccesses    uint64 `json:"p2p_successes"`
		P2PFailures     uint64 `json:"p2p_failures"`
		RelayFallbacks  uint64 `json:"relay_fallbacks"`
		RelaySuccesses  uint64 `json:"relay_successes"`
		RelayFailures   uint64 `json:"relay_failures"`
		NATType         string `json:"nat_type"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{`error`: `invalid payload`})
		return
	}

	// Validate peer token
	store := getPeerStore()
	if _, err := store.Lookup(req.PeerID, req.Token); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{`error`: `invalid credentials`})
		return
	}

	// Update server-side aggregated metrics
	p2pServerMetrics.mu.Lock()
	p2pServerMetrics.totalP2PAttempts += req.P2PAttempts
	p2pServerMetrics.totalP2PSuccesses += req.P2PSuccesses
	p2pServerMetrics.totalP2PFailures += req.P2PFailures
	p2pServerMetrics.totalRelayFallbacks += req.RelayFallbacks
	p2pServerMetrics.totalRelaySuccesses += req.RelaySuccesses
	p2pServerMetrics.totalRelayFailures += req.RelayFailures

	// Update NAT type distribution
	if req.NATType != "" {
		p2pServerMetrics.natTypeDistribution[req.NATType]++
	}

	// Update per-peer metrics
	entry, exists := p2pServerMetrics.peerMetrics[req.PeerID]
	if !exists {
		entry = &peerMetricsEntry{PeerID: req.PeerID}
		p2pServerMetrics.peerMetrics[req.PeerID] = entry
	}
	entry.NATType = req.NATType
	entry.P2PAttempts += req.P2PAttempts
	entry.P2PSuccesses += req.P2PSuccesses
	entry.RelayFallbacks += req.RelayFallbacks
	entry.LastReport = time.Now()

	p2pServerMetrics.mu.Unlock()

	common.Info(c, `P2P_METRICS_REPORT`, `success`, `metrics received`, map[string]any{
		`peer_id`:    req.PeerID,
		`nat_type`:   req.NATType,
		`p2p_rate`:   float64(req.P2PSuccesses) / max(float64(req.P2PAttempts), 1) * 100,
	})

	c.JSON(http.StatusOK, gin.H{`status`: `ok`})
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func init() {
	// Start cleanup goroutine for punch sessions
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpiredPunchSessions()
		}
	}()
}
