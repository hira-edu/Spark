package rendezvous

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

const (
	peerAUUID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	peerBUUID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// setupTestRouter creates a Gin router with rendezvous routes for testing
func setupTestRouter() *gin.Engine {
	r := gin.New()
	deviceGroup := r.Group("/")
	deviceGroup.Use(DeviceAuthMiddleware())
	RegisterDeviceRoutes(deviceGroup)
	RegisterAdminRoutes(r.Group("/"))
	return r
}

// TestCanNATsPunch tests NAT compatibility logic
func TestCanNATsPunch(t *testing.T) {
	tests := []struct {
		name     string
		natA     string
		natB     string
		expected bool
	}{
		{"Symmetric + Symmetric", "Symmetric", "Symmetric", false},
		{"Symmetric + Cone", "Symmetric", "RestrictedCone", false},
		{"Cone + Symmetric", "RestrictedCone", "Symmetric", false},
		{"Cone + Cone", "RestrictedCone", "PortRestricted", true},
		{"FullCone + FullCone", "FullCone", "FullCone", true},
		{"Unknown + Cone", "Unknown", "RestrictedCone", true},
		{"Open + Open", "Open", "Open", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := canNATsPunch(tt.natA, tt.natB)
			if result != tt.expected {
				t.Errorf("canNATsPunch(%s, %s) = %v, want %v",
					tt.natA, tt.natB, result, tt.expected)
			}
		})
	}
}

// TestGetNATTypeFromMeta tests metadata extraction
func TestGetNATTypeFromMeta(t *testing.T) {
	tests := []struct {
		name     string
		meta     map[string]any
		expected string
	}{
		{"nil meta", nil, "Unknown"},
		{"empty meta", map[string]any{}, "Unknown"},
		{"valid nat_type", map[string]any{"nat_type": "RestrictedCone"}, "RestrictedCone"},
		{"wrong type", map[string]any{"nat_type": 123}, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNATTypeFromMeta(tt.meta)
			if result != tt.expected {
				t.Errorf("getNATTypeFromMeta(%v) = %s, want %s",
					tt.meta, result, tt.expected)
			}
		})
	}
}

// TestInitiatePunchHandler tests punch session creation
func TestInitiatePunchHandler(t *testing.T) {
	// Reset the peer store for test isolation
	setPeerStoreForTest(newMemoryPeerStore(peerTTL))

	router := setupTestRouter()

	// First, register two peers
	registerPeerA := map[string]any{
		"peer_id": peerAUUID,
		"endpoints": []map[string]any{
			{"protocol": "tcp", "host": "1.2.3.4", "port": 12345},
		},
		"metadata": map[string]any{"nat_type": "RestrictedCone"},
	}
	registerPeerB := map[string]any{
		"peer_id": peerBUUID,
		"endpoints": []map[string]any{
			{"protocol": "tcp", "host": "5.6.7.8", "port": 54321},
		},
		"metadata": map[string]any{"nat_type": "FullCone"},
	}

	// Register peer A
	bodyA, _ := json.Marshal(registerPeerA)
	reqA := newDeviceRequestWithUUID("POST", "/p2p/rendezvous/register", peerAUUID, bytes.NewReader(bodyA))
	reqA.Header.Set("Content-Type", "application/json")
	respA := httptest.NewRecorder()
	router.ServeHTTP(respA, reqA)

	if respA.Code != http.StatusOK {
		t.Fatalf("Failed to register peer A: %s", respA.Body.String())
	}

	var regRespA struct {
		Token string `json:"token"`
	}
	json.Unmarshal(respA.Body.Bytes(), &regRespA)

	// Register peer B
	bodyB, _ := json.Marshal(registerPeerB)
	reqB := newDeviceRequestWithUUID("POST", "/p2p/rendezvous/register", peerBUUID, bytes.NewReader(bodyB))
	reqB.Header.Set("Content-Type", "application/json")
	respB := httptest.NewRecorder()
	router.ServeHTTP(respB, reqB)

	if respB.Code != http.StatusOK {
		t.Fatalf("Failed to register peer B: %s", respB.Body.String())
	}

	// Now test punch initiation
	punchReq := map[string]any{
		"initiator_id":    peerAUUID,
		"target_id":       peerBUUID,
		"initiator_token": regRespA.Token,
	}

	body, _ := json.Marshal(punchReq)
	req := newDeviceRequestWithUUID("POST", "/p2p/punch/initiate", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.Code, resp.Body.String())
	}

	var punchResp struct {
		SessionID       string `json:"session_id"`
		CanPunch        bool   `json:"can_punch"`
		RecommendRelay  bool   `json:"recommend_relay"`
		TargetNATType   string `json:"target_nat_type"`
		TargetEndpoints []struct {
			Protocol string `json:"protocol"`
			Host     string `json:"host"`
			Port     int    `json:"port"`
		} `json:"target_endpoints"`
	}

	if err := json.Unmarshal(resp.Body.Bytes(), &punchResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify response
	if punchResp.SessionID == "" {
		t.Error("Expected session_id to be set")
	}
	if !punchResp.CanPunch {
		t.Error("Expected can_punch to be true (Cone + Cone)")
	}
	if punchResp.RecommendRelay {
		t.Error("Expected recommend_relay to be false")
	}
	if len(punchResp.TargetEndpoints) != 1 {
		t.Errorf("Expected 1 target endpoint, got %d", len(punchResp.TargetEndpoints))
	}

	t.Logf("Punch session created: %s", punchResp.SessionID)
}

// TestExchangePunchHandler tests punch result exchange
func TestExchangePunchHandler(t *testing.T) {
	// Reset stores
	setPeerStoreForTest(newMemoryPeerStore(peerTTL))
	punchSessionsMu.Lock()
	punchSessions = make(map[string]*PunchSession)
	punchSessionsMu.Unlock()

	router := setupTestRouter()

	// Register a peer
	registerReq := map[string]any{
		"peer_id": peerAUUID,
		"endpoints": []map[string]any{
			{"protocol": "tcp", "host": "1.2.3.4", "port": 12345},
		},
	}
	body, _ := json.Marshal(registerReq)
	req := newDeviceRequestWithUUID("POST", "/p2p/rendezvous/register", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var regResp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(resp.Body.Bytes(), &regResp)

	// Manually create a punch session for testing
	punchSessionsMu.Lock()
	punchSessions["test-session"] = &PunchSession{
		SessionID:   "test-session",
		InitiatorID: peerAUUID,
		TargetID:    peerBUUID,
		Status:      "pending",
		ExpiresAt:   timeNow().Add(punchTTL),
	}
	punchSessionsMu.Unlock()

	// Exchange punch result
	exchangeReq := map[string]any{
		"session_id": "test-session",
		"peer_id":    peerAUUID,
		"token":      regResp.Token,
		"success":    true,
		"local_addr": "192.168.1.100:54321",
	}

	body, _ = json.Marshal(exchangeReq)
	req = newDeviceRequestWithUUID("POST", "/p2p/punch/exchange", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.Code, resp.Body.String())
	}

	var exchangeResp struct {
		Status  string `json:"status"`
		Success bool   `json:"success"`
	}
	json.Unmarshal(resp.Body.Bytes(), &exchangeResp)

	if exchangeResp.Status != "connected" {
		t.Errorf("Expected status 'connected', got '%s'", exchangeResp.Status)
	}
}

// TestExchangePunchInvalidSession tests exchange with invalid session
func TestExchangePunchInvalidSession(t *testing.T) {
	setPeerStoreForTest(newMemoryPeerStore(peerTTL))
	punchSessionsMu.Lock()
	punchSessions = make(map[string]*PunchSession)
	punchSessionsMu.Unlock()

	router := setupTestRouter()

	// Register a peer
	registerReq := map[string]any{
		"peer_id": peerAUUID,
		"endpoints": []map[string]any{
			{"protocol": "tcp", "host": "1.2.3.4", "port": 12345},
		},
	}
	body, _ := json.Marshal(registerReq)
	req := newDeviceRequestWithUUID("POST", "/p2p/rendezvous/register", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var regResp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(resp.Body.Bytes(), &regResp)

	// Try to exchange with invalid session
	exchangeReq := map[string]any{
		"session_id": "invalid-session",
		"peer_id":    peerAUUID,
		"token":      regResp.Token,
		"success":    true,
	}

	body, _ = json.Marshal(exchangeReq)
	req = newDeviceRequestWithUUID("POST", "/p2p/punch/exchange", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Errorf("Expected 404 Not Found, got %d", resp.Code)
	}
}

// TestGetRelayServersHandler tests relay server endpoint
func TestGetRelayServersHandler(t *testing.T) {
	router := setupTestRouter()

	req := newDeviceRequest("GET", "/p2p/punch/relay", nil)
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.Code)
	}

	var relayResp struct {
		RelayServers []struct {
			URL      string `json:"url"`
			Protocol string `json:"protocol"`
			Priority int    `json:"priority"`
		} `json:"relay_servers"`
		WebsocketURL string `json:"websocket_url"`
		LongpollURL  string `json:"longpoll_url"`
	}

	if err := json.Unmarshal(resp.Body.Bytes(), &relayResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(relayResp.RelayServers) == 0 {
		t.Error("Expected at least one relay server")
	}
	if relayResp.WebsocketURL == "" {
		t.Error("Expected websocket_url to be set")
	}
}

// TestPunchSessionExpiry tests that expired sessions are handled
func TestPunchSessionExpiry(t *testing.T) {
	setPeerStoreForTest(newMemoryPeerStore(peerTTL))
	punchSessionsMu.Lock()
	punchSessions = make(map[string]*PunchSession)
	// Add an expired session
	punchSessions["expired-session"] = &PunchSession{
		SessionID:   "expired-session",
		InitiatorID: peerAUUID,
		TargetID:    peerBUUID,
		Status:      "pending",
		ExpiresAt:   timeNow().Add(-1 * time.Second), // Already expired
	}
	punchSessionsMu.Unlock()

	router := setupTestRouter()

	// Register peer
	registerReq := map[string]any{
		"peer_id": peerAUUID,
		"endpoints": []map[string]any{
			{"protocol": "tcp", "host": "1.2.3.4", "port": 12345},
		},
	}
	body, _ := json.Marshal(registerReq)
	req := newDeviceRequestWithUUID("POST", "/p2p/rendezvous/register", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var regResp struct {
		Token string `json:"token"`
	}
	json.Unmarshal(resp.Body.Bytes(), &regResp)

	// Try to exchange with expired session
	exchangeReq := map[string]any{
		"session_id": "expired-session",
		"peer_id":    peerAUUID,
		"token":      regResp.Token,
		"success":    true,
	}

	body, _ = json.Marshal(exchangeReq)
	req = newDeviceRequestWithUUID("POST", "/p2p/punch/exchange", peerAUUID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusGone {
		t.Errorf("Expected 410 Gone for expired session, got %d", resp.Code)
	}
}

// Helper for time mocking in tests
func timeNow() time.Time {
	return time.Now()
}
