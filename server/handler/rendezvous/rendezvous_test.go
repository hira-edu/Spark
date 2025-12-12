package rendezvous

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

const testDeviceUUID = "00112233445566778899aabbccddeeff"

func newDeviceRequest(method, path string, body io.Reader) *http.Request {
	return newDeviceRequestWithUUID(method, path, testDeviceUUID, body)
}

func newDeviceRequestWithUUID(method, path, uuid string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("UUID", uuid)
	req.Header.Set("Key", uuid)
	return req
}

func resetTestStore() *memoryPeerStore {
	store := newMemoryPeerStore(peerTTL)
	setPeerStoreForTest(store)
	return store
}

func testRouter() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	deviceGroup := r.Group("")
	deviceGroup.Use(DeviceAuthMiddleware())
	RegisterDeviceRoutes(deviceGroup)
	RegisterAdminRoutes(r.Group(""))
	return r
}

func TestMemoryPeerStoreLookup(t *testing.T) {
	reg := newMemoryPeerStore(peerTTL)
	record := &PeerRecord{
		PeerID:   "peerA",
		Token:    "token123",
		LastSeen: time.Now(),
	}
	if err := reg.Upsert(record); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	got, err := reg.Lookup("peerA", "token123")
	if err != nil {
		t.Fatalf("expected lookup success, got error: %v", err)
	}
	if got.PeerID != "peerA" {
		t.Fatalf("expected peerA, got %s", got.PeerID)
	}

	if err := reg.UpdateHeartbeat("peerA", "token123"); err != nil {
		t.Fatalf("expected heartbeat success, got %v", err)
	}
}

func TestMemoryPeerStoreLookupFailures(t *testing.T) {
	reg := newMemoryPeerStore(peerTTL)
	stale := &PeerRecord{
		PeerID:   "stale",
		Token:    "secret",
		LastSeen: time.Now().Add(-peerTTL * 2),
	}
	if err := reg.Upsert(stale); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	if _, err := reg.Lookup("missing", "secret"); err == nil {
		t.Fatal("expected lookup to fail for missing peer")
	}
	if _, err := reg.Lookup("stale", "badtoken"); err == nil {
		t.Fatal("expected lookup to fail for token mismatch")
	}
	if _, err := reg.Lookup("stale", "secret"); err == nil {
		t.Fatal("expected lookup to fail for expired peer")
	}
}

func TestRegisterAndRequestHandlers(t *testing.T) {
	resetTestStore()
	router := testRouter()

	registerBody := map[string]any{
		"peer_id": testDeviceUUID,
		"endpoints": []PeerEndpoint{{
			Protocol: "tcp",
			Host:     "203.0.113.10",
			Port:     21115,
		}},
		"metadata": map[string]string{"nat": "cone"},
	}
	body, _ := json.Marshal(registerBody)
	req := newDeviceRequest(http.MethodPost, "/p2p/rendezvous/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected register 200, got %d", resp.Code)
	}
	var registerResp registerPeerResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &registerResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}
	if registerResp.Token == "" {
		t.Fatalf("expected non-empty token")
	}

	requestBody := map[string]string{
		"peer_id": testDeviceUUID,
		"token":   registerResp.Token,
	}
	reqBytes, _ := json.Marshal(requestBody)
	req = newDeviceRequest(http.MethodPost, "/p2p/rendezvous/request", bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("expected request 200, got %d", resp.Code)
	}
	var payload struct {
		PeerID    string         `json:"peer_id"`
		Metadata  map[string]any `json:"metadata"`
		Endpoints []PeerEndpoint `json:"endpoints"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode request payload: %v", err)
	}
	if payload.PeerID != testDeviceUUID {
		t.Fatalf("expected %s, got %s", testDeviceUUID, payload.PeerID)
	}
	if len(payload.Endpoints) != 1 || payload.Endpoints[0].Host != "203.0.113.10" {
		t.Fatalf("unexpected endpoints payload: %+v", payload.Endpoints)
	}
}

func TestRegisterPeerHandlerValidatesEndpoints(t *testing.T) {
	resetTestStore()
	router := testRouter()

	registerBody := []byte(`{"peer_id":"peer-x","endpoints":[]}`)
	req := newDeviceRequest(http.MethodPost, "/p2p/rendezvous/register", bytes.NewReader(registerBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing endpoints, got %d", resp.Code)
	}
}

func TestHeartbeatHandlerUpdatesLastSeen(t *testing.T) {
	memStore := resetTestStore()
	router := testRouter()

	registerBody := map[string]any{
		"peer_id": testDeviceUUID,
		"endpoints": []PeerEndpoint{{
			Protocol: "tcp",
			Host:     "198.51.100.10",
			Port:     4000,
		}},
	}
	body, _ := json.Marshal(registerBody)
	req := newDeviceRequest(http.MethodPost, "/p2p/rendezvous/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	var registerResp registerPeerResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &registerResp); err != nil {
		t.Fatalf("failed to decode register response: %v", err)
	}
	peer, ok := memStore.get(testDeviceUUID)
	if !ok {
		t.Fatal("expected peer to exist after register")
	}
	prev := peer.LastSeen
	time.Sleep(10 * time.Millisecond)

	heartbeatBody := map[string]string{
		"peer_id": testDeviceUUID,
		"token":   registerResp.Token,
	}
	beatBytes, _ := json.Marshal(heartbeatBody)
	req = newDeviceRequest(http.MethodPost, "/p2p/rendezvous/heartbeat", bytes.NewReader(beatBytes))
	req.Header.Set("Content-Type", "application/json")
	resp = httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected heartbeat 204, got %d", resp.Code)
	}
	peerAfter, _ := memStore.get(testDeviceUUID)
	if !peerAfter.LastSeen.After(prev) {
		t.Fatalf("expected heartbeat to update LastSeen")
	}
}

func TestRequestHandlerErrors(t *testing.T) {
	resetTestStore()
	router := testRouter()

	body := []byte(`{"peer_id":"missing","token":"nope"}`)
	req := newDeviceRequest(http.MethodPost, "/p2p/rendezvous/request", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown peer, got %d", resp.Code)
	}
}
