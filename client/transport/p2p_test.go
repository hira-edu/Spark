package transport

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestP2PMetricsRecording(t *testing.T) {
	// Reset metrics before test
	P2PMetrics.Reset()

	// Record some metrics
	P2PMetrics.RecordP2PAttempt()
	P2PMetrics.RecordP2PAttempt()
	P2PMetrics.RecordP2PSuccess(100 * time.Millisecond)
	P2PMetrics.RecordP2PFailure()
	P2PMetrics.RecordRelayFallback()
	P2PMetrics.RecordRelaySuccess()
	P2PMetrics.RecordNATType(NATTypeRestrictedCone)
	P2PMetrics.RecordNATType(NATTypeRestrictedCone)
	P2PMetrics.RecordNATType(NATTypeSymmetric)

	// Get snapshot
	snapshot := P2PMetrics.Snapshot()

	// Verify counts
	if snapshot.P2PAttempts != 2 {
		t.Errorf("Expected 2 P2P attempts, got %d", snapshot.P2PAttempts)
	}
	if snapshot.P2PSuccesses != 1 {
		t.Errorf("Expected 1 P2P success, got %d", snapshot.P2PSuccesses)
	}
	if snapshot.P2PFailures != 1 {
		t.Errorf("Expected 1 P2P failure, got %d", snapshot.P2PFailures)
	}
	if snapshot.RelayFallbacks != 1 {
		t.Errorf("Expected 1 relay fallback, got %d", snapshot.RelayFallbacks)
	}
	if snapshot.RelaySuccesses != 1 {
		t.Errorf("Expected 1 relay success, got %d", snapshot.RelaySuccesses)
	}

	// Verify success rate calculation
	expectedRate := 50.0 // 1 success / 2 attempts * 100
	if snapshot.P2PSuccessRate != expectedRate {
		t.Errorf("Expected P2P success rate of %.1f%%, got %.1f%%", expectedRate, snapshot.P2PSuccessRate)
	}

	// Verify NAT type distribution
	if snapshot.NATTypeDistribution["RestrictedCone"] != 2 {
		t.Errorf("Expected 2 RestrictedCone NATs, got %d", snapshot.NATTypeDistribution["RestrictedCone"])
	}
	if snapshot.NATTypeDistribution["Symmetric"] != 1 {
		t.Errorf("Expected 1 Symmetric NAT, got %d", snapshot.NATTypeDistribution["Symmetric"])
	}

	// Verify average connect time
	if snapshot.AvgP2PConnectMs != 100.0 {
		t.Errorf("Expected avg connect time of 100ms, got %.1fms", snapshot.AvgP2PConnectMs)
	}
}

func TestP2PMetricsReset(t *testing.T) {
	// Record some metrics
	P2PMetrics.RecordP2PAttempt()
	P2PMetrics.RecordP2PSuccess(50 * time.Millisecond)
	P2PMetrics.RecordNATType(NATTypeOpen)

	// Reset
	P2PMetrics.Reset()

	// Verify all zeroed
	snapshot := P2PMetrics.Snapshot()
	if snapshot.P2PAttempts != 0 {
		t.Error("P2PAttempts should be 0 after reset")
	}
	if len(snapshot.NATTypeDistribution) != 0 {
		t.Error("NAT type distribution should be empty after reset")
	}
}

func TestNewP2PTransport(t *testing.T) {
	transport := NewP2PTransport(nil, "")

	if transport.Name() != "p2p" {
		t.Errorf("Expected transport name 'p2p', got '%s'", transport.Name())
	}

	if transport.Priority() != 5 {
		t.Errorf("Expected priority 5, got %d", transport.Priority())
	}

	if transport.natDetector == nil {
		t.Error("NAT detector should be initialized")
	}

	if transport.holePuncher == nil {
		t.Error("Hole puncher should be initialized")
	}
}

func TestTransportSelectorCreation(t *testing.T) {
	config := &Config{
		ServerURL: "https://example.com",
	}

	selector := NewTransportSelector(config)

	if selector.natDetector == nil {
		t.Error("NAT detector should be initialized")
	}

	if selector.p2pTransport == nil {
		t.Error("P2P transport should be initialized")
	}

	if len(selector.fallbackOrder) != 3 {
		t.Errorf("Expected 3 fallback transports, got %d", len(selector.fallbackOrder))
	}
}

func TestP2PConfigDefaults(t *testing.T) {
	config := &P2PConfig{
		PeerID:          "test-peer",
		RendezvousURL:   "https://example.com",
		FallbackToRelay: true,
	}

	if config.PeerID != "test-peer" {
		t.Error("PeerID should be set")
	}

	if !config.FallbackToRelay {
		t.Error("FallbackToRelay should be true")
	}
}

// TestConnectViaRelayNoServers tests that relay connection fails gracefully without servers
func TestConnectViaRelayNoServers(t *testing.T) {
	transport := NewP2PTransport(nil, "")

	config := &P2PConfig{
		PeerID:          "test-peer",
		FallbackToRelay: true,
		RelayServers:    []string{}, // No servers
		RendezvousURL:   "",         // No URL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := transport.connectViaRelay(ctx, config, "target-peer")
	if err == nil {
		t.Error("Expected error when no relay servers configured")
	}

	// Verify relay fallback was recorded
	snapshot := P2PMetrics.Snapshot()
	if snapshot.RelayFallbacks == 0 {
		t.Error("Relay fallback should be recorded")
	}
}

func TestP2PMetricsSnapshot(t *testing.T) {
	P2PMetrics.Reset()

	// Empty snapshot should have zero success rates
	snapshot := P2PMetrics.Snapshot()

	if snapshot.P2PSuccessRate != 0 {
		t.Errorf("Expected 0%% P2P success rate with no attempts, got %.1f%%", snapshot.P2PSuccessRate)
	}

	if snapshot.RelaySuccessRate != 0 {
		t.Errorf("Expected 0%% relay success rate with no fallbacks, got %.1f%%", snapshot.RelaySuccessRate)
	}

	if snapshot.AvgP2PConnectMs != 0 {
		t.Errorf("Expected 0ms avg connect time with no successes, got %.1fms", snapshot.AvgP2PConnectMs)
	}
}

func TestInitiatePunchSession(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/p2p/punch/initiate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body["initiator_id"] != "peer-a" || body["target_id"] != "peer-b" {
			t.Fatalf("unexpected payload: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_id": "session-1",
			"start_time": time.Now().Add(250 * time.Millisecond).UTC(),
			"target_endpoints": []map[string]any{
				{"protocol": "tcp", "host": "203.0.113.10", "port": 5500},
			},
			"target_nat_type": "FullCone",
			"can_punch":       true,
			"recommend_relay": false,
		})
	}))
	defer ts.Close()

	transport := NewP2PTransport(nil, "")
	transport.client = ts.Client()

	cfg := &P2PConfig{
		PeerID:        "peer-a",
		RendezvousURL: ts.URL,
	}

	resp, err := transport.initiatePunchSession(context.Background(), cfg, "peer-b", "token-123")
	if err != nil {
		t.Fatalf("initiatePunchSession failed: %v", err)
	}
	if resp.SessionID != "session-1" {
		t.Fatalf("unexpected session: %+v", resp)
	}
	if len(resp.TargetEndpoints) != 1 || resp.TargetEndpoints[0].Host != "203.0.113.10" {
		t.Fatalf("unexpected endpoints: %+v", resp.TargetEndpoints)
	}
}

func TestExchangePunchResultPayload(t *testing.T) {
	payloadCh := make(chan punchExchangePayload, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/p2p/punch/exchange" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload punchExchangePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		payloadCh <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := NewP2PTransport(nil, "")
	transport.client = ts.Client()

	cfg := &P2PConfig{
		PeerID:        "peer-a",
		RendezvousURL: ts.URL,
	}

	result := &HolePunchResult{
		Success:      true,
		AttemptCount: 2,
		Duration:     150 * time.Millisecond,
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP("10.0.0.5"),
			Port: 48000,
		},
		RemoteAddr: &net.TCPAddr{
			IP:   net.ParseIP("198.51.100.8"),
			Port: 55000,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	transport.exchangePunchResult(ctx, cfg, "session-1", "peer-a", "token", result, nil)

	select {
	case payload := <-payloadCh:
		if !payload.Success {
			t.Fatal("expected success payload")
		}
		if payload.LocalAddr == "" {
			t.Fatal("expected local addr to be set")
		}
		if payload.Metadata == nil {
			t.Fatal("expected metadata")
		}
		if got := payload.Metadata["attempts"]; got != float64(2) {
			t.Fatalf("unexpected attempts metadata: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for exchange payload")
	}
}

// TestSelectWithDetailsReturnsReason verifies the selector provides reasoning
func TestSelectWithDetailsReturnsReason(t *testing.T) {
	config := &Config{}
	selector := NewTransportSelector(config)

	// Note: This will try to contact STUN servers, so may timeout in isolated environments
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := selector.SelectWithDetails(ctx)
	if err != nil {
		t.Fatalf("SelectWithDetails failed: %v", err)
	}

	// Should have a transport selected
	if result.Transport == nil {
		t.Error("Expected a transport to be selected")
	}

	// Should have a reason
	if result.Reason == "" {
		t.Error("Expected selection reason to be set")
	}

	t.Logf("Selected transport: %s, Reason: %s, Fallback: %v",
		result.Transport.Name(), result.Reason, result.FallbackUsed)
}
