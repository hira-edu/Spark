package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNATTypeString(t *testing.T) {
	tests := []struct {
		natType  NATType
		expected string
	}{
		{NATTypeUnknown, "Unknown"},
		{NATTypeOpen, "Open"},
		{NATTypeFullCone, "FullCone"},
		{NATTypeRestrictedCone, "RestrictedCone"},
		{NATTypePortRestricted, "PortRestricted"},
		{NATTypeSymmetric, "Symmetric"},
	}

	for _, tt := range tests {
		if got := tt.natType.String(); got != tt.expected {
			t.Errorf("NATType(%d).String() = %s, want %s", tt.natType, got, tt.expected)
		}
	}
}

func TestNATTypeCanHolePunch(t *testing.T) {
	tests := []struct {
		natType  NATType
		canPunch bool
	}{
		{NATTypeUnknown, false},
		{NATTypeOpen, true},
		{NATTypeFullCone, true},
		{NATTypeRestrictedCone, true},
		{NATTypePortRestricted, true},
		{NATTypeSymmetric, false},
	}

	for _, tt := range tests {
		if got := tt.natType.CanHolePunch(); got != tt.canPunch {
			t.Errorf("NATType(%s).CanHolePunch() = %v, want %v", tt.natType, got, tt.canPunch)
		}
	}
}

func TestNewNATDetector(t *testing.T) {
	// Test with default servers
	detector := NewNATDetector(nil)
	if len(detector.stunServers) != len(DefaultSTUNServers) {
		t.Errorf("Expected default STUN servers, got %d servers", len(detector.stunServers))
	}

	// Test with custom servers
	customServers := []string{"stun.example.com:3478"}
	detector = NewNATDetector(customServers)
	if len(detector.stunServers) != 1 {
		t.Errorf("Expected 1 custom STUN server, got %d", len(detector.stunServers))
	}
}

func TestNATDetectorCaching(t *testing.T) {
	detector := NewNATDetector(nil)

	// Mock a result
	mockResult := &NATInfo{
		Type:       NATTypeRestrictedCone,
		ExternalIP: net.ParseIP("1.2.3.4"),
		DetectedAt: time.Now(),
	}
	detector.lastResult = mockResult

	// Test GetLastResult
	result := detector.GetLastResult()
	if result == nil || result.Type != NATTypeRestrictedCone {
		t.Error("GetLastResult should return cached result")
	}
}

func TestClassifyNAT(t *testing.T) {
	detector := NewNATDetector(nil)

	tests := []struct {
		name     string
		results  []stunResult
		expected NATType
	}{
		{
			name:     "no results",
			results:  []stunResult{},
			expected: NATTypeUnknown,
		},
		{
			name: "public IP (no NAT)",
			results: []stunResult{
				{
					localIP:      net.ParseIP("1.2.3.4"),
					externalIP:   net.ParseIP("1.2.3.4"),
					localPort:    12345,
					externalPort: 12345,
				},
			},
			expected: NATTypeOpen,
		},
		{
			name: "single result (assume cone)",
			results: []stunResult{
				{
					localIP:      net.ParseIP("192.168.1.100"),
					externalIP:   net.ParseIP("1.2.3.4"),
					localPort:    12345,
					externalPort: 54321,
				},
			},
			expected: NATTypeRestrictedCone,
		},
		{
			name: "consistent external port (cone NAT)",
			results: []stunResult{
				{
					localIP:      net.ParseIP("192.168.1.100"),
					externalIP:   net.ParseIP("1.2.3.4"),
					localPort:    12345,
					externalPort: 54321,
				},
				{
					localIP:      net.ParseIP("192.168.1.100"),
					externalIP:   net.ParseIP("1.2.3.4"),
					localPort:    12345,
					externalPort: 54321,
				},
			},
			expected: NATTypeRestrictedCone,
		},
		{
			name: "different external ports (symmetric NAT)",
			results: []stunResult{
				{
					localIP:      net.ParseIP("192.168.1.100"),
					externalIP:   net.ParseIP("1.2.3.4"),
					localPort:    12345,
					externalPort: 54321,
				},
				{
					localIP:      net.ParseIP("192.168.1.100"),
					externalIP:   net.ParseIP("1.2.3.4"),
					localPort:    12345,
					externalPort: 54322, // Different port!
				},
			},
			expected: NATTypeSymmetric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := detector.classifyNAT(context.Background(), tt.results)
			if info.Type != tt.expected {
				t.Errorf("classifyNAT() = %s, want %s", info.Type, tt.expected)
			}
		})
	}
}

// Integration test (requires network access)
func TestNATDetectorIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	detector := NewNATDetector(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Try quick detection (just needs one STUN server)
	info, err := detector.QuickDetect(ctx)
	if err != nil {
		t.Skipf("STUN servers unreachable (expected in isolated environments): %v", err)
	}

	t.Logf("Detected external IP: %s:%d", info.ExternalIP, info.ExternalPort)
	t.Logf("Local IP: %s:%d", info.LocalIP, info.LocalPort)
	t.Logf("Latency: %v", info.Latency)

	// Verify we got valid results
	if info.ExternalIP == nil {
		t.Error("Expected external IP to be detected")
	}
}
