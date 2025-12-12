package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDefaultHolePunchConfig(t *testing.T) {
	config := DefaultHolePunchConfig()

	if config.PunchAttempts != 5 {
		t.Errorf("Expected 5 punch attempts, got %d", config.PunchAttempts)
	}
	if config.PunchTimeout != 3*time.Second {
		t.Errorf("Expected 3s punch timeout, got %v", config.PunchTimeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("Expected 3 max retries, got %d", config.MaxRetries)
	}
}

func TestNewHolePuncher(t *testing.T) {
	// Test with nil config (should use defaults)
	puncher := NewHolePuncher(nil)
	if puncher.config.PunchAttempts != 5 {
		t.Error("Expected default config to be used")
	}

	// Test with custom config
	customConfig := &HolePunchConfig{
		PunchAttempts: 10,
		PunchTimeout:  5 * time.Second,
	}
	puncher = NewHolePuncher(customConfig)
	if puncher.config.PunchAttempts != 10 {
		t.Error("Expected custom config to be used")
	}
}

func TestHolePuncherSetLocalPort(t *testing.T) {
	puncher := NewHolePuncher(nil)

	puncher.SetLocalPort(12345)
	if puncher.GetBoundPort() != 12345 {
		t.Errorf("Expected port 12345, got %d", puncher.GetBoundPort())
	}
}

// TestHolePunchLocalLoopback tests hole punching against localhost
// This validates the SO_REUSEADDR socket option works
func TestHolePunchLocalLoopback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Start a simple TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	t.Logf("Test server listening on %s", serverAddr)

	// Accept connections in background
	serverConnCh := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serverConnCh <- conn
	}()

	// Create hole puncher with short timeouts for testing
	config := &HolePunchConfig{
		PunchAttempts: 3,
		PunchTimeout:  2 * time.Second,
		RetryDelay:    100 * time.Millisecond,
		MaxRetries:    2,
	}
	puncher := NewHolePuncher(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt to punch to the server (this is a regular connect, not real hole punch)
	result, err := puncher.Punch(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Punch failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got failure: %v", result.Error)
	}

	if result.Conn == nil {
		t.Error("Expected connection to be established")
	} else {
		result.Conn.Close()
	}

	t.Logf("Punch result: success=%v, duration=%v, attempts=%d",
		result.Success, result.Duration, result.AttemptCount)

	// Clean up server connection if one was accepted
	select {
	case conn := <-serverConnCh:
		conn.Close()
	default:
	}
}

// TestHolePunchAsync tests the async punch interface
func TestHolePunchAsync(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Start a simple TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)

	// Accept in background
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	config := &HolePunchConfig{
		PunchAttempts: 2,
		PunchTimeout:  1 * time.Second,
		MaxRetries:    1,
	}
	puncher := NewHolePuncher(config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use async interface
	resultCh := puncher.PunchAsync(ctx, serverAddr)

	select {
	case result := <-resultCh:
		if !result.Success {
			t.Errorf("Async punch failed: %v", result.Error)
		}
		if result.Conn != nil {
			result.Conn.Close()
		}
	case <-time.After(10 * time.Second):
		t.Error("Async punch timed out")
	}
}

// TestHolePunchContextCancellation tests that context cancellation works
func TestHolePunchContextCancellation(t *testing.T) {
	// Create a puncher targeting an unreachable address
	config := &HolePunchConfig{
		PunchAttempts: 3,
		PunchTimeout:  5 * time.Second,
		MaxRetries:    3,
	}
	puncher := NewHolePuncher(config)

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Try to punch to an unreachable address
	unreachableAddr := &net.TCPAddr{
		IP:   net.ParseIP("10.255.255.1"),
		Port: 65535,
	}

	_, err := puncher.Punch(ctx, unreachableAddr)
	if err == nil {
		t.Error("Expected error from cancelled context")
	}
}

// TestCreateReuseListener tests the SO_REUSEADDR listener creation
func TestCreateReuseListener(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	puncher := NewHolePuncher(nil)

	localAddr := &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 0, // Auto-assign
	}

	listener, port, err := puncher.createReuseListener(localAddr)
	if err != nil {
		t.Fatalf("Failed to create reuse listener: %v", err)
	}
	defer listener.Close()

	if port == 0 {
		t.Error("Expected non-zero port")
	}

	t.Logf("Created reuse listener on port %d", port)

	// Verify we can create another listener on the same port with reuse
	// (This tests SO_REUSEADDR is working)
	localAddr.Port = port
	listener2, _, err := puncher.createReuseListener(localAddr)
	if err != nil {
		// This is expected on some platforms
		t.Logf("Second listener creation failed (expected on some platforms): %v", err)
	} else {
		listener2.Close()
		t.Log("Successfully created second listener with port reuse")
	}
}

// TestCoordinatedPunchTiming tests that coordinated punch waits for start time
func TestCoordinatedPunchTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	// Start a simple TCP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)

	// Accept in background
	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	config := &HolePunchConfig{
		PunchAttempts: 2,
		PunchTimeout:  2 * time.Second,
		MaxRetries:    1,
	}
	puncher := NewHolePuncher(config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Schedule punch for 500ms in the future
	startTime := time.Now().Add(500 * time.Millisecond)
	beforePunch := time.Now()

	result, err := puncher.CoordinatedPunch(ctx, serverAddr, startTime)

	// Verify timing
	elapsed := time.Since(beforePunch)
	if elapsed < 400*time.Millisecond {
		t.Errorf("Coordinated punch started too early: %v", elapsed)
	}

	if err == nil && result.Success && result.Conn != nil {
		result.Conn.Close()
	}
}
