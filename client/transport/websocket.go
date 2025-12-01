package transport

import (
	"Spark/client/common"
	"Spark/client/config"
	"Spark/utils"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	ws "github.com/gorilla/websocket"
)

// WebSocketTransport implements WebSocket (WS/WSS) transport
type WebSocketTransport struct {
	secure bool // true = WSS, false = WS
	conn   *ws.Conn
}

// NewWebSocketTransport creates a new WebSocket transport
// secure: true for WSS, false for WS
func NewWebSocketTransport(secure bool) *WebSocketTransport {
	return &WebSocketTransport{
		secure: secure,
	}
}

// Name returns the transport name
func (t *WebSocketTransport) Name() string {
	if t.secure {
		return "wss"
	}
	return "ws"
}

// Priority returns the priority level
func (t *WebSocketTransport) Priority() int {
	if t.secure {
		return 15 // WSS is preferred over WS
	}
	return 10 // WS is tried first (fastest)
}

// IsAvailable checks if WebSocket transport is available
func (t *WebSocketTransport) IsAvailable(ctx context.Context) bool {
	// WebSocket is always available
	return true
}

// Connect establishes a WebSocket connection
func (t *WebSocketTransport) Connect(ctx context.Context, cfg *Config) (*common.Conn, error) {
	// Build WebSocket URL
	wsURL, err := t.buildURL(cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	// Create dialer with TLS config
	dialer := &ws.Dialer{
		HandshakeTimeout: cfg.ConnectTimeout,
		TLSClientConfig:  t.buildTLSConfig(cfg),
	}

	// Build request headers with protocol mimicry
	headers := t.buildHeaders(cfg)

	// Dial WebSocket
	wsConn, wsResp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if wsResp != nil && wsResp.Body != nil {
			body, _ := io.ReadAll(wsResp.Body)
			_ = wsResp.Body.Close()

			// Check if blocked by firewall
			if wsResp.StatusCode == 403 || wsResp.StatusCode == 503 {
				return nil, fmt.Errorf("%w: status=%d body=%s", ErrTransportBlocked, wsResp.StatusCode, truncate(body, 256))
			}

			return nil, fmt.Errorf("websocket handshake failed: status=%d body=%s: %w", wsResp.StatusCode, truncate(body, 256), err)
		}
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}

	// Extract secret from response header
	if wsResp == nil {
		wsConn.Close()
		return nil, errors.New("no websocket response received")
	}

	header, find := wsResp.Header[`Secret`]
	if !find || len(header) == 0 {
		wsConn.Close()
		return nil, errors.New("no secret header in websocket response")
	}

	secret, err := hex.DecodeString(header[0])
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}

	// Store connection for cleanup
	t.conn = wsConn

	// Create common connection wrapper
	return common.CreateConn(wsConn, secret), nil
}

// Close closes the WebSocket connection
func (t *WebSocketTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// buildURL converts base URL to WebSocket URL
func (t *WebSocketTransport) buildURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Convert http(s) to ws(s)
	if t.secure {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}

	// Append /ws path
	u.Path = strings.TrimSuffix(u.Path, "/") + "/ws"

	return u.String(), nil
}

// buildTLSConfig creates TLS configuration for WebSocket
func (t *WebSocketTransport) buildTLSConfig(cfg *Config) *tls.Config {
	if !t.secure {
		return nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	// Apply protocol mimicry if enabled
	if cfg.Mimicry != nil && cfg.Mimicry.Enabled {
		// Mimic modern browser cipher suites
		tlsConfig.CipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}

		// Mimic browser curve preferences
		tlsConfig.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		}
	}

	return tlsConfig
}

// buildHeaders creates HTTP headers for WebSocket handshake
func (t *WebSocketTransport) buildHeaders(cfg *Config) http.Header {
	headers := http.Header{}

	// Required headers
	headers.Set("UUID", cfg.UUID)
	headers.Set("Key", cfg.Key)

	// Protocol mimicry headers
	if cfg.Mimicry != nil && cfg.Mimicry.Enabled {
		// Rotate through user agents
		if len(cfg.Mimicry.UserAgents) > 0 {
			ua := cfg.Mimicry.UserAgents[rand.Intn(len(cfg.Mimicry.UserAgents))]
			headers.Set("User-Agent", ua)
		} else {
			// Default Chrome user agent
			headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		}

		// Mimic browser headers
		headers.Set("Accept", "*/*")
		headers.Set("Accept-Language", "en-US,en;q=0.9")
		headers.Set("Accept-Encoding", "gzip, deflate, br")
		headers.Set("Cache-Control", "no-cache")
		headers.Set("Pragma", "no-cache")

		// Add custom headers
		for k, v := range cfg.Mimicry.Headers {
			headers.Set(k, v)
		}
	}

	return headers
}

// truncate truncates byte slice to max length
func truncate(data []byte, max int) string {
	if len(data) == 0 {
		return "<empty>"
	}
	if len(data) > max {
		return string(data[:max]) + "..."
	}
	return string(data)
}
