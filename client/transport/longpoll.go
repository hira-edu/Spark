package transport

import (
	"Rocket/client/common"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LongPollingTransport implements HTTP long polling transport
// Falls back when WebSocket is blocked
type LongPollingTransport struct {
	client      *http.Client
	baseURL     string
	uuid        string
	key         string
	secret      []byte
	ctx         context.Context
	cancel      context.CancelFunc
	sendQueue   chan []byte // Already encrypted data from adapter
	recvQueue   chan []byte // Encrypted data to adapter
	mu          sync.Mutex
	connected   bool
}

// NewLongPollingTransport creates a new long polling transport
func NewLongPollingTransport() *LongPollingTransport {
	return &LongPollingTransport{
		sendQueue: make(chan []byte, 100),
		recvQueue: make(chan []byte, 100),
	}
}

// Name returns the transport name
func (t *LongPollingTransport) Name() string {
	return "long-polling"
}

// Priority returns the priority level
func (t *LongPollingTransport) Priority() int {
	return 30 // Lower priority than WebSocket and QUIC
}

// IsAvailable checks if long polling is available
func (t *LongPollingTransport) IsAvailable(ctx context.Context) bool {
	// Long polling is always available if HTTP works
	return true
}

// Connect establishes a long polling connection
func (t *LongPollingTransport) Connect(ctx context.Context, cfg *Config) (*common.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Parse base URL
	baseURL := strings.TrimSuffix(cfg.ServerURL, "/")
	pollPath := cfg.LongPollPath
	if pollPath == "" {
		pollPath = "/api/longpoll"
	}

	t.baseURL = baseURL + pollPath
	t.uuid = cfg.UUID
	t.key = cfg.Key

	// Create HTTP client with TLS config
	t.client = &http.Client{
		Timeout: cfg.LongPollTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.InsecureSkipVerify,
				MinVersion:         tls.VersionTLS12,
			},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
		},
	}

	// Initial handshake to get secret
	secret, err := t.handshake(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("long polling handshake failed: %w", err)
	}

	t.secret = secret
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.connected = true

	// Start polling loop
	go t.pollLoop()

	// Start send loop
	go t.sendLoop()

	// Create connection wrapper
	return t.createConnWrapper(), nil
}

// handshake performs initial handshake to authenticate and get secret
func (t *LongPollingTransport) handshake(ctx context.Context, cfg *Config) ([]byte, error) {
	u := t.baseURL + "/handshake"

	req, err := http.NewRequestWithContext(ctx, "POST", u, nil)
	if err != nil {
		return nil, err
	}

	// Set authentication headers
	req.Header.Set("UUID", t.uuid)
	req.Header.Set("Key", t.key)
	req.Header.Set("X-Transport", "longpoll")

	// Apply protocol mimicry
	t.applyMimicry(req, cfg)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 503 {
		return nil, ErrTransportBlocked
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("handshake failed: status=%d body=%s", resp.StatusCode, truncate(body, 256))
	}

	// Extract secret from header
	secretHex := resp.Header.Get("Secret")
	if secretHex == "" {
		return nil, errors.New("no secret in handshake response")
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret: %w", err)
	}

	return secret, nil
}

// pollLoop continuously polls server for incoming messages
func (t *LongPollingTransport) pollLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Poll for messages with timeout
		encryptedData, err := t.poll()
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}

		// Queue received encrypted bytes
		if len(encryptedData) > 0 {
			select {
			case t.recvQueue <- encryptedData:
			case <-t.ctx.Done():
				return
			}
		}
	}
}

// poll makes a single poll request and returns encrypted data
func (t *LongPollingTransport) poll() ([]byte, error) {
	u := t.baseURL + "/poll"

	req, err := http.NewRequestWithContext(t.ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("UUID", t.uuid)
	req.Header.Set("Secret", hex.EncodeToString(t.secret))

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 204 {
		// No messages
		return nil, nil
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("poll failed: status=%d", resp.StatusCode)
	}

	// Read encrypted response and return as-is
	// Server sends encrypted data, we pass it to adapter unchanged
	encData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return encData, nil
}

// sendLoop sends queued encrypted bytes to server
func (t *LongPollingTransport) sendLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case encData := <-t.sendQueue:
			if err := t.send(encData); err != nil {
				// Re-queue on failure
				select {
				case t.sendQueue <- encData:
				default:
					// Queue full, drop message
				}
				time.Sleep(1 * time.Second)
			}
		}
	}
}

// send sends encrypted bytes to server
func (t *LongPollingTransport) send(encData []byte) error {
	u := t.baseURL + "/send"

	// Send encrypted data as-is (already encrypted by common.Conn)
	req, err := http.NewRequestWithContext(t.ctx, "POST", u, bytes.NewReader(encData))
	if err != nil {
		return err
	}

	req.Header.Set("UUID", t.uuid)
	req.Header.Set("Secret", hex.EncodeToString(t.secret))
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("send failed: status=%d", resp.StatusCode)
	}

	return nil
}

// applyMimicry applies protocol mimicry headers
func (t *LongPollingTransport) applyMimicry(req *http.Request, cfg *Config) {
	if cfg.Mimicry == nil || !cfg.Mimicry.Enabled {
		return
	}

	// Rotate through user agents
	if len(cfg.Mimicry.UserAgents) > 0 {
		ua := cfg.Mimicry.UserAgents[rand.Intn(len(cfg.Mimicry.UserAgents))]
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	}

	// Mimic browser headers
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	// Add custom headers
	for k, v := range cfg.Mimicry.Headers {
		req.Header.Set(k, v)
	}
}

// createConnWrapper creates a common.Conn wrapper for long polling
func (t *LongPollingTransport) createConnWrapper() *common.Conn {
	// Create adapter that bridges common.Conn and long polling transport
	adapter := &LongPollingAdapter{
		transport: t,
	}

	return common.CreateConnFromAdapter(adapter, t.secret)
}

// Close closes the long polling transport
func (t *LongPollingTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected {
		return nil
	}

	t.connected = false
	if t.cancel != nil {
		t.cancel()
	}

	return nil
}
