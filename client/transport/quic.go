package transport

import (
	"Rocket/client/common"
	"context"
	"crypto/tls"
	"encoding/binary"
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
	conn      *quic.Conn
	stream    *quic.Stream
	secret    []byte
	ctx       context.Context
	cancel    context.CancelFunc
	sendQueue chan []byte // Already encrypted data from adapter
	recvQueue chan []byte // Encrypted data to adapter
	mu        sync.Mutex
	connected bool
}

// NewQUICTransport creates a new QUIC transport
func NewQUICTransport() *QUICTransport {
	return &QUICTransport{
		sendQueue: make(chan []byte, 100),
		recvQueue: make(chan []byte, 100),
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
		NextProtos:         []string{"rocket-quic", "h3"}, // ALPN
		MinVersion:         tls.VersionTLS13,              // QUIC requires TLS 1.3
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

	// Write handshake frame (QUIC streams are byte streams; we must frame messages)
	if err := writeQUICFrame(t.stream, data); err != nil {
		return nil, err
	}

	// Read response with timeout
	t.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer t.stream.SetReadDeadline(time.Time{})

	respPayload, err := readQUICFrame(t.stream, 4096)
	if err != nil {
		return nil, err
	}

	// Parse response
	var response map[string]string
	if err := json.Unmarshal(respPayload, &response); err != nil {
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

// readLoop continuously reads encrypted bytes from QUIC stream
func (t *QUICTransport) readLoop() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		// Read framed message with timeout
		t.stream.SetReadDeadline(time.Now().Add(90 * time.Second))
		payload, err := readQUICFrame(t.stream, common.MaxMessageSize)
		t.stream.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF || errors.Is(err, quic.Err0RTTRejected) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		select {
		case t.recvQueue <- payload:
		case <-t.ctx.Done():
			return
		}
	}
}

// sendLoop sends queued encrypted bytes over QUIC stream
func (t *QUICTransport) sendLoop() {
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
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

// send sends encrypted bytes over QUIC stream
func (t *QUICTransport) send(encData []byte) error {
	// Write framed data as-is (common.Conn will handle JSON/binary payloads)
	t.stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer t.stream.SetWriteDeadline(time.Time{})

	return writeQUICFrame(t.stream, encData)
}

// createConnWrapper creates a common.Conn wrapper for QUIC
func (t *QUICTransport) createConnWrapper() *common.Conn {
	adapter := &QUICAdapter{
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

func readQUICFrame(r io.Reader, maxSize int) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > uint32(maxSize) {
		return nil, fmt.Errorf("invalid frame size: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeQUICFrame(w io.Writer, payload []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if err := writeAll(w, lenBuf[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
