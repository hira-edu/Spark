package transport

import (
	"Spark/client/common"
	"Spark/modules"
	"Spark/utils"
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSTransport implements DNS tunneling transport
// Works even in highly restrictive environments where only DNS is allowed
type DNSTransport struct {
	resolver    *net.Resolver
	domain      string
	uuid        string
	secret      []byte
	ctx         context.Context
	cancel      context.CancelFunc
	sendQueue   chan *modules.Packet
	recvQueue   chan *modules.Packet
	mu          sync.Mutex
	connected   bool
	seq         uint32 // Sequence number for requests
}

const (
	// DNS label max length is 63 bytes
	maxLabelLength = 63
	// DNS name max length is 253 bytes
	maxDNSNameLength = 253
	// Chunk size for data encoding (accounting for base32 expansion)
	dnsChunkSize = 32
)

// NewDNSTransport creates a new DNS tunneling transport
func NewDNSTransport() *DNSTransport {
	return &DNSTransport{
		sendQueue: make(chan *modules.Packet, 100),
		recvQueue: make(chan *modules.Packet, 100),
	}
}

// Name returns the transport name
func (t *DNSTransport) Name() string {
	return "dns"
}

// Priority returns the priority level
func (t *DNSTransport) Priority() int {
	return 40 // Lowest priority (slowest, last resort)
}

// IsAvailable checks if DNS tunneling is available
func (t *DNSTransport) IsAvailable(ctx context.Context) bool {
	// Check if we can resolve DNS queries
	if t.resolver == nil {
		return false
	}

	// Quick DNS test
	testCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err := t.resolver.LookupHost(testCtx, "google.com")
	return err == nil
}

// Connect establishes a DNS tunneling connection
func (t *DNSTransport) Connect(ctx context.Context, cfg *Config) (*common.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if cfg.DNSDomain == "" {
		return nil, errors.New("DNS domain not configured")
	}

	t.domain = cfg.DNSDomain
	t.uuid = cfg.UUID

	// Create custom DNS resolver
	dnsServer := cfg.DNSServer
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53" // Default to Google DNS
	}

	t.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	// Perform handshake via DNS TXT record
	secret, err := t.handshake(ctx)
	if err != nil {
		return nil, fmt.Errorf("DNS handshake failed: %w", err)
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

// handshake performs DNS-based handshake
// Format: handshake.<uuid>.<domain>
// Response: TXT record with hex-encoded secret
func (t *DNSTransport) handshake(ctx context.Context) ([]byte, error) {
	query := fmt.Sprintf("handshake.%s.%s", t.uuid, t.domain)

	txtRecords, err := t.resolver.LookupTXT(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("DNS handshake query failed: %w", err)
	}

	if len(txtRecords) == 0 {
		return nil, errors.New("no TXT records in handshake response")
	}

	// Parse secret from first TXT record
	// Format: "secret=<hex>"
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "secret=") {
			secretHex := strings.TrimPrefix(record, "secret=")
			secret, err := decodeBase32(secretHex)
			if err != nil {
				return nil, fmt.Errorf("invalid secret in TXT record: %w", err)
			}
			return secret, nil
		}
	}

	return nil, errors.New("no secret found in TXT records")
}

// pollLoop polls for incoming messages via DNS
func (t *DNSTransport) pollLoop() {
	ticker := time.NewTicker(2 * time.Second) // Poll every 2 seconds
	defer ticker.Stop()

	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			messages, err := t.poll()
			if err != nil {
				continue
			}

			for _, msg := range messages {
				select {
				case t.recvQueue <- msg:
				case <-t.ctx.Done():
					return
				}
			}
		}
	}
}

// poll makes a DNS query to check for messages
// Format: poll.<seq>.<uuid>.<domain>
// Response: TXT record with base32-encoded encrypted JSON
func (t *DNSTransport) poll() ([]*modules.Packet, error) {
	t.mu.Lock()
	seq := t.seq
	t.seq++
	t.mu.Unlock()

	query := fmt.Sprintf("poll.%d.%s.%s", seq, t.uuid, t.domain)

	pollCtx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer cancel()

	txtRecords, err := t.resolver.LookupTXT(pollCtx, query)
	if err != nil {
		return nil, err
	}

	if len(txtRecords) == 0 {
		return nil, nil // No messages
	}

	// Parse messages from TXT records
	var messages []*modules.Packet
	for _, record := range txtRecords {
		// Decode base32
		encData, err := decodeBase32(record)
		if err != nil {
			continue
		}

		// Decrypt
		data, err := utils.Decrypt(encData, t.secret)
		if err != nil {
			continue
		}

		// Unmarshal
		var msg modules.Packet
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		messages = append(messages, &msg)
	}

	return messages, nil
}

// sendLoop sends queued messages via DNS
func (t *DNSTransport) sendLoop() {
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
				time.Sleep(1 * time.Second)
			}
		}
	}
}

// send sends a message via DNS query
// Large messages are chunked across multiple DNS queries
// Format: send.<seq>.<chunk>.<data>.<uuid>.<domain>
func (t *DNSTransport) send(msg *modules.Packet) error {
	// Marshal message
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Encrypt
	encData, err := utils.Encrypt(data, t.secret)
	if err != nil {
		return err
	}

	// Encode to base32 (DNS-safe)
	encoded := encodeBase32(encData)

	// Chunk data to fit in DNS labels
	chunks := chunkData(encoded, dnsChunkSize)

	t.mu.Lock()
	seq := t.seq
	t.seq++
	t.mu.Unlock()

	// Send each chunk as a separate DNS query
	for i, chunk := range chunks {
		query := fmt.Sprintf("send.%d.%d.%s.%s.%s", seq, i, chunk, t.uuid, t.domain)

		// Validate DNS name length
		if len(query) > maxDNSNameLength {
			return fmt.Errorf("DNS query too long: %d bytes", len(query))
		}

		sendCtx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
		// Make DNS query (we don't care about the response for sends)
		_, _ = t.resolver.LookupTXT(sendCtx, query)
		cancel()

		// Small delay between chunks to avoid rate limiting
		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

// createConnWrapper creates a common.Conn wrapper for DNS tunneling
func (t *DNSTransport) createConnWrapper() *common.Conn {
	adapter := &dnsAdapter{
		transport: t,
	}
	return common.CreateConnFromAdapter(adapter, t.secret)
}

// Close closes the DNS transport
func (t *DNSTransport) Close() error {
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

// dnsAdapter adapts DNS tunneling to WebSocket-like interface
type dnsAdapter struct {
	transport *DNSTransport
}

// Helper functions

// encodeBase32 encodes data to base32 (DNS-safe, no padding)
func encodeBase32(data []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	return strings.ToLower(encoded) // DNS is case-insensitive
}

// decodeBase32 decodes base32-encoded data
func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(s)
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// chunkData splits data into chunks of specified size
func chunkData(data string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}
