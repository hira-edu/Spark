package transport

import (
	"Rocket/client/common"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
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
	sendQueue   chan []byte // Already encrypted data from adapter
	recvQueue   chan []byte // Encrypted data to adapter
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
		sendQueue: make(chan []byte, 100),
		recvQueue: make(chan []byte, 100),
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
	secret, err := t.handshake(ctx, cfg.Key)
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
// Format: handshake.<uuid>.<key>.<domain>
// Response: TXT record with base32-encoded secret
func (t *DNSTransport) handshake(ctx context.Context, key string) ([]byte, error) {
	query := fmt.Sprintf("handshake.%s.%s.%s", t.uuid, key, t.domain)

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
			encData, err := t.poll()
			if err != nil {
				continue
			}

			if len(encData) > 0 {
				select {
				case t.recvQueue <- encData:
				case <-t.ctx.Done():
					return
				}
			}
		}
	}
}

// computeHMAC computes HMAC-SHA256 signature
// HMAC = HMAC-SHA256(secret, operation+nonce+data+uuid)
func (t *DNSTransport) computeHMAC(operation, nonce, data string) string {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(operation))
	mac.Write([]byte(nonce))
	mac.Write([]byte(data))
	mac.Write([]byte(t.uuid))
	return hex.EncodeToString(mac.Sum(nil))
}

// poll makes a DNS query to check for encrypted messages
// Format: poll.<nonce>.<hmac>.<uuid>.<domain>
// Response: TXT record with base32-encoded encrypted data
func (t *DNSTransport) poll() ([]byte, error) {
	// Generate nonce (Unix timestamp)
	nonce := strconv.FormatInt(time.Now().Unix(), 10)

	// Compute HMAC for replay protection
	hmacSig := t.computeHMAC("poll", nonce, "")

	query := fmt.Sprintf("poll.%s.%s.%s.%s", nonce, hmacSig, t.uuid, t.domain)

	pollCtx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer cancel()

	txtRecords, err := t.resolver.LookupTXT(pollCtx, query)
	if err != nil {
		return nil, err
	}

	if len(txtRecords) == 0 {
		return nil, nil // No messages
	}

	// Parse encrypted data from TXT records
	// Server sends base32-encoded encrypted data
	for _, record := range txtRecords {
		// Decode base32
		encData, err := decodeBase32(record)
		if err != nil {
			continue
		}

		// Return encrypted data as-is (common.Conn will decrypt)
		return encData, nil
	}

	return nil, nil
}

// sendLoop sends queued encrypted bytes via DNS
func (t *DNSTransport) sendLoop() {
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
				time.Sleep(1 * time.Second)
			}
		}
	}
}

// send sends encrypted bytes via DNS query with proper chunking
// Format: send.<nonce>.<seq>.<chunk>.<totalChunks>.<data>.<hmac>.<uuid>.<domain>
func (t *DNSTransport) send(encData []byte) error {
	// Encode encrypted data to base32 (DNS-safe)
	encoded := encodeBase32(encData)

	// Chunk data to fit in DNS labels
	chunks := chunkData(encoded, dnsChunkSize)

	t.mu.Lock()
	seq := t.seq
	t.seq++
	t.mu.Unlock()

	totalChunks := len(chunks)

	// Generate nonce (Unix timestamp) - reuse for all chunks in this sequence
	nonce := strconv.FormatInt(time.Now().Unix(), 10)

	// Send each chunk as a separate DNS query
	for i, chunk := range chunks {
		// Compute HMAC including seq/chunk to prevent reordering
		// Must match server format: seq:chunk:totalChunks:data
		hmacData := fmt.Sprintf("%d:%d:%d:%s", seq, i, totalChunks, chunk)
		hmacSig := t.computeHMAC("send", nonce, hmacData)

		// Build query: send.<nonce>.<seq>.<chunk>.<totalChunks>.<data>.<hmac>.<uuid>.<domain>
		query := fmt.Sprintf("send.%s.%d.%d.%d.%s.%s.%s.%s",
			nonce, seq, i, totalChunks, chunk, hmacSig, t.uuid, t.domain)

		// Validate DNS name length
		if len(query) > maxDNSNameLength {
			return fmt.Errorf("DNS query too long: %d bytes", len(query))
		}

		sendCtx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
		// Make DNS query (we don't care about the response for sends)
		_, _ = t.resolver.LookupTXT(sendCtx, query)
		cancel()

		// Small delay between chunks to avoid rate limiting
		if i < len(chunks)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil
}

// createConnWrapper creates a common.Conn wrapper for DNS tunneling
func (t *DNSTransport) createConnWrapper() *common.Conn {
	adapter := &DNSAdapter{
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
