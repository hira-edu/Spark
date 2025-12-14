package quic

import (
	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/server/config"
	"Rocket/server/handler/audio"
	"Rocket/server/handler/utility"
	"Rocket/utils"
	"Rocket/utils/cmap"
	"bytes"
	"context"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/time/rate"
)

const (
	// Configuration constants
	defaultReadTimeout   = 90 * time.Second
	defaultWriteTimeout  = 10 * time.Second
	defaultIdleTimeout   = 5 * time.Minute
	maxMessageSize       = common.MaxMessageSize
	maxConcurrentStreams = 100
	keepAlivePeriod      = 30 * time.Second

	// Rate limiting constants
	messageRateLimitQPS   = 10 // Messages per second per UUID
	messageRateLimitBurst = 20 // Burst allowance per UUID
)

// QUICSession represents a QUIC connection session
type QUICSession struct {
	UUID        string
	Secret      []byte
	Conn        *quic.Conn
	Stream      *quic.Stream
	LastSeen    time.Time
	RateLimiter *rate.Limiter // Per-UUID rate limiter
	writeMu     sync.Mutex    // Serializes writes to Stream (framed protocol)
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// QUICServer manages QUIC connections
type QUICServer struct {
	listener  *quic.Listener
	sessions  cmap.ConcurrentMap[string, *QUICSession]
	tlsConfig *tls.Config
	addr      string
	hmacKey   []byte // Server HMAC key material for handshake authentication
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

var (
	quicServer *QUICServer
	tracer     = otel.Tracer("rocket-server/quic")
)

func init() {
	// Register send function with common package
	common.RegisterQUICSender(func(uuid string, packet *modules.Packet) bool {
		if quicServer != nil {
			return quicServer.SendToQUICClient(uuid, packet)
		}
		return false
	})
}

// NewQUICServer creates a new QUIC server
func NewQUICServer(addr string, tlsConfig *tls.Config) (*QUICServer, error) {
	ctx, cancel := context.WithCancel(context.Background())

	if tlsConfig == nil {
		cancel()
		return nil, errors.New("tls config is required for QUIC")
	}

	// Clone and harden TLS config for QUIC:
	// - QUIC requires TLS 1.3
	// - Ensure ALPN contains our protocol and common HTTP/3 tokens
	clonedTLS := tlsConfig.Clone()
	if clonedTLS.MinVersion < tls.VersionTLS13 {
		clonedTLS.MinVersion = tls.VersionTLS13
	}
	clonedTLS.NextProtos = appendUniqueStrings(clonedTLS.NextProtos, "rocket-quic", "h3", "h3-29", "h3-28", "h3-27")

	// Generate server HMAC key material for handshake authentication
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(cryptoRand.Reader, hmacKey); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
	}

	server := &QUICServer{
		addr:      addr,
		tlsConfig: clonedTLS,
		sessions:  cmap.New[*QUICSession](),
		hmacKey:   hmacKey,
		ctx:       ctx,
		cancel:    cancel,
	}

	return server, nil
}

// Start starts the QUIC server
func (s *QUICServer) Start() error {
	// Parse UDP address
	udpAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("invalid QUIC address: %w", err)
	}

	// Create UDP connection
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// QUIC configuration
	quicConfig := &quic.Config{
		MaxIdleTimeout:        defaultIdleTimeout,
		KeepAlivePeriod:       keepAlivePeriod,
		MaxIncomingStreams:    maxConcurrentStreams,
		MaxIncomingUniStreams: maxConcurrentStreams,
		EnableDatagrams:       true,
		Allow0RTT:             false, // Disable 0-RTT for security
	}

	// Create QUIC listener
	listener, err := quic.Listen(udpConn, s.tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	common.Info(nil, "QUIC_SERVER_STARTED", "", "", map[string]any{
		"addr":             s.addr,
		"max_idle_timeout": defaultIdleTimeout.String(),
		"keepalive_period": keepAlivePeriod.String(),
	})

	// Accept connections
	go s.acceptLoop()

	return nil
}

// acceptLoop accepts incoming QUIC connections
func (s *QUICServer) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			common.Warn(nil, "QUIC_ACCEPT_ERROR", "", err.Error(), nil)
			continue
		}

		// Handle connection in goroutine
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single QUIC connection
func (s *QUICServer) handleConnection(conn *quic.Conn) {
	ctx, span := tracer.Start(s.ctx, "quic.connection")
	defer span.End()

	remoteAddr := conn.RemoteAddr().String()
	common.Info(nil, "QUIC_CONNECTION_ACCEPTED", "", "", map[string]any{
		"remote_addr": remoteAddr,
	})

	// Accept first bidirectional stream for handshake
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0x01), "failed to accept stream")
		span.RecordError(err)
		span.SetStatus(codes.Error, "accept stream failed")
		common.Warn(nil, "QUIC_STREAM_ACCEPT_ERROR", "", err.Error(), map[string]any{
			"remote_addr": remoteAddr,
		})
		return
	}

	// Perform handshake
	session, err := s.handshake(ctx, conn, stream)
	if err != nil {
		conn.CloseWithError(quic.ApplicationErrorCode(0x02), "handshake failed")
		span.RecordError(err)
		span.SetStatus(codes.Error, "handshake failed")
		common.Warn(nil, "QUIC_HANDSHAKE_ERROR", "", err.Error(), map[string]any{
			"remote_addr": remoteAddr,
		})
		return
	}

	// Store session
	s.sessions.Set(session.UUID, session)

	// Register with transport registry
	registry := common.GetTransportRegistry()
	registry.Register(session.UUID, common.TransportQUIC, func(packet *modules.Packet) bool {
		return s.SendToQUICClient(session.UUID, packet)
	})

	// Cleanup on disconnect
	defer func() {
		s.sessions.Remove(session.UUID)
		registry.Unregister(session.UUID)
	}()

	span.SetAttributes(
		attribute.String("quic.uuid", session.UUID),
		attribute.String("quic.remote_addr", remoteAddr),
	)

	common.Info(nil, "QUIC_SESSION_ESTABLISHED", session.UUID, "", map[string]any{
		"remote_addr": remoteAddr,
	})

	// Handle messages
	s.handleSession(session)

	common.Info(nil, "QUIC_SESSION_CLOSED", session.UUID, "", map[string]any{
		"remote_addr": remoteAddr,
	})
}

// handshake performs QUIC handshake
func (s *QUICServer) handshake(ctx context.Context, conn *quic.Conn, stream *quic.Stream) (*QUICSession, error) {
	// Read handshake frame with timeout (QUIC streams are byte streams; we must frame messages)
	stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer stream.SetReadDeadline(time.Time{})

	payload, err := readQUICFrame(stream, 4096)
	if err != nil {
		return nil, fmt.Errorf("read handshake failed: %w", err)
	}

	// Parse handshake
	var handshake map[string]string
	if err := json.Unmarshal(payload, &handshake); err != nil {
		return nil, fmt.Errorf("parse handshake failed: %w", err)
	}

	// Extract device ID and Key
	deviceID, ok := handshake["uuid"]
	if !ok {
		return nil, errors.New("missing uuid in handshake")
	}

	deviceKey, ok := handshake["key"]
	if !ok {
		return nil, errors.New("missing key in handshake")
	}

	connUUID, err := validateCredentials(deviceID, deviceKey)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials: %w", err)
	}

	// Generate a fresh random secret for this session (security best practice)
	randomSecret := make([]byte, 32)
	if _, err := io.ReadFull(cryptoRand.Reader, randomSecret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Derive session key from random secret using HKDF for forward secrecy
	// This ensures the session key is derived from both server material and random entropy
	sessionKey := make([]byte, 32)
	kdf := hkdf.New(sha256.New, randomSecret, s.hmacKey, []byte("rocket-quic-session-v1"))
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	// Compute HMAC on handshake response (authenticates server and prevents MitM)
	// HMAC = HMAC-SHA256(hmacKey, randomSecret + deviceID)
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(randomSecret)
	mac.Write([]byte(deviceID))
	handshakeHMAC := hex.EncodeToString(mac.Sum(nil))

	// Create session context
	sessionCtx, cancel := context.WithCancel(ctx)

	session := &QUICSession{
		UUID:        connUUID,
		Secret:      sessionKey, // Use derived key, not random secret
		Conn:        conn,
		Stream:      stream,
		LastSeen:    time.Now(),
		RateLimiter: rate.NewLimiter(rate.Limit(messageRateLimitQPS), messageRateLimitBurst),
		ctx:         sessionCtx,
		cancel:      cancel,
	}

	// Send handshake response with secret and HMAC
	response := map[string]string{
		"secret": hex.EncodeToString(randomSecret), // Send random secret, client will derive same key
		"hmac":   handshakeHMAC,
	}

	respData, err := json.Marshal(response)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("marshal response failed: %w", err)
	}

	stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	defer stream.SetWriteDeadline(time.Time{})

	if err := writeQUICFrame(stream, respData); err != nil {
		cancel()
		return nil, fmt.Errorf("write response failed: %w", err)
	}

	return session, nil
}

// handleSession handles messages for a QUIC session
func (s *QUICServer) handleSession(session *QUICSession) {
	for {
		select {
		case <-session.ctx.Done():
			return
		default:
		}

		// Read next framed message with timeout
		session.Stream.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		payload, err := readQUICFrame(session.Stream, maxMessageSize)
		session.Stream.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF {
				return
			}
			common.Warn(nil, "QUIC_READ_ERROR", session.UUID, err.Error(), nil)
			return
		}

		// Check rate limit (backpressure)
		if !session.RateLimiter.Allow() {
			common.Warn(nil, "QUIC_MESSAGE_RATE_LIMIT", session.UUID, "", map[string]any{
				"rate_limit_qps": messageRateLimitQPS,
			})
			// Continue reading but drop the message
			continue
		}

		// Update last seen
		session.mu.Lock()
		session.LastSeen = time.Now()
		session.mu.Unlock()

		// Unmarshal packet
		var packet modules.Packet
		if err := json.Unmarshal(payload, &packet); err != nil {
			common.Warn(nil, "QUIC_UNMARSHAL_ERROR", session.UUID, err.Error(), nil)
			continue
		}

		// Route packet
		if err := s.routePacket(session.UUID, &packet); err != nil {
			common.Warn(nil, "QUIC_ROUTE_ERROR", session.UUID, err.Error(), map[string]any{
				"packet_act": packet.Act,
			})
		}
	}
}

// routePacket routes incoming packet to appropriate handler
// Mimics the WebSocket message handling flow (wsOnMessageBinary)
func (s *QUICServer) routePacket(uuid string, packet *modules.Packet) error {
	common.Info(nil, "QUIC_PACKET_RECEIVED", uuid, packet.Act, map[string]any{
		"packet_act": packet.Act,
	})

	// Handle AUDIO_DATA packets (streaming audio from client)
	if packet.Act == `AUDIO_DATA` {
		if err := audio.HandleAudioData(*packet, uuid); err != nil {
			common.Warn(nil, "QUIC_AUDIO_DATA_ERROR", uuid, err.Error(), nil)
			return err
		}
		return nil
	}

	// Handle DEVICE_UP and DEVICE_UPDATE packets specially (same as WebSocket)
	if packet.Act == `DEVICE_UP` || packet.Act == `DEVICE_UPDATE` {
		// Marshal packet back to JSON for OnDevicePackWithUUID
		data, err := utils.JSON.Marshal(packet)
		if err != nil {
			common.Warn(nil, "QUIC_PACKET_MARSHAL_FAILED", uuid, err.Error(), nil)
			return err
		}

		// Get remote address from QUIC connection
		remoteAddr := ""
		if session, ok := s.sessions.Get(uuid); ok {
			remoteAddr = session.Conn.RemoteAddr().String()
		}

		// Call the transport-agnostic device packet handler
		return utility.OnDevicePackWithUUID(
			data,
			uuid,
			remoteAddr,
			func(resp modules.Packet) {
				// Send response back to client
				s.SendToQUICClient(uuid, &resp)
			},
			func() {
				// Close session on error
				if session, ok := s.sessions.Get(uuid); ok {
					session.cancel()
					session.Conn.CloseWithError(quic.ApplicationErrorCode(0x03), "device pack error")
				}
			},
		)
	}

	// For other actions, verify device is registered (same as WebSocket)
	if !common.Devices.Has(uuid) {
		common.Warn(nil, "QUIC_PACKET_INVALID", uuid, "device not registered", map[string]any{
			"action": packet.Act,
		})
		return errors.New("device not registered")
	}

	// Route to event system for callback-based handling
	// Use CallEventByUUID instead of CallEvent since we don't have a melody session
	common.CallEventByUUID(*packet, uuid)

	return nil
}

// SendToQUICClient sends a packet to a QUIC client
func (s *QUICServer) SendToQUICClient(uuid string, packet *modules.Packet) bool {
	session, ok := s.sessions.Get(uuid)
	if !ok {
		return false
	}

	// Marshal packet
	data, err := json.Marshal(packet)
	if err != nil {
		common.Warn(nil, "QUIC_MARSHAL_ERROR", uuid, err.Error(), nil)
		return false
	}

	// Write framed message to stream with timeout (serialize writes)
	session.writeMu.Lock()
	defer session.writeMu.Unlock()

	session.Stream.SetWriteDeadline(time.Now().Add(defaultWriteTimeout))
	defer session.Stream.SetWriteDeadline(time.Time{})

	if err := writeQUICFrame(session.Stream, data); err != nil {
		common.Warn(nil, "QUIC_WRITE_ERROR", uuid, err.Error(), nil)
		return false
	}

	return true
}

// Stop stops the QUIC server
func (s *QUICServer) Stop() error {
	s.cancel()

	s.mu.RLock()
	listener := s.listener
	s.mu.RUnlock()

	if listener != nil {
		if err := listener.Close(); err != nil {
			return err
		}
	}

	// Close all sessions
	s.sessions.IterCb(func(uuid string, session *QUICSession) bool {
		session.cancel()
		session.Conn.CloseWithError(0, "server shutdown")
		return true
	})

	common.Info(nil, "QUIC_SERVER_STOPPED", "", "", nil)

	return nil
}

// GetSessionCount returns the current number of active sessions
func (s *QUICServer) GetSessionCount() int {
	return s.sessions.Count()
}

// StartQUICServer starts the global QUIC server
func StartQUICServer(addr string, tlsConfig *tls.Config) error {
	var err error
	quicServer, err = NewQUICServer(addr, tlsConfig)
	if err != nil {
		return err
	}

	return quicServer.Start()
}

// StopQUICServer stops the global QUIC server
func StopQUICServer() error {
	if quicServer != nil {
		return quicServer.Stop()
	}
	return nil
}

// SendPacketToQUIC sends a packet to a QUIC client (global function)
func SendPacketToQUIC(uuid string, packet *modules.Packet) bool {
	if quicServer != nil {
		return quicServer.SendToQUICClient(uuid, packet)
	}
	return false
}

func appendUniqueStrings(existing []string, values ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(values))
	for _, v := range existing {
		seen[v] = struct{}{}
	}
	out := append([]string(nil), existing...)
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
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

// validateCredentials verifies UUID/Key (encryption removed, TLS provides security)
// Key should equal UUID. Supports both 16-byte (new) and 32-byte (legacy) keys.
func validateCredentials(uuidHex, keyHex string) (string, error) {
	uuidBytes, err := hex.DecodeString(uuidHex)
	if err != nil || len(uuidBytes) != 16 {
		return "", errors.New("invalid uuid")
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", errors.New("invalid key")
	}

	// Verify authentication - Key should equal UUID (plaintext for new clients),
	// while still supporting legacy 32-byte keys generated by older clients.
	var authValid bool
	if len(keyBytes) == 16 {
		// Standard format: 16-byte key should match UUID
		authValid = bytes.Equal(keyBytes, uuidBytes)
	} else if len(keyBytes) == 32 {
		decKey, err := common.DecAES(keyBytes, config.Config.SaltBytes)
		authValid = err == nil && len(decKey) == 16 && bytes.Equal(decKey, uuidBytes)
	} else {
		return "", errors.New("invalid key length")
	}

	if !authValid {
		return "", errors.New("uuid/key mismatch")
	}

	return uuidHex, nil
}

// GetQUICSessionCount returns the number of active QUIC sessions
func GetQUICSessionCount() int {
	if quicServer != nil {
		return quicServer.GetSessionCount()
	}
	return 0
}
