package longpoll

import (
	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/server/handler/audio"
	"Rocket/server/handler/utility"
	"Rocket/utils"
	"Rocket/utils/cmap"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/time/rate"
)

const (
	// Configuration constants (no hardcoded values in logic)
	defaultPollTimeout    = 30 * time.Second
	defaultSessionTimeout = 5 * time.Minute
	maxQueueSize          = 1000
	maxMessageSize        = common.MaxMessageSize
	cleanupInterval       = 1 * time.Minute

	// Rate limiting constants
	sendRateLimitQPS   = 10 // Sends per second per UUID
	sendRateLimitBurst = 20 // Burst allowance per UUID
)

// Session represents a long polling session
type Session struct {
	UUID         string
	Secret       []byte
	LastSeen     time.Time
	MessageQueue chan *modules.Packet
	RateLimiter  *rate.Limiter // Per-UUID rate limiter
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// SessionManager manages all long polling sessions
type SessionManager struct {
	sessions cmap.ConcurrentMap[string, *Session]
	mu       sync.RWMutex
}

var (
	sessionManager *SessionManager
	tracer         = otel.Tracer("rocket-server/longpoll")
)

func init() {
	sessionManager = &SessionManager{
		sessions: cmap.New[*Session](),
	}

	// Start cleanup goroutine
	go sessionManager.cleanupLoop()

	// Register send function with common package
	common.RegisterLongPollSender(SendToLongPollClient)
}

// cleanupLoop periodically removes expired sessions
func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanup()
	}
}

// cleanup removes expired sessions
func (sm *SessionManager) cleanup() {
	now := time.Now()
	sm.sessions.IterCb(func(uuid string, session *Session) bool {
		session.mu.RLock()
		lastSeen := session.LastSeen
		session.mu.RUnlock()

		if now.Sub(lastSeen) > defaultSessionTimeout {
			sm.removeSession(uuid)
			common.Info(nil, "LONGPOLL_SESSION_EXPIRED", uuid, "", map[string]any{
				"last_seen_seconds_ago": now.Sub(lastSeen).Seconds(),
			})
		}
		return true
	})
}

// createSession creates a new long polling session
func (sm *SessionManager) createSession(uuid string, secret []byte) *Session {
	ctx, cancel := context.WithCancel(context.Background())

	session := &Session{
		UUID:         uuid,
		Secret:       secret,
		LastSeen:     time.Now(),
		MessageQueue: make(chan *modules.Packet, maxQueueSize),
		RateLimiter:  rate.NewLimiter(rate.Limit(sendRateLimitQPS), sendRateLimitBurst),
		ctx:          ctx,
		cancel:       cancel,
	}

	sm.sessions.Set(uuid, session)

	// Register session with transport registry
	registry := common.GetTransportRegistry()
	registry.Register(uuid, common.TransportLongPolling, func(packet *modules.Packet) bool {
		return SendToLongPollClient(uuid, packet)
	})

	common.Info(nil, "LONGPOLL_SESSION_CREATED", uuid, "", map[string]any{
		"queue_size": maxQueueSize,
	})

	return session
}

// getSession retrieves a session by UUID
func (sm *SessionManager) getSession(uuid string) (*Session, bool) {
	return sm.sessions.Get(uuid)
}

// removeSession removes a session
func (sm *SessionManager) removeSession(uuid string) {
	if session, ok := sm.sessions.Get(uuid); ok {
		session.cancel()
		close(session.MessageQueue)
		sm.sessions.Remove(uuid)

		// Unregister from transport registry
		registry := common.GetTransportRegistry()
		registry.Unregister(uuid)

		common.Info(nil, "LONGPOLL_SESSION_REMOVED", uuid, "", nil)
	}
}

// updateLastSeen updates the last seen timestamp
func (s *Session) updateLastSeen() {
	s.mu.Lock()
	s.LastSeen = time.Now()
	s.mu.Unlock()
}

// queueMessage queues a message for delivery
func (s *Session) queueMessage(msg *modules.Packet) error {
	select {
	case s.MessageQueue <- msg:
		return nil
	case <-s.ctx.Done():
		return errors.New("session closed")
	default:
		return errors.New("queue full")
	}
}

// Handshake handles initial long polling handshake
// POST /api/longpoll/handshake
func Handshake(ctx *gin.Context) {
	ctxSpan, span := tracer.Start(ctx.Request.Context(), "longpoll.handshake")
	defer span.End()
	ctx.Request = ctx.Request.WithContext(ctxSpan)

	// Extract device ID and Key from headers
	deviceID := ctx.GetHeader("UUID")
	key := ctx.GetHeader("Key")

	if deviceID == "" || key == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "missing UUID or Key")
		common.Warn(ctx, "LONGPOLL_HANDSHAKE_FAILED", "missing_credentials", "", nil)
		return
	}

	connUUID, err := validateCredentials(deviceID, key)
	if err != nil {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		span.SetStatus(codes.Error, "invalid credentials")
		common.Warn(ctx, "LONGPOLL_HANDSHAKE_FAILED", "invalid_credentials", deviceID, map[string]any{
			"error": err.Error(),
		})
		return
	}

	// Generate a fresh random secret for this session (security best practice)
	// Each session gets a unique secret to prevent replay attacks
	secret := make([]byte, 32)
	if _, err := cryptorand.Read(secret); err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to generate secret")
		common.Warn(ctx, "LONGPOLL_HANDSHAKE_FAILED", "secret_generation_failed", deviceID, nil)
		return
	}

	// Create session using connUUID (not deviceID)
	session := sessionManager.createSession(connUUID, secret)

	// Return secret in header
	ctx.Header("Secret", hex.EncodeToString(session.Secret))
	ctx.Header("X-Transport", "longpoll")
	ctx.Status(http.StatusOK)

	span.SetAttributes(
		attribute.String("longpoll.conn_uuid", connUUID),
		attribute.String("longpoll.device_id", deviceID),
		attribute.Int("longpoll.secret_len", len(secret)),
	)

	common.Info(ctx, "LONGPOLL_HANDSHAKE_SUCCESS", connUUID, "", map[string]any{
		"transport": "longpoll",
		"device_id": deviceID,
	})
}

// Poll handles long polling requests
// GET /api/longpoll/poll
func Poll(ctx *gin.Context) {
	ctxSpan, span := tracer.Start(ctx.Request.Context(), "longpoll.poll")
	defer span.End()
	ctx.Request = ctx.Request.WithContext(ctxSpan)

	// Extract UUID and Secret
	uuid := ctx.GetHeader("UUID")
	secretHex := ctx.GetHeader("Secret")

	if uuid == "" || secretHex == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "missing UUID or Secret")
		return
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil || len(secret) != 32 {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "invalid secret format or length")
		return
	}

	// Get session
	session, ok := sessionManager.getSession(uuid)
	if !ok {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		span.SetStatus(codes.Error, "session not found")
		common.Warn(ctx, "LONGPOLL_POLL_FAILED", "session_not_found", uuid, nil)
		return
	}

	// Verify secret
	if !bytesEqual(session.Secret, secret) {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		span.SetStatus(codes.Error, "invalid secret")
		common.Warn(ctx, "LONGPOLL_POLL_FAILED", "invalid_secret", uuid, nil)
		return
	}

	// Update last seen
	session.updateLastSeen()

	// Wait for messages with timeout
	pollCtx, cancel := context.WithTimeout(ctx.Request.Context(), defaultPollTimeout)
	defer cancel()

	var messages []*modules.Packet

	select {
	case <-pollCtx.Done():
		// Timeout - return 204 No Content
		ctx.Status(http.StatusNoContent)
		return

	case msg := <-session.MessageQueue:
		// Got a message
		messages = append(messages, msg)

		// Collect additional messages if available (batch)
		for len(messages) < 10 {
			select {
			case msg := <-session.MessageQueue:
				messages = append(messages, msg)
			default:
				goto send
			}
		}
	}

send:
	// Marshal messages
	data, err := json.Marshal(messages)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		span.RecordError(err)
		span.SetStatus(codes.Error, "marshal failed")
		return
	}

	// Send response
	ctx.Data(http.StatusOK, "application/octet-stream", data)

	span.SetAttributes(
		attribute.String("longpoll.uuid", uuid),
		attribute.Int("longpoll.message_count", len(messages)),
		attribute.Int("longpoll.data_size", len(data)),
	)
}

// Send handles message sending from client
// POST /api/longpoll/send
func Send(ctx *gin.Context) {
	ctxSpan, span := tracer.Start(ctx.Request.Context(), "longpoll.send")
	defer span.End()
	ctx.Request = ctx.Request.WithContext(ctxSpan)

	// Extract UUID and Secret
	uuid := ctx.GetHeader("UUID")
	secretHex := ctx.GetHeader("Secret")

	if uuid == "" || secretHex == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "missing UUID or Secret")
		return
	}

	secret, err := hex.DecodeString(secretHex)
	if err != nil || len(secret) != 32 {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.SetStatus(codes.Error, "invalid secret format or length")
		return
	}

	// Get session
	session, ok := sessionManager.getSession(uuid)
	if !ok {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		span.SetStatus(codes.Error, "session not found")
		return
	}

	// Verify secret
	if !bytesEqual(session.Secret, secret) {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		span.SetStatus(codes.Error, "invalid secret")
		return
	}

	// Check rate limit (backpressure)
	if !session.RateLimiter.Allow() {
		ctx.AbortWithStatus(http.StatusTooManyRequests) // 429
		span.SetStatus(codes.Error, "rate limit exceeded")
		common.Warn(ctx, "LONGPOLL_SEND_RATE_LIMIT", uuid, "", map[string]any{
			"rate_limit_qps": sendRateLimitQPS,
		})
		return
	}

	// Update last seen
	session.updateLastSeen()

	// Read body
	rawData, err := io.ReadAll(io.LimitReader(ctx.Request.Body, maxMessageSize))
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.RecordError(err)
		span.SetStatus(codes.Error, "read body failed")
		return
	}

	// Unmarshal packet
	var packet modules.Packet
	if err := json.Unmarshal(rawData, &packet); err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		span.RecordError(err)
		span.SetStatus(codes.Error, "unmarshal failed")
		return
	}

	// Route packet to appropriate handler
	// This should integrate with existing device handling
	if err := routePacket(uuid, &packet); err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)
		span.RecordError(err)
		span.SetStatus(codes.Error, "route packet failed")
		return
	}

	ctx.Status(http.StatusOK)

	span.SetAttributes(
		attribute.String("longpoll.uuid", uuid),
		attribute.String("longpoll.packet_act", packet.Act),
		attribute.Int("longpoll.data_size", len(rawData)),
	)
}

// routePacket routes incoming packet to appropriate handler
// Mimics the WebSocket message handling flow (wsOnMessageBinary)
func routePacket(uuid string, packet *modules.Packet) error {
	common.Info(nil, "LONGPOLL_PACKET_RECEIVED", uuid, packet.Act, map[string]any{
		"packet_act": packet.Act,
	})

	// Handle AUDIO_DATA packets (streaming audio from client)
	if packet.Act == `AUDIO_DATA` {
		if err := audio.HandleAudioData(*packet, uuid); err != nil {
			common.Warn(nil, "LONGPOLL_AUDIO_DATA_ERROR", uuid, err.Error(), nil)
			return err
		}
		return nil
	}

	// Handle DEVICE_UP and DEVICE_UPDATE packets specially (same as WebSocket)
	if packet.Act == `DEVICE_UP` || packet.Act == `DEVICE_UPDATE` {
		// Marshal packet back to JSON for OnDevicePackWithUUID
		data, err := utils.JSON.Marshal(packet)
		if err != nil {
			common.Warn(nil, "LONGPOLL_PACKET_MARSHAL_FAILED", uuid, err.Error(), nil)
			return err
		}

		// Get remote address if available
		remoteAddr := ""
		if session, ok := sessionManager.getSession(uuid); ok {
			// For longpoll we don't track remote address in session, use "Unknown"
			// Could be enhanced to store it during handshake
			remoteAddr = "Unknown"
			_ = session // Avoid unused warning
		}

		// Call the transport-agnostic device packet handler
		return utility.OnDevicePackWithUUID(
			data,
			uuid,
			remoteAddr,
			func(resp modules.Packet) {
				// Send response back to client
				SendToLongPollClient(uuid, &resp)
			},
			func() {
				// Close session on error
				sessionManager.removeSession(uuid)
			},
		)
	}

	// For other actions, verify device is registered (same as WebSocket)
	if !common.Devices.Has(uuid) {
		common.Warn(nil, "LONGPOLL_PACKET_INVALID", uuid, "device not registered", map[string]any{
			"action": packet.Act,
		})
		return errors.New("device not registered")
	}

	// Route to event system for callback-based handling
	// Use CallEventByUUID instead of CallEvent since we don't have a melody session
	common.CallEventByUUID(*packet, uuid)

	return nil
}

// SendToLongPollClient sends a packet to a long polling client
func SendToLongPollClient(uuid string, packet *modules.Packet) bool {
	session, ok := sessionManager.getSession(uuid)
	if !ok {
		return false
	}

	if err := session.queueMessage(packet); err != nil {
		common.Warn(nil, "LONGPOLL_SEND_FAILED", uuid, "", map[string]any{
			"error": err.Error(),
		})
		return false
	}

	return true
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

	// Verify authentication - Key should equal UUID (no encryption)
	var authValid bool
	if len(keyBytes) == 16 {
		// Standard format: 16-byte key should match UUID
		authValid = bytes.Equal(keyBytes, uuidBytes)
	} else if len(keyBytes) == 32 {
		// Legacy format: compare first 16 bytes with UUID
		authValid = bytes.Equal(keyBytes[:16], uuidBytes)
	} else {
		return "", errors.New("invalid key length")
	}

	if !authValid {
		return "", errors.New("uuid/key mismatch")
	}

	// Check device and register if needed - return connection UUID
	connUUID, ok := common.CheckDevice(uuidHex, "")
	if !ok {
		return "", errors.New("device registration failed")
	}

	return connUUID, nil
}

// bytesEqual compares two byte slices in constant time
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// GetSessionCount returns the current number of active sessions
func GetSessionCount() int {
	return sessionManager.sessions.Count()
}

// CloseSession closes a specific session
func CloseSession(uuid string) {
	sessionManager.removeSession(uuid)
}
