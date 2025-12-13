package share

import (
	"Rocket/modules"
	"Rocket/server/cluster"
	"Rocket/server/common"
	servercfg "Rocket/server/config"
	"Rocket/server/handler/utility"
	"Rocket/server/storage"
	"Rocket/utils"
	"Rocket/utils/melody"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type guestDesktop struct {
	shareID    string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
	viewOnly   bool

	// Rate limiting for input events (security: prevents flood attacks)
	inputTokens      int64     // Available tokens (atomic)
	inputLastRefill  time.Time // Last token refill time
	inputRateLimited bool      // True if currently rate limited
	inputLock        sync.Mutex
}

var (
	repo          *storage.ShareRepository
	guestSessions = melody.New()
)

const (
	defaultTTLSeconds = 14400 // 4 hours
	maxTTLSeconds     = 86400 // 24 hours
)

// Rate limiting constants for input events (security: prevents flood attacks)
// Based on RustDesk and Guacamole best practices
const (
	inputRateTokensPerSecond = 200 // Max events per second (generous for normal use)
	inputRateBucketSize      = 100 // Max burst size
	inputRateRefillInterval  = 50 * time.Millisecond
)

// checkInputRateLimit implements token bucket rate limiting for input events.
// Returns true if the input should be allowed, false if rate limited.
// Following RustDesk pattern: https://github.com/rustdesk/rustdesk
func (g *guestDesktop) checkInputRateLimit(eventCount int) bool {
	g.inputLock.Lock()
	defer g.inputLock.Unlock()

	now := time.Now()

	// Initialize on first call
	if g.inputLastRefill.IsZero() {
		g.inputLastRefill = now
		g.inputTokens = inputRateBucketSize
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(g.inputLastRefill)
	tokensToAdd := int64(elapsed.Seconds() * inputRateTokensPerSecond)
	if tokensToAdd > 0 {
		g.inputTokens += tokensToAdd
		if g.inputTokens > inputRateBucketSize {
			g.inputTokens = inputRateBucketSize
		}
		g.inputLastRefill = now
	}

	// Check if we have enough tokens
	tokensNeeded := int64(eventCount)
	if g.inputTokens >= tokensNeeded {
		g.inputTokens -= tokensNeeded
		g.inputRateLimited = false
		return true
	}

	// Rate limited - log once per burst
	if !g.inputRateLimited {
		g.inputRateLimited = true
		common.Warn(g.srcConn, `SHARE_RATE_LIMIT`, `triggered`, `input rate limited`, map[string]any{
			`share_id`:      g.shareID,
			`tokens`:        g.inputTokens,
			`tokens_needed`: tokensNeeded,
		})
		recordShareRateLimit(g.srcConn, g.shareID, g.inputTokens)
	}
	return false
}

func init() {
	repo = storage.NewShareRepository()
	guestSessions.Config.MaxMessageSize = common.MaxMessageSize
	// Extended timeouts for guest desktop streaming stability:
	// - PongWait: 120s (up from 60s default) to handle network jitter
	// - WriteWait: 30s (up from 10s) for large frame writes
	// - PingPeriod: 90s (3/4 of PongWait) per WebSocket best practices
	guestSessions.Config.PongWait = 120 * time.Second
	guestSessions.Config.WriteWait = 30 * time.Second
	guestSessions.Config.PingPeriod = 90 * time.Second
	guestSessions.HandleConnect(onGuestConnect)
	guestSessions.HandleMessage(onGuestMessage)
	guestSessions.HandleMessageBinary(onGuestMessage)
	guestSessions.HandleDisconnect(onGuestDisconnect)
	go utility.WSHealthCheck(guestSessions, sendGuestPack)
	go safeCleanupExpiredShares()
}

// safeCleanupExpiredShares wraps cleanupExpiredShares with panic recovery.
func safeCleanupExpiredShares() {
	defer func() {
		if r := recover(); r != nil {
			common.Warn(nil, `SHARE_CLEANUP`, `panic`, `cleanup goroutine panicked, restarting`, map[string]any{
				`panic`: r,
			})
			time.Sleep(1 * time.Minute)
			go safeCleanupExpiredShares() // Auto-restart
		}
	}()
	cleanupExpiredShares()
}

func isExpired(entry *storage.ShareEntry, now time.Time) bool {
	if entry == nil {
		return true
	}
	if entry.ExpiresAt.IsZero() {
		return false
	}
	return now.After(entry.ExpiresAt)
}

func ensureDesktop(entry *storage.ShareEntry) string {
	if entry == nil || entry.ID == "" {
		return ""
	}
	ctx := context.Background()
	current, err := repo.GetByID(ctx, entry.ID)
	if err != nil || current == nil || isExpired(current, time.Now()) {
		return ""
	}
	if current.Desktop == "" {
		current.Desktop = utils.GetStrUUID()
		if err := repo.UpdateDesktop(ctx, current.ID, current.Desktop); err != nil {
			common.Warn(nil, `SHARE_UPDATE_DESKTOP`, `fail`, `failed to update desktop ID`, map[string]any{
				`share_id`: entry.ID,
				`error`:    err.Error(),
			})
			// Return empty to signal failure - caller should handle gracefully
			return ""
		}
	}
	return current.Desktop
}

func guestICEConfig(entry *storage.ShareEntry) gin.H {
	ice := gin.H{
		`stun`: []string{},
		`turn`: []string{},
	}
	if entry == nil {
		return ice
	}

	cfg := servercfg.Config.WebRTC
	if cfg != nil {
		// Determine which servers to include
		stunServers := cfg.Stun
		if entry.TurnOnly {
			stunServers = nil // Exclude STUN for TurnOnly shares
		}

		// Use share ID as identifier for audit trail
		identifier := "guest"
		if entry.ID != "" && len(entry.ID) >= 8 {
			identifier = "share:" + entry.ID[:8]
		}

		// Build ICE servers with ephemeral credentials (if configured)
		servers := utility.BuildICEServers(
			stunServers,
			cfg.Turn,
			cfg.TurnSecret,
			identifier,
			cfg.TurnCredentialTTL,
		)

		ice[`ice_servers`] = servers
		ice[`stun`] = stunServers // Legacy format
		ice[`turn`] = cfg.Turn    // Legacy format
		return ice
	}

	// Fallback to public STUN servers when no WebRTC config exists
	if !entry.TurnOnly {
		ice[`stun`] = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun.cloudflare.com:3478",
		}
	}
	return ice
}

// cleanupExpiredShares periodically removes expired share entries
func cleanupExpiredShares() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop() // Prevent resource leak if function ever exits
	for range ticker.C {
		ctx := context.Background()
		count, err := repo.DeleteExpired(ctx, time.Now())
		if err != nil {
			common.Warn(nil, `SHARE_CLEANUP`, `fail`, `failed to cleanup expired shares`, map[string]any{
				`error`: err.Error(),
			})
		} else if count > 0 {
			common.Info(nil, `SHARE_CLEANUP`, `success`, ``, map[string]any{
				`count`: count,
			})
		}
	}
}

// ValidateShareToken verifies that the provided token is valid and not expired
func ValidateShareToken(ctx *gin.Context) {
	token := ctx.Query(`token`)
	if token == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	dbCtx := context.Background()
	entry, err := repo.GetByToken(dbCtx, token)
	if err != nil || entry == nil || isExpired(entry, time.Now()) {
		logAccess(token, ctx, false, "token not found or expired")
		ctx.AbortWithStatusJSON(401, modules.Packet{Code: 1, Msg: `${i18n|COMMON.UNAUTHORIZED}`})
		return
	}

	// Check single-use
	if entry.SingleUse && entry.Used {
		logAccess(token, ctx, false, "single-use token already used")
		ctx.AbortWithStatusJSON(401, modules.Packet{Code: 1, Msg: `${i18n|SHARE.TOKEN_ALREADY_USED}`})
		return
	}

	logAccess(token, ctx, true, "")
	desktopID := ensureDesktop(entry)

	// Return entry with secret for WebSocket authentication
	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{
		`share`: gin.H{
			`id`:        entry.ID,
			`device`:    entry.Device,
			`desktop`:   desktopID,
			`expiresAt`: entry.ExpiresAt,
			`viewOnly`:  entry.ViewOnly,
			`turnOnly`:  entry.TurnOnly,
			`singleUse`: entry.SingleUse,
			`used`:      entry.Used,
			`secret`:    entry.Secret,
		},
	}})
}

// InitGuestDesktop handles guest desktop WebSocket connections
func InitGuestDesktop(ctx *gin.Context) {
	if !ctx.IsWebsocket() {
		common.Warn(ctx, `SHARE_GUEST_HANDSHAKE`, `fail`, `not a websocket request`, map[string]any{
			`is_websocket`: ctx.IsWebsocket(),
		})
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Validate origin for CSWSH protection
	if !utility.ValidateWebSocketOrigin(ctx, true) {
		common.Warn(ctx, `SHARE_GUEST_HANDSHAKE`, `fail`, `origin validation failed`, map[string]any{
			`origin`: ctx.GetHeader("Origin"),
			`host`:   ctx.Request.Host,
		})
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	token := ctx.Query(`token`)
	if token == "" {
		common.Warn(ctx, `SHARE_GUEST_HANDSHAKE`, `fail`, `empty token`, nil)
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	dbCtx := context.Background()
	entry, err := repo.GetByToken(dbCtx, token)
	if err != nil || entry == nil || isExpired(entry, time.Now()) {
		common.Warn(ctx, `SHARE_TOKEN_VALIDATE`, `fail`, `token not found or expired`, map[string]any{
			`token_prefix`: token[:8],
			`error`:        err,
			`entry_exists`: entry != nil,
		})
		logAccess(token, ctx, false, "token not found")
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	secretStr, ok := ctx.GetQuery(`secret`)
	if !ok || len(secretStr) != len(entry.Secret) || strings.ToLower(secretStr) != strings.ToLower(entry.Secret) {
		common.Warn(ctx, `SHARE_TOKEN_VALIDATE`, `fail`, `secret mismatch`, map[string]any{
			`token_prefix`:    token[:8],
			`secret_provided`: ok,
			`secret_len`:      len(secretStr),
			`expected_len`:    len(entry.Secret),
		})
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	secret, err := hex.DecodeString(secretStr)
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	desktopUUID := ensureDesktop(entry)
	if desktopUUID == "" {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Check single-use
	if entry.SingleUse && entry.Used {
		logAccess(token, ctx, false, "single-use token already used")
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Check device exists
	if cluster.RedirectIfNeeded(ctx, entry.Device) {
		return
	}
	connUUID, ok := common.CheckDevice(entry.Device, ``)
	if !ok {
		logAccess(token, ctx, false, "device not connected")
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	}

	// Mark single-use token as used (atomic operation)
	if entry.SingleUse {
		if err := repo.MarkUsed(dbCtx, entry.ID, ctx.ClientIP()); err != nil {
			logAccess(token, ctx, false, "token already used (race condition)")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}

	logAccess(token, ctx, true, "")
	common.Info(ctx, `SHARE_GUEST_CONNECT`, `success`, ``, map[string]any{
		`share_id`:  entry.ID,
		`device`:    entry.Device,
		`view_only`: entry.ViewOnly,
	})

	guestSessions.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Secret`:    secret,
		`ShareID`:   entry.ID,
		`Device`:    entry.Device,
		`ViewOnly`:  entry.ViewOnly,
		`TurnOnly`:  entry.TurnOnly,
		`ConnUUID`:  connUUID,
		`LastPack`:  utils.Unix,
		`ExpiresAt`: entry.ExpiresAt,
		`Desktop`:   desktopUUID,
	})
}

// GetGuestICEConfig returns ICE servers for guest connections
// If TurnOnly is set, STUN servers are filtered out
func GetGuestICEConfig(ctx *gin.Context) {
	token := ctx.Query(`token`)
	if token == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	dbCtx := context.Background()
	entry, err := repo.GetByToken(dbCtx, token)
	if err != nil || entry == nil || isExpired(entry, time.Now()) {
		logAccess(token, ctx, false, "token not found or expired for ice")
		ctx.AbortWithStatusJSON(401, modules.Packet{Code: 1, Msg: `${i18n|COMMON.UNAUTHORIZED}`})
		return
	}

	if entry.SingleUse && entry.Used {
		logAccess(token, ctx, false, "single-use token already used")
		ctx.AbortWithStatusJSON(401, modules.Packet{Code: 1, Msg: `${i18n|SHARE.TOKEN_ALREADY_USED}`})
		return
	}

	if desktop := ensureDesktop(entry); desktop == "" {
		ctx.AbortWithStatusJSON(401, modules.Packet{Code: 1, Msg: `${i18n|COMMON.UNAUTHORIZED}`})
		return
	}

	logAccess(token, ctx, true, "ice")

	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`ice`: guestICEConfig(entry)}})
}

// CreateShare creates a new desktop sharing session
func CreateShare(ctx *gin.Context) {
	var body struct {
		Device    string `json:"device"`
		Desktop   string `json:"desktop"`
		TTL       int    `json:"ttlSeconds"`
		SingleUse bool   `json:"singleUse"`
		ViewOnly  bool   `json:"viewOnly"`
		TurnOnly  bool   `json:"turnOnly"`
	}
	if err := ctx.ShouldBind(&body); err != nil || body.Device == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	// Validate device exists
	if _, ok := common.CheckDevice(body.Device, ``); !ok {
		ctx.AbortWithStatusJSON(404, modules.Packet{Code: 1, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`})
		return
	}

	ttl := body.TTL
	if ttl <= 0 {
		ttl = defaultTTLSeconds
	}
	if ttl > maxTTLSeconds {
		ttl = maxTTLSeconds
	}
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	}

	// TODO: Get admin username from auth context
	adminUser := "admin"

	// Generate per-share secret (32 bytes hex)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}

	entry := &storage.ShareEntry{
		ID:        utils.GetStrUUID(),
		Device:    body.Device,
		Desktop:   body.Desktop,
		Token:     utils.GetStrUUID(),
		Secret:    strings.ToLower(hex.EncodeToString(secretBytes)),
		ExpiresAt: expiresAt,
		SingleUse: body.SingleUse,
		ViewOnly:  body.ViewOnly,
		TurnOnly:  body.TurnOnly,
		CreatedAt: time.Now(),
		CreatedBy: adminUser,
		AccessLog: []storage.AccessLogEntry{},
	}

	dbCtx := context.Background()
	if err := repo.Create(dbCtx, entry); err != nil {
		common.Error(ctx, `SHARE_CREATE`, `fail`, `failed to create share`, map[string]any{
			`error`:  err.Error(),
			`device`: body.Device,
		})
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}

	common.Info(ctx, `SHARE_CREATE`, `success`, ``, map[string]any{
		`share_id`:   entry.ID,
		`device`:     entry.Device,
		`single_use`: entry.SingleUse,
		`view_only`:  entry.ViewOnly,
		`turn_only`:  entry.TurnOnly,
		`ttl`:        ttl,
		`created_by`: adminUser,
	})

	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`share`: entry}})
}

// ListShares returns all active shares
func ListShares(ctx *gin.Context) {
	dbCtx := context.Background()
	shares, err := repo.ListAll(dbCtx, 100, 0) // Limit to 100 shares
	if err != nil {
		common.Error(ctx, `SHARE_LIST`, `fail`, `failed to list shares`, map[string]any{
			`error`: err.Error(),
		})
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}

	// Filter out expired shares
	now := time.Now()
	var items []storage.ShareEntry
	for _, s := range shares {
		if !isExpired(s, now) {
			items = append(items, *s)
		}
	}

	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`shares`: items}})
}

// GetShare returns a specific share by ID
func GetShare(ctx *gin.Context) {
	id := ctx.Param(`id`)
	if id == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	dbCtx := context.Background()
	s, err := repo.GetByID(dbCtx, id)
	if err != nil {
		common.Error(ctx, `SHARE_GET`, `fail`, `failed to get share`, map[string]any{
			`share_id`: id,
			`error`:    err.Error(),
		})
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}
	if s != nil && !isExpired(s, time.Now()) {
		ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`share`: s}})
		return
	}
	ctx.AbortWithStatusJSON(404, modules.Packet{Code: 1, Msg: `${i18n|COMMON.NOT_EXIST}`})
}

// GetShareToken returns the token for a share (admin only)
func GetShareToken(ctx *gin.Context) {
	id := ctx.Param(`id`)
	if id == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	dbCtx := context.Background()
	s, err := repo.GetByID(dbCtx, id)
	if err != nil {
		common.Error(ctx, `SHARE_GET_TOKEN`, `fail`, `failed to get share token`, map[string]any{
			`share_id`: id,
			`error`:    err.Error(),
		})
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}
	if s != nil && !isExpired(s, time.Now()) {
		ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{
			`token`:     s.Token,
			`expiresAt`: s.ExpiresAt,
			`singleUse`: s.SingleUse,
			`used`:      s.Used,
		}})
		return
	}
	ctx.AbortWithStatusJSON(404, modules.Packet{Code: 1, Msg: `${i18n|COMMON.NOT_EXIST}`})
}

// GetShareAccessLog returns the access log for a share
func GetShareAccessLog(ctx *gin.Context) {
	id := ctx.Param(`id`)
	if id == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	dbCtx := context.Background()
	s, err := repo.GetByID(dbCtx, id)
	if err != nil {
		common.Error(ctx, `SHARE_GET_ACCESS_LOG`, `fail`, `failed to get share access log`, map[string]any{
			`share_id`: id,
			`error`:    err.Error(),
		})
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}
	if s != nil {
		ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`accessLog`: s.AccessLog}})
		return
	}
	ctx.AbortWithStatusJSON(404, modules.Packet{Code: 1, Msg: `${i18n|COMMON.NOT_EXIST}`})
}

// RevokeShare revokes a share by ID
func RevokeShare(ctx *gin.Context) {
	var body struct {
		ID string `json:"id"`
	}
	if err := ctx.ShouldBind(&body); err != nil || body.ID == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}

	dbCtx := context.Background()
	s, _ := repo.GetByID(dbCtx, body.ID)
	if err := repo.Delete(dbCtx, body.ID); err != nil {
		common.Error(ctx, `SHARE_REVOKE`, `fail`, `failed to revoke share`, map[string]any{
			`share_id`: body.ID,
			`error`:    err.Error(),
		})
		ctx.AbortWithStatusJSON(500, modules.Packet{Code: 1, Msg: `${i18n|COMMON.INTERNAL_ERROR}`})
		return
	}

	if s != nil {
		common.Info(ctx, `SHARE_REVOKE`, `success`, ``, map[string]any{
			`share_id`: s.ID,
			`device`:   s.Device,
		})
	}

	// Close any active guest sessions for this share
	closeGuestSessionsByShare(body.ID)

	ctx.JSON(200, modules.Packet{Code: 0})
}

// DeleteShare is an alias for RevokeShare
func DeleteShare(ctx *gin.Context) { RevokeShare(ctx) }

// CloseGuestSessionsByDevice clears shares and guest sessions for a device
func CloseGuestSessionsByDevice(deviceID string) {
	if deviceID == "" {
		return
	}

	dbCtx := context.Background()
	count, err := repo.DeleteByDevice(dbCtx, deviceID)
	if err != nil {
		common.Error(nil, `SHARE_AUTO_REVOKE`, `fail`, `failed to delete shares for device`, map[string]any{
			`device`: deviceID,
			`error`:  err.Error(),
		})
	} else if count > 0 {
		common.Info(nil, `SHARE_AUTO_REVOKE`, `success`, `shares auto-revoked on device disconnect`, map[string]any{
			`device`: deviceID,
			`count`:  count,
		})
	}

	// Close guest WebSocket sessions
	var toClose []*melody.Session
	guestSessions.IterSessions(func(_ string, session *melody.Session) bool {
		if device, ok := session.Get(`Device`); ok && device.(string) == deviceID {
			toClose = append(toClose, session)
		}
		return true
	})
	for _, session := range toClose {
		sendGuestPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|DESKTOP.SESSION_CLOSED}`}, session)
		session.Close()
	}
}

// closeGuestSessionsByShare closes all guest sessions for a specific share
func closeGuestSessionsByShare(shareID string) {
	var toClose []*melody.Session
	guestSessions.IterSessions(func(_ string, session *melody.Session) bool {
		if sid, ok := session.Get(`ShareID`); ok && sid.(string) == shareID {
			toClose = append(toClose, session)
		}
		return true
	})
	for _, session := range toClose {
		sendGuestPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|SHARE.SESSION_REVOKED}`}, session)
		session.Close()
	}
}

func isShareActive(id string) bool {
	if id == "" {
		return false
	}
	dbCtx := context.Background()
	s, err := repo.GetByID(dbCtx, id)
	if err != nil || s == nil || isExpired(s, time.Now()) {
		return false
	}
	if s.SingleUse && s.Used {
		return false
	}
	return true
}

// isShareValidForSession checks if a share is still valid for an existing session.
// Unlike isShareActive, this does NOT check the single-use Used flag because:
// - Single-use shares are marked as Used at connection time (before WebSocket upgrade)
// - An existing session already passed validation at connection time
// - The session should remain valid until expiration or revocation (deletion)
// This prevents the race condition where single-use shares were immediately terminated
// after their first message because isShareActive returned false.
func isShareValidForSession(id string) bool {
	if id == "" {
		return false
	}
	dbCtx := context.Background()
	s, err := repo.GetByID(dbCtx, id)
	// Share deleted (revoked) or not found - close session
	if err != nil || s == nil {
		return false
	}
	// Share expired - close session
	if isExpired(s, time.Now()) {
		return false
	}
	// Don't check SingleUse && Used for existing sessions
	// They were already validated at connection time
	return true
}

func logAccess(token string, ctx *gin.Context, success bool, reason string) {
	dbCtx := context.Background()
	entry := storage.AccessLogEntry{
		Timestamp: time.Now(),
		IP:        ctx.ClientIP(),
		UserAgent: ctx.GetHeader("User-Agent"),
		Success:   success,
		Reason:    reason,
	}
	if err := repo.AppendAccessLog(dbCtx, token, entry); err != nil {
		common.Warn(ctx, `SHARE_ACCESS_LOG`, `fail`, `failed to log access`, map[string]any{
			`token_prefix`: token[:8],
			`error`:        err.Error(),
		})
	}
}

func expiredSession(session *melody.Session, shareID string) bool {
	if session == nil {
		return true
	}
	if expVal, ok := session.Get(`ExpiresAt`); ok {
		if expAt, ok := expVal.(time.Time); ok && !expAt.IsZero() && time.Now().After(expAt) {
			sendGuestPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|DESKTOP.SESSION_CLOSED}`}, session)
			session.Close()
			recordShareExpirationEnforcement(session, shareID, "expired")
			return true
		}
	}
	// Use isShareValidForSession for existing sessions (doesn't check single-use Used flag)
	if shareID == "" || isShareValidForSession(shareID) {
		return false
	}
	sendGuestPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|SHARE.SESSION_REVOKED}`}, session)
	session.Close()
	recordShareExpirationEnforcement(session, shareID, "revoked")
	return true
}

// Guest WebSocket handlers

func onGuestConnect(session *melody.Session) {
	shareID, ok := session.Get(`ShareID`)
	if !ok {
		common.Warn(session, `SHARE_GUEST_WS_CONNECT`, `fail`, `no ShareID in session`, nil)
		sendGuestPack(modules.Packet{Act: `WARN`, Msg: `${i18n|SHARE.INVALID_TOKEN}`}, session)
		session.Close()
		return
	}

	device, _ := session.Get(`Device`)
	connUUID, _ := session.Get(`ConnUUID`)
	viewOnly, _ := session.Get(`ViewOnly`)
	desktopVal, _ := session.Get(`Desktop`)
	desktopUUID, _ := desktopVal.(string)
	if desktopUUID == "" {
		common.Warn(session, `SHARE_GUEST_WS_CONNECT`, `fail`, `empty desktopUUID`, map[string]any{
			`share_id`: shareID,
		})
		sendGuestPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		session.Close()
		return
	}

	deviceConn, ok := common.Melody.GetSessionByUUID(connUUID.(string))
	if !ok {
		common.Warn(session, `SHARE_GUEST_WS_CONNECT`, `fail`, `device session not found`, map[string]any{
			`share_id`:  shareID,
			`conn_uuid`: connUUID,
		})
		sendGuestPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`}, session)
		session.Close()
		return
	}
	shareIDStr := shareID.(string)
	viewOnlyBool, _ := viewOnly.(bool)
	guest := &guestDesktop{
		shareID:    shareIDStr,
		device:     device.(string),
		srcConn:    session,
		deviceConn: deviceConn,
		viewOnly:   viewOnlyBool,
	}
	session.Set(`Guest`, guest)
	session.Set(`DesktopUUID`, desktopUUID)

	// Register event callback for this guest
	common.AddEvent(guestEventWrapper(guest, desktopUUID), connUUID.(string), desktopUUID)

	// Request desktop init from device (include allowControl so the device can enforce view-only even
	// when control is carried over direct WebRTC data channels).
	common.SendPack(modules.Packet{Act: `DESKTOP_INIT`, Data: gin.H{
		`desktop`:      desktopUUID,
		`allowControl`: !viewOnlyBool,
	}, Event: desktopUUID}, deviceConn)

	common.Info(session, `SHARE_GUEST_WS_CONNECT`, `success`, ``, map[string]any{
		`share_id`:  shareIDStr,
		`desktop`:   desktopUUID,
		`view_only`: viewOnlyBool,
	})
}

func onGuestMessage(session *melody.Session, data []byte) {
	val, ok := session.Get(`Guest`)
	if !ok {
		return
	}
	guest := val.(*guestDesktop)
	desktopUUID, _ := session.Get(`DesktopUUID`)
	shareVal, _ := session.Get(`ShareID`)
	shareIDStr, _ := shareVal.(string)
	if expiredSession(session, guest.shareID) {
		return
	}

	// Check if share is still valid for this existing session (expired or revoked)
	// Uses isShareValidForSession which does NOT check single-use Used flag
	// since that was already validated at connection time
	if guest.shareID != "" && !isShareValidForSession(guest.shareID) {
		sendGuestPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|SHARE.SESSION_REVOKED}`}, session)
		session.Close()
		recordShareExpirationEnforcement(session, guest.shareID, "revoked")
		return
	}

	service, op, isBinary := utils.CheckBinaryPack(data)
	if !isBinary || service != 20 {
		sendGuestPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	if op != 03 {
		sendGuestPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}

	data = utility.SimpleDecrypt(data[8:], session)
	var pack modules.Packet
	if utils.JSON.Unmarshal(data, &pack) != nil {
		sendGuestPack(modules.Packet{Code: -1}, session)
		session.Close()
		return
	}
	session.Set(`LastPack`, utils.Unix)

	switch pack.Act {
	case `DESKTOP_PING`:
		// Forward ping to device for keep-alive
		common.SendPack(modules.Packet{Act: `DESKTOP_PING`, Data: gin.H{
			`desktop`: desktopUUID,
		}, Event: desktopUUID.(string)}, guest.deviceConn)
		// Send quick ACK so guest browser sees server-side round trip
		sendGuestPack(modules.Packet{Act: `DESKTOP_PONG`, Data: gin.H{
			`source`: `server`,
		}}, session)
		return

	case `DESKTOP_BROWSER_STATS`:
		statsPayload := utility.CollectBrowserStats(pack.Data)
		if desktopUUIDStr, ok := desktopUUID.(string); ok {
			statsPayload[`desktop_uuid`] = desktopUUIDStr
		} else {
			statsPayload[`desktop_uuid`] = desktopUUID
		}
		statsPayload[`share_id`] = shareIDStr
		if guest.device != `` {
			deviceID := guest.device
			if len(deviceID) > 16 {
				deviceID = deviceID[:16] + `...`
			}
			statsPayload[`device_id`] = deviceID
		}
		common.Info(session, `[SERVER_SHARE_BROWSER_STATS]`, ``, `Browser telemetry snapshot`, statsPayload)
		return

	case `DESKTOP_KILL`:
		common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
			`desktop`: desktopUUID,
		}, Event: desktopUUID.(string)}, guest.deviceConn)
		return

	case `DESKTOP_SHOT`:
		common.SendPack(modules.Packet{Act: `DESKTOP_SHOT`, Data: gin.H{
			`desktop`: desktopUUID,
		}, Event: desktopUUID.(string)}, guest.deviceConn)
		return

	case `DESKTOP_CONFIG`:
		// Forward a sanitized config payload to the device.
		// NOTE: share links may be view-only; the server is authoritative for allowControl.
		payload := gin.H{}
		if pack.Data != nil {
			if fps, ok := pack.Data[`fps`]; ok {
				payload[`fps`] = fps
			}
			if quality, ok := pack.Data[`quality`]; ok {
				payload[`quality`] = quality
			}
			// Accept both "monitor" and "display"; map to "monitor" for the device.
			if monitor, ok := pack.Data[`monitor`]; ok {
				payload[`monitor`] = monitor
			} else if display, ok := pack.Data[`display`]; ok {
				payload[`monitor`] = display
			}
			if codec, ok := pack.Data[`codec`].(string); ok && codec != "" {
				payload[`codec`] = strings.ToLower(strings.TrimSpace(codec))
			}
			if transport, ok := pack.Data[`transport`].(string); ok && transport != "" {
				payload[`transport`] = strings.ToLower(strings.TrimSpace(transport))
			}
		}
		// The share link (server) is authoritative for control permissions.
		// Never allow the guest to flip allowControl and then inject input over WebRTC data channels.
		payload[`allowControl`] = !guest.viewOnly
		payload[`desktop`] = desktopUUID
		common.SendPack(modules.Packet{Act: `DESKTOP_CONFIG`, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
		return

	case `DESKTOP_INPUT`:
		// Block input for view-only guests
		if guest.viewOnly {
			common.Warn(session, `[SERVER_SHARE_INPUT_BLOCKED]`, ``, `View-only guest attempted input`, map[string]any{
				`share_id`: shareIDStr,
			})
			recordShareViewOnlyBlock(session, pack.Act, shareIDStr)
			sendGuestPack(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: `${i18n|SHARE.VIEW_ONLY}`}, session)
			return
		}
		// Forward input to device
		events, ok := normalizeInputEvents(pack.Data)
		if !ok || len(events) == 0 {
			return
		}
		// Rate limiting: prevent flood attacks (security)
		// Token bucket algorithm: 200 events/sec, burst of 100
		if !guest.checkInputRateLimit(len(events)) {
			sendGuestPack(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: `${i18n|SHARE.RATE_LIMITED}`}, session)
			return
		}
		common.SendPack(modules.Packet{
			Act: `DESKTOP_INPUT`,
			Data: gin.H{
				`events`:       events,
				`desktop`:      desktopUUID,
				`allowControl`: !guest.viewOnly,
			},
			Event: desktopUUID.(string),
		}, guest.deviceConn)
		return

	case `DESKTOP_CLIPBOARD`:
		if guest.viewOnly {
			common.Warn(session, `[SERVER_SHARE_CLIPBOARD_BLOCKED]`, ``, `View-only guest attempted clipboard`, map[string]any{
				`share_id`: shareIDStr,
			})
			recordShareViewOnlyBlock(session, pack.Act, shareIDStr)
			sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|SHARE.VIEW_ONLY}`}, session)
			return
		}
		if payload, ok := normalizeClipboard(pack.Data); ok {
			payload[`desktop`] = desktopUUID
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
			return
		}
		sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return

	case `DESKTOP_FILE_DROP`:
		if guest.viewOnly {
			common.Warn(session, `[SERVER_SHARE_FILEDROP_BLOCKED]`, ``, `View-only guest attempted file drop`, map[string]any{
				`share_id`: shareIDStr,
			})
			recordShareViewOnlyBlock(session, pack.Act, shareIDStr)
			sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|SHARE.VIEW_ONLY}`}, session)
			return
		}
		if payload, ok := normalizeFileDrop(pack.Data); ok {
			payload[`desktop`] = desktopUUID
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
			return
		}
		sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return

	case `DESKTOP_AUDIO`:
		if guest.viewOnly {
			common.Warn(session, `[SERVER_SHARE_AUDIO_BLOCKED]`, ``, `View-only guest attempted audio control`, map[string]any{
				`share_id`: shareIDStr,
			})
			recordShareViewOnlyBlock(session, pack.Act, shareIDStr)
			sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|SHARE.VIEW_ONLY}`}, session)
			return
		}
		if payload, ok := normalizeAudioControl(pack.Data); ok {
			payload[`desktop`] = desktopUUID
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
			return
		}
		sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return

	case `DESKTOP_WEBRTC_OFFER`:
		if payload, ok := normalizeSDP(pack.Data); ok {
			payload[`desktop`] = desktopUUID

			// Provide ICE/TURN config (with ephemeral TURN creds when configured) to the device.
			// This lets guest WebRTC sessions work reliably without per-agent env config.
			if servercfg.Config.WebRTC != nil {
				cfg := servercfg.Config.WebRTC
				stunServers := cfg.Stun
				if turnOnlyVal, ok := session.Get(`TurnOnly`); ok {
					if turnOnly, okBool := turnOnlyVal.(bool); okBool && turnOnly {
						stunServers = nil
					}
				}
				identifier := "guest"
				if shareIDStr != "" && len(shareIDStr) >= 8 {
					identifier = "share:" + shareIDStr[:8]
				}
				payload[`ice_servers`] = utility.BuildICEServers(
					stunServers,
					cfg.Turn,
					cfg.TurnSecret,
					identifier,
					cfg.TurnCredentialTTL,
				)
			}

			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
			return
		}
		sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return

	case `DESKTOP_WEBRTC_ANSWER`:
		if payload, ok := normalizeSDP(pack.Data); ok {
			payload[`desktop`] = desktopUUID
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
			return
		}
		sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return

	case `DESKTOP_WEBRTC_ICE`:
		if payload, ok := normalizeCandidate(pack.Data); ok {
			payload[`desktop`] = desktopUUID
			common.SendPack(modules.Packet{Act: pack.Act, Data: payload, Event: desktopUUID.(string)}, guest.deviceConn)
			return
		}
		sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		return
	}
	common.Warn(session, `[SERVER_SHARE_UNKNOWN_ACTION]`, ``, `Unknown share desktop action from guest`, map[string]any{
		`act`:      pack.Act,
		`share_id`: shareIDStr,
	})
	sendGuestPack(modules.Packet{Act: pack.Act, Code: 1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
	return
}

func onGuestDisconnect(session *melody.Session) {
	val, ok := session.Get(`Guest`)
	if !ok {
		return
	}
	guest := val.(*guestDesktop)
	desktopUUID, _ := session.Get(`DesktopUUID`)

	common.SendPack(modules.Packet{Act: `DESKTOP_KILL`, Data: gin.H{
		`desktop`: desktopUUID,
	}, Event: desktopUUID.(string)}, guest.deviceConn)
	common.RemoveEvent(desktopUUID.(string))
	session.Set(`Guest`, nil)

	common.Info(session, `SHARE_GUEST_DISCONNECT`, `success`, ``, map[string]any{
		`share_id`: guest.shareID,
		`desktop`:  desktopUUID,
	})
}

func guestEventWrapper(guest *guestDesktop, desktopUUID string) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			data := *pack.Data[`data`].(*[]byte)
			if utility.IsFrameOp(data[5]) {
				guest.srcConn.WriteBinary(data)
				return
			}
			if data[5] != utility.BinaryOpShareControl {
				return
			}
			// Binary protocol header is 24 bytes: magic(4) + service(1) + op(1) + event(16) + length(2)
			data = data[24:]
			data = utility.SimpleDecrypt(data, device)
			if utils.JSON.Unmarshal(data, &pack) != nil {
				return
			}
		}

		switch pack.Act {
		case `DESKTOP_INIT`:
			if pack.Code != 0 {
				msg := `${i18n|DESKTOP.CREATE_SESSION_FAILED}`
				if len(pack.Msg) > 0 {
					msg += `: ` + pack.Msg
				}
				sendGuestPack(modules.Packet{Act: `QUIT`, Msg: msg}, guest.srcConn)
				common.RemoveEvent(desktopUUID)
				guest.srcConn.Close()
				return
			}

			// Forward DESKTOP_INIT success payload so guests resize their canvas
			// before the first binary frame arrives (mirrors primary desktop handler).
			sendGuestPack(modules.Packet{Act: `DESKTOP_INIT`, Code: 0, Data: pack.Data}, guest.srcConn)
		case `DESKTOP_QUIT`:
			msg := `${i18n|DESKTOP.SESSION_CLOSED}`
			if len(pack.Msg) > 0 {
				msg = pack.Msg
			}
			sendGuestPack(modules.Packet{Act: `QUIT`, Msg: msg}, guest.srcConn)
			common.RemoveEvent(desktopUUID)
			guest.srcConn.Close()
		case `DESKTOP_INPUT`:
			if pack.Code != 0 {
				sendGuestPack(pack, guest.srcConn)
			}
		case `CURSOR_UPDATE`:
			sendGuestPack(pack, guest.srcConn)
		case `DESKTOP_PONG`:
			payload := gin.H{`source`: `device`}
			if pack.Data != nil {
				for k, v := range pack.Data {
					payload[k] = v
				}
			}
			sendGuestPack(modules.Packet{Act: `DESKTOP_PONG`, Code: pack.Code, Data: payload}, guest.srcConn)
		case `DESKTOP_CONFIG_ACK`:
			sendGuestPack(modules.Packet{Act: `DESKTOP_CONFIG_ACK`, Code: pack.Code, Data: pack.Data, Msg: pack.Msg}, guest.srcConn)
		case `DESKTOP_CLIPBOARD`, `DESKTOP_AUDIO`, `DESKTOP_FILE_DROP`:
			if pack.Code != 0 {
				sendGuestPack(pack, guest.srcConn)
			}
		case `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`, `DESKTOP_WEBRTC_ICE`:
			sendGuestPack(pack, guest.srcConn)
		}
	}
}

func sendGuestPack(pack modules.Packet, session *melody.Session) bool {
	if session == nil {
		return false
	}
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return false
	}
	data = utility.SimpleEncrypt(data, session)
	err = session.WriteBinary(append([]byte{34, 22, 19, 17, 20, 03}, data...))
	return err == nil
}

// Payload limits are now centralized in utility/limits.go
// See: REMOTE_DESKTOP_PIPELINE_AUDIT.md - Payload Constant Centralization

func normalizeInputEvents(data map[string]any) ([]any, bool) {
	if data == nil {
		return nil, false
	}
	rawEvents, ok := data[`events`]
	if !ok {
		return nil, false
	}
	switch events := rawEvents.(type) {
	case []any:
		if len(events) > utility.MaxDesktopInputBatch {
			return events[:utility.MaxDesktopInputBatch], true
		}
		return events, true
	default:
		return nil, false
	}
}

func normalizeSDP(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	sdp, ok := data[`sdp`].(string)
	if !ok || len(sdp) == 0 || len(sdp) > utility.MaxSDPLength {
		return nil, false
	}
	if !isValidSDP(sdp) {
		return nil, false
	}
	t, ok := data[`type`].(string)
	if !ok || len(t) == 0 {
		return nil, false
	}
	payload := gin.H{`sdp`: sdp, `type`: t}
	if role, ok := data[`role`].(string); ok {
		payload[`role`] = role
	}
	if retry, ok := data[`retry`].(float64); ok {
		payload[`retry`] = retry
	}
	return payload, true
}

func normalizeCandidate(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	candidate, ok := data[`candidate`].(string)
	if !ok || len(candidate) == 0 || len(candidate) > utility.MaxCandidateLength {
		return nil, false
	}
	if !isValidICECandidate(candidate) {
		return nil, false
	}
	payload := gin.H{`candidate`: candidate}
	if mid, ok := data[`sdpMid`].(string); ok {
		payload[`sdpMid`] = mid
	}
	if idx, ok := data[`mLine`].(float64); ok {
		payload[`mLine`] = idx
	} else if idx, ok := data[`sdpMLineIndex`].(float64); ok {
		payload[`mLine`] = idx
	}
	if role, ok := data[`role`].(string); ok {
		payload[`role`] = role
	}
	if retry, ok := data[`retry`].(float64); ok {
		payload[`retry`] = retry
	}
	return payload, true
}

func isValidSDP(sdp string) bool {
	if sdp == "" {
		return false
	}
	return strings.Contains(sdp, "v=") && strings.Contains(sdp, "m=")
}

func isValidICECandidate(candidate string) bool {
	if candidate == "" {
		return true
	}
	return strings.Contains(candidate, " ") &&
		(strings.HasPrefix(candidate, "candidate:") || strings.Contains(candidate, "typ "))
}

func normalizeClipboard(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	text, ok := data[`text`].(string)
	if !ok || len(text) == 0 {
		return nil, false
	}
	if len(text) > utility.MaxClipboardBytes {
		text = text[:utility.MaxClipboardBytes]
	}
	payload := gin.H{`text`: text}
	if mime, ok := data[`mime`].(string); ok && len(mime) > 0 {
		payload[`mime`] = strings.ToLower(mime)
	}
	return payload, true
}

func normalizeFileDrop(data map[string]any) (gin.H, bool) {
	if data == nil {
		return nil, false
	}
	rawFiles, ok := data[`files`]
	if !ok {
		return nil, false
	}
	list, ok := rawFiles.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}

	files := make([]gin.H, 0, len(list))
	for _, item := range list {
		if len(files) >= utility.MaxFileDropEntries {
			break
		}
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m[`name`].(string)
		if len(name) > utility.MaxFileNameLength {
			name = name[:utility.MaxFileNameLength]
		}
		size := int64(0)
		switch v := m[`size`].(type) {
		case float64:
			size = int64(v)
		case int64:
			size = v
		case int:
			size = int64(v)
		}
		if len(name) == 0 && size <= 0 {
			continue
		}
		file := gin.H{`name`: name}
		if size > 0 {
			file[`size`] = size
		}
		if mime, ok := m[`type`].(string); ok && len(mime) > 0 {
			file[`type`] = mime
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return nil, false
	}
	return gin.H{`files`: files}, true
}

func normalizeAudioControl(data map[string]any) (gin.H, bool) {
	if data == nil {
		return gin.H{}, true
	}
	payload := gin.H{}
	if muted, ok := data[`muted`].(bool); ok {
		payload[`muted`] = muted
	}
	if op, ok := data[`op`].(string); ok && len(op) > 0 {
		payload[`op`] = strings.ToLower(op)
	}
	if mode, ok := data[`mode`].(string); ok && len(mode) > 0 {
		payload[`mode`] = strings.ToLower(mode)
	}
	return payload, true
}
