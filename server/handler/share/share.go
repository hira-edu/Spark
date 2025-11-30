package share

import (
	"Spark/modules"
	"Spark/server/common"
	servercfg "Spark/server/config"
	"Spark/server/handler/utility"
	"Spark/utils"
	"Spark/utils/melody"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kataras/golog"
)

// ShareEntry represents a desktop sharing session
type ShareEntry struct {
	ID        string           `json:"id"`
	Device    string           `json:"device"`
	Desktop   string           `json:"desktop"`
	Token     string           `json:"token"`
	ExpiresAt time.Time        `json:"expiresAt"`
	SingleUse bool             `json:"singleUse"`
	ViewOnly  bool             `json:"viewOnly"`
	TurnOnly  bool             `json:"turnOnly"`
	Used      bool             `json:"used"`
	UsedAt    time.Time        `json:"usedAt,omitempty"`
	UsedBy    string           `json:"usedBy,omitempty"`
	CreatedAt time.Time        `json:"createdAt"`
	AccessLog []AccessLogEntry `json:"accessLog,omitempty"`
}

// AccessLogEntry records guest access attempts
type AccessLogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"userAgent"`
	Success   bool      `json:"success"`
	Reason    string    `json:"reason,omitempty"`
}

type guestDesktop struct {
	shareID    string
	device     string
	srcConn    *melody.Session
	deviceConn *melody.Session
	viewOnly   bool
}

var (
	storeMu sync.RWMutex
	store   = map[string]*ShareEntry{}

	guestSessions = melody.New()
)

const (
	defaultTTLSeconds = 3600  // 1 hour
	maxTTLSeconds     = 86400 // 24 hours
)

func init() {
	guestSessions.Config.MaxMessageSize = common.MaxMessageSize
	guestSessions.HandleConnect(onGuestConnect)
	guestSessions.HandleMessage(onGuestMessage)
	guestSessions.HandleMessageBinary(onGuestMessage)
	guestSessions.HandleDisconnect(onGuestDisconnect)
	go utility.WSHealthCheck(guestSessions, sendGuestPack)
	go cleanupExpiredShares()
}

func isExpired(entry *ShareEntry, now time.Time) bool {
	if entry == nil {
		return true
	}
	if entry.ExpiresAt.IsZero() {
		return false
	}
	return now.After(entry.ExpiresAt)
}

func ensureDesktop(entry *ShareEntry) string {
	if entry == nil || entry.ID == "" {
		return ""
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	current, ok := store[entry.ID]
	if !ok || isExpired(current, time.Now()) {
		return ""
	}
	if current.Desktop == "" {
		current.Desktop = utils.GetStrUUID()
	}
	return current.Desktop
}

func guestICEConfig(entry *ShareEntry) gin.H {
	ice := gin.H{
		`stun`: []string{},
		`turn`: []string{},
	}
	if entry == nil {
		return ice
	}
	if cfg := servercfg.Config.WebRTC; cfg != nil {
		if !entry.TurnOnly {
			ice[`stun`] = append(ice[`stun`].([]string), cfg.Stun...)
		}
		ice[`turn`] = append(ice[`turn`].([]string), cfg.Turn...)
		return ice
	}
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
	for range ticker.C {
		now := time.Now()
		expired := make([]string, 0)
		storeMu.Lock()
		for id, s := range store {
			if isExpired(s, now) {
				expired = append(expired, id)
				delete(store, id)
			}
		}
		storeMu.Unlock()
		// Close any guest sessions tied to expired shares
		for _, id := range expired {
			closeGuestSessionsByShare(id)
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

	entry := getByToken(token)
	if entry == nil {
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

	// Return sanitized entry (without internal fields)
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
		},
	}})
}

// InitGuestDesktop handles guest desktop WebSocket connections
func InitGuestDesktop(ctx *gin.Context) {
	if !ctx.IsWebsocket() {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	// Validate origin for CSWSH protection
	if !validateGuestOrigin(ctx) {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	token := ctx.Query(`token`)
	if token == "" {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	secretStr, ok := ctx.GetQuery(`secret`)
	if !ok || len(secretStr) != 32 {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	secret, err := hex.DecodeString(secretStr)
	if err != nil {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	entry := getByToken(token)
	if entry == nil {
		logAccess(token, ctx, false, "token not found")
		ctx.AbortWithStatus(http.StatusUnauthorized)
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
	connUUID, ok := common.CheckDevice(entry.Device, ``)
	if !ok {
		logAccess(token, ctx, false, "device not connected")
		ctx.AbortWithStatus(http.StatusNotFound)
		return
	}

	// Mark single-use token as used
	if entry.SingleUse {
		markTokenUsed(entry.ID, ctx)
	}

	logAccess(token, ctx, true, "")
	golog.Infof("Guest desktop connection: share=%s device=%s ip=%s", entry.ID, entry.Device, ctx.ClientIP())

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

	entry := getByToken(token)
	if entry == nil {
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
	if ttl < 0 {
		ttl = defaultTTLSeconds
	}
	if ttl > maxTTLSeconds {
		ttl = maxTTLSeconds
	}
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	}

	entry := &ShareEntry{
		ID:        utils.GetStrUUID(),
		Device:    body.Device,
		Desktop:   body.Desktop,
		Token:     utils.GetStrUUID(),
		ExpiresAt: expiresAt,
		SingleUse: body.SingleUse,
		ViewOnly:  body.ViewOnly,
		TurnOnly:  body.TurnOnly,
		CreatedAt: time.Now(),
		AccessLog: []AccessLogEntry{},
	}

	storeMu.Lock()
	store[entry.ID] = entry
	storeMu.Unlock()

	golog.Infof("Share created: id=%s device=%s singleUse=%v viewOnly=%v turnOnly=%v ttl=%ds",
		entry.ID, entry.Device, entry.SingleUse, entry.ViewOnly, entry.TurnOnly, ttl)

	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`share`: entry}})
}

// ListShares returns all active shares
func ListShares(ctx *gin.Context) {
	storeMu.Lock()
	defer storeMu.Unlock()
	now := time.Now()
	var items []ShareEntry
	for id, s := range store {
		if isExpired(s, now) {
			delete(store, id)
			continue
		}
		items = append(items, *s)
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
	storeMu.RLock()
	defer storeMu.RUnlock()
	if s, ok := store[id]; ok && !isExpired(s, time.Now()) {
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
	storeMu.RLock()
	defer storeMu.RUnlock()
	if s, ok := store[id]; ok && !isExpired(s, time.Now()) {
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
	storeMu.RLock()
	defer storeMu.RUnlock()
	if s, ok := store[id]; ok {
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

	storeMu.Lock()
	if s, ok := store[body.ID]; ok {
		golog.Infof("Share revoked: id=%s device=%s", s.ID, s.Device)
		delete(store, body.ID)
	}
	storeMu.Unlock()

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

	storeMu.Lock()
	for id, s := range store {
		if s.Device == deviceID {
			golog.Infof("Share auto-revoked on device disconnect: id=%s device=%s", s.ID, s.Device)
			delete(store, id)
		}
	}
	storeMu.Unlock()

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

func getByToken(token string) *ShareEntry {
	storeMu.RLock()
	defer storeMu.RUnlock()
	now := time.Now()
	for _, s := range store {
		if s.Token == token && !isExpired(s, now) {
			return s
		}
	}
	return nil
}

func isShareActive(id string) bool {
	if id == "" {
		return false
	}
	storeMu.RLock()
	defer storeMu.RUnlock()
	if s, ok := store[id]; ok && !isExpired(s, time.Now()) {
		return true
	}
	return false
}

func markTokenUsed(id string, ctx *gin.Context) {
	storeMu.Lock()
	defer storeMu.Unlock()
	if s, ok := store[id]; ok {
		s.Used = true
		s.UsedAt = time.Now()
		s.UsedBy = ctx.ClientIP()
	}
}

func logAccess(token string, ctx *gin.Context, success bool, reason string) {
	storeMu.Lock()
	defer storeMu.Unlock()
	now := time.Now()
	for _, s := range store {
		if s.Token == token {
			if isExpired(s, now) {
				continue
			}
			s.AccessLog = append(s.AccessLog, AccessLogEntry{
				Timestamp: now,
				IP:        ctx.ClientIP(),
				UserAgent: ctx.GetHeader("User-Agent"),
				Success:   success,
				Reason:    reason,
			})
			// Keep only last 100 entries
			if len(s.AccessLog) > 100 {
				s.AccessLog = s.AccessLog[len(s.AccessLog)-100:]
			}
			return
		}
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
			return true
		}
	}
	if shareID == "" || isShareActive(shareID) {
		return false
	}
	sendGuestPack(modules.Packet{Act: `QUIT`, Msg: `${i18n|SHARE.SESSION_REVOKED}`}, session)
	session.Close()
	return true
}

// Guest WebSocket handlers

func onGuestConnect(session *melody.Session) {
	shareID, ok := session.Get(`ShareID`)
	if !ok {
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
		sendGuestPack(modules.Packet{Act: `WARN`, Msg: `${i18n|COMMON.INVALID_PARAMETER}`}, session)
		session.Close()
		return
	}

	deviceConn, ok := common.Melody.GetSessionByUUID(connUUID.(string))
	if !ok {
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

	// Request desktop init from device
	common.SendPack(modules.Packet{Act: `DESKTOP_INIT`, Data: gin.H{
		`desktop`: desktopUUID,
	}, Event: desktopUUID}, deviceConn)

	golog.Infof("Guest connected: share=%s desktop=%s viewOnly=%v", shareIDStr, desktopUUID, viewOnlyBool)
}

func onGuestMessage(session *melody.Session, data []byte) {
	val, ok := session.Get(`Guest`)
	if !ok {
		return
	}
	guest := val.(*guestDesktop)
	desktopUUID, _ := session.Get(`DesktopUUID`)
	if expiredSession(session, guest.shareID) {
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
		common.SendPack(modules.Packet{Act: `DESKTOP_PING`, Data: gin.H{
			`desktop`: desktopUUID,
		}, Event: desktopUUID.(string)}, guest.deviceConn)
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

	case `DESKTOP_INPUT`:
		// Block input for view-only guests
		if guest.viewOnly {
			sendGuestPack(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: `${i18n|SHARE.VIEW_ONLY}`}, session)
			return
		}
		// Forward input to device
		events, ok := normalizeInputEvents(pack.Data)
		if !ok || len(events) == 0 {
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

	case `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`:
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
	session.Close()
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

	golog.Infof("Guest disconnected: share=%s desktop=%s", guest.shareID, desktopUUID)
}

func guestEventWrapper(guest *guestDesktop, desktopUUID string) common.EventCallback {
	return func(pack modules.Packet, device *melody.Session) {
		if pack.Act == `RAW_DATA_ARRIVE` && pack.Data != nil {
			data := *pack.Data[`data`].(*[]byte)
			if data[5] == 00 || data[5] == 01 || data[5] == 02 {
				guest.srcConn.WriteBinary(data)
				return
			}
			if data[5] != 03 {
				return
			}
			data = data[8:]
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
			}
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

func validateGuestOrigin(ctx *gin.Context) bool {
	origin := ctx.GetHeader("Origin")
	if origin == "" {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil {
		return false
	}
	requestHost := ctx.Request.Host
	requestHostWithoutPort := strings.Split(requestHost, ":")[0]
	originHostWithoutPort := strings.Split(originURL.Host, ":")[0]
	if originHostWithoutPort == requestHostWithoutPort {
		return true
	}
	if isLocalhost(originHostWithoutPort) && isLocalhost(requestHostWithoutPort) {
		return true
	}
	return false
}

func isLocalhost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	default:
		return false
	}
}

// Helper functions for validation (same as desktop handler)

const (
	maxGuestInputBatch = 32
	maxSDPLength       = 1 << 15
	maxCandidateLength = 4096
)

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
		if len(events) > maxGuestInputBatch {
			return events[:maxGuestInputBatch], true
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
	if !ok || len(sdp) == 0 || len(sdp) > maxSDPLength {
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
	if !ok || len(candidate) == 0 || len(candidate) > maxCandidateLength {
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
