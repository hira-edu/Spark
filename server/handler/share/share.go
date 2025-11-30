package share

import (
	"Spark/modules"
	"Spark/utils"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type shareEntry struct {
	ID        string    `json:"id"`
	Device    string    `json:"device"`
	Desktop   string    `json:"desktop"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}

var (
	storeMu sync.Mutex
	store   = map[string]*shareEntry{}
)

// ValidateShareToken verifies that the provided token is valid and not expired.
func ValidateShareToken(ctx *gin.Context) {
	token := ctx.Query(`token`)
	if token == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	if entry := getByToken(token); entry != nil && time.Now().Before(entry.ExpiresAt) {
		ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`share`: entry}})
		return
	}
	ctx.AbortWithStatusJSON(401, modules.Packet{Code: 1, Msg: `${i18n|COMMON.UNAUTHORIZED}`})
}

// InitGuestDesktop is a placeholder; guests are not streamed yet.
func InitGuestDesktop(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(501, modules.Packet{Code: -1, Msg: `${i18n|DESKTOP.UNSUPPORTED_PLATFORM}`})
}

func CreateShare(ctx *gin.Context) {
	var body struct {
		Device  string `json:"device"`
		Desktop string `json:"desktop"`
		TTL     int    `json:"ttlSeconds"`
	}
	if err := ctx.ShouldBind(&body); err != nil || body.Device == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	if body.TTL <= 0 {
		body.TTL = 3600
	}
	entry := &shareEntry{
		ID:        utils.GetStrUUID(),
		Device:    body.Device,
		Desktop:   body.Desktop,
		Token:     utils.GetStrUUID(),
		ExpiresAt: time.Now().Add(time.Duration(body.TTL) * time.Second),
	}
	storeMu.Lock()
	store[entry.ID] = entry
	storeMu.Unlock()
	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`share`: entry}})
}

func ListShares(ctx *gin.Context) {
	storeMu.Lock()
	defer storeMu.Unlock()
	now := time.Now()
	var items []shareEntry
	for id, s := range store {
		if now.After(s.ExpiresAt) {
			delete(store, id)
			continue
		}
		items = append(items, *s)
	}
	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`shares`: items}})
}

func GetShare(ctx *gin.Context) {
	id := ctx.Param(`id`)
	if id == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if s, ok := store[id]; ok && time.Now().Before(s.ExpiresAt) {
		ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`share`: s}})
		return
	}
	ctx.AbortWithStatusJSON(404, modules.Packet{Code: 1, Msg: `${i18n|COMMON.NOT_EXIST}`})
}

func GetShareToken(ctx *gin.Context) {
	id := ctx.Param(`id`)
	if id == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	if s, ok := store[id]; ok && time.Now().Before(s.ExpiresAt) {
		ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{`token`: s.Token, `expiresAt`: s.ExpiresAt}})
		return
	}
	ctx.AbortWithStatusJSON(404, modules.Packet{Code: 1, Msg: `${i18n|COMMON.NOT_EXIST}`})
}

func RevokeShare(ctx *gin.Context) {
	var body struct {
		ID string `json:"id"`
	}
	if err := ctx.ShouldBind(&body); err != nil || body.ID == "" {
		ctx.AbortWithStatusJSON(400, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	storeMu.Lock()
	delete(store, body.ID)
	storeMu.Unlock()
	ctx.JSON(200, modules.Packet{Code: 0})
}

func DeleteShare(ctx *gin.Context) { RevokeShare(ctx) }

// CloseGuestSessionsByDevice clears shares for a device.
func CloseGuestSessionsByDevice(deviceID string) {
	if deviceID == "" {
		return
	}
	storeMu.Lock()
	defer storeMu.Unlock()
	for id, s := range store {
		if s.Device == deviceID {
			delete(store, id)
		}
	}
}

func getByToken(token string) *shareEntry {
	storeMu.Lock()
	defer storeMu.Unlock()
	for id, s := range store {
		if s.Token == token && time.Now().Before(s.ExpiresAt) {
			return s
		}
		if time.Now().After(s.ExpiresAt) {
			delete(store, id)
		}
	}
	return nil
}
