package auth

import (
	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/server/storage"
	"Rocket/utils"
	"context"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kataras/golog"
)

var (
	userRepo *storage.UserRepository
	sessions = make(map[string]*Session) // token -> Session
)

// Session represents an authenticated session
type Session struct {
	Token     string
	Username  string
	Role      string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastSeen  time.Time
}

func init() {
	go cleanupSessions()
}

// Init initializes the auth module (must be called after MongoDB is initialized)
func Init() {
	userRepo = storage.NewUserRepository()
	golog.Info("Auth module initialized with MongoDB user repository")
}

// cleanupSessions removes expired sessions periodically
func cleanupSessions() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		expired := []string{}
		for token, session := range sessions {
			if now.After(session.ExpiresAt) {
				expired = append(expired, token)
			}
		}
		for _, token := range expired {
			delete(sessions, token)
		}
		if len(expired) > 0 {
			golog.Infof("Cleaned up %d expired sessions", len(expired))
		}
	}
}

// Login handles user login
func Login(ctx *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|COMMON.INVALID_PARAMETER}"})
		return
	}

	dbCtx := context.Background()
	user, err := userRepo.ValidatePassword(dbCtx, body.Username, body.Password)
	if err != nil {
		common.Warn(ctx, "LOGIN_FAILED", "invalid_credentials", body.Username, map[string]any{
			"ip": ctx.ClientIP(),
		})
		ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.INVALID_CREDENTIALS}"})
		return
	}

	// Update last login
	userRepo.UpdateLastLogin(dbCtx, user.Username, ctx.ClientIP())

	// Create session
	token := utils.GetStrUUID()
	session := &Session{
		Token:     token,
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
		LastSeen:  time.Now(),
	}
	sessions[token] = session

	// Set cookie
	ctx.SetCookie(
		"Authorization",
		token,
		int((24 * time.Hour).Seconds()),
		"/",
		"",
		false, // Set to true if using HTTPS
		true,  // HttpOnly
	)

	common.Info(ctx, "LOGIN_SUCCESS", "", "", map[string]any{
		"user": user.Username,
		"role": user.Role,
		"ip":   ctx.ClientIP(),
	})

	ctx.JSON(200, modules.Packet{
		Code: 0,
		Data: gin.H{
			"user": gin.H{
				"username":    user.Username,
				"role":        user.Role,
				"email":       user.Email,
				"lastLoginAt": user.LastLoginAt,
			},
			"token": token,
		},
	})
}

// Logout handles user logout
func Logout(ctx *gin.Context) {
	token, err := ctx.Cookie("Authorization")
	if err == nil && token != "" {
		if session, ok := sessions[token]; ok {
			common.Info(ctx, "LOGOUT", "", "", map[string]any{
				"user": session.Username,
				"ip":   ctx.ClientIP(),
			})
			delete(sessions, token)
		}
	}

	// Clear cookie
	ctx.SetCookie("Authorization", "", -1, "/", "", false, true)

	ctx.JSON(200, modules.Packet{Code: 0})
}

// CheckAuth is a middleware that verifies user authentication
func CheckAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip auth for public endpoints
		if isPublicEndpoint(ctx.Request.URL.Path) {
			ctx.Next()
			return
		}

		token, err := ctx.Cookie("Authorization")
		if err != nil || token == "" {
			ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.UNAUTHORIZED}"})
			ctx.Abort()
			return
		}

		session, ok := sessions[token]
		if !ok {
			ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.SESSION_EXPIRED}"})
			ctx.Abort()
			return
		}

		// Check if session expired
		if time.Now().After(session.ExpiresAt) {
			delete(sessions, token)
			ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.SESSION_EXPIRED}"})
			ctx.Abort()
			return
		}

		// Update last seen
		session.LastSeen = time.Now()

		// Set user context
		ctx.Set("user", session.Username)
		ctx.Set("role", session.Role)

		ctx.Next()
	}
}

// GetCurrentUser returns the currently authenticated user info
func GetCurrentUser(ctx *gin.Context) {
	username, exists := ctx.Get("user")
	if !exists {
		ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.UNAUTHORIZED}"})
		return
	}

	dbCtx := context.Background()
	user, err := userRepo.GetUser(dbCtx, username.(string))
	if err != nil || user == nil {
		ctx.JSON(404, modules.Packet{Code: 1, Msg: "${i18n|AUTH.USER_NOT_FOUND}"})
		return
	}

	ctx.JSON(200, modules.Packet{
		Code: 0,
		Data: gin.H{
			"user": gin.H{
				"username":    user.Username,
				"role":        user.Role,
				"email":       user.Email,
				"createdAt":   user.CreatedAt,
				"lastLoginAt": user.LastLoginAt,
			},
		},
	})
}

// CheckSetup checks if initial setup is needed (no users exist)
func CheckSetup(ctx *gin.Context) {
	dbCtx := context.Background()
	count, err := userRepo.CountUsers(dbCtx)
	if err != nil {
		ctx.JSON(500, modules.Packet{Code: 1, Msg: "${i18n|COMMON.INTERNAL_ERROR}"})
		return
	}

	ctx.JSON(200, modules.Packet{
		Code: 0,
		Data: gin.H{
			"needsSetup": count == 0,
		},
	})
}

// InitialSetup creates the first admin user
func InitialSetup(ctx *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|COMMON.INVALID_PARAMETER}"})
		return
	}

	// Validate input
	if len(body.Username) < 3 {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|AUTH.USERNAME_TOO_SHORT}"})
		return
	}
	if len(body.Password) < 6 {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|AUTH.PASSWORD_TOO_SHORT}"})
		return
	}

	dbCtx := context.Background()

	// Check if setup already done
	count, err := userRepo.CountUsers(dbCtx)
	if err != nil {
		ctx.JSON(500, modules.Packet{Code: 1, Msg: "${i18n|COMMON.INTERNAL_ERROR}"})
		return
	}
	if count > 0 {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|AUTH.SETUP_ALREADY_DONE}"})
		return
	}

	// Create admin user
	user, err := userRepo.CreateUser(dbCtx, body.Username, body.Password, "admin", body.Email)
	if err != nil {
		golog.Errorf("Failed to create admin user: %v", err)
		ctx.JSON(500, modules.Packet{Code: 1, Msg: "${i18n|COMMON.INTERNAL_ERROR}"})
		return
	}

	common.Info(ctx, "INITIAL_SETUP", "success", "", map[string]any{
		"user": user.Username,
		"ip":   ctx.ClientIP(),
	})

	ctx.JSON(200, modules.Packet{Code: 0, Data: gin.H{
		"user": gin.H{
			"username": user.Username,
			"role":     user.Role,
			"email":    user.Email,
		},
	}})
}

// ChangePassword allows users to change their password
func ChangePassword(ctx *gin.Context) {
	username, exists := ctx.Get("user")
	if !exists {
		ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.UNAUTHORIZED}"})
		return
	}

	var body struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|COMMON.INVALID_PARAMETER}"})
		return
	}

	if len(body.NewPassword) < 6 {
		ctx.JSON(400, modules.Packet{Code: -1, Msg: "${i18n|AUTH.PASSWORD_TOO_SHORT}"})
		return
	}

	dbCtx := context.Background()

	// Validate old password
	_, err := userRepo.ValidatePassword(dbCtx, username.(string), body.OldPassword)
	if err != nil {
		ctx.JSON(401, modules.Packet{Code: 1, Msg: "${i18n|AUTH.INVALID_OLD_PASSWORD}"})
		return
	}

	// Update password
	err = userRepo.UpdatePassword(dbCtx, username.(string), body.NewPassword)
	if err != nil {
		golog.Errorf("Failed to update password: %v", err)
		ctx.JSON(500, modules.Packet{Code: 1, Msg: "${i18n|COMMON.INTERNAL_ERROR}"})
		return
	}

	common.Info(ctx, "PASSWORD_CHANGED", "success", "", map[string]any{
		"user": username,
		"ip":   ctx.ClientIP(),
	})

	ctx.JSON(200, modules.Packet{Code: 0})
}

// isPublicEndpoint checks if an endpoint should be accessible without authentication
func isPublicEndpoint(path string) bool {
	// Exact match public endpoints
	publicPaths := []string{
		"/api/auth/login",
		"/api/auth/logout",
		"/api/auth/setup/check",
		"/api/auth/setup",
		"/api/share/validate",
		"/api/share/ice",
		"/api/share/desktop",
		"/api/bridge/push",
		"/api/bridge/pull",
		"/api/client/update",
	}

	for _, p := range publicPaths {
		if path == p {
			return true
		}
	}

	// Prefix match for share guest access and long polling
	publicPrefixes := []string{
		"/api/longpoll/",
	}

	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}
