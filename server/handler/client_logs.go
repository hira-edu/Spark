package handler

import (
	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/server/storage"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// ClientLogEntry represents a single log entry from the client
type ClientLogEntry struct {
	SessionID uint32                 `json:"sessionId"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source,omitempty"`
	Network   string                 `json:"network,omitempty"`
	Attempt   int                    `json:"attempt,omitempty"`
	CloseCode int                    `json:"closeCode,omitempty"`
	CloseReason string               `json:"closeReason,omitempty"`
}

// UploadClientLogs receives and stores client logs in MongoDB
func UploadClientLogs(ctx *gin.Context) {
	session := common.CheckClientReq(ctx)
	if session == nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, modules.Packet{Code: 1, Msg: "unauthorized"})
		return
	}

	// Get device info from session
	device, ok := common.Devices.Get(session.UUID)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: 1, Msg: "device not registered"})
		return
	}

	// Parse log entries from request
	var logs []ClientLogEntry
	if err := ctx.ShouldBindJSON(&logs); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: 1, Msg: "invalid log format: " + err.Error()})
		return
	}

	if len(logs) == 0 {
		ctx.JSON(http.StatusOK, modules.Packet{Code: 0, Msg: "no logs to save"})
		return
	}

	// Convert to storage format
	storageLogs := make([]storage.ClientLog, len(logs))
	for i, entry := range logs {
		storageLogs[i] = storage.ClientLog{
			DeviceID:   device.ID,
			DeviceUUID: session.UUID,
			DeviceName: device.Hostname,
			SessionID:  entry.SessionID,
			Level:      entry.Level,
			Message:    entry.Message,
			Data:       entry.Data,
			Timestamp:  entry.Timestamp,
			Source:     entry.Source,
			Network:    entry.Network,
			Attempt:    entry.Attempt,
			CloseCode:  entry.CloseCode,
			CloseReason: entry.CloseReason,
		}
	}

	// Save to MongoDB
	if err := storage.SaveClientLogs(ctx.Request.Context(), storageLogs); err != nil {
		common.Warn(ctx, "CLIENT_LOGS_SAVE", "fail", err.Error(), map[string]any{
			"device":    device.ID,
			"log_count": len(logs),
		})
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: "failed to save logs"})
		return
	}

	common.Info(ctx, "CLIENT_LOGS_SAVE", "success", "", map[string]any{
		"device":    device.Hostname,
		"log_count": len(logs),
		"uuid":      session.UUID[:8] + "...",
	})

	ctx.JSON(http.StatusOK, modules.Packet{Code: 0, Data: map[string]any{
		"saved": len(logs),
	}})
}

// GetClientLogs retrieves client logs from MongoDB with filtering
func GetClientLogs(ctx *gin.Context) {
	// Build filter from query parameters
	filter := storage.ClientLogFilter{}

	if deviceID := ctx.Query("device"); deviceID != "" {
		filter.DeviceID = deviceID
	}
	if uuid := ctx.Query("uuid"); uuid != "" {
		filter.DeviceUUID = uuid
	}
	if sessionIDStr := ctx.Query("session_id"); sessionIDStr != "" {
		if sid, err := strconv.ParseUint(sessionIDStr, 10, 32); err == nil {
			sessionID := uint32(sid)
			filter.SessionID = &sessionID
		}
	}
	if level := ctx.Query("level"); level != "" {
		filter.Level = level
	}
	if minLevel := ctx.Query("min_level"); minLevel != "" {
		filter.MinLevel = minLevel
	}
	if afterStr := ctx.Query("after"); afterStr != "" {
		if after, err := time.Parse(time.RFC3339, afterStr); err == nil {
			filter.After = after
		}
	}
	if beforeStr := ctx.Query("before"); beforeStr != "" {
		if before, err := time.Parse(time.RFC3339, beforeStr); err == nil {
			filter.Before = before
		}
	}

	// Default: last hour
	if filter.After.IsZero() && filter.Before.IsZero() {
		filter.After = time.Now().UTC().Add(-1 * time.Hour)
	}

	// Get limit from query (default 1000, max 10000)
	limit := 1000
	if limitStr := ctx.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
			if limit > 10000 {
				limit = 10000
			}
		}
	}

	// Query logs
	logs, err := storage.GetClientLogs(ctx.Request.Context(), filter, limit)
	if err != nil {
		common.Warn(ctx, "CLIENT_LOGS_GET", "fail", err.Error(), nil)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: "failed to get logs"})
		return
	}

	ctx.JSON(http.StatusOK, modules.Packet{Code: 0, Data: map[string]any{
		"logs":  logs,
		"count": len(logs),
	}})
}

// initClientLogsRoutes initializes client log endpoints
func initClientLogsRoutes(group *gin.RouterGroup) {
	group.POST("/client/logs/upload", UploadClientLogs)
	group.GET("/client/logs", GetClientLogs)
}
