package core

import (
	"Rocket/client/common"
	"Rocket/client/config"
	"Rocket/client/telemetry"

	"github.com/kataras/golog"
)

// InitLogStreaming initializes log streaming to server
// Should be called after successful WebSocket connection
func InitLogStreaming() {
	if common.WSConn == nil {
		return
	}

	secret := common.WSConn.GetSecretHex()
	serverURL := config.GetBaseURL(false)

	// Create send function that uses the secret for auth
	sendFunc := func(logs []telemetry.LogEntry) error {
		return telemetry.SendLogsToServer(serverURL, secret, logs)
	}

	// Initialize streamer with session ID 0 (will be updated for user sessions)
	streamer := telemetry.InitLogStreamer(0, sendFunc)

	golog.Info("client: log streaming to server enabled")

	// Return streamer for caller to manage
	_ = streamer
}

// UpdateLogSessionID updates the session ID in the log streamer
// Should be called when transitioning between Session 0 and user sessions
func UpdateLogSessionID(sessionID uint32) {
	telemetry.UpdateSessionID(sessionID)
	golog.Infof("client: log streaming session ID updated to %d", sessionID)
}
