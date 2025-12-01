//go:build windows
// +build windows

package lifecycle

import (
	"Rocket/client/ipc"
	"Rocket/client/service/desktop"
	"errors"
	"time"

	"github.com/kataras/golog"
	"golang.org/x/sys/windows"
)

// RunUIOnlyMode starts the desktop bridge for handling desktop capture in user session
func RunUIOnlyMode() error {
	golog.Info("runner: Starting desktop bridge in UI-only mode")

	for {
		// Get current session ID
		var sessionID uint32
		err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID)
		if err != nil {
			golog.Errorf("runner: Failed to get session ID: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		golog.Infof("runner: Current session ID: %d", sessionID)

		// Start the desktop bridge to handle IPC from Session 0
		if err := desktop.StartBridge(sessionID); err != nil {
			// If another bridge is already running, exit gracefully
			if errors.Is(err, ipc.ErrBridgeAlreadyRunning) {
				golog.Info("runner: Another desktop bridge is already running, exiting")
				return nil
			}
			golog.Errorf("runner: Failed to start desktop bridge: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		golog.Info("runner: Desktop bridge started, waiting for commands from Session 0")
		break
	}

	// Block forever - service lifecycle manages this process
	select {}
}

// SetServiceMode configures the desktop relay for Session 0 operation
func SetServiceMode(sessionID uint32) {
	golog.Infof("runner: Enabling Session 0 mode, active user session: %d", sessionID)
	desktop.SetSession0Mode(true)
	desktop.SetActiveSessionID(sessionID)
}
