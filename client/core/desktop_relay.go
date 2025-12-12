//go:build windows
// +build windows

package core

import (
	"Rocket/client/common"
	"Rocket/client/service/desktop"
	"Rocket/modules"
)

// initDesktopWithRelay handles DESKTOP_INIT with Session 0 relay support
func initDesktopWithRelay(pack modules.Packet, wsConn *common.Conn) {
	// If running in Session 0 (service mode), relay to user session
	if desktop.IsSession0Mode() {
		sessionID := desktop.GetActiveSessionID()
		if sessionID == 0 {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INIT`, Code: 1, Msg: `${i18n|DESKTOP.NO_USER_SESSION}`}, pack)
			return
		}
		relay := desktop.GetOrCreateRelay(sessionID)
		if err := relay.Connect(); err != nil {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INIT`, Code: 1, Msg: err.Error()}, pack)
			return
		}
		if err := relay.SendInit(pack); err != nil {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INIT`, Code: 1, Msg: err.Error()}, pack)
			return
		}
		// DO NOT send success response here - wait for Session 1's actual response via IPC
		// The response will come through relay.handlePacket → sendDesktopPacket → WebSocket
		// Sending premature response causes race condition and duplicate packets
		return
	}

	// Direct mode - handle locally
	err := desktop.InitDesktop(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INIT`, Code: 1, Msg: err.Error()}, pack)
	}
	// DO NOT send success response here - desktop.InitDesktop already sends DESKTOP_INIT
	// with resolution data (width, height, monitors) via sendDesktopPacket.
	// Sending another response without this data would cause the browser to
	// miss the resolution info and fail to size the canvas properly.
}

// pingDesktopWithRelay handles DESKTOP_PING with Session 0 relay support
func pingDesktopWithRelay(pack modules.Packet, wsConn *common.Conn) {
	if desktop.IsSession0Mode() {
		sessionID := desktop.GetActiveSessionID()
		if sessionID == 0 {
			return
		}
		relay := desktop.GetOrCreateRelay(sessionID)
		relay.SendPing(pack)
		return
	}
	desktop.PingDesktop(pack)
}

// killDesktopWithRelay handles DESKTOP_KILL with Session 0 relay support
func killDesktopWithRelay(pack modules.Packet, wsConn *common.Conn) {
	if desktop.IsSession0Mode() {
		sessionID := desktop.GetActiveSessionID()
		if sessionID == 0 {
			return
		}
		relay := desktop.GetOrCreateRelay(sessionID)
		relay.SendKill(pack)
		return
	}
	desktop.KillDesktop(pack)
}

// getDesktopWithRelay handles DESKTOP_SHOT with Session 0 relay support
func getDesktopWithRelay(pack modules.Packet, wsConn *common.Conn) {
	if desktop.IsSession0Mode() {
		sessionID := desktop.GetActiveSessionID()
		if sessionID == 0 {
			return
		}
		relay := desktop.GetOrCreateRelay(sessionID)
		relay.SendShot(pack)
		return
	}
	desktop.GetDesktop(pack)
}

// inputDesktopWithRelay handles DESKTOP_INPUT with Session 0 relay support
func inputDesktopWithRelay(pack modules.Packet, wsConn *common.Conn) {
	if desktop.IsSession0Mode() {
		sessionID := desktop.GetActiveSessionID()
		if sessionID == 0 {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: `${i18n|DESKTOP.NO_USER_SESSION}`}, pack)
			return
		}
		relay := desktop.GetOrCreateRelay(sessionID)
		if err := relay.SendInput(pack); err != nil {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: err.Error()}, pack)
			return
		}
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 0}, pack)
		return
	}

	err := desktop.HandleInput(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_INPUT`, Code: 0}, pack)
}

// configDesktopWithRelay handles DESKTOP_CONFIG with Session 0 relay support
func configDesktopWithRelay(pack modules.Packet, wsConn *common.Conn) {
	if desktop.IsSession0Mode() {
		sessionID := desktop.GetActiveSessionID()
		if sessionID == 0 {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 1, Msg: `${i18n|DESKTOP.NO_USER_SESSION}`}, pack)
			return
		}
		relay := desktop.GetOrCreateRelay(sessionID)
		if err := relay.SendConfig(pack); err != nil {
			wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 1, Msg: err.Error()}, pack)
			return
		}
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 0}, pack)
		return
	}

	err := desktop.HandleConfig(pack)
	if err != nil {
		wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 1, Msg: err.Error()}, pack)
		return
	}
	wsConn.SendCallback(modules.Packet{Act: `DESKTOP_CONFIG`, Code: 0}, pack)
}

func init() {
	// Override desktop handlers to use relay-aware versions on Windows
	RegisterHandler(`DESKTOP_INIT`, initDesktopWithRelay)
	RegisterHandler(`DESKTOP_PING`, pingDesktopWithRelay)
	RegisterHandler(`DESKTOP_KILL`, killDesktopWithRelay)
	RegisterHandler(`DESKTOP_SHOT`, getDesktopWithRelay)
	RegisterHandler(`DESKTOP_INPUT`, inputDesktopWithRelay)
	RegisterHandler(`DESKTOP_CONFIG`, configDesktopWithRelay)
}
