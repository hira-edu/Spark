package desktop

import (
	"Rocket/client/ipc"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"Rocket/utils"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Bridge handles desktop capture in user session and sends frames via IPC
type Bridge struct {
	sessionID uint32
	server    *ipc.Server
	running   bool
	mu        sync.Mutex

	// Desktop session state
	desktopUUID string
	eventHex    string
	wsConnected bool
	lastDropLog time.Time
}

var (
	bridgeInstance *Bridge
	bridgeMu       sync.Mutex
)

// StartBridge initializes the IPC server for desktop capture in user session
func StartBridge(sessionID uint32) error {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	if bridgeInstance != nil {
		return nil // Already running
	}

	bridge := &Bridge{
		sessionID:   sessionID,
		wsConnected: true,
	}

	server, err := ipc.NewServer(sessionID, bridge.handleMessage)
	if err != nil {
		if errors.Is(err, ipc.ErrBridgeAlreadyRunning) {
			// Another UI bridge already owns the pipe; treat as success and avoid churn.
			telemetry.LogStructured("INFO", "Desktop bridge already running, skipping new instance", map[string]interface{}{
				"session_id": sessionID,
				"pipe":       ipc.GetPipeName(sessionID),
			})
			return nil
		}
		return err
	}

	bridge.server = server
	bridgeInstance = bridge

	server.Start()
	telemetry.LogStructured("INFO", "Desktop bridge started", map[string]interface{}{
		"session_id": sessionID,
		"pipe":       ipc.GetPipeName(sessionID),
	})

	return nil
}

// StopBridge shuts down the desktop bridge
func StopBridge() {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()

	if bridgeInstance == nil {
		return
	}

	if bridgeInstance.server != nil {
		bridgeInstance.server.Close()
	}
	bridgeInstance = nil
}

// handleMessage processes incoming IPC messages from Session 0
func (b *Bridge) handleMessage(msg *ipc.Message) {
	switch msg.Type {
	case ipc.MsgTypeHello:
		b.handleHello(msg.Payload)
	case ipc.MsgTypeState:
		b.handleState(msg.Payload)
	case ipc.MsgTypeDesktopInit:
		b.handleInit(msg.Payload)
	case ipc.MsgTypeDesktopKill:
		b.handleKill(msg.Payload)
	case ipc.MsgTypeDesktopPing:
		b.handlePing(msg.Payload)
	case ipc.MsgTypeDesktopInput:
		b.handleInput(msg.Payload)
	case ipc.MsgTypeDesktopConfig:
		b.handleConfig(msg.Payload)
	case ipc.MsgTypeDesktopShot:
		b.handleShot(msg.Payload)
	case ipc.MsgTypeDesktopPacket:
		b.handleDesktopPacket(msg.Payload)
	case ipc.MsgTypeHeartbeat:
		// Respond to heartbeat
		b.server.Send(&ipc.Message{Type: ipc.MsgTypeHeartbeat})
	}
}

func (b *Bridge) handleInit(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("ERROR", "Bridge: failed to unmarshal init", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	b.mu.Lock()
	b.desktopUUID, _ = pack.Data["desktop"].(string)
	b.eventHex = pack.Event
	b.mu.Unlock()

	// Initialize desktop capture - this runs in user session so it has access to desktop
	err := initDesktopCapture(pack, b.sendFrame)
	if err != nil {
		telemetry.LogStructured("ERROR", "Bridge: desktop init failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Send error response
		errPack := modules.Packet{
			Act:   "DESKTOP_INIT",
			Code:  1,
			Msg:   err.Error(),
			Event: pack.Event,
		}
		data, _ := utils.JSON.Marshal(errPack)
		b.server.Send(&ipc.Message{Type: ipc.MsgTypeDesktopQuit, Payload: data})
	}
}

func (b *Bridge) handleKill(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}
	KillDesktop(pack)
}

func (b *Bridge) handlePing(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}
	PingDesktop(pack)
}

func (b *Bridge) handleInput(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}
	HandleInput(pack)
}

func (b *Bridge) handleConfig(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}
	HandleConfig(pack)
}

func (b *Bridge) handleShot(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}
	GetDesktop(pack)
}

func (b *Bridge) handleHello(payload []byte) {
	state := map[string]any{}
	if err := utils.JSON.Unmarshal(payload, &state); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to parse hello from service", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	b.mu.Lock()
	if sid, ok := state["session_id"].(float64); ok {
		b.sessionID = uint32(sid)
	}
	changed := b.setWSStateLocked(parseBool(state["ws_connected"], b.wsConnected))
	b.mu.Unlock()

	if changed {
		telemetry.LogStructured("INFO", "Bridge: handshake updated WS state", map[string]interface{}{
			"session_id":   b.sessionID,
			"ws_connected": b.wsConnected,
		})
	}

	if b.server != nil {
		_ = b.server.Send(&ipc.Message{Type: ipc.MsgTypeHelloAck})
	}
}

func (b *Bridge) handleState(payload []byte) {
	state := map[string]any{}
	if err := utils.JSON.Unmarshal(payload, &state); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to parse state update", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	b.mu.Lock()
	changed := b.setWSStateLocked(parseBool(state["ws_connected"], b.wsConnected))
	sessionID := b.sessionID
	wsConnected := b.wsConnected
	b.mu.Unlock()

	if changed {
		telemetry.LogStructured("INFO", "Bridge: WS state change", map[string]interface{}{
			"session_id":   sessionID,
			"ws_connected": wsConnected,
		})
	}
}

func (b *Bridge) handleDesktopPacket(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to decode desktop packet", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
	b.dispatchDesktopPacket(pack)
}

func (b *Bridge) dispatchDesktopPacket(pack modules.Packet) {
	switch pack.Act {
	case "DESKTOP_WEBRTC_OFFER":
		resp, err := HandleWebRTCOffer(pack)
		if err != nil {
			SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: 1, Msg: err.Error(), Event: pack.Event})
			return
		}
		SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: 0, Data: resp, Event: pack.Event})
	case "DESKTOP_WEBRTC_ANSWER":
		err := HandleWebRTCAnswer(pack)
		code := 0
		msg := ""
		if err != nil {
			code = 1
			msg = err.Error()
		}
		SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event})
	case "DESKTOP_WEBRTC_ICE":
		err := HandleWebRTCIce(pack)
		code := 0
		msg := ""
		if err != nil {
			code = 1
			msg = err.Error()
		}
		SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event})
	case "DESKTOP_INIT":
		if data, err := utils.JSON.Marshal(pack); err == nil {
			b.handleInit(data)
		}
	case "DESKTOP_KILL":
		if data, err := utils.JSON.Marshal(pack); err == nil {
			b.handleKill(data)
		}
	case "DESKTOP_PING":
		if data, err := utils.JSON.Marshal(pack); err == nil {
			b.handlePing(data)
		}
	case "DESKTOP_INPUT":
		if data, err := utils.JSON.Marshal(pack); err == nil {
			b.handleInput(data)
		}
	case "DESKTOP_CONFIG":
		if data, err := utils.JSON.Marshal(pack); err == nil {
			b.handleConfig(data)
		}
	case "DESKTOP_SHOT":
		if data, err := utils.JSON.Marshal(pack); err == nil {
			b.handleShot(data)
		}
	default:
		telemetry.LogStructured("WARN", "Bridge: unhandled desktop packet", map[string]interface{}{
			"act":       pack.Act,
			"sessionID": b.sessionID,
		})
	}
}

func (b *Bridge) setWSStateLocked(newState bool) bool {
	if b.wsConnected == newState {
		return false
	}
	b.wsConnected = newState
	// reset drop log timer so next drop/resume is logged promptly
	b.lastDropLog = time.Time{}
	return true
}

func parseBool(val any, def bool) bool {
	switch v := val.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	default:
		return def
	}
}

// sendFrame sends a captured frame back to Session 0 via IPC
func (b *Bridge) sendFrame(data []byte) {
	if b.server == nil || !b.server.IsConnected() {
		return
	}
	b.server.Send(&ipc.Message{Type: ipc.MsgTypeDesktopFrame, Payload: data})
}

// sendIPCMessage sends a typed IPC message to Session 0
func sendIPCMessage(msgType uint16, payload []byte) error {
	bridgeMu.Lock()
	b := bridgeInstance
	bridgeMu.Unlock()

	if b == nil || b.server == nil {
		return errors.New("bridge not initialized")
	}
	return b.server.Send(&ipc.Message{Type: msgType, Payload: payload})
}

// initDesktopCapture initializes desktop capture with a frame callback
func initDesktopCapture(pack modules.Packet, frameCallback func([]byte)) error {
	// Store the frame callback for use by the worker
	setFrameCallback(frameCallback)
	return InitDesktop(pack)
}

// Frame callback storage
var (
	frameCallbackMu sync.Mutex
	frameCallback   func([]byte)
)

func setFrameCallback(cb func([]byte)) {
	frameCallbackMu.Lock()
	frameCallback = cb
	frameCallbackMu.Unlock()
}

func getFrameCallback() func([]byte) {
	frameCallbackMu.Lock()
	defer frameCallbackMu.Unlock()
	return frameCallback
}

// SendFrameViaIPC is called by the desktop worker to send frames
// This is used when running in bridge mode (user session)
func SendFrameViaIPC(data []byte) bool {
	cb := getFrameCallback()
	if cb != nil {
		cb(data)
		return true
	}
	return false
}

// SendPacketViaIPC forwards a control packet back to Session 0 for delivery to the server.
func SendPacketViaIPC(pack modules.Packet) bool {
	bridgeMu.Lock()
	bridge := bridgeInstance
	bridgeMu.Unlock()
	if bridge == nil || bridge.server == nil || !bridge.server.IsConnected() {
		return false
	}

	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return false
	}

	return sendIPCMessage(ipc.MsgTypeDesktopPacket, data) == nil
}

// IsBridgeMode returns true if running in bridge mode (IPC server active)
func IsBridgeMode() bool {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	return bridgeInstance != nil && bridgeInstance.server != nil
}

// GetBridgeEventHex returns the event hex for the current desktop session
func GetBridgeEventHex() string {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	if bridgeInstance == nil {
		return ""
	}
	bridgeInstance.mu.Lock()
	defer bridgeInstance.mu.Unlock()
	return bridgeInstance.eventHex
}

// GetRawEventForBridge returns the raw event bytes for IPC mode
func GetRawEventForBridge() []byte {
	eventHex := GetBridgeEventHex()
	if eventHex == "" {
		return nil
	}
	raw, _ := hex.DecodeString(eventHex)
	return raw
}
