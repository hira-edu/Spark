package desktop

import (
	"Rocket/client/ipc"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"Rocket/utils"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

type bridgeState int

const (
	bridgeStateIdle bridgeState = iota
	bridgeStateServing
	bridgeStateCapturing
	bridgeStatePaused
	bridgeStateClosing
)

// Bridge handles desktop capture in user session and sends frames via IPC
type Bridge struct {
	sessionID uint32
	server    *ipc.Server
	running   bool
	mu        sync.Mutex
	state     bridgeState

	// Desktop session state
	desktopUUID     string
	eventHex        string
	wsConnected     bool
	lastDropLog     time.Time
	lastDropUnix    atomic.Int64
	wsConnectedFlag atomic.Bool
	lastSeq         uint64
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
		state:       bridgeStateServing,
	}
	bridge.wsConnectedFlag.Store(true)

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
	telemetry.LogStructured("INFO", "[IPC_BRIDGE_MSG_RECEIVED] IPC message received from Session 0", map[string]interface{}{
		"type":         msg.Type,
		"payload_size": len(msg.Payload),
		"session_id":   b.sessionID,
	})

	switch msg.Type {
	case ipc.MsgTypeHello:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing HELLO", nil)
		b.handleHello(msg.Payload)
	case ipc.MsgTypeState:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing STATE update", nil)
		b.handleState(msg.Payload)
	case ipc.MsgTypeDesktopInit:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing DESKTOP_INIT", map[string]interface{}{
			"payload_size": len(msg.Payload),
		})
		b.handleInit(msg.Payload)
	case ipc.MsgTypeDesktopKill:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing DESKTOP_KILL", nil)
		b.handleKill(msg.Payload)
	case ipc.MsgTypeDesktopPing:
		telemetry.LogStructured("DEBUG", "[IPC_BRIDGE] Processing DESKTOP_PING", nil)
		b.handlePing(msg.Payload)
	case ipc.MsgTypeDesktopInput:
		telemetry.LogStructured("DEBUG", "[IPC_BRIDGE] Processing DESKTOP_INPUT", nil)
		b.handleInput(msg.Payload)
	case ipc.MsgTypeDesktopConfig:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing DESKTOP_CONFIG", nil)
		b.handleConfig(msg.Payload)
	case ipc.MsgTypeDesktopShot:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing DESKTOP_SHOT", nil)
		b.handleShot(msg.Payload)
	case ipc.MsgTypeDesktopPacket:
		telemetry.LogStructured("INFO", "[IPC_BRIDGE] Processing DESKTOP_PACKET", nil)
		b.handleDesktopPacket(msg.Payload)
	case ipc.MsgTypeHeartbeat:
		telemetry.LogStructured("DEBUG", "[IPC_BRIDGE] Processing HEARTBEAT", nil)
		// Respond to heartbeat
		b.server.Send(&ipc.Message{Type: ipc.MsgTypeHeartbeat})
	default:
		telemetry.LogStructured("WARN", "[IPC_BRIDGE] Unknown message type", map[string]interface{}{
			"type": msg.Type,
		})
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

	telemetry.LogStructured("INFO", "Bridge: received DESKTOP_INIT", map[string]interface{}{
		"session_id": b.sessionID,
		"event":      pack.Event,
		"desktop":    pack.Data["desktop"],
	})

	b.mu.Lock()
	b.desktopUUID, _ = pack.Data["desktop"].(string)
	b.eventHex = pack.Event
	b.state = bridgeStateCapturing
	b.mu.Unlock()

	// Initialize desktop capture - this runs in user session so it has access to desktop
	err := initDesktopCapture(pack, b.sendFrame)
	if err != nil {
		telemetry.LogStructured("ERROR", "Bridge: desktop init failed", map[string]interface{}{
			"error":      err.Error(),
			"session_id": b.sessionID,
		})
		// Send error response via IPC
		errPack := modules.Packet{
			Act:   "DESKTOP_INIT",
			Code:  1,
			Msg:   err.Error(),
			Event: pack.Event,
		}
		data, _ := utils.JSON.Marshal(errPack)
		b.server.Send(&ipc.Message{Type: ipc.MsgTypeDesktopPacket, Payload: data})
		return
	}

	// Desktop init succeeded - response will be sent by InitDesktop via sendDesktopPacket → SendPacketViaIPC
	telemetry.LogStructured("INFO", "Bridge: desktop init succeeded, response will be sent via IPC", map[string]interface{}{
		"session_id": b.sessionID,
		"desktop":    b.desktopUUID,
	})
}

func (b *Bridge) handleKill(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to unmarshal KILL packet", map[string]interface{}{
			"error":        err.Error(),
			"payload_size": len(payload),
		})
		return
	}
	if b.shouldDropPacket(&pack) {
		return
	}
	KillDesktop(pack)
}

func (b *Bridge) handlePing(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to unmarshal PING packet", map[string]interface{}{
			"error":        err.Error(),
			"payload_size": len(payload),
		})
		return
	}
	if b.shouldDropPacket(&pack) {
		return
	}
	PingDesktop(pack)
}

func (b *Bridge) handleInput(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to unmarshal INPUT packet", map[string]interface{}{
			"error":        err.Error(),
			"payload_size": len(payload),
		})
		return
	}
	if b.shouldDropPacket(&pack) {
		return
	}
	HandleInput(pack)
}

func (b *Bridge) handleConfig(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to unmarshal CONFIG packet", map[string]interface{}{
			"error":        err.Error(),
			"payload_size": len(payload),
		})
		return
	}
	if b.shouldDropPacket(&pack) {
		return
	}
	HandleConfig(pack)
}

func (b *Bridge) handleShot(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		telemetry.LogStructured("WARN", "Bridge: failed to unmarshal SHOT packet", map[string]interface{}{
			"error":        err.Error(),
			"payload_size": len(payload),
		})
		return
	}
	if b.shouldDropPacket(&pack) {
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
	if b.shouldDropPacket(&pack) {
		return
	}
	b.dispatchDesktopPacket(pack)
}

func (b *Bridge) dispatchDesktopPacket(pack modules.Packet) {
	switch pack.Act {
	case "DESKTOP_WEBRTC_OFFER":
		resp, err := HandleWebRTCOffer(pack)
		if err != nil {
			// Browser is the offerer; the device must reply with an ANSWER (even on error)
			// so the frontend can correlate signaling failures.
			SendPacketViaIPC(modules.Packet{Act: "DESKTOP_WEBRTC_ANSWER", Code: 1, Msg: err.Error(), Event: pack.Event})
			return
		}
		SendPacketViaIPC(modules.Packet{Act: "DESKTOP_WEBRTC_ANSWER", Code: 0, Data: resp, Event: pack.Event})
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
	case "DESKTOP_CLIPBOARD":
		code := 0
		msg := ""
		if err := HandleClipboard(pack); err != nil {
			code = 1
			msg = err.Error()
		}
		SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event})
	case "DESKTOP_FILE_DROP":
		code := 0
		msg := ""
		if err := HandleFileDrop(pack); err != nil {
			code = 1
			msg = err.Error()
		}
		SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event})
	case "DESKTOP_AUDIO":
		code := 0
		msg := ""
		if err := HandleAudio(pack); err != nil {
			code = 1
			msg = err.Error()
		}
		SendPacketViaIPC(modules.Packet{Act: pack.Act, Code: code, Msg: msg, Event: pack.Event})
	default:
		telemetry.LogStructured("WARN", "Bridge: unhandled desktop packet", map[string]interface{}{
			"act":       pack.Act,
			"sessionID": b.sessionID,
		})
	}
}

func (b *Bridge) setWSStateLocked(newState bool) bool {
	changed := b.wsConnected != newState
	b.wsConnected = newState
	b.wsConnectedFlag.Store(newState)

	// reset drop log timer so next drop/resume is logged promptly
	b.lastDropLog = time.Time{}

	if !newState {
		b.state = bridgeStatePaused
	} else if b.desktopUUID != "" {
		b.state = bridgeStateCapturing
	} else {
		b.state = bridgeStateServing
	}
	return changed
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

func getPacketSeq(data map[string]any) (uint64, bool) {
	if data == nil {
		return 0, false
	}
	raw, ok := data[controlSeqKey]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case uint64:
		return v, true
	case int:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case float64:
		return uint64(v), true
	default:
		return 0, false
	}
}

// shouldDropPacket returns true if the packet sequence is stale.
func (b *Bridge) shouldDropPacket(pack *modules.Packet) bool {
	seq, ok := getPacketSeq(pack.Data)
	if !ok {
		return false
	}
	for {
		prev := atomic.LoadUint64(&b.lastSeq)
		if seq <= prev {
			telemetry.LogStructured("WARN", "Bridge: dropping stale control packet", map[string]interface{}{
				"seq":       seq,
				"prev_seq":  prev,
				"act":       pack.Act,
				"sessionID": b.sessionID,
			})
			return true
		}
		if atomic.CompareAndSwapUint64(&b.lastSeq, prev, seq) {
			return false
		}
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
	telemetry.LogStructured("INFO", "[IPC_SEND_PACKET_START] Sending packet via IPC to Session 0", map[string]interface{}{
		"act":      pack.Act,
		"code":     pack.Code,
		"has_data": pack.Data != nil,
	})

	bridgeMu.Lock()
	bridge := bridgeInstance
	bridgeMu.Unlock()

	if bridge == nil || bridge.server == nil || !bridge.server.IsConnected() {
		telemetry.LogStructured("ERROR", "[IPC_SEND_PACKET_FAILED] Bridge not available", map[string]interface{}{
			"bridge_nil":    bridge == nil,
			"server_nil":    bridge == nil || bridge.server == nil,
			"not_connected": bridge != nil && bridge.server != nil && !bridge.server.IsConnected(),
		})
		return false
	}

	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		telemetry.LogStructured("ERROR", "[IPC_SEND_PACKET_MARSHAL_ERROR] Failed to marshal packet", map[string]interface{}{
			"error": err.Error(),
			"act":   pack.Act,
		})
		return false
	}

	telemetry.LogStructured("INFO", "[IPC_SEND_PACKET_MARSHALED] Packet marshaled", map[string]interface{}{
		"size": len(data),
		"act":  pack.Act,
	})

	err = sendIPCMessage(ipc.MsgTypeDesktopPacket, data)
	if err != nil {
		telemetry.LogStructured("ERROR", "[IPC_SEND_PACKET_FAILED] IPC send failed", map[string]interface{}{
			"error": err.Error(),
			"act":   pack.Act,
		})
		return false
	}

	telemetry.LogStructured("INFO", "[IPC_SEND_PACKET_SUCCESS] Packet sent via IPC successfully", map[string]interface{}{
		"act": pack.Act,
	})
	return true
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
