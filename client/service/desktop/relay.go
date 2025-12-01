package desktop

import (
	"Rocket/client/common"
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

// Relay handles forwarding desktop commands from Session 0 to user sessions
type Relay struct {
	sessionID uint32
	client    *ipc.Client
	connected bool
	helloSent bool
	mu        sync.Mutex
}

var (
	relays   = make(map[uint32]*Relay)
	relaysMu sync.RWMutex
	wsConnectedFlag atomic.Bool
)

// GetOrCreateRelay gets or creates a relay for a session
func GetOrCreateRelay(sessionID uint32) *Relay {
	relaysMu.Lock()
	defer relaysMu.Unlock()

	if relay, ok := relays[sessionID]; ok {
		return relay
	}

	relay := &Relay{
		sessionID: sessionID,
	}
	relays[sessionID] = relay
	return relay
}

// RemoveRelay removes a relay for a session
func RemoveRelay(sessionID uint32) {
	relaysMu.Lock()
	defer relaysMu.Unlock()

	if relay, ok := relays[sessionID]; ok {
		relay.Close()
		delete(relays, sessionID)
	}
}

// Connect establishes connection to user session's IPC server
func (r *Relay) Connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ensureConnectedLocked()
}

// handleMessage processes messages from user session (frames, responses)
func (r *Relay) handleMessage(msg *ipc.Message) {
	switch msg.Type {
	case ipc.MsgTypeDesktopFrame:
		// Relay frame to server via WebSocket
		r.relayFrame(msg.Payload)
	case ipc.MsgTypeDesktopQuit:
		// Desktop session ended
		r.handleQuit(msg.Payload)
	case ipc.MsgTypeDesktopPacket:
		r.handlePacket(msg.Payload)
	case ipc.MsgTypeHeartbeat:
		// Heartbeat response - connection is alive
	case ipc.MsgTypeHelloAck:
		telemetry.LogStructured("INFO", "Desktop relay handshake acknowledged", map[string]interface{}{
			"session_id": r.sessionID,
		})
	}
}

// relayFrame sends a frame received from user session to the server
func (r *Relay) relayFrame(data []byte) {
	if common.WSConn == nil {
		return
	}
	if err := common.WSConn.SendData(data); err != nil {
		telemetry.LogStructured("ERROR", "Desktop relay failed to forward frame", map[string]interface{}{
			"session_id": r.sessionID,
			"error":      err.Error(),
		})
	}
}

// handleQuit handles desktop quit message from user session
func (r *Relay) handleQuit(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}
	// The quit message contains error info, could log or handle
	telemetry.LogStructured("INFO", "Desktop session quit via relay", map[string]interface{}{
		"session_id": r.sessionID,
		"msg":        pack.Msg,
	})

	var rawEvent []byte
	if len(pack.Event) > 0 {
		if ev, err := hex.DecodeString(pack.Event); err == nil {
			rawEvent = ev
		} else {
			telemetry.LogStructured("WARN", "Desktop relay: failed to decode event hex", map[string]interface{}{
				"session_id": r.sessionID,
				"event":      pack.Event,
				"error":      err.Error(),
			})
		}
	}

	sendDesktopPacket(pack, rawEvent)
}

// handlePacket forwards a generic desktop packet back to the server
func (r *Relay) handlePacket(payload []byte) {
	var pack modules.Packet
	if err := utils.JSON.Unmarshal(payload, &pack); err != nil {
		return
	}

	var rawEvent []byte
	if len(pack.Event) > 0 {
		if ev, err := hex.DecodeString(pack.Event); err == nil {
			rawEvent = ev
		} else {
			telemetry.LogStructured("WARN", "Desktop relay: failed to decode event hex", map[string]interface{}{
				"session_id": r.sessionID,
				"event":      pack.Event,
				"error":      err.Error(),
			})
		}
	}

	sendDesktopPacket(pack, rawEvent)
}

// SendInit forwards DESKTOP_INIT to user session
func (r *Relay) SendInit(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopInit, Payload: data})
}

// SendKill forwards DESKTOP_KILL to user session
func (r *Relay) SendKill(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopKill, Payload: data})
}

// SendPing forwards DESKTOP_PING to user session
func (r *Relay) SendPing(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopPing, Payload: data})
}

// SendInput forwards DESKTOP_INPUT to user session
func (r *Relay) SendInput(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopInput, Payload: data})
}

// SendConfig forwards DESKTOP_CONFIG to user session
func (r *Relay) SendConfig(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopConfig, Payload: data})
}

// SendShot forwards DESKTOP_SHOT to user session
func (r *Relay) SendShot(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopShot, Payload: data})
}

// SendPacket forwards a generic desktop packet to the user session for handling (UI-only mode).
func (r *Relay) SendPacket(pack modules.Packet) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}
	return r.send(&ipc.Message{Type: ipc.MsgTypeDesktopPacket, Payload: data})
}

func (r *Relay) send(msg *ipc.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.ensureConnectedLocked(); err != nil {
		return err
	}
	if err := r.client.Send(msg); err != nil {
		if errors.Is(err, ipc.ErrPipeClosed) {
			// Attempt a single reconnect before giving up
			r.client = nil
			r.connected = false
			if errReconnect := r.ensureConnectedLocked(); errReconnect == nil {
				return r.client.Send(msg)
			}
		}
		return err
	}
	return nil
}

// IsConnected returns whether the relay is connected
func (r *Relay) IsConnected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.client != nil && r.client.IsConnected()
}

func (r *Relay) ensureConnectedLocked() error {
	if r.client != nil && r.client.IsConnected() {
		return nil
	}

	client := ipc.NewClient(r.sessionID, r.handleMessage)
	if err := client.Connect(); err != nil {
		return err
	}

	r.client = client
	r.connected = true
	r.helloSent = false

	telemetry.LogStructured("INFO", "Desktop relay connected", map[string]interface{}{
		"session_id": r.sessionID,
		"pipe":       ipc.GetPipeName(r.sessionID),
	})

	// Send handshake and latest state
	r.sendHelloLocked()
	r.sendStateLocked(wsConnectedFlag.Load())
	return nil
}

func (r *Relay) sendHelloLocked() {
	if r.client == nil || !r.client.IsConnected() || r.helloSent {
		return
	}
	payload, _ := utils.JSON.Marshal(map[string]any{
		"session_id":   r.sessionID,
		"ws_connected": wsConnectedFlag.Load(),
		"role":         "service",
		"ts":           time.Now().Unix(),
	})
	_ = r.client.Send(&ipc.Message{Type: ipc.MsgTypeHello, Payload: payload})
	r.helloSent = true
}

func (r *Relay) sendStateLocked(wsConnected bool) {
	if r.client == nil || !r.client.IsConnected() {
		return
	}
	payload, _ := utils.JSON.Marshal(map[string]any{
		"session_id":   r.sessionID,
		"ws_connected": wsConnected,
		"ts":           time.Now().Unix(),
	})
	_ = r.client.Send(&ipc.Message{Type: ipc.MsgTypeState, Payload: payload})
}

// Close closes the relay connection
func (r *Relay) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.client != nil {
		r.client.Close()
		r.client = nil
	}
	r.connected = false
	r.helloSent = false
	return nil
}

// IsSession0 returns true if running in Session 0 (service mode)
// This is determined by checking if we're running as a service
var isSession0Mode bool
var isSession0Once sync.Once

func SetSession0Mode(val bool) {
	isSession0Once.Do(func() {
		isSession0Mode = val
	})
}

func IsSession0Mode() bool {
	return isSession0Mode
}

// GetActiveSessionID returns the active user session ID
// This should be called from Session 0 to find which session to relay to
func GetActiveSessionID() uint32 {
	// This will be set by the service when it detects an active session
	return activeUserSessionID
}

var activeUserSessionID uint32
var activeSessionMu sync.RWMutex

func SetActiveSessionID(id uint32) {
	activeSessionMu.Lock()
	prev := activeUserSessionID
	activeUserSessionID = id
	activeSessionMu.Unlock()

	if prev != id {
		// Drop stale relays when the active session changes
		pruneRelaysForActive(id)
		broadcastState(wsConnectedFlag.Load())
	}
}

// SetWSConnected broadcasts WebSocket connectivity changes to all relays so the UI worker can backpressure.
func SetWSConnected(connected bool) {
	if wsConnectedFlag.Swap(connected) == connected {
		return
	}
	broadcastState(connected)
}

func broadcastState(wsConnected bool) {
	relaysMu.RLock()
	defer relaysMu.RUnlock()

	for _, relay := range relays {
		relay.mu.Lock()
		relay.sendStateLocked(wsConnected)
		relay.mu.Unlock()
	}
}

func pruneRelaysForActive(active uint32) {
	relaysMu.Lock()
	defer relaysMu.Unlock()

	for id, relay := range relays {
		if active == 0 || id != active {
			relay.Close()
			delete(relays, id)
		}
	}
}
