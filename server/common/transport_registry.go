package common

import (
	"Rocket/modules"
	"sync"

	"github.com/kataras/golog"
)

// TransportType represents the type of transport
type TransportType string

const (
	TransportWebSocket   TransportType = "websocket"
	TransportLongPolling TransportType = "longpoll"
	TransportQUIC        TransportType = "quic"
	TransportDNS         TransportType = "dns"
)

// TransportSession represents an active transport session
type TransportSession struct {
	UUID      string
	Transport TransportType
	SendFunc  func(*modules.Packet) bool // Function to send packet to this session
}

// TransportRegistry manages active non-WebSocket transport sessions
// This avoids import cycles by using function pointers registered by handlers
type TransportRegistry struct {
	sessions map[string]*TransportSession // UUID -> TransportSession
	mu       sync.RWMutex
}

var (
	// Global transport registry instance
	transportRegistry *TransportRegistry
)

func init() {
	transportRegistry = &TransportRegistry{
		sessions: make(map[string]*TransportSession),
	}
}

// GetTransportRegistry returns the global transport registry
func GetTransportRegistry() *TransportRegistry {
	return transportRegistry
}

// Register registers a new transport session for a UUID
func (tr *TransportRegistry) Register(uuid string, transportType TransportType, sendFunc func(*modules.Packet) bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	// Check if UUID already has an active session
	if existing, exists := tr.sessions[uuid]; exists {
		golog.Warnf("TransportRegistry: UUID %s already registered with %s, replacing with %s",
			uuid[:8]+"...", existing.Transport, transportType)
	}

	tr.sessions[uuid] = &TransportSession{
		UUID:      uuid,
		Transport: transportType,
		SendFunc:  sendFunc,
	}

	golog.Debugf("TransportRegistry: Registered %s session for UUID %s", transportType, uuid[:8]+"...")
}

// Unregister removes a transport session for a UUID
func (tr *TransportRegistry) Unregister(uuid string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()

	if session, exists := tr.sessions[uuid]; exists {
		golog.Debugf("TransportRegistry: Unregistered %s session for UUID %s",
			session.Transport, uuid[:8]+"...")
		delete(tr.sessions, uuid)
	}
}

// Get retrieves the transport session for a UUID
func (tr *TransportRegistry) Get(uuid string) (*TransportSession, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	session, exists := tr.sessions[uuid]
	return session, exists
}

// SendTo sends a packet to the registered transport for a UUID
func (tr *TransportRegistry) SendTo(uuid string, packet *modules.Packet) bool {
	tr.mu.RLock()
	session, exists := tr.sessions[uuid]
	tr.mu.RUnlock()

	if !exists {
		return false
	}

	// Call the registered send function
	return session.SendFunc(packet)
}

// GetActiveTransport returns the transport type for a UUID (if any)
func (tr *TransportRegistry) GetActiveTransport(uuid string) (TransportType, bool) {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	if session, exists := tr.sessions[uuid]; exists {
		return session.Transport, true
	}
	return "", false
}

// Count returns the number of active transport sessions
func (tr *TransportRegistry) Count() int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	return len(tr.sessions)
}

// CountByType returns the number of sessions per transport type
func (tr *TransportRegistry) CountByType() map[TransportType]int {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	counts := make(map[TransportType]int)
	for _, session := range tr.sessions {
		counts[session.Transport]++
	}
	return counts
}

// List returns all active UUIDs (for debugging/monitoring)
func (tr *TransportRegistry) List() []string {
	tr.mu.RLock()
	defer tr.mu.RUnlock()

	uuids := make([]string, 0, len(tr.sessions))
	for uuid := range tr.sessions {
		uuids = append(uuids, uuid)
	}
	return uuids
}
