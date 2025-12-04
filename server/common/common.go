package common

import (
	"Rocket/modules"
	"Rocket/utils"
	"Rocket/utils/cmap"
	"Rocket/utils/melody"
	"bytes"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"net"
	"strings"
)

const MaxMessageSize = (2 << 15) + 1024

var Melody = melody.New()
var Devices = cmap.New[*modules.Device]()

func SendPackByUUID(pack modules.Packet, uuid string) bool {
	// Try WebSocket first (highest priority, lowest latency)
	session, ok := Melody.GetSessionByUUID(uuid)
	if ok {
		return SendPack(pack, session)
	}

	// WebSocket not available, try registered alternative transports via registry
	// The transport registry avoids import cycles by using function pointers
	registry := GetTransportRegistry()
	if registry.SendTo(uuid, &pack) {
		return true
	}

	// No active transport found for this UUID
	return false
}

func SendPack(pack modules.Packet, session *melody.Session) bool {
	if session == nil {
		return false
	}
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return false
	}
	// No encryption - send JSON directly
	err = session.WriteBinary(data)
	return err == nil
}

// Encryption removed - these functions are no longer needed

func GetAddrIP(addr net.Addr) string {
	switch addr.(type) {
	case *net.TCPAddr:
		return addr.(*net.TCPAddr).IP.String()
	case *net.UDPAddr:
		return addr.(*net.UDPAddr).IP.String()
	case *net.IPAddr:
		return addr.(*net.IPAddr).IP.String()
	default:
		return addr.String()
	}
}

func GetRealIP(ctx *gin.Context) string {
	addr, ok := ctx.Request.Context().Value(`ClientIP`).(string)
	if !ok {
		return GetRemoteAddr(ctx)
	}
	return addr
}

func GetRemoteAddr(ctx *gin.Context) string {
	remoteStr := ctx.RemoteIP()
	remote := net.ParseIP(remoteStr)

	if remote != nil && remote.IsLoopback() {
		forwarded := ctx.GetHeader(`X-Forwarded-For`)
		if len(forwarded) > 0 {
			return forwarded
		}
		realIP := ctx.GetHeader(`X-Real-IP`)
		if len(realIP) > 0 {
			return realIP
		}
	}

	if remote != nil {
		return remote.String()
	}

	forwarded := ctx.GetHeader(`X-Forwarded-For`)
	if len(forwarded) > 0 {
		return forwarded
	}
	if realIP := ctx.GetHeader(`X-Real-IP`); len(realIP) > 0 {
		return realIP
	}

	addr := ctx.Request.RemoteAddr
	if pos := strings.LastIndex(addr, `:`); pos > -1 {
		return strings.Trim(addr[:pos], `[]`)
	}
	return addr
}

func CheckClientReq(ctx *gin.Context) *melody.Session {
	secret, err := hex.DecodeString(ctx.GetHeader(`Secret`))
	if err != nil || len(secret) != 32 {
		return nil
	}
	var result *melody.Session = nil
	Melody.IterSessions(func(uuid string, s *melody.Session) bool {
		if val, ok := s.Get(`Secret`); ok {
			// Check if there's a connection matches this secret.
			if b, ok := val.([]byte); ok && bytes.Equal(b, secret) {
				result = s
				return false
			}
		}
		return true
	})
	return result
}

func CheckDevice(deviceID, connUUID string) (string, bool) {
	if len(connUUID) > 0 {
		if !Devices.Has(connUUID) {
			return connUUID, true
		}
	} else {
		tempConnUUID := ``
		Devices.IterCb(func(uuid string, device *modules.Device) bool {
			if device.ID == deviceID {
				tempConnUUID = uuid
				return false
			}
			return true
		})
		return tempConnUUID, len(tempConnUUID) > 0
	}
	return ``, false
}

// EncAES - Encryption removed; TLS provides transport security.
// Returns data unchanged. Key parameter kept for API compatibility.
// Used for both config encryption and client key generation.
func EncAES(data []byte, key []byte) ([]byte, error) {
	_ = key // Unused - kept for API compatibility
	// Return a copy for safety (no encryption needed - TLS handles security)
	return append([]byte(nil), data...), nil
}

// DecAES - Decryption removed; TLS provides transport security.
// Returns data unchanged. Supports both old encrypted format and new plaintext.
// Key parameter kept for API compatibility.
func DecAES(data []byte, key []byte) ([]byte, error) {
	_ = key // Unused - kept for API compatibility
	if len(data) == 0 {
		return nil, nil
	}
	// Return a copy for safety (no decryption needed - TLS handles security)
	return append([]byte(nil), data...), nil
}

// Legacy function registration system - DEPRECATED
// Replaced by TransportRegistry for cleaner architecture
// These remain for backward compatibility but are no longer used by SendPackByUUID
var (
	sendToLongPoll func(uuid string, pack *modules.Packet) bool // DEPRECATED: Use TransportRegistry
	sendToQUIC     func(uuid string, pack *modules.Packet) bool // DEPRECATED: Use TransportRegistry
	sendToDNS      func(uuid string, pack *modules.Packet) bool // DEPRECATED: Use TransportRegistry
)

// RegisterLongPollSender - DEPRECATED: Use TransportRegistry.Register instead
func RegisterLongPollSender(fn func(uuid string, pack *modules.Packet) bool) {
	sendToLongPoll = fn
}

// RegisterQUICSender - DEPRECATED: Use TransportRegistry.Register instead
func RegisterQUICSender(fn func(uuid string, pack *modules.Packet) bool) {
	sendToQUIC = fn
}

// RegisterDNSSender - DEPRECATED: Use TransportRegistry.Register instead
func RegisterDNSSender(fn func(uuid string, pack *modules.Packet) bool) {
	sendToDNS = fn
}
