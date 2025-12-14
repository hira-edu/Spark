package common

import (
	"Rocket/modules"
	"Rocket/utils"
	"Rocket/utils/cmap"
	"Rocket/utils/melody"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

// EncAES is kept for format compatibility with older clients.
// Newer builds do not apply application-layer encryption (TLS provides transport security),
// so this returns a copy of data unchanged.
func EncAES(data []byte, key []byte) ([]byte, error) {
	_ = key // Unused - kept for API compatibility
	return append([]byte(nil), data...), nil
}

// DecAES supports backward compatibility with older clients that used a lightweight
// obfuscation scheme: MD5[16] + AES-CTR(plaintext, iv=MD5, key=saltBytes).
//
// For newer plaintext payloads, it returns a copy of data unchanged.
func DecAES(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) <= 16 {
		// New format: plaintext (just return a copy as-is)
		return append([]byte(nil), data...), nil
	}

	// Old format: try to decrypt and verify.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, data[:16])
	decBuffer := make([]byte, len(data)-16)
	stream.XORKeyStream(decBuffer, data[16:])
	hash, _ := utils.GetMD5(decBuffer)
	if !bytes.Equal(hash, data[:16]) {
		// Not in legacy encrypted format, return as-is.
		return append([]byte(nil), data...), nil
	}
	return decBuffer, nil
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
