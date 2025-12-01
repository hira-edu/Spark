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
	data, ok := Encrypt(data, session)
	if !ok {
		return false
	}
	err = session.WriteBinary(data)
	return err == nil
}

func Encrypt(data []byte, session *melody.Session) ([]byte, bool) {
	temp, ok := session.Get(`Secret`)
	if !ok {
		return nil, false
	}
	secret := temp.([]byte)
	dec, err := utils.Encrypt(data, secret)
	if err != nil {
		return nil, false
	}
	return dec, true
}

func Decrypt(data []byte, session *melody.Session) ([]byte, bool) {
	temp, ok := session.Get(`Secret`)
	if !ok {
		return nil, false
	}
	secret := temp.([]byte)
	dec, err := utils.Decrypt(data, secret)
	if err != nil {
		return nil, false
	}
	return dec, true
}

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

func EncAES(data []byte, key []byte) ([]byte, error) {
	hash, _ := utils.GetMD5(data)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, hash)
	encBuffer := make([]byte, len(data))
	stream.XORKeyStream(encBuffer, data)
	return append(hash, encBuffer...), nil
}

func DecAES(data []byte, key []byte) ([]byte, error) {
	// MD5[16 bytes] + Data[n bytes]
	dataLen := len(data)
	if dataLen <= 16 {
		return nil, utils.ErrEntityInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, data[:16])
	decBuffer := make([]byte, dataLen-16)
	stream.XORKeyStream(decBuffer, data[16:])
	hash, _ := utils.GetMD5(decBuffer)
	if !bytes.Equal(hash, data[:16]) {
		return nil, utils.ErrFailedVerification
	}
	return decBuffer[:dataLen-16], nil
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
