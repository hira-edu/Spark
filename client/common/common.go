package common

import (
	"Rocket/client/config"
	"Rocket/modules"
	"Rocket/utils"
	"encoding/binary"
	"encoding/hex"
	"errors"
	ws "github.com/gorilla/websocket"
	"github.com/imroc/req/v3"
	"sync"
	"time"
)

type Conn struct {
	*ws.Conn                   // WebSocket connection (nil if using adapter)
	adapter   TransportAdapter // Generic transport adapter (nil if using WebSocket)
	secret    []byte
	secretHex string
	writeMu   sync.Mutex // Separate write mutex for better concurrency
}

const MaxMessageSize = (2 << 15) + 1024

var WSConn *Conn
var Mutex = &sync.RWMutex{} // Upgraded to RWMutex for read/write separation
var HTTP = CreateClient()

func CreateConn(wsConn *ws.Conn, secret []byte) *Conn {
	return &Conn{
		Conn:      wsConn,
		secret:    secret,
		secretHex: hex.EncodeToString(secret),
	}
}

// CreateConnWithAdapter creates a Conn using a transport adapter (P2P, QUIC, etc.)
func CreateConnWithAdapter(adapter TransportAdapter, secret []byte) *Conn {
	var secretHex string
	if secret != nil {
		secretHex = hex.EncodeToString(secret)
	}
	return &Conn{
		Conn:      nil,
		adapter:   adapter,
		secret:    secret,
		secretHex: secretHex,
	}
}

// NewConnWithAdapter is an alias for CreateConnWithAdapter (Phase 3 P2P)
func NewConnWithAdapter(adapter TransportAdapter, secret []byte) (*Conn, error) {
	return CreateConnWithAdapter(adapter, secret), nil
}

func CreateClient() *req.Client {
	return req.C().SetUserAgent(`SPARK COMMIT: ` + config.Commit)
}

func (wsConn *Conn) SendData(data []byte) error {
	// Use per-connection write mutex instead of global mutex
	wsConn.writeMu.Lock()
	defer wsConn.writeMu.Unlock()

	// Check if connection is still valid
	Mutex.RLock()
	connected := (WSConn != nil)
	Mutex.RUnlock()

	if !connected {
		return errors.New(`${i18n|COMMON.DISCONNECTED}`)
	}

	// Route to appropriate transport
	if wsConn.adapter != nil {
		// Using transport adapter (QUIC, Long Polling, DNS, etc.)
		wsConn.adapter.SetWriteDeadline(utils.Now.Add(5 * time.Second))
		defer wsConn.adapter.SetWriteDeadline(time.Time{})
		return wsConn.adapter.Write(data)
	}

	// Using WebSocket
	wsConn.SetWriteDeadline(utils.Now.Add(5 * time.Second))
	defer wsConn.SetWriteDeadline(time.Time{})
	return wsConn.WriteMessage(ws.BinaryMessage, data)
}

func (wsConn *Conn) SendPack(pack any) error {
	data, err := utils.JSON.Marshal(pack)
	if err != nil {
		return err
	}

	// Use HTTP fallback for large messages
	if len(data) > MaxMessageSize {
		_, err = HTTP.R().
			SetBody(data).
			SetHeader(`Secret`, wsConn.secretHex).
			Send(`POST`, config.GetBaseURL(false)+`/ws`)
		return err
	}

	// Use per-connection write mutex
	wsConn.writeMu.Lock()
	defer wsConn.writeMu.Unlock()

	// Check if connection is still valid
	Mutex.RLock()
	connected := (WSConn != nil)
	Mutex.RUnlock()

	if !connected {
		return errors.New(`${i18n|COMMON.DISCONNECTED}`)
	}

	// Route to appropriate transport
	if wsConn.adapter != nil {
		// Using transport adapter
		wsConn.adapter.SetWriteDeadline(utils.Now.Add(5 * time.Second))
		defer wsConn.adapter.SetWriteDeadline(time.Time{})
		return wsConn.adapter.Write(data)
	}

	// Using WebSocket
	wsConn.SetWriteDeadline(utils.Now.Add(5 * time.Second))
	defer wsConn.SetWriteDeadline(time.Time{})
	return wsConn.WriteMessage(ws.BinaryMessage, data)
}

func (wsConn *Conn) SendRawData(event, data []byte, service byte, op byte) error {
	// Use per-connection write mutex
	wsConn.writeMu.Lock()
	defer wsConn.writeMu.Unlock()

	// Check if connection is still valid
	Mutex.RLock()
	connected := (WSConn != nil)
	Mutex.RUnlock()

	if !connected {
		return errors.New(`${i18n|COMMON.DISCONNECTED}`)
	}

	buffer := make([]byte, 24)
	copy(buffer[6:22], event)
	copy(buffer[:4], []byte{34, 22, 19, 17})
	buffer[4] = service
	buffer[5] = op
	binary.BigEndian.PutUint16(buffer[22:24], uint16(len(data)))
	buffer = append(buffer, data...)

	// Route to appropriate transport
	if wsConn.adapter != nil {
		// Using transport adapter
		wsConn.adapter.SetWriteDeadline(utils.Now.Add(5 * time.Second))
		defer wsConn.adapter.SetWriteDeadline(time.Time{})
		return wsConn.adapter.Write(buffer)
	}

	// Using WebSocket
	wsConn.SetWriteDeadline(utils.Now.Add(5 * time.Second))
	defer wsConn.SetWriteDeadline(time.Time{})
	return wsConn.WriteMessage(ws.BinaryMessage, buffer)
}

// Close closes the connection (WebSocket or adapter)
func (wsConn *Conn) Close() error {
	if wsConn.adapter != nil {
		return wsConn.adapter.Close()
	}
	if wsConn.Conn != nil {
		return wsConn.Conn.Close()
	}
	return nil
}

// ReadMessage reads a message from the connection
func (wsConn *Conn) ReadMessage() (int, []byte, error) {
	if wsConn.adapter != nil {
		// Using transport adapter
		data, err := wsConn.adapter.Read()
		if err != nil {
			return 0, nil, err
		}
		return ws.BinaryMessage, data, nil
	}

	// Using WebSocket
	return wsConn.Conn.ReadMessage()
}

func (wsConn *Conn) SendCallback(pack, prev modules.Packet) error {
	if len(prev.Event) > 0 {
		pack.Event = prev.Event
	}
	return wsConn.SendPack(pack)
}

func (wsConn *Conn) GetSecret() []byte {
	return wsConn.secret
}

func (wsConn *Conn) GetSecretHex() string {
	return wsConn.secretHex
}
