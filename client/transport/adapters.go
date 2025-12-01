package transport

import (
	"errors"
	"time"
)

// WebSocketAdapter is not needed since WebSocket is natively supported

// LongPollingAdapter implements common.TransportAdapter for long polling
type LongPollingAdapter struct {
	transport *LongPollingTransport
}

func (a *LongPollingAdapter) Write(data []byte) error {
	// Data is already encrypted from common.Conn.SendPack/SendRawData
	// Pass it through to the transport unchanged
	select {
	case a.transport.sendQueue <- data:
		return nil
	case <-a.transport.ctx.Done():
		return a.transport.ctx.Err()
	default:
		return errors.New("send queue full")
	}
}

func (a *LongPollingAdapter) Read() ([]byte, error) {
	// Block until encrypted bytes available from transport
	// Return them unchanged - common.Conn will decrypt
	select {
	case data := <-a.transport.recvQueue:
		return data, nil
	case <-a.transport.ctx.Done():
		return nil, a.transport.ctx.Err()
	}
}

func (a *LongPollingAdapter) Close() error {
	return a.transport.Close()
}

func (a *LongPollingAdapter) SetWriteDeadline(deadline interface{}) error {
	// Long polling doesn't support deadlines directly
	return nil
}

func (a *LongPollingAdapter) IsConnected() bool {
	a.transport.mu.Lock()
	defer a.transport.mu.Unlock()
	return a.transport.connected
}

// DNSAdapter implements common.TransportAdapter for DNS tunneling
type DNSAdapter struct {
	transport *DNSTransport
}

func (a *DNSAdapter) Write(data []byte) error {
	// Data is already encrypted - pass through unchanged
	select {
	case a.transport.sendQueue <- data:
		return nil
	case <-a.transport.ctx.Done():
		return a.transport.ctx.Err()
	default:
		return errors.New("send queue full")
	}
}

func (a *DNSAdapter) Read() ([]byte, error) {
	// Return encrypted bytes unchanged
	select {
	case data := <-a.transport.recvQueue:
		return data, nil
	case <-a.transport.ctx.Done():
		return nil, a.transport.ctx.Err()
	}
}

func (a *DNSAdapter) Close() error {
	return a.transport.Close()
}

func (a *DNSAdapter) SetWriteDeadline(deadline interface{}) error {
	return nil
}

func (a *DNSAdapter) IsConnected() bool {
	a.transport.mu.Lock()
	defer a.transport.mu.Unlock()
	return a.transport.connected
}

// QUICAdapter implements common.TransportAdapter for QUIC
type QUICAdapter struct {
	transport *QUICTransport
}

func (a *QUICAdapter) Write(data []byte) error {
	// Data is already encrypted - pass through unchanged
	select {
	case a.transport.sendQueue <- data:
		return nil
	case <-a.transport.ctx.Done():
		return a.transport.ctx.Err()
	default:
		return errors.New("send queue full")
	}
}

func (a *QUICAdapter) Read() ([]byte, error) {
	// Return encrypted bytes unchanged
	select {
	case data := <-a.transport.recvQueue:
		return data, nil
	case <-a.transport.ctx.Done():
		return nil, a.transport.ctx.Err()
	}
}

func (a *QUICAdapter) Close() error {
	return a.transport.Close()
}

func (a *QUICAdapter) SetWriteDeadline(deadline interface{}) error {
	// QUIC supports deadlines
	if t, ok := deadline.(time.Time); ok {
		return a.transport.stream.SetWriteDeadline(t)
	}
	return nil
}

func (a *QUICAdapter) IsConnected() bool {
	a.transport.mu.Lock()
	defer a.transport.mu.Unlock()
	return a.transport.connected
}
