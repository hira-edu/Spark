package common

import (
	"Spark/modules"
	"io"
)

// TransportAdapter is an interface that all transport types must implement
// This allows common.Conn to work with WebSocket, QUIC, Long Polling, DNS, etc.
type TransportAdapter interface {
	// Write sends raw binary data
	Write(data []byte) error

	// Read reads incoming binary data (blocking)
	Read() ([]byte, error)

	// Close closes the transport connection
	Close() error

	// SetWriteDeadline sets write timeout
	SetWriteDeadline(deadline interface{}) error

	// IsConnected returns whether the transport is connected
	IsConnected() bool
}

// CreateConnFromAdapter creates a Conn from a transport adapter
func CreateConnFromAdapter(adapter TransportAdapter, secret []byte) *Conn {
	return &Conn{
		adapter:   adapter,
		secret:    secret,
		secretHex: encodeHex(secret),
	}
}

// Helper function to encode secret
func encodeHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}
