package ipc

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// Message types for IPC communication
const (
	MsgTypeDesktopInit   = 1
	MsgTypeDesktopKill   = 2
	MsgTypeDesktopPing   = 3
	MsgTypeDesktopFrame  = 4
	MsgTypeDesktopInput  = 5
	MsgTypeDesktopConfig = 6
	MsgTypeDesktopShot   = 7
	MsgTypeDesktopQuit   = 8
	MsgTypeHeartbeat     = 9
	MsgTypeDesktopPacket = 10
	MsgTypeHello         = 11
	MsgTypeHelloAck      = 12
	MsgTypeState         = 13
)

// Message represents an IPC message between Session 0 and user session
type Message struct {
	Type    uint16
	Payload []byte
}

// ErrPipeClosed indicates the pipe was closed
var ErrPipeClosed = errors.New("pipe closed")

func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

// WriteMessage writes a message to the pipe with length prefix
func WriteMessage(w io.Writer, msg *Message) error {
	// Header: 2 bytes type + 4 bytes payload length
	header := make([]byte, 6)
	binary.BigEndian.PutUint16(header[0:2], msg.Type)
	binary.BigEndian.PutUint32(header[2:6], uint32(len(msg.Payload)))

	if err := writeAll(w, header); err != nil {
		return err
	}
	if len(msg.Payload) > 0 {
		if err := writeAll(w, msg.Payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadMessage reads a message from the pipe
func ReadMessage(r io.Reader) (*Message, error) {
	header := make([]byte, 6)
	if _, err := io.ReadFull(r, header); err != nil {
		if err == io.EOF {
			return nil, ErrPipeClosed
		}
		return nil, err
	}

	msgType := binary.BigEndian.Uint16(header[0:2])
	payloadLen := binary.BigEndian.Uint32(header[2:6])

	var payload []byte
	if payloadLen > 0 {
		// Limit payload size to 16MB to prevent memory issues
		if payloadLen > 16*1024*1024 {
			return nil, errors.New("payload too large")
		}
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Message{Type: msgType, Payload: payload}, nil
}

// MessageHandler is called for each received message
type MessageHandler func(msg *Message)

// PipeConn wraps a pipe connection with message framing
type PipeConn struct {
	conn    io.ReadWriteCloser
	writeMu sync.Mutex
	handler MessageHandler
	closed  bool
	closeMu sync.Mutex
}

// NewPipeConn creates a new pipe connection wrapper
func NewPipeConn(conn io.ReadWriteCloser, handler MessageHandler) *PipeConn {
	return &PipeConn{
		conn:    conn,
		handler: handler,
	}
}

// Send sends a message over the pipe
func (p *PipeConn) Send(msg *Message) error {
	p.closeMu.Lock()
	if p.closed {
		p.closeMu.Unlock()
		return ErrPipeClosed
	}
	p.closeMu.Unlock()

	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return WriteMessage(p.conn, msg)
}

// StartReading starts reading messages in a loop
func (p *PipeConn) StartReading() {
	for {
		msg, err := ReadMessage(p.conn)
		if err != nil {
			p.closeMu.Lock()
			p.closed = true
			p.closeMu.Unlock()
			return
		}
		if p.handler != nil {
			p.handler(msg)
		}
	}
}

// Close closes the pipe connection
func (p *PipeConn) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.conn.Close()
}

// IsClosed returns whether the connection is closed
func (p *PipeConn) IsClosed() bool {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	return p.closed
}
