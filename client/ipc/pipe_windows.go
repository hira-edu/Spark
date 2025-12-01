//go:build windows
// +build windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	// PipeNamePrefix is the base name for named pipes
	PipeNamePrefix = `\\.\pipe\spark-desktop-`
)

// ErrBridgeAlreadyRunning indicates another bridge process owns the pipe
var ErrBridgeAlreadyRunning = errors.New("another desktop bridge is already running for this session")

// GetPipeName returns the pipe name for a specific session
func GetPipeName(sessionID uint32) string {
	return fmt.Sprintf("%s%d", PipeNamePrefix, sessionID)
}

// Server listens for connections from Session 0 service
type Server struct {
	listener  net.Listener
	sessionID uint32
	handler   MessageHandler
	conn      *PipeConn
	connMu    sync.Mutex
	done      chan struct{}
}

// NewServer creates a new IPC server for the user session
func NewServer(sessionID uint32, handler MessageHandler) (*Server, error) {
	pipeName := GetPipeName(sessionID)

	// Create named pipe with security that allows service to connect
	// Security descriptor breakdown:
	// D:P - DACL is protected
	// (A;;GA;;;WD) - Allow Generic All for Everyone (World)
	// (A;;GA;;;SY) - Allow Generic All for SYSTEM
	// (A;;GA;;;BA) - Allow Generic All for Built-in Administrators
	// (A;;GA;;;CO) - Allow Generic All for Creator Owner
	// S:(ML;;NW;;;LW) - Mandatory Label: Low integrity (allows low integrity processes)
	cfg := &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;CO)S:(ML;;NW;;;LW)",
		MessageMode:        false,  // Stream mode for our framed messages
		InputBufferSize:    1024 * 1024, // 1MB buffer
		OutputBufferSize:   1024 * 1024,
	}

	listener, err := winio.ListenPipe(pipeName, cfg)
	if err != nil {
		// Check if the pipe already exists (another bridge is running)
		// Try to connect to verify it is alive
		testConn, dialErr := winio.DialPipe(pipeName, nil)
		if dialErr == nil {
			// Pipe exists and is accepting connections - another bridge is running
			testConn.Close()
			return nil, ErrBridgeAlreadyRunning
		}
		// Pipe exists but not accepting connections (stale) - try again after a short delay
		// This can happen if the previous process crashed
		time.Sleep(500 * time.Millisecond)
		listener, err = winio.ListenPipe(pipeName, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create pipe %s: %w", pipeName, err)
		}
	}

	return &Server{
		listener:  listener,
		sessionID: sessionID,
		handler:   handler,
		done:      make(chan struct{}),
	}, nil
}

// Start begins accepting connections
func (s *Server) Start() {
	go s.acceptLoop()
}

func (s *Server) acceptLoop() {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				// Log error and continue
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		// Close any existing connection
		s.connMu.Lock()
		if s.conn != nil {
			s.conn.Close()
		}
		s.conn = NewPipeConn(conn, s.handler)
		s.connMu.Unlock()

		// Start reading in a goroutine
		go s.conn.StartReading()
	}
}

// Send sends a message to the connected client
func (s *Server) Send(msg *Message) error {
	s.connMu.Lock()
	conn := s.conn
	s.connMu.Unlock()

	if conn == nil {
		return ErrPipeClosed
	}
	return conn.Send(msg)
}

// IsConnected returns whether a client is connected
func (s *Server) IsConnected() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.conn != nil && !s.conn.IsClosed()
}

// Close shuts down the server
func (s *Server) Close() error {
	close(s.done)
	s.connMu.Lock()
	if s.conn != nil {
		s.conn.Close()
	}
	s.connMu.Unlock()
	return s.listener.Close()
}

// Client connects to the user session IPC server
type Client struct {
	sessionID uint32
	conn      *PipeConn
	handler   MessageHandler
	connMu    sync.Mutex
}

// NewClient creates a new IPC client for Session 0
func NewClient(sessionID uint32, handler MessageHandler) *Client {
	return &Client{
		sessionID: sessionID,
		handler:   handler,
	}
}

// Connect establishes connection to the user session pipe
func (c *Client) Connect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn != nil && !c.conn.IsClosed() {
		return nil // Already connected
	}

	pipeName := GetPipeName(c.sessionID)

	// Try to connect with timeout
	var conn net.Conn
	var err error

	for i := 0; i < 10; i++ {
		conn, err = winio.DialPipe(pipeName, nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to pipe %s: %w", pipeName, err)
	}

	c.conn = NewPipeConn(conn, c.handler)
	go c.conn.StartReading()

	return nil
}

// Send sends a message to the user session
func (c *Client) Send(msg *Message) error {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil || conn.IsClosed() {
		return ErrPipeClosed
	}
	return conn.Send(msg)
}

// IsConnected returns whether connected to user session
func (c *Client) IsConnected() bool {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.conn != nil && !c.conn.IsClosed()
}

// Close closes the connection
func (c *Client) Close() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
