//go:build !windows
// +build !windows

package ipc

import "errors"

var errNotImplemented = errors.New("IPC not implemented on this platform")

// ErrBridgeAlreadyRunning indicates another bridge process owns the pipe
var ErrBridgeAlreadyRunning = errors.New("another desktop bridge is already running for this session")

func GetPipeName(sessionID uint32) string {
	return ""
}

type Server struct{}

func NewServer(sessionID uint32, handler MessageHandler) (*Server, error) {
	return nil, errNotImplemented
}

func (s *Server) Start()                      {}
func (s *Server) Send(msg *Message) error     { return errNotImplemented }
func (s *Server) IsConnected() bool           { return false }
func (s *Server) Close() error                { return nil }

type Client struct{}

func NewClient(sessionID uint32, handler MessageHandler) *Client {
	return nil
}

func (c *Client) Connect() error              { return errNotImplemented }
func (c *Client) Send(msg *Message) error     { return errNotImplemented }
func (c *Client) IsConnected() bool           { return false }
func (c *Client) Close() error                { return nil }
