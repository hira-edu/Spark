//go:build windows

package transport

import "syscall"

// setReuseAddr applies SO_REUSEADDR on Windows sockets.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
