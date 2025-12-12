//go:build linux

package transport

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// setReusePort sets SO_REUSEPORT on Linux
// This allows multiple sockets to bind to the same port
func setReusePort(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
}
