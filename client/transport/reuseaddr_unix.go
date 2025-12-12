//go:build !windows

package transport

import "syscall"

// setReuseAddr applies SO_REUSEADDR on POSIX sockets.
func setReuseAddr(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
