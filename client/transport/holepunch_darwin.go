//go:build darwin

package transport

import "syscall"

// setReusePort sets SO_REUSEPORT on macOS
func setReusePort(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}
