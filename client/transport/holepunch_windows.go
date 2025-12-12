//go:build windows

package transport

// setReusePort is a no-op on Windows
// Windows doesn't have SO_REUSEPORT, but SO_REUSEADDR provides similar behavior
func setReusePort(fd int) error {
	// Windows allows port reuse with just SO_REUSEADDR
	return nil
}
