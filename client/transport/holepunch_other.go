//go:build !linux && !darwin && !windows

package transport

// setReusePort is a stub for unsupported platforms
func setReusePort(fd int) error {
	return nil
}
