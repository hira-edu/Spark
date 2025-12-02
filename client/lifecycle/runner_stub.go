//go:build !windows
// +build !windows

package lifecycle

import "errors"

// RunUIOnlyMode is a stub for non-Windows platforms
func RunUIOnlyMode() error {
	return errors.New("UI only mode not supported on this platform")
}
