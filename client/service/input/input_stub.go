//go:build !windows

package input

import "errors"

var errUnsupported = errors.New("input: injection not supported on this platform")

// Enabled reports whether native injection is available.
func Enabled() bool {
	return false
}

func PointerEnabled() bool {
	return false
}

func KeyboardEnabled() bool {
	return false
}

func SendPointerEvent(_ PointerEvent) error {
	return errUnsupported
}

func SendKeyboardEvent(_ KeyboardEvent) error {
	return errUnsupported
}
