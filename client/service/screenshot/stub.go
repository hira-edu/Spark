//go:build !windows

package screenshot

import "errors"

var errUnsupported = errors.New("screenshot: feature available on Windows endpoints only")

func GetScreenshot(bridge string) error {
	return errUnsupported
}
