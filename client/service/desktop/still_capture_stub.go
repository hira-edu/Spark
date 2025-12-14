//go:build !windows

package desktop

import (
	"image"

	"github.com/kbinani/screenshot"
)

func stillCapture(rect image.Rectangle) (*image.RGBA, error) {
	return screenshot.CaptureRect(rect)
}
