//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
)

func stillCapture(rect image.Rectangle) (_ *image.RGBA, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("still capture panic: %v", r)
		}
	}()

	if rect.Dx() <= 0 || rect.Dy() <= 0 {
		return nil, errors.New("invalid capture rect")
	}

	cap := &ScreenGDICompat{}
	if err := cap.Init(0, rect); err != nil {
		return nil, err
	}
	frame, err := cap.Capture()
	if err != nil {
		return nil, err
	}
	if frame == nil || frame.Image == nil {
		return nil, errors.New("still capture returned nil frame")
	}
	return frame.Image, nil
}
