//go:build windows && cgo
// +build windows,cgo

package desktop

import "github.com/go-vgo/robotgo"

func movePointerAbsolute(x, y int) error {
	robotgo.MoveMouse(x, y)
	return nil
}

func movePointerRelative(dx, dy int) error {
	if dx == 0 && dy == 0 {
		return nil
	}
	robotgo.MoveRelative(dx, dy)
	return nil
}

func mouseButton(button string, down bool) error {
	state := `up`
	if down {
		state = `down`
	}
	robotgo.MouseToggle(state, button)
	return nil
}

func scrollMouse(deltaX, deltaY int) error {
	if deltaY != 0 {
		dir := `down`
		if deltaY < 0 {
			dir = `up`
		}
		robotgo.ScrollMouse(abs(deltaY), dir)
	}
	if deltaX != 0 {
		dir := `right`
		if deltaX < 0 {
			dir = `left`
		}
		robotgo.ScrollMouse(abs(deltaX), dir)
	}
	return nil
}

func keyEvent(key string, down bool) error {
	state := `up`
	if down {
		state = `down`
	}
	robotgo.KeyToggle(key, state)
	return nil
}
