//go:build !windows && !darwin && cgo
// +build !windows,!darwin,cgo

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
	btn := normalizeButton(button)
	if btn == `` {
		btn = `left`
	}
	state := `up`
	if down {
		state = `down`
	}
	robotgo.MouseToggle(state, btn)
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
	if key == `` {
		return nil
	}
	state := `up`
	if down {
		state = `down`
	}
	normalized := key
	if normalized == `escape` {
		normalized = `esc`
	}
	robotgo.KeyToggle(normalized, state)
	return nil
}
