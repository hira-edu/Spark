//go:build windows

package input

import (
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	user32           = windows.NewLazySystemDLL("user32.dll")
	procSetCursorPos = user32.NewProc("SetCursorPos")
	procMouseEvent   = user32.NewProc("mouse_event")
	procKeybdEvent   = user32.NewProc("keybd_event")
)

const (
	buttonLeft = iota
	buttonMiddle
	buttonRight

	flagLeftDown  = 0x0002
	flagLeftUp    = 0x0004
	flagRightDown = 0x0008
	flagRightUp   = 0x0010
	flagMidDown   = 0x0020
	flagMidUp     = 0x0040
	flagWheel     = 0x0800

	keyFlagKeyUp = 0x0002
)

// Enabled reports whether native injection is available (alias of PointerEnabled).
func Enabled() bool {
	return true
}

// PointerEnabled indicates pointer injection support.
func PointerEnabled() bool {
	return true
}

// KeyboardEnabled indicates keyboard injection support.
func KeyboardEnabled() bool {
	return true
}

// SendPointerEvent injects a pointer event via the User32 APIs.
func SendPointerEvent(evt PointerEvent) error {
	switch strings.ToLower(evt.Action) {
	case "move":
		return setCursorPos(int32(evt.X), int32(evt.Y))
	case "down":
		return mouseEvent(mouseButtonFlag(evt.Button, true), 0)
	case "up":
		return mouseEvent(mouseButtonFlag(evt.Button, false), 0)
	case "wheel":
		delta := evt.DeltaY
		if delta == 0 {
			delta = 120
		}
		return mouseEvent(flagWheel, int32(delta))
	default:
		return fmt.Errorf("input: unsupported mouse action %s", evt.Action)
	}
}

func setCursorPos(x, y int32) error {
	ret, _, err := procSetCursorPos.Call(uintptr(x), uintptr(y))
	if ret == 0 {
		if err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("input: SetCursorPos failed")
	}
	return nil
}

func mouseEvent(flags uint32, data int32) error {
	if flags == 0 {
		return fmt.Errorf("input: invalid mouse flags")
	}
	procMouseEvent.Call(uintptr(flags), 0, 0, uintptr(data), 0)
	return nil
}

func mouseButtonFlag(button int, down bool) uint32 {
	switch button {
	case buttonMiddle:
		if down {
			return flagMidDown
		}
		return flagMidUp
	case buttonRight:
		if down {
			return flagRightDown
		}
		return flagRightUp
	default:
		if down {
			return flagLeftDown
		}
		return flagLeftUp
	}
}

// SendKeyboardEvent injects a key press/release via keybd_event.
func SendKeyboardEvent(evt KeyboardEvent) error {
	action := strings.ToLower(evt.Action)
	if action != "down" && action != "up" {
		return fmt.Errorf("input: unsupported keyboard action %s", evt.Action)
	}
	vk := lookupVirtualKey(evt)
	if vk == 0 {
		return fmt.Errorf("input: unsupported key %s (%s)", evt.Key, evt.Code)
	}
	flags := uintptr(0)
	if action == "up" {
		flags = keyFlagKeyUp
	}
	ret, _, err := procKeybdEvent.Call(uintptr(vk), 0, flags, 0)
	if ret == 0 && err != syscall.Errno(0) {
		return err
	}
	return nil
}

func lookupVirtualKey(evt KeyboardEvent) byte {
	if evt.KeyCode > 0 && evt.KeyCode < 256 {
		return byte(evt.KeyCode)
	}
	if len(evt.Key) == 1 {
		ch := evt.Key[0]
		if ch >= 'a' && ch <= 'z' {
			return ch - 32
		}
		if ch >= 'A' && ch <= 'Z' {
			return ch
		}
		if ch >= '0' && ch <= '9' {
			return ch
		}
	}
	code := strings.ToUpper(evt.Code)
	switch code {
	case "SPACE":
		return 0x20
	case "ENTER":
		return 0x0D
	case "TAB":
		return 0x09
	case "BACKSPACE":
		return 0x08
	case "ESCAPE":
		return 0x1B
	case "DELETE":
		return 0x2E
	case "ARROWLEFT":
		return 0x25
	case "ARROWRIGHT":
		return 0x27
	case "ARROWUP":
		return 0x26
	case "ARROWDOWN":
		return 0x28
	case "SHIFTLEFT", "SHIFTRIGHT":
		return 0x10
	case "CONTROLLEFT", "CONTROLRIGHT":
		return 0x11
	case "ALTLEFT", "ALTRIGHT":
		return 0x12
	case "METALEFT", "METARIGHT":
		return 0x5B
	default:
		return 0
	}
}
