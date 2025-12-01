//go:build windows
// +build windows

package desktop

import (
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	inputTypeMouse    = 0
	inputTypeKeyboard = 1

	mouseeventfMove           = 0x0001
	mouseeventfLeftDown       = 0x0002
	mouseeventfLeftUp         = 0x0004
	mouseeventfRightDown      = 0x0008
	mouseeventfRightUp        = 0x0010
	mouseeventfMiddleDown     = 0x0020
	mouseeventfMiddleUp       = 0x0040
	mouseeventfWheel          = 0x0800
	mouseeventfHWheel         = 0x01000
	mouseeventfMoveNoCoalesce = 0x2000
	mouseeventfVirtualDesk    = 0x4000
	mouseeventfAbsolute       = 0x8000

	keyeventfExtended = 0x0001
	keyeventfKeyUp    = 0x0002
	keyeventfScancode = 0x0008

	wheelDelta = 120
)

const (
	esSystemRequired  = 0x00000001
	esDisplayRequired = 0x00000002
	esContinuous      = 0x80000000
)

// https://learn.microsoft.com/windows/win32/hidpi/wm-dpichanged#dpi-awareness-context
const dpiContextPerMonitorAwareV2 = -4

// System metrics constants
const (
	smCxVirtualScreen = 78
	smCyVirtualScreen = 79
	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
)

type mouseInput struct {
	Dx          int32
	Dy          int32
	MouseData   uint32
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type keyboardInput struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type inputMouse struct {
	Type uint32
	_    uint32
	Mi   mouseInput
}

type inputKeyboard struct {
	Type uint32
	_    uint32
	Ki   keyboardInput
}

func sendMouse(mi mouseInput) error {
	ensureDPI()
	ensureAwake()
	in := inputMouse{Type: inputTypeMouse, Mi: mi}
	ret, _, err := procSendInput.Call(
		uintptr(1),
		uintptr(unsafe.Pointer(&in)),
		unsafe.Sizeof(in),
	)
	if ret == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			return windows.ERROR_INVALID_PARAMETER
		}
		return err
	}
	return nil
}

func sendKeyboard(ki keyboardInput) error {
	ensureDPI()
	ensureAwake()
	in := inputKeyboard{Type: inputTypeKeyboard, Ki: ki}
	ret, _, err := procSendInput.Call(
		uintptr(1),
		uintptr(unsafe.Pointer(&in)),
		unsafe.Sizeof(in),
	)
	if ret == 0 {
		if err == nil || err == windows.ERROR_SUCCESS {
			return windows.ERROR_INVALID_PARAMETER
		}
		return err
	}
	return nil
}

func movePointerAbsolute(x, y int) error {
	ensureDPI()
	ensureAwake()
	originX, originY, width, height := virtualDesktop()
	nx := normalizeAbsolute(x, originX, width)
	ny := normalizeAbsolute(y, originY, height)
	return sendMouse(mouseInput{
		Dx:        nx,
		Dy:        ny,
		DwFlags:   mouseeventfMove | mouseeventfAbsolute | mouseeventfVirtualDesk | mouseeventfMoveNoCoalesce,
		MouseData: 0,
	})
}

func movePointerRelative(dx, dy int) error {
	ensureDPI()
	ensureAwake()
	if dx == 0 && dy == 0 {
		return nil
	}
	return sendMouse(mouseInput{
		Dx:        int32(dx),
		Dy:        int32(dy),
		DwFlags:   mouseeventfMove | mouseeventfMoveNoCoalesce,
		MouseData: 0,
	})
}

func mouseButton(button string, down bool) error {
	ensureDPI()
	ensureAwake()
	flag := uint32(0)
	switch button {
	case `left`:
		if down {
			flag = mouseeventfLeftDown
		} else {
			flag = mouseeventfLeftUp
		}
	case `right`:
		if down {
			flag = mouseeventfRightDown
		} else {
			flag = mouseeventfRightUp
		}
	case `center`:
		if down {
			flag = mouseeventfMiddleDown
		} else {
			flag = mouseeventfMiddleUp
		}
	default:
		return nil
	}
	return sendMouse(mouseInput{DwFlags: flag})
}

func scrollMouse(deltaX, deltaY int) error {
	ensureDPI()
	ensureAwake()
	if deltaY != 0 {
		amt := int32(deltaY * wheelDelta)
		if err := sendMouse(mouseInput{MouseData: uint32(amt), DwFlags: mouseeventfWheel}); err != nil {
			return err
		}
	}
	if deltaX != 0 {
		amt := int32(deltaX * wheelDelta)
		if err := sendMouse(mouseInput{MouseData: uint32(amt), DwFlags: mouseeventfHWheel}); err != nil {
			return err
		}
	}
	return nil
}

func keyEvent(key string, down bool) error {
	ensureDPI()
	ensureAwake()
	vk, sc, ok := lookupKey(key)
	if !ok {
		return errInputInvalid
	}
	flags := uint32(0)
	if sc != 0 {
		flags |= keyeventfScancode
	}
	if !down {
		flags |= keyeventfKeyUp
	}
	if isExtendedKey(key) {
		flags |= keyeventfExtended
	}
	return sendKeyboard(keyboardInput{WVk: vk, WScan: sc, DwFlags: flags})
}

func normalizeAbsolute(coord, origin, size int) int32 {
	if size <= 1 {
		return 0
	}
	return int32((uint64(coord-origin) * 65535) / uint64(size-1))
}

func virtualDesktop() (x, y, width, height int) {
	r1, _, _ := procGetSystemMetrics.Call(uintptr(smXVirtualScreen))
	x = int(r1)
	r2, _, _ := procGetSystemMetrics.Call(uintptr(smYVirtualScreen))
	y = int(r2)
	r3, _, _ := procGetSystemMetrics.Call(uintptr(smCxVirtualScreen))
	width = int(r3)
	r4, _, _ := procGetSystemMetrics.Call(uintptr(smCyVirtualScreen))
	height = int(r4)
	return
}

var (
	user32                    = windows.NewLazySystemDLL("user32.dll")
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procSendInput             = user32.NewProc("SendInput")
	procSetDPI                = user32.NewProc("SetThreadDpiAwarenessContext")
	procGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	procMapVirtualKeyEx       = user32.NewProc("MapVirtualKeyExW")
	procSetThreadExecutionState = kernel32.NewProc("SetThreadExecutionState")
	onceDPI                   sync.Once
	onceAwake                 sync.Once
)

const mapvkVkToVsc = 0

func lookupKey(key string) (uint16, uint16, bool) {
	key = strings.ToLower(key)

	if len(key) == 1 {
		r := key[0]
		switch {
		case r >= 'a' && r <= 'z':
			vk := uint16('A' + (r - 'a'))
			return vk, scancodeForVK(vk), true
		case r >= '0' && r <= '9':
			vk := uint16('0' + (r - '0'))
			return vk, scancodeForVK(vk), true
		}
	}

	if vk, ok := vkTable[key]; ok {
		return vk, scancodeForVK(vk), true
	}
	if strings.HasPrefix(key, "f") && len(key) <= 3 {
		if vk := functionVK(key); vk != 0 {
			return vk, scancodeForVK(vk), true
		}
	}
	return 0, 0, false
}

func scancodeForVK(vk uint16) uint16 {
	ret, _, _ := procMapVirtualKeyEx.Call(uintptr(vk), uintptr(mapvkVkToVsc), 0)
	return uint16(ret)
}

func functionVK(key string) uint16 {
	switch key {
	case "f1":
		return 0x70
	case "f2":
		return 0x71
	case "f3":
		return 0x72
	case "f4":
		return 0x73
	case "f5":
		return 0x74
	case "f6":
		return 0x75
	case "f7":
		return 0x76
	case "f8":
		return 0x77
	case "f9":
		return 0x78
	case "f10":
		return 0x79
	case "f11":
		return 0x7A
	case "f12":
		return 0x7B
	default:
		return 0
	}
}

var vkTable = map[string]uint16{
	`backspace`: 0x08,
	`tab`:       0x09,
	`enter`:     0x0D,
	`shift`:     0x10,
	`ctrl`:      0x11,
	`alt`:       0x12,
	`pause`:     0x13,
	`capslock`:  0x14,
	`escape`:    0x1B,
	`space`:     0x20,
	`pageup`:    0x21,
	`pagedown`:  0x22,
	`end`:       0x23,
	`home`:      0x24,
	`left`:      0x25,
	`up`:        0x26,
	`right`:     0x27,
	`down`:      0x28,
	`insert`:    0x2D,
	`delete`:    0x2E,
	`cmd`:       0x5B,
	`menu`:      0x5D,
}

func isExtendedKey(key string) bool {
	switch key {
	case `insert`, `delete`, `home`, `end`, `pageup`, `pagedown`, `left`, `right`, `up`, `down`, `cmd`, `menu`:
		return true
	default:
		return false
	}
}

func ensureDPI() {
	onceDPI.Do(func() {
		if procSetDPI == nil {
			return
		}
		// DPI_AWARENESS_CONTEXT is a handle represented as uintptr
		// -4 is a special predefined value that needs to be cast via ^uintptr(3)
		// This is equivalent to (uintptr)(intptr)(-4)
		procSetDPI.Call(^uintptr(3)) // -4 as uintptr
	})
}

func ensureAwake() {
	// keep display/system awake while input is being injected
	onceAwake.Do(func() {
		procSetThreadExecutionState.Call(uintptr(esContinuous | esSystemRequired | esDisplayRequired))
	})
}
