//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	gdi32                = syscall.NewLazyDLL("gdi32.dll")
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procBeginPaint       = user32.NewProc("BeginPaint")
	procEndPaint         = user32.NewProc("EndPaint")
	procSetTimer         = user32.NewProc("SetTimer")
	procKillTimer        = user32.NewProc("KillTimer")
	procInvalidateRect   = user32.NewProc("InvalidateRect")
	procFillRect         = user32.NewProc("FillRect")
	procCreateSolidBrush = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject     = gdi32.NewProc("DeleteObject")
	procDestroyWindow    = user32.NewProc("DestroyWindow")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procSetWindowPos     = user32.NewProc("SetWindowPos")
	procGetClientRect    = user32.NewProc("GetClientRect")
	procGetWindowRect    = user32.NewProc("GetWindowRect")
	procGetSystemMetrics = user32.NewProc("GetSystemMetrics")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	procSetProcessDPIAware            = user32.NewProc("SetProcessDPIAware")
)

const (
	// Window styles
	wsPopup   = 0x80000000
	wsVisible = 0x10000000

	// Extended window styles
	wsExTopmost    = 0x00000008
	wsExToolWindow = 0x00000080

	// ShowWindow commands
	swShow = 5

	// Messages
	wmDestroy = 0x0002
	wmPaint   = 0x000F
	wmClose   = 0x0010
	wmTimer   = 0x0113

	// Timer IDs
	timerTick = 1

	// SetWindowPos
	hwndTopmost   = ^uintptr(1) + 1 // (HWND)-1
	swpNoActivate = 0x0010
	swpShowWindow = 0x0040

	// System metrics
	smCxScreen = 0
	smCyScreen = 1
)

type (
	hwnd   uintptr
	hbrush uintptr
)

type point struct {
	X, Y int32
}

type msg struct {
	HWnd    hwnd
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type rect struct {
	Left, Top, Right, Bottom int32
}

type paintStruct struct {
	Hdc         uintptr
	Erase       int32
	RcPaint     rect
	Restore     int32
	IncUpdate   int32
	RgbReserved [32]byte
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type perfConfig struct {
	X         int
	Y         int
	W         int
	H         int
	FPS       int
	Duration  time.Duration
	MarkerPad int
	MarkerSz  int
	MarkerGap int
}

var (
	cfg perfConfig
	// markerTs24 stores the lower 24 bits of UnixMillis.
	markerTs24 atomic.Uint32
	tickCount  atomic.Uint32
)

func rgbToColorref(r, g, b uint8) uint32 {
	// COLORREF = 0x00bbggrr
	return uint32(r) | (uint32(g) << 8) | (uint32(b) << 16)
}

func updateMarker() {
	ts := uint32(time.Now().UnixMilli()) & 0x00FFFFFF
	markerTs24.Store(ts)
	tickCount.Add(1)
}

func wndProc(h hwnd, msgID uint32, wParam, lParam uintptr) uintptr {
	switch msgID {
	case wmTimer:
		updateMarker()
		procInvalidateRect.Call(uintptr(h), 0, 1)
		return 0
	case wmPaint:
		var ps paintStruct
		hdc, _, _ := procBeginPaint.Call(uintptr(h), uintptr(unsafe.Pointer(&ps)))
		defer procEndPaint.Call(uintptr(h), uintptr(unsafe.Pointer(&ps)))

		var rc rect
		procGetClientRect.Call(uintptr(h), uintptr(unsafe.Pointer(&rc)))

		// Background: mid-gray to be visible, but not too bright.
		bgBrush, _, _ := procCreateSolidBrush.Call(uintptr(rgbToColorref(0x22, 0x22, 0x22)))
		procFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), bgBrush)
		procDeleteObject.Call(bgBrush)

		// Marker pattern:
		// - A fast-toggling checkerboard background to ensure the capture pipeline
		//   sees changes every tick even if delta thresholds are conservative.
		// - A 6x4 grid of black/white cells encoding the current ts24 (binary),
		//   robust to lossy codecs via threshold decoding.

		const (
			gridCols         = 6
			gridRows         = 4
			checkerCellPx    = 8
			checkerFillInset = 0
		)

		pad := max(0, cfg.MarkerPad)
		cell := max(6, cfg.MarkerSz)
		gap := max(0, cfg.MarkerGap)

		areaW := gridCols*cell + (gridCols-1)*gap
		areaH := gridRows*cell + (gridRows-1)*gap
		area := rect{
			Left:   int32(pad),
			Top:    int32(pad),
			Right:  int32(pad + areaW),
			Bottom: int32(pad + areaH),
		}

		// Toggle checkerboard phase each tick for maximum visual change.
		phase := int(tickCount.Load() & 1)
		for y := int(area.Top); y < int(area.Bottom); y += checkerCellPx {
			for x := int(area.Left); x < int(area.Right); x += checkerCellPx {
				on := ((x/checkerCellPx)+(y/checkerCellPx)+phase)&1 == 0
				var c uint32
				if on {
					c = rgbToColorref(0xF0, 0xF0, 0xF0)
				} else {
					c = rgbToColorref(0x10, 0x10, 0x10)
				}
				r2 := rect{
					Left:   int32(x + checkerFillInset),
					Top:    int32(y + checkerFillInset),
					Right:  int32(min(int(area.Right), x+checkerCellPx-checkerFillInset)),
					Bottom: int32(min(int(area.Bottom), y+checkerCellPx-checkerFillInset)),
				}
				br, _, _ := procCreateSolidBrush.Call(uintptr(c))
				procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r2)), br)
				procDeleteObject.Call(br)
			}
		}

		ts24 := markerTs24.Load()
		for bit := 0; bit < gridCols*gridRows; bit++ {
			col := bit % gridCols
			row := bit / gridCols

			// Map MSB -> top-left, LSB -> bottom-right.
			mask := uint32(1) << uint((gridCols*gridRows-1)-bit)
			on := (ts24 & mask) != 0

			x0 := pad + col*(cell+gap)
			y0 := pad + row*(cell+gap)
			r2 := rect{
				Left:   int32(x0),
				Top:    int32(y0),
				Right:  int32(x0 + cell),
				Bottom: int32(y0 + cell),
			}
			var c uint32
			if on {
				c = rgbToColorref(0xFF, 0xFF, 0xFF)
			} else {
				c = rgbToColorref(0x00, 0x00, 0x00)
			}
			br, _, _ := procCreateSolidBrush.Call(uintptr(c))
			procFillRect.Call(hdc, uintptr(unsafe.Pointer(&r2)), br)
			procDeleteObject.Call(br)
		}

		return 0
	case wmClose:
		procDestroyWindow.Call(uintptr(h))
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	default:
		ret, _, _ := procDefWindowProcW.Call(uintptr(h), uintptr(msgID), wParam, lParam)
		return ret
	}
}

func mustUTF16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		panic(err)
	}
	return p
}

func getSystemMetric(which int) int {
	v, _, _ := procGetSystemMetrics.Call(uintptr(which))
	return int(int32(v))
}

func clampToScreen(x, y, w, h int) (int, int) {
	sw := getSystemMetric(smCxScreen)
	sh := getSystemMetric(smCyScreen)
	if sw <= 0 || sh <= 0 {
		return x, y
	}
	if w <= 0 {
		w = 1
	}
	if h <= 0 {
		h = 1
	}
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	if x+w > sw {
		x = max(0, sw-w)
	}
	if y+h > sh {
		y = max(0, sh-h)
	}
	return x, y
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func enableDPIAwareness() {
	// Best-effort: make coordinates match physical pixels so capture sampling aligns.
	// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = (DPI_AWARENESS_CONTEXT)-4
	const dpiAwarenessContextPerMonitorAwareV2 = ^uintptr(3)
	if procSetProcessDpiAwarenessContext.Find() == nil {
		r, _, _ := procSetProcessDpiAwarenessContext.Call(dpiAwarenessContextPerMonitorAwareV2)
		if r != 0 {
			return
		}
	}
	// Fallback for older Windows: system DPI aware.
	if procSetProcessDPIAware.Find() == nil {
		_, _, _ = procSetProcessDPIAware.Call()
	}
}

func main() {
	var (
		xPos     = flag.Int("x", 16, "Window X position (screen coords)")
		yPos     = flag.Int("y", 16, "Window Y position (screen coords)")
		winW     = flag.Int("w", 180, "Window width")
		winH     = flag.Int("h", 180, "Window height")
		fps      = flag.Int("fps", 30, "Marker update rate (Hz)")
		duration = flag.Duration("duration", 30*time.Second, "How long to run before auto-exit (0 = until killed)")
		pad      = flag.Int("marker-pad", 8, "Marker square padding (px)")
		sz       = flag.Int("marker-size", 24, "Marker cell size (px)")
		gap      = flag.Int("marker-gap", 2, "Marker grid gap (px)")
	)
	flag.Parse()

	enableDPIAwareness()

	if *fps <= 0 {
		*fps = 30
	}
	if *winW <= 0 {
		*winW = 180
	}
	if *winH <= 0 {
		*winH = 180
	}
	if *pad < 0 {
		*pad = 0
	}
	if *sz <= 0 {
		*sz = 24
	}
	if *gap < 0 {
		*gap = 0
	}

	cfg = perfConfig{
		X:         *xPos,
		Y:         *yPos,
		W:         *winW,
		H:         *winH,
		FPS:       *fps,
		Duration:  *duration,
		MarkerPad: *pad,
		MarkerSz:  *sz,
		MarkerGap: *gap,
	}
	cfg.X, cfg.Y = clampToScreen(cfg.X, cfg.Y, cfg.W, cfg.H)

	updateMarker()

	className := mustUTF16Ptr("RocketPerfMarkerWindow")
	windowName := mustUTF16Ptr("Rocket Perf Marker")

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	wcex := wndClassEx{
		Size:      uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   syscall.NewCallback(wndProc),
		Instance:  hInstance,
		ClassName: className,
	}
	if atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcex))); atom == 0 {
		fmt.Fprintln(os.Stderr, "RegisterClassExW failed:", err)
		os.Exit(2)
	}

	h, _, err := procCreateWindowExW.Call(
		wsExTopmost|wsExToolWindow,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		wsPopup|wsVisible,
		uintptr(cfg.X),
		uintptr(cfg.Y),
		uintptr(cfg.W),
		uintptr(cfg.H),
		0,
		0,
		hInstance,
		0,
	)
	if h == 0 {
		fmt.Fprintln(os.Stderr, "CreateWindowExW failed:", err)
		os.Exit(2)
	}

	// Force topmost without activation.
	procSetWindowPos.Call(h, hwndTopmost, uintptr(cfg.X), uintptr(cfg.Y), uintptr(cfg.W), uintptr(cfg.H), swpNoActivate|swpShowWindow)
	procShowWindow.Call(h, swShow)
	procUpdateWindow.Call(h)

	tickInterval := time.Second / time.Duration(cfg.FPS)
	if tickInterval < 5*time.Millisecond {
		tickInterval = 5 * time.Millisecond
	}
	procSetTimer.Call(h, timerTick, uintptr(tickInterval.Milliseconds()), 0)

	// Resolve actual screen-space position (after DPI awareness & clamping).
	var wr rect
	procGetWindowRect.Call(h, uintptr(unsafe.Pointer(&wr)))
	actualX := int(wr.Left)
	actualY := int(wr.Top)
	actualW := int(wr.Right - wr.Left)
	actualH := int(wr.Bottom - wr.Top)

	fmt.Printf("READY x=%d y=%d w=%d h=%d fps=%d marker_pad=%d marker_size=%d marker_gap=%d grid=%dx%d\n",
		actualX, actualY, actualW, actualH, cfg.FPS, cfg.MarkerPad, cfg.MarkerSz, cfg.MarkerGap, 6, 4,
	)

	// Allow Ctrl+C to close the window cleanly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		procPostMessageW.Call(h, wmClose, 0, 0)
	}()

	if cfg.Duration > 0 {
		go func() {
			time.Sleep(cfg.Duration)
			procPostMessageW.Call(h, wmClose, 0, 0)
		}()
	}

	var m msg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	procKillTimer.Call(h, timerTick)
}
