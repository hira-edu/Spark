//go:build windows

package desktop

import (
	"Rocket/client/telemetry"
	"Rocket/modules"
	"encoding/base64"
	"hash/crc32"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	// user32 is already declared in input_windows.go, reuse it
	gdi32Dll          = syscall.NewLazyDLL("gdi32.dll")
	procGetCursorInfo = user32.NewProc("GetCursorInfo")
	procGetCursorPos  = user32.NewProc("GetCursorPos")
	procGetIconInfo   = user32.NewProc("GetIconInfo")
	procGetDIBits     = gdi32Dll.NewProc("GetDIBits")
	procGetDC         = user32.NewProc("GetDC")
	procReleaseDC     = user32.NewProc("ReleaseDC")
	procDeleteObject  = gdi32Dll.NewProc("DeleteObject")
	procGetObject     = gdi32Dll.NewProc("GetObjectW")
	procGetBitmapBits = gdi32Dll.NewProc("GetBitmapBits")

	cursorCaptureActive atomic.Bool
	lastCursorHash      uint32
	lastCursorVisible   bool
	lastCursorX         int32
	lastCursorY         int32
)

const (
	CURSOR_SHOWING = 0x00000001
	DIB_RGB_COLORS = 0
)

type CURSORINFO struct {
	CbSize      uint32
	Flags       uint32
	HCursor     uintptr
	PtScreenPos POINT
}

type POINT struct {
	X int32
	Y int32
}

type ICONINFO struct {
	FIcon    uint32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

type BITMAP struct {
	BmType       int32
	BmWidth      int32
	BmHeight     int32
	BmWidthBytes int32
	BmPlanes     uint16
	BmBitsPixel  uint16
	BmBits       uintptr
}

type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// CursorData represents cursor information to send to web client
type CursorData struct {
	X       int32  `json:"x"`
	Y       int32  `json:"y"`
	HotX    int32  `json:"hotX"`
	HotY    int32  `json:"hotY"`
	Width   int32  `json:"width"`
	Height  int32  `json:"height"`
	Visible bool   `json:"visible"`
	Data    string `json:"data"` // base64 RGBA bitmap
	Hash    uint32 `json:"hash"`
	Format  string `json:"format,omitempty"`
}

// StartCursorCapture starts the cursor capture loop (30Hz)
func StartCursorCapture(rawEvent []byte) {
	if !cursorCaptureActive.CompareAndSwap(false, true) {
		return // Already running
	}

	// Reset cache so the first frame of a new session is always sent
	lastCursorHash = 0
	lastCursorVisible = false
	lastCursorX = 0
	lastCursorY = 0

	go cursorCaptureLoop(rawEvent)
}

// StopCursorCapture stops the cursor capture loop
func StopCursorCapture() {
	cursorCaptureActive.Store(false)
}

func cursorCaptureLoop(rawEvent []byte) {
	ticker := time.NewTicker(time.Second / 30) // 30 Hz
	defer ticker.Stop()

	telemetry.LogStructured("INFO", "cursor: capture loop started", nil)

	for cursorCaptureActive.Load() {
		<-ticker.C

		cursor, err := captureCursor()
		if err != nil {
			continue
		}

		// Check if cursor changed (position OR appearance)
		if cursor.Hash == lastCursorHash &&
			cursor.Visible == lastCursorVisible &&
			cursor.X == lastCursorX &&
			cursor.Y == lastCursorY {
			continue // No change, skip
		}

		// Update cache
		lastCursorHash = cursor.Hash
		lastCursorVisible = cursor.Visible
		lastCursorX = cursor.X
		lastCursorY = cursor.Y

		// Send cursor update
		sendDesktopPacket(modules.Packet{
			Act: "CURSOR_UPDATE",
			Data: map[string]any{
				"x":       cursor.X,
				"y":       cursor.Y,
				"hotX":    cursor.HotX,
				"hotY":    cursor.HotY,
				"width":   cursor.Width,
				"height":  cursor.Height,
				"visible": cursor.Visible,
				"data":    cursor.Data,
				"hash":    cursor.Hash,
				"format":  cursor.Format,
			},
		}, rawEvent)
	}

	telemetry.LogStructured("INFO", "cursor: capture loop stopped", nil)
}

// captureCursor captures current cursor state
func captureCursor() (*CursorData, error) {
	// Get cursor position
	var pt POINT
	ret, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	if ret == 0 {
		return nil, syscall.GetLastError()
	}

	// Get cursor info (handle + visibility)
	var ci CURSORINFO
	ci.CbSize = uint32(unsafe.Sizeof(ci))
	ret, _, _ = procGetCursorInfo.Call(uintptr(unsafe.Pointer(&ci)))
	if ret == 0 {
		return nil, syscall.GetLastError()
	}

	// Check visibility
	if ci.Flags&CURSOR_SHOWING == 0 {
		return &CursorData{
			X:       pt.X,
			Y:       pt.Y,
			Visible: false,
			Hash:    0,
		}, nil
	}

	// Get icon info (hotspot + bitmaps)
	var ii ICONINFO
	ret, _, _ = procGetIconInfo.Call(ci.HCursor, uintptr(unsafe.Pointer(&ii)))
	if ret == 0 {
		return nil, syscall.GetLastError()
	}
	defer func() {
		if ii.HbmMask != 0 {
			procDeleteObject.Call(ii.HbmMask)
		}
		if ii.HbmColor != 0 {
			procDeleteObject.Call(ii.HbmColor)
		}
	}()

	// Get bitmap dimensions
	var bm BITMAP
	ret, _, _ = procGetObject.Call(ii.HbmMask, unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm)))
	if ret == 0 {
		return nil, syscall.GetLastError()
	}

	width := bm.BmWidth
	maskHeight := bm.BmHeight
	maskStride := bm.BmWidthBytes
	height := maskHeight
	if ii.HbmColor == 0 {
		// Monochrome cursor: mask height is 2x image height (AND mask + XOR mask)
		height = height / 2
	}
	if width <= 0 || height <= 0 {
		return nil, syscall.EINVAL
	}

	// Extract RGBA bitmap data
	rgba, err := extractCursorBitmap(ii.HbmColor, ii.HbmMask, width, height, maskStride, maskHeight)
	if err != nil {
		return nil, err
	}

	// Compute hash for change detection
	hash := crc32.ChecksumIEEE(rgba)

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(rgba)

	return &CursorData{
		X:       pt.X,
		Y:       pt.Y,
		HotX:    int32(ii.XHotspot),
		HotY:    int32(ii.YHotspot),
		Width:   width,
		Height:  height,
		Visible: true,
		Data:    encoded,
		Hash:    hash,
		Format:  "argb32",
	}, nil
}

// extractCursorBitmap converts Windows cursor bitmap to RGBA format
func extractCursorBitmap(hbmColor, hbmMask uintptr, width, height, maskStride, maskHeight int32) ([]byte, error) {
	rgba := make([]byte, width*height*4)

	// Fallback stride/height if the bitmap metadata is missing
	stride := maskStride
	if stride <= 0 {
		// 1bpp bitmaps are DWORD aligned
		stride = ((width + 31) / 32) * 4
	}
	if maskHeight <= 0 {
		maskHeight = height
	}

	if hbmColor != 0 {
		// Color cursor: extract color bitmap
		if err := getBitmapData(hbmColor, width, height, rgba); err != nil {
			return nil, err
		}

		// Apply mask for alpha channel
		maskBytes := stride * height
		fullMaskSize := stride * maskHeight
		if fullMaskSize < maskBytes {
			fullMaskSize = maskBytes
		}
		if fullMaskSize > 0 {
			mask := make([]byte, fullMaskSize)
			ret, _, _ := procGetBitmapBits.Call(hbmMask, uintptr(fullMaskSize), uintptr(unsafe.Pointer(&mask[0])))
			if ret == 0 {
				return nil, syscall.GetLastError()
			}
			applyMaskToAlpha(rgba, mask, width, height, stride)
		}
	} else {
		// Monochrome cursor: convert mask to RGBA
		if maskHeight < height*2 {
			// Expect AND + XOR planes
			maskHeight = height * 2
		}
		maskSize := stride * maskHeight
		if maskSize > 0 {
			mask := make([]byte, maskSize)
			ret, _, _ := procGetBitmapBits.Call(hbmMask, uintptr(maskSize), uintptr(unsafe.Pointer(&mask[0])))
			if ret == 0 {
				return nil, syscall.GetLastError()
			}

			convertMonochromeCursor(rgba, mask, width, height, stride)
		}
	}

	// Convert BGRA to RGBA
	for i := 0; i < len(rgba); i += 4 {
		rgba[i], rgba[i+2] = rgba[i+2], rgba[i] // Swap B and R
	}

	return rgba, nil
}

// getBitmapData extracts color bitmap using GetDIBits
func getBitmapData(hBitmap uintptr, width, height int32, output []byte) error {
	hDC, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, hDC)

	var bi BITMAPINFOHEADER
	bi.BiSize = uint32(unsafe.Sizeof(bi))
	bi.BiWidth = width
	bi.BiHeight = -height // Negative for top-down bitmap
	bi.BiPlanes = 1
	bi.BiBitCount = 32
	bi.BiCompression = 0 // BI_RGB

	ret, _, _ := procGetDIBits.Call(
		hDC,
		hBitmap,
		0,
		uintptr(height),
		uintptr(unsafe.Pointer(&output[0])),
		uintptr(unsafe.Pointer(&bi)),
		DIB_RGB_COLORS,
	)

	if ret == 0 {
		return syscall.GetLastError()
	}

	return nil
}

// applyMaskToAlpha applies AND mask to set alpha channel
func applyMaskToAlpha(rgba, mask []byte, width, height, stride int32) {
	if stride <= 0 {
		stride = ((width + 31) / 32) * 4
	}

	rowBytes := int(stride)
	for y := int32(0); y < height; y++ {
		for x := int32(0); x < width; x++ {
			pixelIdx := (y*width + x) * 4

			byteIdx := rowBytes*int(y) + int(x/8)
			if byteIdx < 0 || byteIdx >= len(mask) {
				continue
			}

			bitIdx := 7 - (x % 8)
			maskBit := (mask[byteIdx] >> bitIdx) & 1

			if maskBit == 1 {
				rgba[pixelIdx+3] = 0 // Transparent
			} else {
				rgba[pixelIdx+3] = 255 // Opaque
			}
		}
	}
}

// convertMonochromeCursor converts monochrome cursor (AND + XOR masks) to RGBA
func convertMonochromeCursor(rgba, mask []byte, width, height, stride int32) {
	if stride <= 0 {
		stride = ((width + 31) / 32) * 4
	}

	rowBytes := int(stride)
	andMaskSize := rowBytes * int(height)

	for y := int32(0); y < height; y++ {
		for x := int32(0); x < width; x++ {
			pixelIdx := (y*width + x) * 4

			byteIdx := rowBytes*int(y) + int(x/8)
			if byteIdx < 0 || byteIdx >= len(mask) {
				continue
			}
			xorByte := andMaskSize + byteIdx
			if xorByte >= len(mask) {
				continue
			}

			bitIdx := 7 - (x % 8)
			andBit := (mask[byteIdx] >> bitIdx) & 1
			xorBit := (mask[xorByte] >> bitIdx) & 1

			// Cursor logic: AND=0,XOR=0 → Black, AND=0,XOR=1 → White, AND=1 → Transparent
			if andBit == 1 {
				rgba[pixelIdx+0] = 0 // R
				rgba[pixelIdx+1] = 0 // G
				rgba[pixelIdx+2] = 0 // B
				rgba[pixelIdx+3] = 0 // A (transparent)
			} else {
				color := uint8(255 * xorBit)
				rgba[pixelIdx+0] = color // R
				rgba[pixelIdx+1] = color // G
				rgba[pixelIdx+2] = color // B
				rgba[pixelIdx+3] = 255   // A (opaque)
			}
		}
	}
}
