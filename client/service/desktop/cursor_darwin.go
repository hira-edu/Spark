//go:build darwin

package desktop

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

type cgPoint struct {
	X float64
	Y float64
}

var (
	cgOnce sync.Once
	cgErr  error

	cgLib uintptr
	cfLib uintptr

	cgEventCreate          func(uintptr) uintptr
	cgEventGetLocation     func(uintptr) cgPoint
	cgDisplayCopyCursor    func(*cgPoint) uintptr
	cgCursorIsVisible      func() bool
	cgImageGetWidth        func(uintptr) uintptr
	cgImageGetHeight       func(uintptr) uintptr
	cgImageGetBytesPerRow  func(uintptr) uintptr
	cgImageGetBitsPerPixel func(uintptr) uintptr
	cgImageGetBitmapInfo   func(uintptr) uint32
	cgImageGetDataProvider func(uintptr) uintptr
	cgDataProviderCopyData func(uintptr) uintptr

	cfDataGetLength  func(uintptr) int64
	cfDataGetBytePtr func(uintptr) unsafe.Pointer
	cfRelease        func(uintptr)
)

func initCoreGraphics() error {
	cgOnce.Do(func() {
		var err error
		cgLib, err = purego.Dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			cgErr = err
			return
		}
		cfLib, err = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			cgErr = err
			return
		}

		purego.RegisterLibFunc(&cgEventCreate, cgLib, "CGEventCreate")
		purego.RegisterLibFunc(&cgEventGetLocation, cgLib, "CGEventGetLocation")
		purego.RegisterLibFunc(&cgDisplayCopyCursor, cgLib, "CGDisplayCopyCursorImage")
		purego.RegisterLibFunc(&cgCursorIsVisible, cgLib, "CGCursorIsVisible")
		purego.RegisterLibFunc(&cgImageGetWidth, cgLib, "CGImageGetWidth")
		purego.RegisterLibFunc(&cgImageGetHeight, cgLib, "CGImageGetHeight")
		purego.RegisterLibFunc(&cgImageGetBytesPerRow, cgLib, "CGImageGetBytesPerRow")
		purego.RegisterLibFunc(&cgImageGetBitsPerPixel, cgLib, "CGImageGetBitsPerPixel")
		purego.RegisterLibFunc(&cgImageGetBitmapInfo, cgLib, "CGImageGetBitmapInfo")
		purego.RegisterLibFunc(&cgImageGetDataProvider, cgLib, "CGImageGetDataProvider")
		purego.RegisterLibFunc(&cgDataProviderCopyData, cgLib, "CGDataProviderCopyData")

		purego.RegisterLibFunc(&cfDataGetLength, cfLib, "CFDataGetLength")
		purego.RegisterLibFunc(&cfDataGetBytePtr, cfLib, "CFDataGetBytePtr")
		purego.RegisterLibFunc(&cfRelease, cfLib, "CFRelease")
	})
	return cgErr
}

func captureCursorPlatform() (*CursorData, []byte, error) {
	if err := initCoreGraphics(); err != nil {
		return nil, nil, err
	}

	event := cgEventCreate(0)
	if event == 0 {
		return nil, nil, fmt.Errorf("coregraphics: CGEventCreate failed")
	}
	loc := cgEventGetLocation(event)
	cfRelease(event)

	hot := cgPoint{}
	img := cgDisplayCopyCursor(&hot)
	if img == 0 {
		return &CursorData{X: int32(loc.X), Y: int32(loc.Y), Visible: false}, nil, nil
	}
	defer cfRelease(img)

	width := int(cgImageGetWidth(img))
	height := int(cgImageGetHeight(img))
	if width <= 0 || height <= 0 {
		return &CursorData{X: int32(loc.X), Y: int32(loc.Y), Visible: false}, nil, nil
	}

	if int(cgImageGetBitsPerPixel(img)) != 32 {
		return &CursorData{X: int32(loc.X), Y: int32(loc.Y), Visible: false}, nil, nil
	}

	bytesPerRow := int(cgImageGetBytesPerRow(img))
	if bytesPerRow < width*4 {
		bytesPerRow = width * 4
	}

	provider := cgImageGetDataProvider(img)
	if provider == 0 {
		return nil, nil, fmt.Errorf("coregraphics: CGImageGetDataProvider failed")
	}
	dataRef := cgDataProviderCopyData(provider)
	if dataRef == 0 {
		return nil, nil, fmt.Errorf("coregraphics: CGDataProviderCopyData failed")
	}
	defer cfRelease(dataRef)

	dataLen := int(cfDataGetLength(dataRef))
	dataPtr := cfDataGetBytePtr(dataRef)
	if dataPtr == nil || dataLen <= 0 {
		return nil, nil, fmt.Errorf("coregraphics: empty cursor image data")
	}

	raw := make([]byte, dataLen)
	copy(raw, unsafe.Slice((*byte)(dataPtr), dataLen))

	// Convert CGImage backing bytes to RGBA. Common cases:
	// - 32Little + AlphaPremultipliedFirst => BGRA
	// - 32Big + AlphaPremultipliedLast => RGBA
	const (
		cgBitmapByteOrderMask          = 0x7000
		cgBitmapByteOrder32Little      = 0x2000
		cgBitmapByteOrder32Big         = 0x4000
		cgImageAlphaInfoMask           = 0x1F
		cgImageAlphaPremultipliedLast  = 1
		cgImageAlphaPremultipliedFirst = 2
		cgImageAlphaLast               = 3
		cgImageAlphaFirst              = 4
		cgImageAlphaNoneSkipLast       = 5
		cgImageAlphaNoneSkipFirst      = 6
	)

	bitmapInfo := cgImageGetBitmapInfo(img)
	byteOrder := bitmapInfo & cgBitmapByteOrderMask
	alphaInfo := bitmapInfo & cgImageAlphaInfoMask

	rgba := make([]byte, width*height*4)
	for y := 0; y < height; y++ {
		rowStart := y * bytesPerRow
		for x := 0; x < width; x++ {
			i := rowStart + x*4
			if i+3 >= len(raw) {
				continue
			}
			var r, g, b, a byte

			switch byteOrder {
			case cgBitmapByteOrder32Big:
				// Big-endian layouts are typically RGBA (alpha last) or ARGB (alpha first).
				if alphaInfo == cgImageAlphaPremultipliedLast || alphaInfo == cgImageAlphaLast || alphaInfo == cgImageAlphaNoneSkipLast {
					r, g, b = raw[i+0], raw[i+1], raw[i+2]
					if alphaInfo == cgImageAlphaNoneSkipLast {
						a = 255
					} else {
						a = raw[i+3]
					}
				} else {
					// Assume ARGB.
					a, r, g, b = raw[i+0], raw[i+1], raw[i+2], raw[i+3]
				}
			case cgBitmapByteOrder32Little:
				// Little-endian layouts are typically BGRA (alpha first).
				b, g, r = raw[i+0], raw[i+1], raw[i+2]
				if alphaInfo == cgImageAlphaNoneSkipFirst {
					a = 255
				} else {
					a = raw[i+3]
				}
			default:
				// Fallback to BGRA.
				b, g, r, a = raw[i+0], raw[i+1], raw[i+2], raw[i+3]
			}

			o := (y*width + x) * 4
			rgba[o+0] = r
			rgba[o+1] = g
			rgba[o+2] = b
			rgba[o+3] = a
		}
	}

	visible := true
	if cgCursorIsVisible != nil {
		visible = cgCursorIsVisible()
	}

	return &CursorData{
		X:       int32(loc.X),
		Y:       int32(loc.Y),
		HotX:    int32(hot.X),
		HotY:    int32(hot.Y),
		Width:   int32(width),
		Height:  int32(height),
		Visible: visible,
	}, rgba, nil
}
