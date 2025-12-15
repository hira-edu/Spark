//go:build windows

package main

import (
	"Rocket/client/service/desktop"
	"fmt"
	"image"
	"time"

	"github.com/kbinani/screenshot"
)

type captureCase struct {
	name string
	new  func() desktop.ScreenCapture
}

func main() {
	displayIndex := 0
	bounds := screenshot.GetDisplayBounds(displayIndex)

	// Use full monitor bounds to match the real capture session initialization path.
	rect := bounds
	fmt.Printf("Display=%d Bounds=%s Rect=%s\n", displayIndex, bounds.String(), rect.String())

	cases := []captureCase{
		{name: "dxgi_nv12", new: func() desktop.ScreenCapture { return &desktop.ScreenDXGINV12{} }},
		{name: "dxgi", new: func() desktop.ScreenCapture { return &desktop.ScreenDXGI{} }},
		{name: "gdi", new: func() desktop.ScreenCapture { return &desktop.ScreenGDI{} }},
		{name: "gdi_compat", new: func() desktop.ScreenCapture { return &desktop.ScreenGDICompat{} }},
		{name: "screenshot", new: func() desktop.ScreenCapture { return &desktop.ScreenScreenshot{} }},
		// Optional: shared surface is gated by config; we still exercise Init() to confirm it's either enabled or cleanly skipped.
		{name: "shared_surface", new: func() desktop.ScreenCapture { return &desktop.ScreenSharedSurface{} }},
	}

	var failed bool
	for _, tc := range cases {
		fmt.Printf("\n[%s] Init...\n", tc.name)
		cap := tc.new()
		initStart := time.Now()
		if err := cap.Init(uint(displayIndex), rect); err != nil {
			fmt.Printf("[%s] INIT FAIL: %v\n", tc.name, err)
			// Shared surface is expected to be disabled unless explicitly enabled in config.
			if tc.name == "shared_surface" {
				fmt.Printf("[%s] SKIP (disabled)\n", tc.name)
				continue
			}
			failed = true
			continue
		}
		fmt.Printf("[%s] Init OK (%s)\n", tc.name, time.Since(initStart))

		ok, lastErr := tryCapture(tc.name, cap, rect)
		cap.Release()
		if !ok {
			fmt.Printf("[%s] CAPTURE FAIL: %v\n", tc.name, lastErr)
			failed = true
			continue
		}
		fmt.Printf("[%s] Capture OK\n", tc.name)
	}

	if failed {
		panic("one or more capture backends failed")
	}
}

func tryCapture(name string, cap desktop.ScreenCapture, rect image.Rectangle) (bool, error) {
	deadline := time.Now().Add(2 * time.Second)
	var lastErr error

	for time.Now().Before(deadline) {
		start := time.Now()
		frame, err := cap.Capture()
		dur := time.Since(start)
		if err != nil {
			lastErr = err
			if desktop.IsNoImageError(err) {
				time.Sleep(33 * time.Millisecond)
				continue
			}
			time.Sleep(33 * time.Millisecond)
			continue
		}

		if frame == nil {
			lastErr = fmt.Errorf("nil frame")
			time.Sleep(33 * time.Millisecond)
			continue
		}

		switch name {
		case "dxgi_nv12":
			if frame.GPU == nil || frame.GPU.Backend != "dxgi_nv12" {
				return false, fmt.Errorf("expected GPU NV12 frame, got %+v", frame.GPU)
			}
		default:
			if frame.Image == nil {
				return false, fmt.Errorf("expected CPU image frame")
			}
			if frame.Image.Bounds().Dx() != rect.Dx() || frame.Image.Bounds().Dy() != rect.Dy() {
				return false, fmt.Errorf("unexpected frame bounds: got=%s want=%dx%d", frame.Image.Bounds().String(), rect.Dx(), rect.Dy())
			}
		}

		fmt.Printf("[%s] Capture OK (%s)\n", name, dur)
		return true, nil
	}

	return false, lastErr
}
