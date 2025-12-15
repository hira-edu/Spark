//go:build windows

package desktop

import (
	"errors"
	"testing"
	"time"
)

func TestDXGINV12CapturerCreation(t *testing.T) {
	bounds, err := getDisplayBoundsForMonitor(0)
	if err != nil {
		t.Skip("No active display:", err)
	}
	capturer, err := NewDXGINV12Capturer(0, bounds)
	if err != nil {
		t.Skip("DXGI NV12 capturer unavailable:", err)
	}
	defer capturer.Release()

	if capturer.device == nil {
		t.Fatal("device is nil after creation")
	}
	if capturer.deviceCtx == nil {
		t.Fatal("device context is nil after creation")
	}
	if capturer.videoDevice == nil {
		t.Fatal("video device is nil after creation")
	}
	if capturer.videoContext == nil {
		t.Fatal("video context is nil after creation")
	}
	if capturer.videoProcessor == nil {
		t.Fatal("video processor is nil after creation")
	}
	if capturer.outputDup == nil {
		t.Fatal("output duplication is nil after creation")
	}
}

func TestDXGINV12Capture(t *testing.T) {
	bounds, err := getDisplayBoundsForMonitor(0)
	if err != nil {
		t.Skip("No active display:", err)
	}
	capturer, err := NewDXGINV12Capturer(0, bounds)
	if err != nil {
		t.Skip("DXGI NV12 capturer unavailable:", err)
	}
	defer capturer.Release()

	var frame *CaptureFrame
	maxAttempts := 10
	for i := 0; i < maxAttempts; i++ {
		frame, err = capturer.Capture()
		if err == nil {
			break
		}
		if errors.Is(err, errNoImage) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		t.Fatal("Capture failed:", err)
	}
	if frame == nil {
		t.Skip("No frame captured after", maxAttempts, "attempts")
	}
	defer frame.Close()

	if frame.GPU == nil {
		t.Fatal("frame has no GPU texture")
	}
	if frame.GPU.Backend != "dxgi_nv12" {
		t.Fatalf("unexpected backend: %q", frame.GPU.Backend)
	}
	if frame.GPU.Format != "NV12" {
		t.Fatalf("unexpected format: %q", frame.GPU.Format)
	}
	if frame.GPU.Resource == nil {
		t.Fatal("GPU resource is nil")
	}
}

func TestDXGINV12MultipleCaptures(t *testing.T) {
	bounds, err := getDisplayBoundsForMonitor(0)
	if err != nil {
		t.Skip("No active display:", err)
	}
	capturer, err := NewDXGINV12Capturer(0, bounds)
	if err != nil {
		t.Skip("DXGI NV12 capturer unavailable:", err)
	}
	defer capturer.Release()

	captureCount := 10
	successCount := 0

	for i := 0; i < captureCount; i++ {
		frame, err := capturer.Capture()
		if err != nil {
			if errors.Is(err, errNoImage) {
				time.Sleep(16 * time.Millisecond)
				continue
			}
			t.Logf("Capture %d failed: %v", i, err)
			time.Sleep(16 * time.Millisecond)
			continue
		}
		if frame != nil {
			frame.Close()
			successCount++
		}
		time.Sleep(16 * time.Millisecond)
	}

	if successCount == 0 {
		t.Skip("No successful captures")
	}
}

func TestScreenDXGINV12Wrapper(t *testing.T) {
	bounds, err := getDisplayBoundsForMonitor(0)
	if err != nil {
		t.Skip("No active display:", err)
	}
	screen := &ScreenDXGINV12{}

	if err := screen.Init(0, bounds); err != nil {
		t.Skip("ScreenDXGINV12 unavailable:", err)
	}
	defer screen.Release()

	frame, err := screen.Capture()
	if err != nil && !errors.Is(err, errNoImage) {
		t.Fatal("Capture failed:", err)
	}
	if frame != nil {
		frame.Close()
		if frame.GPU == nil {
			t.Fatal("frame has no GPU texture")
		}
	}

	if screen.GetD3D11Device() == nil {
		t.Fatal("GetD3D11Device returned nil")
	}
	if screen.Stats() == nil {
		t.Fatal("Stats returned nil")
	}
}

func BenchmarkDXGINV12Capture(b *testing.B) {
	bounds, err := getDisplayBoundsForMonitor(0)
	if err != nil {
		b.Skip("No active display:", err)
	}
	capturer, err := NewDXGINV12Capturer(0, bounds)
	if err != nil {
		b.Skip("DXGI NV12 capturer unavailable:", err)
	}
	defer capturer.Release()

	b.ReportAllocs()
	b.ResetTimer()

	successCount := 0
	for i := 0; i < b.N; i++ {
		frame, err := capturer.Capture()
		if err == nil && frame != nil {
			frame.Close()
			successCount++
		}
	}
	b.ReportMetric(float64(successCount)/float64(b.N)*100, "success_%")
}
