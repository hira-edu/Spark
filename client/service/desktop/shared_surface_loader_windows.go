//go:build windows

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// Expected DLL exports (stdcall):
// - SparkCapture_Init(adapterLuidLow uint32, adapterLuidHigh int32) uintptr (returns context handle, 0 on error)
// - SparkCapture_Start(ctx uintptr, target uint32) int32 (0 ok, non-zero error)
// - SparkCapture_NextFrame(ctx uintptr, frame *captureFrame) int32 (0 ok, 1 no frame, <0 error)
// - SparkCapture_Stop(ctx uintptr)
// - SparkCapture_Shutdown(ctx uintptr)

// captureFrame mirrors the structure expected by the DLL.
type captureFrame struct {
	Data   uintptr
	Size   uint32
	Width  uint32
	Height uint32
	Stride uint32
	Format uint32 // reserved; expect BGRA 8-bit
}

type sharedSurfaceModule struct {
	once sync.Once
	err  error
	dll  *syscall.DLL
	api  sharedSurfaceAPI
}

type sharedSurfaceAPI struct {
	initProc      *syscall.Proc
	startProc     *syscall.Proc
	nextFrameProc *syscall.Proc
	stopProc      *syscall.Proc
	shutdownProc  *syscall.Proc
}

var sharedSurface sharedSurfaceModule

func (m *sharedSurfaceModule) loadAndBind() error {
	m.once.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			m.err = err
			return
		}
		path := filepath.Join(filepath.Dir(exe), "spark_capture.dll")
		m.dll, m.err = syscall.LoadDLL(path)
		if m.err != nil {
			m.err = errors.New("shared surface module not found: " + path)
			return
		}
		if m.api.initProc, err = m.dll.FindProc("SparkCapture_Init"); err != nil {
			m.err = err
			return
		}
		if m.api.startProc, err = m.dll.FindProc("SparkCapture_Start"); err != nil {
			m.err = err
			return
		}
		if m.api.nextFrameProc, err = m.dll.FindProc("SparkCapture_NextFrame"); err != nil {
			m.err = err
			return
		}
		if m.api.stopProc, err = m.dll.FindProc("SparkCapture_Stop"); err != nil {
			m.err = err
			return
		}
		if m.api.shutdownProc, err = m.dll.FindProc("SparkCapture_Shutdown"); err != nil {
			m.err = err
			return
		}
	})
	return m.err
}

func (m *sharedSurfaceModule) init(adapterLuid string) (uintptr, error) {
	if m.err != nil || m.api.initProc == nil {
		return 0, errors.New("shared surface module not loaded")
	}
	low, high := splitLuid(adapterLuid)
	handle, _, callErr := m.api.initProc.Call(uintptr(low), uintptr(high))
	if callErr != syscall.Errno(0) {
		return 0, callErr
	}
	if handle == 0 {
		return 0, errors.New("shared surface init failed")
	}
	return handle, nil
}

func (m *sharedSurfaceModule) start(ctx uintptr, target uint32) error {
	if m.api.startProc == nil {
		return errors.New("shared surface module not loaded")
	}
	ret, _, callErr := m.api.startProc.Call(ctx, uintptr(target))
	if callErr != syscall.Errno(0) {
		return callErr
	}
	if ret != 0 {
		return errors.New("shared surface start failed")
	}
	return nil
}

func (m *sharedSurfaceModule) nextFrame(ctx uintptr, frame *captureFrame) (int32, error) {
	if m.api.nextFrameProc == nil {
		return -1, errors.New("shared surface module not loaded")
	}
	ret, _, callErr := m.api.nextFrameProc.Call(ctx, uintptr(unsafe.Pointer(frame)))
	if callErr != syscall.Errno(0) {
		return -1, callErr
	}
	return int32(ret), nil
}

func (m *sharedSurfaceModule) stop(ctx uintptr) {
	if m.api.stopProc != nil {
		m.api.stopProc.Call(ctx)
	}
}

func (m *sharedSurfaceModule) shutdown(ctx uintptr) {
	if m.api.shutdownProc != nil {
		m.api.shutdownProc.Call(ctx)
	}
}

func splitLuid(luid string) (low uint32, high int32) {
	if luid == "" {
		return 0, 0
	}
	parts := strings.Split(luid, "-")
	if len(parts) == 2 {
		if v, err := strconv.ParseUint(parts[0], 16, 32); err == nil {
			low = uint32(v)
		}
		if v, err := strconv.ParseInt(parts[1], 16, 32); err == nil {
			high = int32(v)
		}
	}
	return
}
