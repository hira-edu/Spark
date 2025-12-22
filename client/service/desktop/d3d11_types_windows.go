//go:build windows

package desktop

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hresultError converts an HRESULT to a Go error.
// Returns nil if HRESULT indicates success (S_OK or S_FALSE).
func hresultError(hr uintptr, context string) error {
	if hr == 0 || hr == 1 { // S_OK or S_FALSE
		return nil
	}
	if context == "" {
		return fmt.Errorf("HRESULT 0x%08X", hr)
	}
	return fmt.Errorf("%s: HRESULT 0x%08X", context, hr)
}

// mfError wraps a Media Foundation HRESULT error code.
type mfError struct {
	hr      uintptr
	context string
}

func (e mfError) Error() string {
	if e.context == "" {
		return fmt.Sprintf("MF HRESULT 0x%08X", e.hr)
	}
	return fmt.Sprintf("%s: MF HRESULT 0x%08X", e.context, e.hr)
}

// parseGUID parses a GUID string (without braces) into a windows.GUID.
func parseGUID(s string) (windows.GUID, error) {
	// Add braces for windows.GUIDFromString which expects {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
	return windows.GUIDFromString("{" + s + "}")
}

// envIsTruthy checks if an environment variable is set to a truthy value.
func envIsTruthy(name string) bool {
	val := os.Getenv(name)
	if val == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

// iDXGISurface represents IDXGISurface COM interface
type iDXGISurface struct {
	vtbl *iDXGISurfaceVtbl
}

type iDXGISurfaceVtbl struct {
	QueryInterface          uintptr
	AddRef                  uintptr
	Release                 uintptr
	SetPrivateData          uintptr
	SetPrivateDataInterface uintptr
	GetPrivateData          uintptr
	GetParent               uintptr
	GetDevice               uintptr
	GetDesc                 uintptr
	Map                     uintptr
	Unmap                   uintptr
}

func (s *iDXGISurface) Release() {
	if s == nil || s.vtbl == nil {
		return
	}
	syscall.SyscallN(s.vtbl.Release, uintptr(unsafe.Pointer(s)))
}

// imfTransform represents IMFTransform COM interface (minimal definition for codec API)
type imfTransform struct {
	vtbl *imfTransformVtbl
}

type imfTransformVtbl struct {
	QueryInterface            uintptr
	AddRef                    uintptr
	Release                   uintptr
	GetStreamLimits           uintptr
	GetStreamCount            uintptr
	GetStreamIDs              uintptr
	GetInputStreamInfo        uintptr
	GetOutputStreamInfo       uintptr
	GetAttributes             uintptr
	GetInputStreamAttributes  uintptr
	GetOutputStreamAttributes uintptr
	DeleteInputStream         uintptr
	AddInputStreams           uintptr
	GetInputAvailableType     uintptr
	GetOutputAvailableType    uintptr
	SetInputType              uintptr
	SetOutputType             uintptr
	GetInputCurrentType       uintptr
	GetOutputCurrentType      uintptr
	GetInputStatus            uintptr
	GetOutputStatus           uintptr
	SetOutputBounds           uintptr
	ProcessEvent              uintptr
	ProcessMessage            uintptr
	ProcessInput              uintptr
	ProcessOutput             uintptr
}

func (t *imfTransform) Release() {
	if t == nil || t.vtbl == nil {
		return
	}
	syscall.SyscallN(t.vtbl.Release, uintptr(unsafe.Pointer(t)))
}

// ProcessMessage sends a message to the MFT.
func (t *imfTransform) ProcessMessage(msgType uint32, param uintptr) error {
	if t == nil || t.vtbl == nil {
		return fmt.Errorf("nil transform")
	}
	r0, _, _ := syscall.SyscallN(
		t.vtbl.ProcessMessage,
		uintptr(unsafe.Pointer(t)),
		uintptr(msgType),
		param,
	)
	return hresultError(r0, "ProcessMessage")
}
