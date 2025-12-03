//go:build windows

package lifecycle

import (
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/kardianos/service"
	"github.com/kataras/golog"
	"golang.org/x/sys/windows/svc"
)

var (
	shell32          = syscall.NewLazyDLL("shell32.dll")
	shellExecuteW    = shell32.NewProc("ShellExecuteW")
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	openProcessToken = advapi32.NewProc("OpenProcessToken")
	getTokenInfo     = advapi32.NewProc("GetTokenInformation")
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	getCurrentProc   = kernel32.NewProc("GetCurrentProcess")
)

const (
	tokenQuery      = 0x0008
	tokenElevation  = 20
	swHide          = 0
	swShowNormal    = 1  // SW_SHOWNORMAL - needed for UAC prompt to appear
)

// EnsureElevated relaunches the process with UAC if not running with
// administrative privileges (interactive sessions only).
func EnsureElevated() {
	if os.Getenv("SPARK_SKIP_ELEVATE") == "1" {
		return
	}
	// Always allow elevation so install/update can run (even if a stale service entry exists).
	// Only skip for explicit console/debug/uninstall/ui-only actions.
	for _, arg := range os.Args[1:] {
		if arg == "--console" || arg == "--debug" || arg == "--uninstall" || arg == "--ui-only" {
			return
		}
	}
	if isService, err := svc.IsWindowsService(); err == nil && isService {
		return
	}
	if !service.Interactive() {
		return
	}
	if isProcessElevated() {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	argsPtr, _ := syscall.UTF16PtrFromString(args)

	ret, _, _ := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		0,
		swShowNormal, // Use SW_SHOWNORMAL to ensure UAC prompt appears
	)
	if ret > 32 {
		os.Exit(0)
	} else {
		golog.Errorf("failed to trigger elevation prompt")
	}
}

func isProcessElevated() bool {
	procHandle, _, _ := getCurrentProc.Call()

	var token syscall.Token
	ret, _, err := openProcessToken.Call(
		procHandle,
		uintptr(tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		golog.Errorf("OpenProcessToken failed: %v", err)
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(token))

	var elevation uint32
	var size uint32
	ret, _, err = getTokenInfo.Call(
		uintptr(token),
		uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elevation)),
		4,
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		golog.Errorf("GetTokenInformation failed: %v", err)
		return false
	}
	return elevation != 0
}
