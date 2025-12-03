//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	user32DLL      = syscall.NewLazyDLL("user32.dll")
	procMessageBox = user32DLL.NewProc("MessageBoxW")
)

// debugMsgBox shows a Windows MessageBox for debugging startup issues
// Only use this for critical errors that prevent normal operation
func debugMsgBox(title, message string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	msgPtr, _ := syscall.UTF16PtrFromString(message)
	procMessageBox.Call(
		0,
		uintptr(unsafe.Pointer(msgPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		0x00000010, // MB_ICONERROR
	)
}
