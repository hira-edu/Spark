//go:build windows
// +build windows

package main

import (
	"golang.org/x/sys/windows"
)

// maybeHideConsole detaches the console window for silent/background runs.
// We keep it visible for explicit console/debug modes.
func maybeHideConsole(args []string) {
	// Leave console intact when user explicitly requested console/debug.
	for _, arg := range args[1:] {
		if arg == "--console" || arg == "--debug" {
			return
		}
	}
	// FreeConsole closes the attached console so scheduled-task / run-key launches stay silent.
	// windows.FreeConsole is not exposed; call via syscall.
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	freeConsole := kernel32.NewProc("FreeConsole")
	_, _, _ = freeConsole.Call()
}
