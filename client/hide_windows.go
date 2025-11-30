//go:build windows

package main

import "syscall"

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	freeConsole  = kernel32.NewProc("FreeConsole")
)

func init() {
	// Detach any console quickly to avoid visible flicker when launched directly.
	freeConsole.Call()
}
