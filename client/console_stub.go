//go:build !windows
// +build !windows

package main

func maybeHideConsole(args []string) {
	// no-op on non-Windows
}
