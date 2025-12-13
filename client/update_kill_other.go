//go:build !windows

package main

func killProcessesUsingPath(_ string) int {
	return 0
}
