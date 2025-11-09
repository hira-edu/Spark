//go:build !windows

package winsession

import "fmt"

// Info is a placeholder on non-Windows builds.
type Info struct {
	SessionID uint32
	SID       string
	User      string
}

// QueryProcess is unavailable outside Windows.
func QueryProcess(pid uint32) (Info, error) {
	return Info{}, fmt.Errorf("winsession: unsupported platform")
}

// QueryCurrentProcess is unavailable outside Windows.
func QueryCurrentProcess() (Info, error) {
	return Info{}, fmt.Errorf("winsession: unsupported platform")
}
