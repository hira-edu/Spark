//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func killProcessesUsingPath(targetPath string) int {
	if targetPath == "" {
		return 0
	}

	targetPath = filepath.Clean(targetPath)
	currentPID := windows.GetCurrentProcessId()

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}

	killed := 0
	for {
		pid := entry.ProcessID
		if pid != 0 && pid != currentPID {
			handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, pid)
			if err == nil {
				buf := make([]uint16, 32768)
				size := uint32(len(buf))
				if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err == nil && size > 0 {
					imagePath := windows.UTF16ToString(buf[:size])
					if strings.EqualFold(filepath.Clean(imagePath), targetPath) {
						if err := windows.TerminateProcess(handle, 1); err == nil {
							killed++
						}
					}
				}
				windows.CloseHandle(handle)
			}
		}

		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	return killed
}
