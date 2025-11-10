//go:build windows

package winsession

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Info describes the Windows session/SID for a process.
type Info struct {
	SessionID uint32
	SID       string
	User      string
}

// QueryProcess returns the session metadata for the provided PID.
func QueryProcess(pid uint32) (Info, error) {
	var info Info
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(pid, &sessionID); err == nil {
		info.SessionID = sessionID
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return info, err
	}
	defer windows.CloseHandle(handle)

	var token windows.Token
	if err = windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err != nil {
		return info, err
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return info, err
	}
	if tokenUser == nil || tokenUser.User.Sid == nil {
		return info, fmt.Errorf("winsession: missing SID for pid %d", pid)
	}
	sid := tokenUser.User.Sid
	info.SID = sidString(sid)
	info.User = lookupAccount(sid)
	return info, nil
}

// QueryCurrentProcess resolves session details for the current process.
func QueryCurrentProcess() (Info, error) {
	return QueryProcess(uint32(windows.GetCurrentProcessId()))
}

func lookupAccount(sid *windows.SID) string {
	if sid == nil {
		return ""
	}
	sidStr := sidString(sid)
	var (
		nameLen   uint32
		domainLen uint32
		sidUse    uint32
	)
	_ = windows.LookupAccountSid(nil, sid, nil, &nameLen, nil, &domainLen, &sidUse)
	if nameLen == 0 || domainLen == 0 {
		return sidStr
	}
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen)
	err := windows.LookupAccountSid(nil, sid, &name[0], &nameLen, &domain[0], &domainLen, &sidUse)
	if err != nil {
		return sidStr
	}
	return fmt.Sprintf("%s\\%s", windows.UTF16ToString(domain), windows.UTF16ToString(name))
}

func sidString(sid *windows.SID) string {
	if sid == nil {
		return ""
	}
	if stringer, ok := interface{}(sid).(interface{ String() string }); ok {
		return stringer.String()
	}
	if stringer, ok := interface{}(sid).(interface{ String() (string, error) }); ok {
		if s, err := stringer.String(); err == nil {
			return s
		}
	}
	var ptr *uint16
	if err := windows.ConvertSidToStringSid(sid, &ptr); err != nil || ptr == nil {
		return ""
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(ptr)))
	return windows.UTF16PtrToString(ptr)
}
