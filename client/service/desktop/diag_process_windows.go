//go:build windows

package desktop

import "golang.org/x/sys/windows"

func processExtraDiag() map[string]any {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID); err != nil {
		return map[string]any{
			"process_session_id_error": err.Error(),
		}
	}
	return map[string]any{
		"process_session_id": sessionID,
	}
}
