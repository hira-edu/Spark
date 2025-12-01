//go:build windows
// +build windows

package lifecycle

import (
	"github.com/kataras/golog"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceInstalledAndRunning returns true when our service is already installed and running.
// This lets interactive launches skip the install/update flow (and its UAC prompt)
// and instead start the UI-only helper that talks to the running Session 0 service.
func serviceInstalledAndRunning() bool {
	m, err := mgr.Connect()
	if err != nil {
		golog.Warnf("mode: could not connect to SCM: %v", err)
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		golog.Warnf("mode: service query failed: %v", err)
		return false
	}

	switch st.State {
	case svc.Running, svc.StartPending, svc.ContinuePending:
		return true
	default:
		return false
	}
}

// serviceInstalledAnyState returns true if the service entry exists in SCM, regardless of state.
// This is used to avoid repeated UAC prompts on double-click after initial install.
func serviceInstalledAnyState() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return false
	}
	_ = s.Close()
	return true
}
