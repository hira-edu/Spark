package desktop

import (
	"sync"
	"sync/atomic"
	"time"
)

// bridgeSupervisorDiag stores lightweight service-side diagnostics about the UI bridge
// process lifecycle (launch/exit/terminate). This helps debug "0 FPS / black screen"
// issues caused by repeated UI restarts in Session 0 + IPC relay mode.
type bridgeSupervisorDiag struct {
	lastEnsureUnixNs atomic.Int64
	ensureCount      atomic.Uint64
	lastEnsureReason atomic.Value // string

	lastLaunchUnixNs atomic.Int64
	lastLaunchPID    atomic.Uint32
	launchCount      atomic.Uint64

	lastExitUnixNs      atomic.Int64
	lastExitPID         atomic.Uint32
	lastExitCode        atomic.Uint32
	lastExitRuntimeMs   atomic.Int64
	exitCount           atomic.Uint64
	lastExitWasClean    atomic.Bool
	lastExitReason      atomic.Value // string
	lastTerminateUnixNs atomic.Int64
	lastTerminatePID    atomic.Uint32
	terminateCount      atomic.Uint64
	lastTerminateReason atomic.Value // string
}

func newBridgeSupervisorDiag() *bridgeSupervisorDiag {
	d := &bridgeSupervisorDiag{}
	d.lastEnsureReason.Store("")
	d.lastExitReason.Store("")
	d.lastTerminateReason.Store("")
	return d
}

var bridgeSupervisorBySession sync.Map // map[uint32]*bridgeSupervisorDiag

func supervisorDiagForSession(sessionID uint32) *bridgeSupervisorDiag {
	if v, ok := bridgeSupervisorBySession.Load(sessionID); ok {
		if d, ok := v.(*bridgeSupervisorDiag); ok && d != nil {
			return d
		}
	}
	d := newBridgeSupervisorDiag()
	actual, _ := bridgeSupervisorBySession.LoadOrStore(sessionID, d)
	if out, ok := actual.(*bridgeSupervisorDiag); ok && out != nil {
		return out
	}
	return d
}

// RecordBridgeEnsure records a service-side "ensure bridge" request.
func RecordBridgeEnsure(sessionID uint32, reason string) {
	d := supervisorDiagForSession(sessionID)
	d.ensureCount.Add(1)
	d.lastEnsureUnixNs.Store(time.Now().UnixNano())
	if reason == "" {
		reason = "unknown"
	}
	d.lastEnsureReason.Store(reason)
}

// RecordBridgeLaunch records that the service launched a UI bridge process.
func RecordBridgeLaunch(sessionID uint32, pid uint32) {
	d := supervisorDiagForSession(sessionID)
	d.launchCount.Add(1)
	d.lastLaunchUnixNs.Store(time.Now().UnixNano())
	d.lastLaunchPID.Store(pid)
}

// RecordBridgeExit records that a UI bridge process exited.
func RecordBridgeExit(sessionID uint32, pid uint32, exitCode uint32, runtime time.Duration) {
	d := supervisorDiagForSession(sessionID)
	d.exitCount.Add(1)
	d.lastExitUnixNs.Store(time.Now().UnixNano())
	d.lastExitPID.Store(pid)
	d.lastExitCode.Store(exitCode)
	d.lastExitRuntimeMs.Store(runtime.Milliseconds())
	d.lastExitWasClean.Store(exitCode == 0)
}

// RecordBridgeExitReason optionally records a human-readable reason describing why the
// bridge process exited (best-effort, for explicit terminations).
func RecordBridgeExitReason(sessionID uint32, reason string) {
	if reason == "" {
		return
	}
	d := supervisorDiagForSession(sessionID)
	d.lastExitReason.Store(reason)
}

// RecordBridgeTerminate records that the service terminated a UI bridge process.
func RecordBridgeTerminate(sessionID uint32, pid uint32, reason string) {
	d := supervisorDiagForSession(sessionID)
	d.terminateCount.Add(1)
	d.lastTerminateUnixNs.Store(time.Now().UnixNano())
	d.lastTerminatePID.Store(pid)
	if reason == "" {
		reason = "terminate"
	}
	d.lastTerminateReason.Store(reason)
}

// BridgeSupervisorDiag returns a JSON-friendly snapshot of the supervisor state for sessionID.
func BridgeSupervisorDiag(sessionID uint32) map[string]any {
	d := supervisorDiagForSession(sessionID)

	now := time.Now().UnixNano()
	stats := map[string]any{
		"ensure_count":          d.ensureCount.Load(),
		"last_ensure_unixns":    d.lastEnsureUnixNs.Load(),
		"launch_count":          d.launchCount.Load(),
		"last_launch_unixns":    d.lastLaunchUnixNs.Load(),
		"last_launch_pid":       d.lastLaunchPID.Load(),
		"exit_count":            d.exitCount.Load(),
		"last_exit_unixns":      d.lastExitUnixNs.Load(),
		"last_exit_pid":         d.lastExitPID.Load(),
		"last_exit_code":        d.lastExitCode.Load(),
		"last_exit_runtime_ms":  d.lastExitRuntimeMs.Load(),
		"last_exit_was_clean":   d.lastExitWasClean.Load(),
		"terminate_count":       d.terminateCount.Load(),
		"last_terminate_unixns": d.lastTerminateUnixNs.Load(),
		"last_terminate_pid":    d.lastTerminatePID.Load(),
	}

	if v := d.lastEnsureReason.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["last_ensure_reason"] = s
		}
	}
	if v := d.lastExitReason.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["last_exit_reason"] = s
		}
	}
	if v := d.lastTerminateReason.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["last_terminate_reason"] = s
		}
	}

	if ts := d.lastEnsureUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_ensure_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := d.lastLaunchUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_launch_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := d.lastExitUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_exit_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := d.lastTerminateUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_terminate_age_ms"] = (now - ts) / int64(time.Millisecond)
	}

	return stats
}
