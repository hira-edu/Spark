package desktop

import (
	"sync/atomic"
	"time"
)

type desktopWorkerDiag struct {
	startUnixNs atomic.Int64
	stage       atomic.Value // string

	ticksTotal       atomic.Uint64
	lastTickUnixNs   atomic.Int64
	lastSessionsSeen atomic.Int64
	skippedNoSession atomic.Uint64

	captureAttempts     atomic.Uint64
	lastCaptureStartNs  atomic.Int64
	lastCaptureEndNs    atomic.Int64
	lastCaptureErr      atomic.Value // string
	lastCaptureOKUnixNs atomic.Int64
}

func newDesktopWorkerDiag() *desktopWorkerDiag {
	d := &desktopWorkerDiag{}
	d.stage.Store("idle")
	d.lastCaptureErr.Store("")
	return d
}

var workerDiag = newDesktopWorkerDiag()

func (d *desktopWorkerDiag) setStage(stage string) {
	if stage == "" {
		stage = "unknown"
	}
	d.stage.Store(stage)
}

func (d *desktopWorkerDiag) setCaptureErr(err error) {
	if err == nil {
		d.lastCaptureErr.Store("")
		return
	}
	d.lastCaptureErr.Store(err.Error())
}

func WorkerDiagStats() map[string]any {
	now := time.Now().UnixNano()

	stats := map[string]any{
		"stage":              "unknown",
		"start_unixns":       workerDiag.startUnixNs.Load(),
		"ticks_total":        workerDiag.ticksTotal.Load(),
		"capture_attempts":   workerDiag.captureAttempts.Load(),
		"skipped_no_session": workerDiag.skippedNoSession.Load(),
		"last_sessions_seen": workerDiag.lastSessionsSeen.Load(),
	}

	if v := workerDiag.stage.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["stage"] = s
		}
	}
	if v := workerDiag.lastCaptureErr.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["last_capture_error"] = s
		}
	}

	if ts := workerDiag.lastTickUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_tick_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := workerDiag.lastCaptureStartNs.Load(); ts > 0 && now >= ts {
		stats["last_capture_start_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := workerDiag.lastCaptureEndNs.Load(); ts > 0 && now >= ts {
		stats["last_capture_end_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := workerDiag.lastCaptureOKUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_capture_ok_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if start := workerDiag.startUnixNs.Load(); start > 0 && now >= start {
		stats["worker_uptime_ms"] = (now - start) / int64(time.Millisecond)
	}
	return stats
}
