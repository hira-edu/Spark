package desktop

import (
	"Rocket/client/telemetry"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"
)

var (
	panicTotal      atomic.Uint64
	lastPanicUnixNs atomic.Int64
	lastPanicData   atomic.Value // map[string]any
)

func truncateString(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func recordRecoveredPanic(context string, recovered any) {
	count := panicTotal.Add(1)
	now := time.Now().UnixNano()
	lastPanicUnixNs.Store(now)

	panicStr := fmt.Sprintf("%v", recovered)
	stack := string(debug.Stack())

	// Keep the stored payload reasonably small so it can be shipped in DESKTOP_CONFIG_ACK diag.
	payload := map[string]any{
		"count":     count,
		"unixns":    now,
		"context":   context,
		"panic":     truncateString(panicStr, 512),
		"stack":     truncateString(stack, 4096),
		"stack_len": len(stack),
	}
	lastPanicData.Store(payload)

	telemetry.LogStructured("ERROR", "panic recovered", map[string]interface{}{
		"context":   context,
		"panic":     panicStr,
		"stack":     stack,
		"panic_num": count,
	})
}

// LastPanicDiag returns the last recovered panic (if any), with ages for UI debugging.
func LastPanicDiag() map[string]any {
	now := time.Now().UnixNano()
	stats := map[string]any{
		"count_total":       panicTotal.Load(),
		"last_panic_unixns": lastPanicUnixNs.Load(),
	}
	if ts := lastPanicUnixNs.Load(); ts > 0 && now >= ts {
		stats["last_panic_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if v := lastPanicData.Load(); v != nil {
		if m, ok := v.(map[string]any); ok && len(m) > 0 {
			stats["last"] = m
		}
	}
	return stats
}
