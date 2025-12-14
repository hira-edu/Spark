package desktop

import (
	"Rocket/utils"
	"os"
	"runtime"
	"time"
)

var (
	processBootID     = utils.GetStrUUID()
	processBootUnixNs = time.Now().UnixNano()
)

func ProcessDiagStats() map[string]any {
	now := time.Now().UnixNano()
	stats := map[string]any{
		"boot_id":       processBootID,
		"boot_unixns":   processBootUnixNs,
		"uptime_ms":     (now - processBootUnixNs) / int64(time.Millisecond),
		"pid":           os.Getpid(),
		"goos":          runtime.GOOS,
		"goarch":        runtime.GOARCH,
		"num_goroutine": runtime.NumGoroutine(),
	}
	if extra := processExtraDiag(); extra != nil {
		for k, v := range extra {
			stats[k] = v
		}
	}
	return stats
}
