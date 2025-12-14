//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var errCaptureEngineTimeout = errors.New("desktop capture engine timeout")

type captureEngineResult struct {
	frame *CaptureFrame
	err   error
}

var (
	captureEngineGen           atomic.Uint64
	captureEngineStarts        atomic.Uint64
	captureEngineStops         atomic.Uint64
	captureEngineLastGen       atomic.Uint64
	captureEngineLastOverride  atomic.Value // string
	captureEngineInitStartUnix atomic.Int64
	captureEngineInitEndUnix   atomic.Int64
	captureEngineInitDone      atomic.Bool
	captureEngineCaptureCalls  atomic.Uint64
	captureEngineReqEnqueued   atomic.Uint64
	captureEngineReqReceived   atomic.Uint64
	captureEngineRespSent      atomic.Uint64
	captureEngineLastCallUnix  atomic.Int64
	captureEngineLastReqUnix   atomic.Int64
	captureEngineLastRespUnix  atomic.Int64
	captureEngineLastTimeouts  atomic.Uint64
	captureEngineLastError     atomic.Value // string
)

// desktopCaptureEngine runs desktop capture on a dedicated OS thread (Windows),
// and communicates with the main worker via channels. If the capture backend
// hangs in Init/Capture, the worker can time out and rotate to a new engine.
type desktopCaptureEngine struct {
	displayIndex uint
	rect         image.Rectangle
	override     CaptureBackendMode
	gen          uint64

	reqCh  chan struct{}
	respCh chan captureEngineResult

	stopCh   chan struct{}
	stopOnce sync.Once
}

func newDesktopCaptureEngine(displayIndex uint, rect image.Rectangle, override CaptureBackendMode) *desktopCaptureEngine {
	gen := captureEngineGen.Add(1)
	captureEngineStarts.Add(1)
	captureEngineLastGen.Store(gen)
	captureEngineLastOverride.Store(captureBackendName(override))

	e := &desktopCaptureEngine{
		displayIndex: displayIndex,
		rect:         rect,
		override:     override,
		gen:          gen,
		reqCh:        make(chan struct{}, 1),
		respCh:       make(chan captureEngineResult, 1),
		stopCh:       make(chan struct{}),
	}
	go e.run()
	return e
}

func (e *desktopCaptureEngine) run() {
	defer func() {
		if r := recover(); r != nil {
			captureEngineLastError.Store(fmt.Sprintf("panic: %v", r))
			// Best-effort: stop the engine so the worker can restart cleanly.
			e.Stop()
		}
	}()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	captureEngineInitDone.Store(false)
	captureEngineInitStartUnix.Store(time.Now().UnixNano())
	captureEngineInitEndUnix.Store(0)
	captureEngineLastError.Store("")

	var screen Screen
	screen.overrideBackend = e.override
	screen.Init(e.displayIndex, e.rect)
	captureEngineInitEndUnix.Store(time.Now().UnixNano())
	captureEngineInitDone.Store(true)
	defer screen.Release()

	for {
		select {
		case <-e.stopCh:
			return
		case <-e.reqCh:
			captureEngineReqReceived.Add(1)
			captureEngineLastReqUnix.Store(time.Now().UnixNano())
			frame, err := screen.Capture()
			if err != nil && err != errNoImage {
				captureEngineLastError.Store(err.Error())
			}
			res := captureEngineResult{frame: frame, err: err}

			// Non-blocking send: keep the newest result.
			select {
			case e.respCh <- res:
				captureEngineRespSent.Add(1)
				captureEngineLastRespUnix.Store(time.Now().UnixNano())
			default:
				select {
				case <-e.respCh:
				default:
				}
				select {
				case e.respCh <- res:
					captureEngineRespSent.Add(1)
					captureEngineLastRespUnix.Store(time.Now().UnixNano())
				default:
				}
			}
		}
	}
}

func (e *desktopCaptureEngine) Stop() {
	if e == nil {
		return
	}
	e.stopOnce.Do(func() {
		captureEngineStops.Add(1)
		close(e.stopCh)
	})
}

func (e *desktopCaptureEngine) Capture(timeout time.Duration) (*CaptureFrame, error) {
	if e == nil {
		return nil, errCaptureEngineTimeout
	}

	captureEngineCaptureCalls.Add(1)
	captureEngineLastCallUnix.Store(time.Now().UnixNano())

	// Ensure at most one pending request.
	select {
	case e.reqCh <- struct{}{}:
		captureEngineReqEnqueued.Add(1)
	default:
	}

	select {
	case res := <-e.respCh:
		return res.frame, res.err
	case <-time.After(timeout):
		captureEngineLastTimeouts.Add(1)
		return nil, errCaptureEngineTimeout
	case <-e.stopCh:
		return nil, errCaptureEngineTimeout
	}
}

func CaptureEngineStats() map[string]any {
	stats := map[string]any{
		"engine_starts_total":      captureEngineStarts.Load(),
		"engine_stops_total":       captureEngineStops.Load(),
		"engine_last_gen":          captureEngineLastGen.Load(),
		"engine_override":          "unknown",
		"engine_init_done":         captureEngineInitDone.Load(),
		"engine_capture_calls":     captureEngineCaptureCalls.Load(),
		"engine_req_enqueued":      captureEngineReqEnqueued.Load(),
		"engine_req_received":      captureEngineReqReceived.Load(),
		"engine_resp_sent":         captureEngineRespSent.Load(),
		"engine_timeouts_total":    captureEngineLastTimeouts.Load(),
		"engine_init_start_unixns": captureEngineInitStartUnix.Load(),
		"engine_init_end_unixns":   captureEngineInitEndUnix.Load(),
	}

	now := time.Now().UnixNano()
	if ts := captureEngineLastCallUnix.Load(); ts > 0 && now >= ts {
		stats["last_capture_call_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := captureEngineLastReqUnix.Load(); ts > 0 && now >= ts {
		stats["last_req_received_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := captureEngineLastRespUnix.Load(); ts > 0 && now >= ts {
		stats["last_resp_sent_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := captureEngineInitStartUnix.Load(); ts > 0 && now >= ts {
		stats["init_start_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if ts := captureEngineInitEndUnix.Load(); ts > 0 && now >= ts {
		stats["init_end_age_ms"] = (now - ts) / int64(time.Millisecond)
	}
	if v := captureEngineLastOverride.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["engine_override"] = s
		}
	}
	if v := captureEngineLastError.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			stats["engine_last_error"] = s
		}
	}
	return stats
}
