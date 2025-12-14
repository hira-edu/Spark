//go:build windows

package desktop

import (
	"errors"
	"image"
	"runtime"
	"sync"
	"time"
)

var errCaptureEngineTimeout = errors.New("desktop capture engine timeout")

type captureEngineResult struct {
	frame *CaptureFrame
	err   error
}

// desktopCaptureEngine runs desktop capture on a dedicated OS thread (Windows),
// and communicates with the main worker via channels. If the capture backend
// hangs in Init/Capture, the worker can time out and rotate to a new engine.
type desktopCaptureEngine struct {
	displayIndex uint
	rect         image.Rectangle
	override     CaptureBackendMode

	reqCh  chan struct{}
	respCh chan captureEngineResult

	stopCh   chan struct{}
	stopOnce sync.Once
}

func newDesktopCaptureEngine(displayIndex uint, rect image.Rectangle, override CaptureBackendMode) *desktopCaptureEngine {
	e := &desktopCaptureEngine{
		displayIndex: displayIndex,
		rect:         rect,
		override:     override,
		reqCh:        make(chan struct{}, 1),
		respCh:       make(chan captureEngineResult, 1),
		stopCh:       make(chan struct{}),
	}
	go e.run()
	return e
}

func (e *desktopCaptureEngine) run() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var screen Screen
	screen.overrideBackend = e.override
	screen.Init(e.displayIndex, e.rect)
	defer screen.Release()

	for {
		select {
		case <-e.stopCh:
			return
		case <-e.reqCh:
			frame, err := screen.Capture()
			res := captureEngineResult{frame: frame, err: err}

			// Non-blocking send: keep the newest result.
			select {
			case e.respCh <- res:
			default:
				select {
				case <-e.respCh:
				default:
				}
				select {
				case e.respCh <- res:
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
		close(e.stopCh)
	})
}

func (e *desktopCaptureEngine) Capture(timeout time.Duration) (*CaptureFrame, error) {
	if e == nil {
		return nil, errCaptureEngineTimeout
	}

	// Ensure at most one pending request.
	select {
	case e.reqCh <- struct{}{}:
	default:
	}

	select {
	case res := <-e.respCh:
		return res.frame, res.err
	case <-time.After(timeout):
		return nil, errCaptureEngineTimeout
	case <-e.stopCh:
		return nil, errCaptureEngineTimeout
	}
}
