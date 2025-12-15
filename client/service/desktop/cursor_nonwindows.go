//go:build !windows

package desktop

import (
	"Rocket/client/telemetry"
	"Rocket/modules"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"image"
	"runtime"
	"sync/atomic"
	"time"
)

// cursorSessionState holds per-session cursor capture state.
type cursorSessionState struct {
	active      atomic.Bool
	lastHash    uint32
	lastVisible bool
	lastX       int32
	lastY       int32
}

func newCursorSessionState() *cursorSessionState { return &cursorSessionState{} }

// CursorData represents cursor information to send to web client.
type CursorData struct {
	X       int32  `json:"x"`
	Y       int32  `json:"y"`
	HotX    int32  `json:"hotX"`
	HotY    int32  `json:"hotY"`
	Width   int32  `json:"width"`
	Height  int32  `json:"height"`
	Visible bool   `json:"visible"`
	Data    string `json:"data"` // base64 RGBA bitmap
	Hash    uint32 `json:"hash"`
	Format  string `json:"format,omitempty"`
}

// StartCursorCapture starts the cursor capture loop (30Hz) for a session.
func StartCursorCapture(rawEvent []byte) {
	eventHex := ""
	if len(rawEvent) > 0 {
		eventHex = hex.EncodeToString(rawEvent)
	}

	sess, ok := sessions.Get(eventHex)
	if !ok {
		// Fallback: find any active session.
		sessions.IterCb(func(key string, s *session) bool {
			if !s.escape.Load() {
				sess = s
				return false
			}
			return true
		})
	}

	if sess == nil {
		telemetry.LogStructured("WARN", "cursor: no session found for capture", map[string]interface{}{
			"platform": runtime.GOOS,
		})
		return
	}

	if sess.cursorState == nil {
		sess.cursorState = newCursorSessionState()
	}

	if !sess.cursorState.active.CompareAndSwap(false, true) {
		return
	}

	// Reset cache so the first frame of a new session is always sent.
	sess.cursorState.lastHash = 0
	sess.cursorState.lastVisible = false
	sess.cursorState.lastX = 0
	sess.cursorState.lastY = 0

	go cursorCaptureLoop(rawEvent, sess.cursorState)
}

// StopCursorCapture stops the cursor capture loop for all sessions.
func StopCursorCapture() {
	sessions.IterCb(func(key string, s *session) bool {
		if s.cursorState != nil {
			s.cursorState.active.Store(false)
		}
		return true
	})
}

func cursorCaptureLoop(rawEvent []byte, state *cursorSessionState) {
	if state == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			state.active.Store(false)
			telemetry.LogStructured("ERROR", "cursor: capture loop panic recovered", map[string]interface{}{
				"panic":    fmt.Sprintf("%v", r),
				"platform": runtime.GOOS,
			})
		}
	}()

	ticker := time.NewTicker(time.Second / 30)
	defer ticker.Stop()

	for state.active.Load() {
		<-ticker.C

		cursor, err := captureCursor()
		if err != nil || cursor == nil {
			continue
		}

		if cursor.Hash == state.lastHash &&
			cursor.Visible == state.lastVisible &&
			cursor.X == state.lastX &&
			cursor.Y == state.lastY {
			continue
		}

		state.lastHash = cursor.Hash
		state.lastVisible = cursor.Visible
		state.lastX = cursor.X
		state.lastY = cursor.Y

		sendDesktopPacket(modules.Packet{
			Act: "CURSOR_UPDATE",
			Data: map[string]any{
				"x":       cursor.X,
				"y":       cursor.Y,
				"hotX":    cursor.HotX,
				"hotY":    cursor.HotY,
				"width":   cursor.Width,
				"height":  cursor.Height,
				"visible": cursor.Visible,
				"data":    cursor.Data,
				"hash":    cursor.Hash,
				"format":  cursor.Format,
			},
		}, rawEvent)
	}
}

func captureCursor() (*CursorData, error) {
	cursor, rgba, err := captureCursorPlatform()
	if err != nil || cursor == nil {
		return nil, err
	}

	if rgba != nil && len(rgba) > 0 {
		cursor.Hash = crc32.ChecksumIEEE(rgba)
		cursor.Data = base64.StdEncoding.EncodeToString(rgba)
		cursor.Format = "rgba"
	}

	// Convert absolute desktop coordinates to coordinates relative to the captured display.
	boundsVal := displayBounds.Load()
	if boundsVal != nil {
		bounds := boundsVal.(image.Rectangle)
		cursor.X -= int32(bounds.Min.X)
		cursor.Y -= int32(bounds.Min.Y)
	}

	return cursor, nil
}
