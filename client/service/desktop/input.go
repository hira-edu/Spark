package desktop

import (
	"Rocket/client/ipc"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"Rocket/utils"
	"encoding/json"
	"errors"
	"image"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const (
	inputBatchLimit   = 32
	inputRatePerSec   = 1024
	scrollStepDivisor = 120
	scrollCap         = 2400
)

var (
	errInputInvalid     = errors.New(`${i18n|COMMON.INVALID_PARAMETER}`)
	errInputSessionGone = errors.New(`${i18n|DESKTOP.SESSION_CLOSED}`)
	errInputUnsupported = errors.New(`${i18n|DESKTOP.UNSUPPORTED_PLATFORM}`)

	inputWindowSecond atomic.Int64
	inputWindowCount  atomic.Int64
)

type inputEvent struct {
	Type    string
	X       int
	Y       int
	DeltaX  int
	DeltaY  int
	Button  string
	Down    bool
	Key     string
	KeyCode int
}

const (
	inputTypeMove   = `move`
	inputTypeButton = `button`
	inputTypeScroll = `scroll`
	inputTypeKey    = `key`
)

// HandleInput injects desktop input events from the web client.
func HandleInput(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopInput); forwarded {
		return err
	}

	desktopIDVal, ok := pack.GetData(`desktop`, reflect.String)
	if !ok {
		return errInputInvalid
	}
	desktopID := desktopIDVal.(string)
	if pack.Data == nil {
		return errInputInvalid
	}
	session, ok := sessions.Get(desktopID)
	if !ok || session.escape.Load() {
		return errInputSessionGone
	}
	if allow, ok := pack.GetData(`allowControl`, reflect.Bool); ok {
		session.allowControl.Store(allow.(bool))
		if !allow.(bool) {
			return errInputUnsupported
		}
	}
	if !session.allowControl.Load() {
		return errInputUnsupported
	}

	// FIXED: Load displayBounds from atomic.Value (Issue #3)
	boundsVal := displayBounds.Load()
	if boundsVal == nil {
		return errNoImage
	}
	bounds := boundsVal.(image.Rectangle)
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		return errNoImage
	}

	rawEvents, ok := pack.Data[`events`]
	if !ok {
		return errInputInvalid
	}
	events, err := parseInputEvents(rawEvents)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	if shouldThrottleBatch(len(events)) {
		return nil
	}

	var (
		firstErr     error
		successCount int
		failCount    int
	)
	for _, event := range events {
		if err := applyInputEvent(event, bounds); err != nil {
			failCount++
			if firstErr == nil {
				firstErr = err
			}
			telemetry.LogStructured("WARN", "desktop input event failed", map[string]interface{}{
				"desktop": desktopID,
				"type":    event.Type,
				"error":   err.Error(),
			})
			continue
		}
		successCount++
	}
	session.lastPack = utils.Unix
	if failCount > 0 {
		telemetry.LogStructured("WARN", "desktop input batch partially applied", map[string]interface{}{
			"desktop":   desktopID,
			"succeeded": successCount,
			"failed":    failCount,
		})
	}
	if successCount == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}

func parseInputEvents(raw any) ([]inputEvent, error) {
	if raw == nil {
		return nil, nil
	}
	var values []any
	switch v := raw.(type) {
	case []any:
		values = v
	default:
		return nil, errInputInvalid
	}
	if len(values) > inputBatchLimit {
		values = values[:inputBatchLimit]
	}

	result := make([]inputEvent, 0, len(values))
	for _, val := range values {
		if event, ok := parseInputEvent(val); ok {
			result = append(result, event)
		}
	}
	return result, nil
}

func parseInputEvent(raw any) (inputEvent, bool) {
	m, ok := raw.(map[string]any)
	if !ok {
		return inputEvent{}, false
	}

	eventType := strings.ToLower(strFromAny(m[`type`]))
	switch eventType {
	case inputTypeMove, inputTypeButton, inputTypeScroll, inputTypeKey:
	default:
		return inputEvent{}, false
	}

	event := inputEvent{
		Type:   eventType,
		Button: strings.ToLower(strFromAny(m[`button`])),
		Down:   boolFromAny(m[`down`]),
		Key:    strFromAny(m[`key`]),
	}
	event.X, _ = intFromAny(m[`x`])
	event.Y, _ = intFromAny(m[`y`])
	event.DeltaX, _ = intFromAny(m[`deltaX`])
	event.DeltaY, _ = intFromAny(m[`deltaY`])
	event.KeyCode, _ = intFromAny(m[`keyCode`])
	return event, true
}

func applyInputEvent(event inputEvent, bounds image.Rectangle) error {
	switch event.Type {
	case inputTypeMove:
		if event.DeltaX != 0 || event.DeltaY != 0 {
			return movePointerRelative(event.DeltaX, event.DeltaY)
		}
		x := clampToBounds(event.X, bounds.Dx()) + bounds.Min.X
		y := clampToBounds(event.Y, bounds.Dy()) + bounds.Min.Y
		return movePointerAbsolute(x, y)
	case inputTypeButton:
		button := normalizeButton(event.Button)
		if len(button) == 0 {
			button = `left`
		}
		return mouseButton(button, event.Down)
	case inputTypeScroll:
		dx := normalizeScroll(event.DeltaX, false)
		dy := normalizeScroll(event.DeltaY, true)
		if dx == 0 && dy == 0 {
			return nil
		}
		return scrollMouse(dx, dy)
	case inputTypeKey:
		key := mapKey(event.KeyCode, event.Key)
		if len(key) == 0 {
			return nil
		}
		return keyEvent(key, event.Down)
	default:
		return nil
	}
}

// shouldThrottleBatch uses compare-and-swap to safely reset the rate limiter window
func shouldThrottleBatch(count int) bool {
	if count <= 0 {
		return false
	}
	now := time.Now().Unix()
	for {
		window := inputWindowSecond.Load()
		if window == now {
			// Same window, just add the count
			return inputWindowCount.Add(int64(count)) > inputRatePerSec
		}
		// Try to claim the new window atomically
		if inputWindowSecond.CompareAndSwap(window, now) {
			// We claimed the new window, reset count
			inputWindowCount.Store(int64(count))
			return int64(count) > inputRatePerSec
		}
		// Another goroutine claimed it, retry
	}
}

func normalizeScroll(delta int, invert bool) int {
	if delta == 0 {
		return 0
	}
	if invert {
		delta = -delta
	}
	if delta > scrollCap {
		delta = scrollCap
	} else if delta < -scrollCap {
		delta = -scrollCap
	}
	step := delta / scrollStepDivisor
	if step == 0 {
		if delta > 0 {
			step = 1
		} else {
			step = -1
		}
	}
	return step
}

func mapKey(code int, key string) string {
	if mapped, ok := keyCodeMap[code]; ok {
		return mapped
	}

	normalized := normalizeKeyName(key)
	if normalized != `` {
		return normalized
	}

	if code >= 65 && code <= 90 {
		return strings.ToLower(string(rune(code)))
	}
	if len(key) == 1 {
		return strings.ToLower(key)
	}
	return ``
}

var keyCodeMap = map[int]string{
	8:   `backspace`,
	9:   `tab`,
	13:  `enter`,
	16:  `shift`,
	17:  `ctrl`,
	18:  `alt`,
	19:  `pause`,
	20:  `capslock`,
	27:  `escape`,
	32:  `space`,
	33:  `pageup`,
	34:  `pagedown`,
	35:  `end`,
	36:  `home`,
	37:  `left`,
	38:  `up`,
	39:  `right`,
	40:  `down`,
	45:  `insert`,
	46:  `delete`,
	91:  `cmd`,
	92:  `cmd`,
	93:  `menu`,
	112: `f1`,
	113: `f2`,
	114: `f3`,
	115: `f4`,
	116: `f5`,
	117: `f6`,
	118: `f7`,
	119: `f8`,
	120: `f9`,
	121: `f10`,
	122: `f11`,
	123: `f12`,
}

func normalizeKeyName(key string) string {
	if len(key) == 0 {
		return ``
	}
	key = strings.ToLower(key)
	switch key {
	case `escape`, `esc`:
		return `escape`
	case `enter`, `return`:
		return `enter`
	case `backspace`:
		return `backspace`
	case `delete`, `del`:
		return `delete`
	case `tab`:
		return `tab`
	case `control`, `ctrl`:
		return `ctrl`
	case `alt`, `altgraph`:
		return `alt`
	case `meta`, `os`, `super`, `cmd`, `command`:
		return `cmd`
	case `contextmenu`:
		return `menu`
	case `space`, `spacebar`, ` `:
		return `space`
	case `arrowup`:
		return `up`
	case `arrowdown`:
		return `down`
	case `arrowleft`:
		return `left`
	case `arrowright`:
		return `right`
	case `home`:
		return `home`
	case `end`:
		return `end`
	case `pageup`:
		return `pageup`
	case `pagedown`:
		return `pagedown`
	case `capslock`:
		return `capslock`
	case `insert`:
		return `insert`
	}

	if utf8.RuneCountInString(key) == 1 {
		return key
	}
	if len(key) > 1 && key[0] == 'f' {
		if num, err := strconv.Atoi(key[1:]); err == nil && num >= 1 && num <= 24 {
			return key
		}
	}
	return ``
}

func normalizeButton(button string) string {
	switch button {
	case `middle`, `center`, `mouse3`:
		return `center`
	case `right`, `mouse2`:
		return `right`
	case `left`, `mouse1`:
		return `left`
	default:
		return strings.ToLower(button)
	}
}

func clampToBounds(val, limit int) int {
	if limit <= 0 {
		return val
	}
	if val < 0 {
		return 0
	}
	if val >= limit {
		return limit - 1
	}
	return val
}

func intFromAny(val any) (int, bool) {
	switch v := val.(type) {
	case float64:
		return int(v), true
	case float32:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case uint64:
		return int(v), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i), true
		}
	}
	return 0, false
}

func strFromAny(val any) string {
	if str, ok := val.(string); ok {
		return str
	}
	return ``
}

func boolFromAny(val any) bool {
	if b, ok := val.(bool); ok {
		return b
	}
	return false
}
