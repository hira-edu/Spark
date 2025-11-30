package desktop

import (
	"Spark/modules"
	"Spark/utils"
	"encoding/json"
	"errors"
	"image"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
)

const (
	inputBatchLimit   = 32
	inputRatePerSec   = 60
	scrollStepDivisor = 40
	scrollCap         = 1200
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
	desktopIDVal, ok := pack.GetData(`desktop`, reflect.String)
	if !ok {
		return errInputInvalid
	}
	session, ok := sessions.Get(desktopIDVal.(string))
	if !ok || session.escape {
		return errInputSessionGone
	}
	bounds := displayBounds
	if bounds.Dx() == 0 || bounds.Dy() == 0 {
		return errNoImage
	}

	events, err := parseInputEvents(pack.Data[`events`])
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	if shouldThrottleBatch() {
		return nil
	}

	for _, event := range events {
		if err := applyInputEvent(event, bounds); err != nil {
			return err
		}
	}
	session.lastPack = utils.Unix
	return nil
}

func parseInputEvents(raw any) ([]inputEvent, error) {
	if raw == nil {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok {
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
		dx := normalizeScroll(event.DeltaX)
		dy := normalizeScroll(event.DeltaY)
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

func shouldThrottleBatch() bool {
	now := time.Now().Unix()
	window := inputWindowSecond.Load()
	if window != now {
		inputWindowSecond.Store(now)
		inputWindowCount.Store(0)
	}
	return inputWindowCount.Add(1) > inputRatePerSec
}

func normalizeScroll(delta int) int {
	if delta == 0 {
		return 0
	}
	if delta > scrollCap {
		delta = scrollCap
	} else if delta < -scrollCap {
		delta = -scrollCap
	}
	step := delta / scrollStepDivisor
	if step == 0 {
		step = sign(delta)
	}
	return step
}

func mapKey(code int, key string) string {
	key = strings.ToLower(key)
	specialKeys := map[int]string{
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
		93:  `cmd`,
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
	if mapped, ok := specialKeys[code]; ok {
		return mapped
	}
	switch key {
	case `contextmenu`:
		return `cmd`
	case `meta`:
		return `cmd`
	}
	if len(key) == 1 {
		return key
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func sign(x int) int {
	if x < 0 {
		return -1
	}
	return 1
}
