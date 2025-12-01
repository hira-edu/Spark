package common

import (
	"Spark/modules"
	"Spark/utils/cmap"
	"Spark/utils/melody"
	"time"
)

type EventCallback func(modules.Packet, *melody.Session)
type event struct {
	connection string
	callback   EventCallback
	finish     chan bool
	remove     chan bool
}

var events = cmap.New[*event]()

// CallEvent tries to call the callback with the given uuid
// after that, it will notify the caller via the channel
func CallEvent(pack modules.Packet, session *melody.Session) {
	if len(pack.Event) == 0 {
		return
	}
	ev, ok := events.Get(pack.Event)
	if !ok {
		Debug(session, `EVENT_CALL`, `miss`, `event not found`, map[string]any{
			`event`:  pack.Event,
			`action`: pack.Act,
		})
		return
	}
	if session != nil && session.UUID != ev.connection {
		Debug(session, `EVENT_CALL`, `skip`, `session mismatch`, map[string]any{
			`event`:        pack.Event,
			`action`:       pack.Act,
			`sessionUUID`:  session.UUID[:8] + `...`,
			`expectedUUID`: ev.connection[:8] + `...`,
		})
		return
	}
	ev.callback(pack, session)
	if ev.finish != nil {
		ev.finish <- true
	}
	Debug(session, `EVENT_CALL`, `success`, ``, map[string]any{
		`event`:  pack.Event,
		`action`: pack.Act,
	})
}

// AddEventOnce adds a new event only once and client
// can call back the event with the given event trigger.
// Event trigger should be uuid to make every event unique.
func AddEventOnce(fn EventCallback, connUUID, trigger string, timeout time.Duration) bool {
	ev := &event{
		connection: connUUID,
		callback:   fn,
		finish:     make(chan bool),
		remove:     make(chan bool),
	}
	events.Set(trigger, ev)
	Debug(nil, `EVENT_ADD_ONCE`, ``, ``, map[string]any{
		`event`:      trigger,
		`connUUID`:   connUUID[:8] + `...`,
		`timeout_ms`: timeout.Milliseconds(),
	})
	defer close(ev.remove)
	defer close(ev.finish)
	select {
	case ok := <-ev.finish:
		events.Remove(trigger)
		return ok
	case ok := <-ev.remove:
		events.Remove(trigger)
		return ok
	case <-time.After(timeout):
		events.Remove(trigger)
		return false
	}
}

// AddEvent adds a new event and client can call back
// the event with the given event trigger.
func AddEvent(fn EventCallback, connUUID, trigger string) {
	ev := &event{
		connection: connUUID,
		callback:   fn,
	}
	events.Set(trigger, ev)
	Debug(nil, `EVENT_ADD`, ``, ``, map[string]any{
		`event`:    trigger,
		`connUUID`: connUUID[:8] + `...`,
	})
}

// RemoveEvent deletes the event with the given event trigger.
// The ok will be returned to caller if the event is temp (only once).
func RemoveEvent(trigger string, ok ...bool) {
	ev, found := events.Get(trigger)
	if !found {
		return
	}
	events.Remove(trigger)
	if ev.remove != nil {
		if len(ok) > 0 {
			ev.remove <- ok[0]
		} else {
			ev.remove <- false
		}
	}
	ev = nil
}

// HasEvent returns if the event exists.
func HasEvent(trigger string) bool {
	return events.Has(trigger)
}
