// Package utility provides rate limiting for input events.
// Based on industry best practices from RustDesk, Guacamole, and noVNC.
//
// Security Purpose:
// - Prevents input flooding attacks (DoS via mouse move spam)
// - Rate limits clipboard operations (prevent data exfiltration)
// - Throttles keyboard events (prevent macro attacks)
//
// Design:
// - Token bucket algorithm for smooth rate limiting
// - Per-session limits (one client can't affect others)
// - Different limits per input type (mouse more lenient than clipboard)
package utility

import (
	"sync"
	"sync/atomic"
	"time"
)

// Rate limit constants (based on human input speeds + margin)
const (
	// Mouse: ~120 events/sec max (gaming mouse polling rate ~1000Hz, but we batch)
	MouseRateLimit     = 120
	MouseBurstCapacity = 60 // Allow burst of 60 events

	// Keyboard: ~40 events/sec max (fast typing ~100wpm = ~8 chars/sec, with key up/down)
	KeyboardRateLimit     = 40
	KeyboardBurstCapacity = 30

	// Clipboard: 1 operation per 500ms (prevent rapid paste attacks)
	ClipboardRateLimit     = 2
	ClipboardBurstCapacity = 2

	// Scroll: ~30 events/sec max
	ScrollRateLimit     = 30
	ScrollBurstCapacity = 20

	// File drop: 1 per second (prevent spam)
	FileDropRateLimit     = 1
	FileDropBurstCapacity = 3

	// Default bucket refill interval
	RefillInterval = 100 * time.Millisecond
)

// InputType categorizes input events for rate limiting
type InputType int

const (
	InputTypeMouse InputType = iota
	InputTypeKeyboard
	InputTypeClipboard
	InputTypeScroll
	InputTypeFileDrop
)

// TokenBucket implements the token bucket algorithm for rate limiting.
// Thread-safe for concurrent access.
type TokenBucket struct {
	tokens     atomic.Int64
	capacity   int64
	refillRate int64 // tokens per second
	lastRefill atomic.Int64
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket.
// capacity: maximum tokens (burst capacity)
// ratePerSecond: tokens added per second
func NewTokenBucket(capacity, ratePerSecond int64) *TokenBucket {
	tb := &TokenBucket{
		capacity:   capacity,
		refillRate: ratePerSecond,
	}
	tb.tokens.Store(capacity)
	tb.lastRefill.Store(time.Now().UnixNano())
	return tb
}

// TryConsume attempts to consume n tokens.
// Returns true if tokens were available, false if rate limited.
func (tb *TokenBucket) TryConsume(n int64) bool {
	tb.refill()

	for {
		current := tb.tokens.Load()
		if current < n {
			return false
		}
		if tb.tokens.CompareAndSwap(current, current-n) {
			return true
		}
	}
}

// refill adds tokens based on elapsed time
func (tb *TokenBucket) refill() {
	now := time.Now().UnixNano()
	last := tb.lastRefill.Load()
	elapsed := now - last

	// Calculate tokens to add
	tokensToAdd := (elapsed * tb.refillRate) / int64(time.Second)
	if tokensToAdd <= 0 {
		return
	}

	// Try to update lastRefill atomically
	if !tb.lastRefill.CompareAndSwap(last, now) {
		return // Another goroutine updated it
	}

	// Add tokens up to capacity
	for {
		current := tb.tokens.Load()
		newTokens := current + tokensToAdd
		if newTokens > tb.capacity {
			newTokens = tb.capacity
		}
		if tb.tokens.CompareAndSwap(current, newTokens) {
			return
		}
	}
}

// Available returns current token count
func (tb *TokenBucket) Available() int64 {
	tb.refill()
	return tb.tokens.Load()
}

// InputRateLimiter manages rate limits for all input types per session.
type InputRateLimiter struct {
	buckets map[InputType]*TokenBucket
	stats   struct {
		allowed atomic.Uint64
		denied  atomic.Uint64
	}
}

// NewInputRateLimiter creates a rate limiter with default limits.
func NewInputRateLimiter() *InputRateLimiter {
	return &InputRateLimiter{
		buckets: map[InputType]*TokenBucket{
			InputTypeMouse:    NewTokenBucket(MouseBurstCapacity, MouseRateLimit),
			InputTypeKeyboard: NewTokenBucket(KeyboardBurstCapacity, KeyboardRateLimit),
			InputTypeClipboard: NewTokenBucket(ClipboardBurstCapacity, ClipboardRateLimit),
			InputTypeScroll:   NewTokenBucket(ScrollBurstCapacity, ScrollRateLimit),
			InputTypeFileDrop: NewTokenBucket(FileDropBurstCapacity, FileDropRateLimit),
		},
	}
}

// Allow checks if an input event should be allowed.
// eventCount: number of events to consume (usually 1, can be batch size)
func (rl *InputRateLimiter) Allow(inputType InputType, eventCount int64) bool {
	bucket, ok := rl.buckets[inputType]
	if !ok {
		// Unknown input type, allow but log
		rl.stats.allowed.Add(1)
		return true
	}

	if bucket.TryConsume(eventCount) {
		rl.stats.allowed.Add(uint64(eventCount))
		return true
	}

	rl.stats.denied.Add(uint64(eventCount))
	return false
}

// AllowMouse checks if mouse events should be allowed
func (rl *InputRateLimiter) AllowMouse(count int64) bool {
	return rl.Allow(InputTypeMouse, count)
}

// AllowKeyboard checks if keyboard events should be allowed
func (rl *InputRateLimiter) AllowKeyboard(count int64) bool {
	return rl.Allow(InputTypeKeyboard, count)
}

// AllowClipboard checks if clipboard operations should be allowed
func (rl *InputRateLimiter) AllowClipboard() bool {
	return rl.Allow(InputTypeClipboard, 1)
}

// AllowScroll checks if scroll events should be allowed
func (rl *InputRateLimiter) AllowScroll(count int64) bool {
	return rl.Allow(InputTypeScroll, count)
}

// AllowFileDrop checks if file drop should be allowed
func (rl *InputRateLimiter) AllowFileDrop() bool {
	return rl.Allow(InputTypeFileDrop, 1)
}

// Stats returns rate limiter statistics
func (rl *InputRateLimiter) Stats() (allowed, denied uint64) {
	return rl.stats.allowed.Load(), rl.stats.denied.Load()
}

// SessionRateLimitManager manages rate limiters per session ID.
// Thread-safe for concurrent access.
type SessionRateLimitManager struct {
	limiters sync.Map // map[string]*InputRateLimiter
}

// Global session rate limit manager
var globalRateLimitManager = &SessionRateLimitManager{}

// GetSessionRateLimiter returns the rate limiter for a session.
func GetSessionRateLimiter(sessionID string) *InputRateLimiter {
	return globalRateLimitManager.Get(sessionID)
}

// Get returns or creates a rate limiter for a session
func (m *SessionRateLimitManager) Get(sessionID string) *InputRateLimiter {
	if rl, ok := m.limiters.Load(sessionID); ok {
		return rl.(*InputRateLimiter)
	}

	rl := NewInputRateLimiter()
	actual, _ := m.limiters.LoadOrStore(sessionID, rl)
	return actual.(*InputRateLimiter)
}

// Remove deletes a session's rate limiter
func (m *SessionRateLimitManager) Remove(sessionID string) {
	m.limiters.Delete(sessionID)
}

// Cleanup removes stale sessions (call periodically)
func (m *SessionRateLimitManager) Cleanup() {
	// In production, implement LRU eviction based on activity
	// For now, this is a no-op placeholder
}

// ValidateInputBatch validates and rate-limits an input event batch.
// Returns the events that passed rate limiting, and count of dropped events.
func ValidateInputBatch(sessionID string, events []map[string]interface{}) (allowed []map[string]interface{}, dropped int) {
	if len(events) == 0 {
		return nil, 0
	}

	rl := GetSessionRateLimiter(sessionID)
	allowed = make([]map[string]interface{}, 0, len(events))

	// Count events by type
	var mouseCount, keyCount, scrollCount int64

	for _, event := range events {
		eventType, ok := event["type"].(string)
		if !ok {
			dropped++
			continue
		}

		switch eventType {
		case "mousemove", "mousedown", "mouseup", "click", "dblclick":
			mouseCount++
		case "keydown", "keyup", "keypress":
			keyCount++
		case "scroll", "wheel":
			scrollCount++
		case "clipboard":
			if rl.AllowClipboard() {
				allowed = append(allowed, event)
			} else {
				dropped++
			}
			continue
		case "filedrop":
			if rl.AllowFileDrop() {
				allowed = append(allowed, event)
			} else {
				dropped++
			}
			continue
		default:
			// Unknown event type, pass through
			allowed = append(allowed, event)
			continue
		}
	}

	// Check rate limits for batched events
	if mouseCount > 0 && rl.AllowMouse(mouseCount) {
		for _, event := range events {
			if t, ok := event["type"].(string); ok {
				switch t {
				case "mousemove", "mousedown", "mouseup", "click", "dblclick":
					allowed = append(allowed, event)
				}
			}
		}
	} else if mouseCount > 0 {
		dropped += int(mouseCount)
	}

	if keyCount > 0 && rl.AllowKeyboard(keyCount) {
		for _, event := range events {
			if t, ok := event["type"].(string); ok {
				switch t {
				case "keydown", "keyup", "keypress":
					allowed = append(allowed, event)
				}
			}
		}
	} else if keyCount > 0 {
		dropped += int(keyCount)
	}

	if scrollCount > 0 && rl.AllowScroll(scrollCount) {
		for _, event := range events {
			if t, ok := event["type"].(string); ok {
				switch t {
				case "scroll", "wheel":
					allowed = append(allowed, event)
				}
			}
		}
	} else if scrollCount > 0 {
		dropped += int(scrollCount)
	}

	return allowed, dropped
}
