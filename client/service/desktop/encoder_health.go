package desktop

import (
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"Rocket/client/telemetry"
)

// EncoderState represents the current state of the encoder fallback system.
type EncoderState int32

const (
	// EncoderStateNVENCOK - NVENC is working normally (GPU H.264 encoding)
	EncoderStateNVENCOK EncoderState = iota
	// EncoderStateNVENCFailing - NVENC has intermittent errors, monitoring for fallback
	EncoderStateNVENCFailing
	// EncoderStateVP8 - Fell back to VP8 software encoding (requires SDP renegotiation)
	EncoderStateVP8
	// EncoderStateTiles - Fell back to JPEG tiles over WebSocket/DataChannel
	EncoderStateTiles
)

// String returns a human-readable name for the encoder state.
func (s EncoderState) String() string {
	switch s {
	case EncoderStateNVENCOK:
		return "nvenc_ok"
	case EncoderStateNVENCFailing:
		return "nvenc_failing"
	case EncoderStateVP8:
		return "vp8"
	case EncoderStateTiles:
		return "tiles"
	default:
		return "unknown"
	}
}

// EncoderHealthMonitor tracks encoder health and manages fallback transitions.
// It implements a state machine that progressively degrades encoding quality
// when errors occur, ensuring the stream remains functional.
type EncoderHealthMonitor struct {
	state              atomic.Int32 // Current EncoderState
	consecutiveErrors  atomic.Int32 // Consecutive encoding errors
	lastSuccessTime    atomic.Int64 // Unix nano of last successful encode
	totalFramesEncoded atomic.Uint64
	totalFramesFailed  atomic.Uint64
	fallbackTriggered  atomic.Bool
	lastFallbackReason atomic.Value // string

	// Thresholds (configurable via environment)
	errorThresholdFailing  int32 // Errors before entering FAILING state (default: 5)
	errorThresholdFallback int32 // Errors before triggering fallback (default: 10)
	stallTimeoutMs         int64 // No success timeout in ms (default: 2000)
}

// NewEncoderHealthMonitor creates a new health monitor with default or
// environment-configured thresholds.
func NewEncoderHealthMonitor() *EncoderHealthMonitor {
	m := &EncoderHealthMonitor{
		errorThresholdFailing:  5,
		errorThresholdFallback: 10,
		stallTimeoutMs:         2000,
	}

	// Allow environment overrides
	if val := os.Getenv("SPARK_ENCODER_ERROR_THRESHOLD"); val != "" {
		if n, err := strconv.ParseInt(val, 10, 32); err == nil && n > 0 {
			m.errorThresholdFallback = int32(n)
			m.errorThresholdFailing = int32(n / 2)
			if m.errorThresholdFailing < 1 {
				m.errorThresholdFailing = 1
			}
		}
	}

	if val := os.Getenv("SPARK_ENCODER_STALL_TIMEOUT_MS"); val != "" {
		if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
			m.stallTimeoutMs = n
		}
	}

	m.state.Store(int32(EncoderStateNVENCOK))
	m.lastSuccessTime.Store(time.Now().UnixNano())
	m.lastFallbackReason.Store("")

	return m
}

// RecordSuccess records a successful encoding operation.
// Resets the consecutive error counter and updates last success time.
func (m *EncoderHealthMonitor) RecordSuccess() {
	m.consecutiveErrors.Store(0)
	m.lastSuccessTime.Store(time.Now().UnixNano())
	m.totalFramesEncoded.Add(1)
}

// RecordError records an encoding error and returns the new encoder state.
// If fatal is true, immediately triggers fallback. Otherwise, uses thresholds.
func (m *EncoderHealthMonitor) RecordError(fatal bool) EncoderState {
	errCount := m.consecutiveErrors.Add(1)
	m.totalFramesFailed.Add(1)

	currentState := EncoderState(m.state.Load())

	// Fatal errors immediately trigger fallback
	if fatal {
		return m.transitionToFallback("fatal encoder error")
	}

	// Check if we've exceeded the fallback threshold
	if errCount >= m.errorThresholdFallback {
		return m.transitionToFallback("consecutive errors exceeded threshold")
	}

	// Check if we should enter failing state (for monitoring)
	if errCount >= m.errorThresholdFailing && currentState == EncoderStateNVENCOK {
		m.state.Store(int32(EncoderStateNVENCFailing))
		telemetry.LogStructured("WARN", "encoder: entering failing state", map[string]interface{}{
			"consecutiveErrors": errCount,
			"threshold":         m.errorThresholdFailing,
		})
		return EncoderStateNVENCFailing
	}

	return currentState
}

// transitionToFallback moves to the next fallback state based on current state
// and available encoders.
func (m *EncoderHealthMonitor) transitionToFallback(reason string) EncoderState {
	m.fallbackTriggered.Store(true)
	m.lastFallbackReason.Store(reason)

	currentState := EncoderState(m.state.Load())

	// Determine next state based on current state and availability
	var nextState EncoderState
	switch currentState {
	case EncoderStateNVENCOK, EncoderStateNVENCFailing:
		// Check if VP8 fallback is disabled
		if envDisableVP8Fallback() {
			nextState = EncoderStateTiles
		} else if isVPXAvailable() {
			nextState = EncoderStateVP8
		} else {
			nextState = EncoderStateTiles
		}
	case EncoderStateVP8:
		nextState = EncoderStateTiles
	default:
		nextState = EncoderStateTiles
	}

	oldState := currentState
	m.state.Store(int32(nextState))
	m.consecutiveErrors.Store(0)

	telemetry.LogStructured("WARN", "encoder: fallback triggered", map[string]interface{}{
		"from":   oldState.String(),
		"to":     nextState.String(),
		"reason": reason,
	})

	return nextState
}

// GetState returns the current encoder state.
func (m *EncoderHealthMonitor) GetState() EncoderState {
	return EncoderState(m.state.Load())
}

// GetConsecutiveErrors returns the current consecutive error count.
func (m *EncoderHealthMonitor) GetConsecutiveErrors() int32 {
	return m.consecutiveErrors.Load()
}

// IsStalled returns true if no successful encode has occurred within the stall timeout.
func (m *EncoderHealthMonitor) IsStalled() bool {
	last := m.lastSuccessTime.Load()
	if last == 0 {
		return false
	}
	elapsed := time.Now().UnixNano() - last
	return elapsed > m.stallTimeoutMs*1_000_000
}

// IsFallbackTriggered returns true if any fallback has been triggered.
func (m *EncoderHealthMonitor) IsFallbackTriggered() bool {
	return m.fallbackTriggered.Load()
}

// GetLastFallbackReason returns the reason for the last fallback transition.
func (m *EncoderHealthMonitor) GetLastFallbackReason() string {
	if v := m.lastFallbackReason.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// Reset resets the health monitor to initial state.
// Used when a new session starts or after manual recovery.
func (m *EncoderHealthMonitor) Reset() {
	m.state.Store(int32(EncoderStateNVENCOK))
	m.consecutiveErrors.Store(0)
	m.lastSuccessTime.Store(time.Now().UnixNano())
	m.fallbackTriggered.Store(false)
	m.lastFallbackReason.Store("")
}

// GetStats returns health monitor statistics for telemetry.
func (m *EncoderHealthMonitor) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"state":             EncoderState(m.state.Load()).String(),
		"consecutiveErrors": m.consecutiveErrors.Load(),
		"totalEncoded":      m.totalFramesEncoded.Load(),
		"totalFailed":       m.totalFramesFailed.Load(),
		"fallbackTriggered": m.fallbackTriggered.Load(),
		"isStalled":         m.IsStalled(),
	}
}

// envDisableVP8Fallback checks if VP8 fallback is disabled via environment.
func envDisableVP8Fallback() bool {
	val := strings.TrimSpace(os.Getenv("SPARK_DISABLE_VP8_FALLBACK"))
	return val == "1" || strings.ToLower(val) == "true"
}
