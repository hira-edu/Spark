package telemetry

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// ReconnectStrategy implements exponential backoff with jitter
type ReconnectStrategy struct {
	mu          sync.Mutex
	attempt     int
	baseBackoff time.Duration
	maxBackoff  time.Duration
	jitterRatio float64 // 0.0 to 1.0, typically 0.2 for ±20% jitter
}

// NewReconnectStrategy creates a new reconnection strategy
// baseBackoff: initial backoff duration (e.g., 1 second)
// maxBackoff: maximum backoff duration (e.g., 60 seconds)
// jitterRatio: jitter randomness ratio, 0.2 = ±20%
func NewReconnectStrategy(baseBackoff, maxBackoff time.Duration, jitterRatio float64) *ReconnectStrategy {
	return &ReconnectStrategy{
		attempt:     0,
		baseBackoff: baseBackoff,
		maxBackoff:  maxBackoff,
		jitterRatio: jitterRatio,
	}
}

// NextBackoff returns the next backoff duration with exponential growth and jitter
// Formula: min(maxBackoff, baseBackoff * 2^attempt) with ±jitter
func (r *ReconnectStrategy) NextBackoff() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Calculate exponential backoff: baseBackoff * 2^attempt
	backoff := float64(r.baseBackoff) * math.Pow(2, float64(r.attempt))

	// Cap at maxBackoff
	if backoff > float64(r.maxBackoff) {
		backoff = float64(r.maxBackoff)
	}

	// Add jitter: random value between -jitterRatio and +jitterRatio
	// Example: if jitterRatio=0.2, jitter is between -20% and +20%
	jitter := backoff * r.jitterRatio * (2*rand.Float64() - 1)
	backoffWithJitter := time.Duration(backoff + jitter)

	// Ensure minimum backoff of 100ms
	if backoffWithJitter < 100*time.Millisecond {
		backoffWithJitter = 100 * time.Millisecond
	}

	r.attempt++

	// Record metric
	WSBackoffDuration.Observe(backoffWithJitter.Seconds())

	return backoffWithJitter
}

// Reset resets the backoff attempt counter (call on successful connection)
func (r *ReconnectStrategy) Reset() {
	r.mu.Lock()
	r.attempt = 0
	r.mu.Unlock()
}

// GetAttempt returns the current attempt number
func (r *ReconnectStrategy) GetAttempt() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempt
}

// CircuitBreaker implements the circuit breaker pattern
// States: closed (normal), open (failing), half_open (testing recovery)
type CircuitBreaker struct {
	mu sync.Mutex

	// Configuration
	name             string
	failureThreshold int           // failures to trigger open state
	successThreshold int           // successes to close from half_open
	openDuration     time.Duration // time to wait before half_open

	// State
	state        string // "closed", "open", "half_open"
	failureCount int
	successCount int
	openedAt     time.Time
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, failureThreshold, successThreshold int, openDuration time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:             name,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		openDuration:     openDuration,
		state:            "closed",
	}

	// Set initial metric
	cb.updateMetric()

	return cb
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.allowRequest() {
		return fmt.Errorf("circuit breaker %s is open, retry after %v", cb.name, cb.getRetryAfter())
	}

	err := fn()

	if err != nil {
		cb.onFailure(err)
		return err
	}

	cb.onSuccess()
	return nil
}

// allowRequest checks if a request can proceed
func (cb *CircuitBreaker) allowRequest() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case "closed":
		return true
	case "half_open":
		return true
	case "open":
		// Check if enough time has passed to transition to half_open
		if time.Since(cb.openedAt) > cb.openDuration {
			cb.state = "half_open"
			cb.successCount = 0
			cb.failureCount = 0
			cb.updateMetric()
			LogStructured("info", fmt.Sprintf("circuit breaker %s: open -> half_open (retry window)", cb.name), nil)
			return true
		}
		return false
	default:
		return false
	}
}

// onFailure records a failure
// Permanent errors open the circuit immediately
func (cb *CircuitBreaker) onFailure(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.successCount = 0

	// Check if this is a permanent error (auth, bad credentials)
	isPermanent := false
	if err != nil {
		errStr := err.Error()
		isPermanent = strings.Contains(errStr, "401") ||
			strings.Contains(errStr, "403") ||
			strings.Contains(errStr, "Unauthorized") ||
			strings.Contains(errStr, "Forbidden") ||
			strings.Contains(errStr, "authentication") ||
			strings.Contains(errStr, "bad credentials")
	}

	switch cb.state {
	case "closed":
		// Permanent errors open circuit immediately
		if isPermanent || cb.failureCount >= cb.failureThreshold {
			cb.state = "open"
			cb.openedAt = time.Now()
			cb.updateMetric()
			CircuitBreakerOpens.WithLabelValues(cb.name).Inc()
			if isPermanent {
				LogStructured("error", fmt.Sprintf("circuit breaker %s: closed -> open (permanent error: %v)", cb.name, err), nil)
			} else {
				LogStructured("error", fmt.Sprintf("circuit breaker %s: closed -> open (failure threshold reached: %d)", cb.name, cb.failureCount), nil)
			}
		}
	case "half_open":
		cb.state = "open"
		cb.openedAt = time.Now()
		cb.updateMetric()
		CircuitBreakerOpens.WithLabelValues(cb.name).Inc()
		LogStructured("warn", fmt.Sprintf("circuit breaker %s: half_open -> open (retry failed)", cb.name), nil)
	}
}

// onSuccess records a success
func (cb *CircuitBreaker) onSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount = 0
	cb.successCount++

	if cb.state == "half_open" && cb.successCount >= cb.successThreshold {
		cb.state = "closed"
		cb.updateMetric()
		LogStructured("info", fmt.Sprintf("circuit breaker %s: half_open -> closed (recovery confirmed: %d successes)", cb.name, cb.successCount), nil)
	}
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() string {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// IsOpen returns true if the circuit breaker is open
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.GetState() == "open"
}

// getRetryAfter returns duration until retry is allowed
func (cb *CircuitBreaker) getRetryAfter() time.Duration {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != "open" {
		return 0
	}

	elapsed := time.Since(cb.openedAt)
	if elapsed >= cb.openDuration {
		return 0
	}

	return cb.openDuration - elapsed
}

// updateMetric updates the Prometheus metric
func (cb *CircuitBreaker) updateMetric() {
	var stateValue float64
	switch cb.state {
	case "closed":
		stateValue = 0
		GetHealth().SetCircuitBreaker(false)
	case "half_open":
		stateValue = 1
		GetHealth().SetCircuitBreaker(false)
	case "open":
		stateValue = 2
		GetHealth().SetCircuitBreaker(true)
	}
	CircuitBreakerState.WithLabelValues(cb.name).Set(stateValue)
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = "closed"
	cb.failureCount = 0
	cb.successCount = 0
	cb.updateMetric()
	LogStructured("info", fmt.Sprintf("circuit breaker %s manually reset to closed", cb.name), nil)
}
