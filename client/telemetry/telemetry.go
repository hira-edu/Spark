package telemetry

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kataras/golog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics
var (
	// WebSocket connection metrics
	WSConnectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rocket_ws_connections_total",
		Help: "Total WebSocket connection attempts",
	})

	WSConnectionsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rocket_ws_connections_active",
		Help: "Currently active WebSocket connections (0 or 1)",
	})

	WSDisconnectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rocket_ws_disconnects_total",
		Help: "WebSocket disconnections by reason and close code",
	}, []string{"reason", "code"})

	WSConnectionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "rocket_ws_connection_duration_seconds",
		Help:    "Duration of WebSocket connections",
		Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
	})

	WSReconnectAttempts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rocket_ws_reconnect_attempts_total",
		Help: "Total reconnection attempts after disconnect",
	})

	WSBackoffDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "rocket_ws_backoff_duration_seconds",
		Help:    "Backoff delay duration before reconnection",
		Buckets: []float64{1, 2, 4, 8, 16, 32, 60},
	})

	// Circuit breaker metrics
	CircuitBreakerState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rocket_circuit_breaker_state",
		Help: "Circuit breaker state (0=closed, 1=half_open, 2=open)",
	}, []string{"name"})

	CircuitBreakerOpens = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rocket_circuit_breaker_opens_total",
		Help: "Total circuit breaker open events",
	}, []string{"name"})

	// Session management metrics
	SessionLaunchesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rocket_session_launches_total",
		Help: "UI client launches by result (success, no_token, job_error, etc.)",
	}, []string{"result"})

	SessionLaunchDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "rocket_session_launch_duration_seconds",
		Help:    "Time to launch UI client",
		Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
	})

	SessionProcessesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rocket_session_processes_active",
		Help: "Number of active UI processes in user sessions",
	})

	SessionEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rocket_session_events_total",
		Help: "Windows session change events received by type",
	}, []string{"event_type", "scope"})

	// Process lifecycle metrics
	UIProcessCrashesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rocket_ui_crashes_total",
		Help: "Total unexpected UI process terminations",
	})

	UIProcessRestarts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rocket_ui_restarts_total",
		Help: "Total UI process restart attempts",
	})

	// Heartbeat metrics
	HeartbeatsSentTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rocket_heartbeats_sent_total",
		Help: "Total heartbeat/ping messages sent",
	})

	HeartbeatsFailedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "rocket_heartbeats_failed_total",
		Help: "Total heartbeat/ping failures",
	})

	LastHeartbeatTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "rocket_last_heartbeat_timestamp",
		Help: "Unix timestamp of last successful heartbeat",
	})
)

// HealthStatus tracks the overall health of the agent
type HealthStatus struct {
	mu                 sync.RWMutex
	wsConnected        atomic.Bool
	lastConnectTime    time.Time
	lastDisconnectTime time.Time
	activeSessionID    uint32
	uiProcessRunning   atomic.Bool
	uiProcessPID       uint32
	startTime          time.Time
	lastHeartbeat      time.Time
	circuitBreakerOpen atomic.Bool
}

var globalHealth = &HealthStatus{
	startTime: time.Now(),
}

// GetHealth returns the current health status
func GetHealth() *HealthStatus {
	return globalHealth
}

// SetWSConnected updates WebSocket connection status
func (h *HealthStatus) SetWSConnected(connected bool) {
	h.wsConnected.Store(connected)
	h.mu.Lock()
	if connected {
		h.lastConnectTime = time.Now()
		WSConnectionsActive.Set(1)
	} else {
		h.lastDisconnectTime = time.Now()
		WSConnectionsActive.Set(0)
	}
	h.mu.Unlock()
}

// IsWSConnected returns whether WebSocket is connected
func (h *HealthStatus) IsWSConnected() bool {
	return h.wsConnected.Load()
}

// SetUIProcess updates UI process status
func (h *HealthStatus) SetUIProcess(running bool, sessionID, pid uint32) {
	h.uiProcessRunning.Store(running)
	h.mu.Lock()
	h.activeSessionID = sessionID
	h.uiProcessPID = pid
	h.mu.Unlock()

	if running {
		SessionProcessesActive.Inc()
	} else {
		SessionProcessesActive.Dec()
	}
}

// IsUIProcessRunning returns whether UI process is running
func (h *HealthStatus) IsUIProcessRunning() bool {
	return h.uiProcessRunning.Load()
}

// SetHeartbeat updates last heartbeat timestamp
func (h *HealthStatus) SetHeartbeat() {
	now := time.Now()
	h.mu.Lock()
	h.lastHeartbeat = now
	h.mu.Unlock()
	LastHeartbeatTimestamp.Set(float64(now.Unix()))
}

// GetLastHeartbeat returns the last heartbeat time
func (h *HealthStatus) GetLastHeartbeat() time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lastHeartbeat
}

// SetCircuitBreaker updates circuit breaker status
func (h *HealthStatus) SetCircuitBreaker(open bool) {
	h.circuitBreakerOpen.Store(open)
}

// IsCircuitBreakerOpen returns whether circuit breaker is open
func (h *HealthStatus) IsCircuitBreakerOpen() bool {
	return h.circuitBreakerOpen.Load()
}

// GetSnapshot returns a snapshot of the health status
func (h *HealthStatus) GetSnapshot() HealthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return HealthSnapshot{
		WSConnected:         h.wsConnected.Load(),
		LastConnectTime:     h.lastConnectTime,
		LastDisconnectTime:  h.lastDisconnectTime,
		ActiveSessionID:     h.activeSessionID,
		UIProcessRunning:    h.uiProcessRunning.Load(),
		UIProcessPID:        h.uiProcessPID,
		UptimeSeconds:       int64(time.Since(h.startTime).Seconds()),
		LastHeartbeat:       h.lastHeartbeat,
		CircuitBreakerOpen:  h.circuitBreakerOpen.Load(),
	}
}

// HealthSnapshot is a point-in-time snapshot of health status
type HealthSnapshot struct {
	WSConnected         bool      `json:"ws_connected"`
	LastConnectTime     time.Time `json:"last_connect_time"`
	LastDisconnectTime  time.Time `json:"last_disconnect_time,omitempty"`
	ActiveSessionID     uint32    `json:"active_session_id,omitempty"`
	UIProcessRunning    bool      `json:"ui_process_running"`
	UIProcessPID        uint32    `json:"ui_process_pid,omitempty"`
	UptimeSeconds       int64     `json:"uptime_seconds"`
	LastHeartbeat       time.Time `json:"last_heartbeat,omitempty"`
	CircuitBreakerOpen  bool      `json:"circuit_breaker_open"`
}

// IsHealthy returns true if the agent is in a healthy state
func (s *HealthSnapshot) IsHealthy() bool {
	// Healthy if:
	// 1. WebSocket is connected OR circuit breaker is not open
	// 2. UI process is running in an active session OR no session is active
	return (s.WSConnected || !s.CircuitBreakerOpen) &&
		(s.UIProcessRunning || s.ActiveSessionID == 0)
}

// LogStructured logs a structured message with context fields
func LogStructured(level, message string, fields map[string]interface{}) {
	// Build structured log message
	msg := message
	if fields != nil && len(fields) > 0 {
		for k, v := range fields {
			msg += fmt.Sprintf(" %s=%v", k, v)
		}
	}

	switch level {
	case "debug":
		golog.Debug(msg)
	case "info":
		golog.Info(msg)
	case "warn":
		golog.Warn(msg)
	case "error":
		golog.Error(msg)
	default:
		golog.Info(msg)
	}
}

// LogWSEvent logs WebSocket events with structured context
func LogWSEvent(event string, fields map[string]interface{}) {
	LogStructured("info", "ws: "+event, fields)
}

// LogWSError logs WebSocket errors with structured context
func LogWSError(event string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	if err != nil {
		fields["error"] = err.Error()
	}
	LogStructured("error", "ws: "+event, fields)
}

// LogSessionEvent logs session change events with structured context
func LogSessionEvent(event string, sessionID uint32, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["session_id"] = sessionID
	LogStructured("info", "session: "+event, fields)
}

// LogSessionError logs session errors with structured context
func LogSessionError(event string, sessionID uint32, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["session_id"] = sessionID
	if err != nil {
		fields["error"] = err.Error()
	}
	LogStructured("error", "session: "+event, fields)
}
