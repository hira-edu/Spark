package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single log entry to be sent to server
type LogEntry struct {
	SessionID   uint32                 `json:"sessionId"`
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Data        map[string]interface{} `json:"data,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      string                 `json:"source,omitempty"`
	Network     string                 `json:"network,omitempty"`
	Attempt     int                    `json:"attempt,omitempty"`
	CloseCode   int                    `json:"closeCode,omitempty"`
	CloseReason string                 `json:"closeReason,omitempty"`
}

// LogStreamer buffers and sends logs to the server
type LogStreamer struct {
	buffer     []LogEntry
	bufferMu   sync.Mutex
	maxBuffer  int
	flushTimer *time.Ticker
	sendFunc   func([]LogEntry) error
	sessionID  uint32
	enabled    bool
}

var (
	globalStreamer *LogStreamer
	streamerMu     sync.Mutex
)

// InitLogStreamer initializes the log streaming system
func InitLogStreamer(sessionID uint32, sendFunc func([]LogEntry) error) *LogStreamer {
	streamerMu.Lock()
	defer streamerMu.Unlock()

	if globalStreamer != nil {
		globalStreamer.Stop()
	}

	streamer := &LogStreamer{
		buffer:     make([]LogEntry, 0, 100),
		maxBuffer:  100,
		flushTimer: time.NewTicker(5 * time.Second), // Send logs every 5 seconds
		sendFunc:   sendFunc,
		sessionID:  sessionID,
		enabled:    sendFunc != nil,
	}

	globalStreamer = streamer

	// Start background flusher
	go streamer.flusher()

	return streamer
}

// GetLogStreamer returns the global log streamer
func GetLogStreamer() *LogStreamer {
	streamerMu.Lock()
	defer streamerMu.Unlock()
	return globalStreamer
}

// LogWriter implements io.Writer and captures all golog output
type LogWriter struct {
	original  io.Writer
	sessionID uint32
}

// Write implements io.Writer
func (w *LogWriter) Write(p []byte) (n int, err error) {
	// Write to original output first
	if w.original != nil {
		w.original.Write(p)
	}

	// Parse and stream to server
	w.parseAndStream(p)

	return len(p), nil
}

// parseAndStream parses golog format and adds to stream buffer
func (w *LogWriter) parseAndStream(data []byte) {
	line := string(bytes.TrimSpace(data))
	if line == "" {
		return
	}

	// Parse golog format: [LEVEL] timestamp message
	// Example: [INFO] 2025/12/02 15:00:00 Desktop capture initialized
	level := "INFO"
	message := line
	source := ""

	// Extract level if present
	if strings.HasPrefix(line, "[") {
		endIdx := strings.Index(line, "]")
		if endIdx > 0 {
			level = line[1:endIdx]
			message = strings.TrimSpace(line[endIdx+1:])
		}
	}

	// Try to parse as structured log (JSON)
	var structuredData map[string]interface{}
	if strings.Contains(message, "{") && strings.Contains(message, "}") {
		jsonStart := strings.Index(message, "{")
		jsonPart := message[jsonStart:]
		if err := json.Unmarshal([]byte(jsonPart), &structuredData); err == nil {
			// Successfully parsed structured data
			// Extract message before JSON if present
			if jsonStart > 0 {
				textPart := strings.TrimSpace(message[:jsonStart])
				if textPart != "" {
					message = textPart
				} else if event, ok := structuredData["event"].(string); ok {
					message = event
				}
			}
		}
	}

	entry := LogEntry{
		SessionID: w.sessionID,
		Level:     strings.ToUpper(level),
		Message:   message,
		Data:      structuredData,
		Timestamp: time.Now(),
		Source:    source,
	}

	streamerMu.Lock()
	streamer := globalStreamer
	streamerMu.Unlock()

	if streamer != nil && streamer.enabled {
		streamer.Add(entry)
	}
}

// Add adds a log entry to the buffer
func (s *LogStreamer) Add(entry LogEntry) {
	if !s.enabled {
		return
	}

	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	s.buffer = append(s.buffer, entry)

	// Flush if buffer is full
	if len(s.buffer) >= s.maxBuffer {
		s.flushLocked()
	}
}

// flusher runs in background and periodically flushes logs
func (s *LogStreamer) flusher() {
	for range s.flushTimer.C {
		if !s.enabled {
			return
		}
		s.Flush()
	}
}

// Flush sends all buffered logs to the server
func (s *LogStreamer) Flush() {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()
	s.flushLocked()
}

// flushLocked sends logs (caller must hold bufferMu)
func (s *LogStreamer) flushLocked() {
	if len(s.buffer) == 0 || !s.enabled {
		return
	}

	// Copy buffer
	toSend := make([]LogEntry, len(s.buffer))
	copy(toSend, s.buffer)

	// Clear buffer
	s.buffer = s.buffer[:0]

	// Send asynchronously to not block logging
	go func(logs []LogEntry) {
		if err := s.sendFunc(logs); err != nil {
			// Failed to send - log locally but don't retry (avoid infinite loop)
			fmt.Printf("[LOG_STREAM_ERROR] Failed to send %d logs to server: %v\n", len(logs), err)
		}
	}(toSend)
}

// Stop stops the log streamer
func (s *LogStreamer) Stop() {
	s.enabled = false
	if s.flushTimer != nil {
		s.flushTimer.Stop()
	}
	s.Flush() // Final flush
}

// SetSessionID updates the session ID for future logs
func (s *LogStreamer) SetSessionID(sessionID uint32) {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()
	s.sessionID = sessionID
}

// NewLogStreamWriter creates a multi-writer that writes to both file and server
func NewLogStreamWriter(fileWriter io.Writer, sessionID uint32) io.Writer {
	logWriter := &LogWriter{
		original:  fileWriter,
		sessionID: sessionID,
	}
	return logWriter
}

// UpdateSessionID updates the session ID for the global log writer
func UpdateSessionID(sessionID uint32) {
	streamerMu.Lock()
	streamer := globalStreamer
	streamerMu.Unlock()

	if streamer != nil {
		streamer.SetSessionID(sessionID)
	}
}

// LogEvent adds a structured log entry directly to the streamer (bypassing golog parsing).
func LogEvent(level, message string, data map[string]interface{}) {
	streamerMu.Lock()
	streamer := globalStreamer
	streamerMu.Unlock()
	if streamer == nil || !streamer.enabled {
		return
	}

	entry := LogEntry{
		SessionID: streamer.sessionID,
		Level:     strings.ToUpper(level),
		Message:   message,
		Data:      data,
		Timestamp: time.Now(),
	}
	if v, ok := data["network"].(string); ok {
		entry.Network = v
	}
	if v, ok := data["attempt"].(int); ok {
		entry.Attempt = v
	}
	if v, ok := data["closeCode"].(int); ok {
		entry.CloseCode = v
	}
	if v, ok := data["closeReason"].(string); ok {
		entry.CloseReason = v
	}

	streamer.Add(entry)
}
