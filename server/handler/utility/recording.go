// Package utility provides session recording for audit trails.
// Based on Apache Guacamole's recording approach.
//
// Features:
// - Records all desktop frames and input events
// - Supports multiple output formats (raw binary, WebM)
// - Configurable retention and storage backends
// - Playback support via timestamp indexing
//
// Storage Format (Guacamole-compatible):
// - Header: magic(4) + version(2) + session_id(16) + start_time(8)
// - Records: timestamp(8) + type(1) + length(4) + data(length)
// - Index: frame_offsets for seek support
//
// Record Types:
// - 0x01: Frame (resolution, codec, image data)
// - 0x02: Input (mouse, keyboard, clipboard)
// - 0x03: Cursor (position, shape)
// - 0x04: Resolution change
// - 0x05: Session metadata
package utility

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Recording format constants
const (
	RecordingMagic   = 0x524B5244 // "RKRD" - Rocket Recording
	RecordingVersion = 1

	// Record types
	RecordTypeFrame      = 0x01
	RecordTypeInput      = 0x02
	RecordTypeCursor     = 0x03
	RecordTypeResolution = 0x04
	RecordTypeMetadata   = 0x05
	RecordTypeAudio      = 0x06

	// Frame sub-types
	FrameSubTypeJPEG = 0x01
	FrameSubTypePNG  = 0x02
	FrameSubTypeRAW  = 0x03
	FrameSubTypeVP8  = 0x04
	FrameSubTypeVP9  = 0x05
	FrameSubTypeH264 = 0x06

	// Input sub-types
	InputSubTypeMouse     = 0x01
	InputSubTypeKeyboard  = 0x02
	InputSubTypeClipboard = 0x03
	InputSubTypeScroll    = 0x04

	// Default settings
	DefaultBufferSize   = 64 * 1024 // 64KB write buffer
	DefaultMaxFileSize  = 1 << 30   // 1GB max per file
	DefaultIndexEvery   = 100       // Index every 100 frames
)

var (
	ErrRecordingClosed    = errors.New("recording: session closed")
	ErrRecordingCorrupt   = errors.New("recording: file corrupt")
	ErrRecordingTooLarge  = errors.New("recording: exceeds max size")
	ErrRecordingNotFound  = errors.New("recording: not found")
	ErrRecordingExists    = errors.New("recording: already exists")
)

// RecordingConfig configures a recording session
type RecordingConfig struct {
	// OutputPath is the directory for recording files
	OutputPath string

	// SessionID identifies the recording
	SessionID string

	// MaxFileSize limits recording size (0 = unlimited)
	MaxFileSize int64

	// BufferSize for write buffering
	BufferSize int

	// IndexEveryN frames (for seeking support)
	IndexEvery int

	// Metadata to include in recording header
	Metadata map[string]string
}

// DefaultRecordingConfig returns sensible defaults
func DefaultRecordingConfig(outputPath, sessionID string) RecordingConfig {
	return RecordingConfig{
		OutputPath:  outputPath,
		SessionID:   sessionID,
		MaxFileSize: DefaultMaxFileSize,
		BufferSize:  DefaultBufferSize,
		IndexEvery:  DefaultIndexEvery,
		Metadata:    make(map[string]string),
	}
}

// Recording represents an active recording session
type Recording struct {
	config    RecordingConfig
	file      *os.File
	writer    *bufio.Writer
	startTime time.Time

	// State
	frameCount  atomic.Uint64
	bytesWriten atomic.Int64
	closed      atomic.Bool
	mu          sync.Mutex

	// Index for seeking
	frameIndex []int64 // Byte offsets for indexed frames
}

// NewRecording creates a new recording session
func NewRecording(config RecordingConfig) (*Recording, error) {
	if config.OutputPath == "" || config.SessionID == "" {
		return nil, errors.New("recording: output path and session ID required")
	}

	// Ensure directory exists
	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		return nil, err
	}

	// Generate unique filename with timestamp
	filename := filepath.Join(config.OutputPath,
		config.SessionID+"_"+time.Now().Format("20060102_150405")+".rkrd")

	// Check if file already exists
	if _, err := os.Stat(filename); err == nil {
		return nil, ErrRecordingExists
	}

	// Create file
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}

	r := &Recording{
		config:     config,
		file:       file,
		writer:     bufio.NewWriterSize(file, config.BufferSize),
		startTime:  time.Now(),
		frameIndex: make([]int64, 0, 1024),
	}

	// Write header
	if err := r.writeHeader(); err != nil {
		file.Close()
		os.Remove(filename)
		return nil, err
	}

	return r, nil
}

// writeHeader writes the recording file header
func (r *Recording) writeHeader() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Magic (4 bytes)
	if err := binary.Write(r.writer, binary.BigEndian, uint32(RecordingMagic)); err != nil {
		return err
	}

	// Version (2 bytes)
	if err := binary.Write(r.writer, binary.BigEndian, uint16(RecordingVersion)); err != nil {
		return err
	}

	// Session ID (16 bytes, padded/truncated)
	sessionIDBytes := make([]byte, 16)
	copy(sessionIDBytes, r.config.SessionID)
	if _, err := r.writer.Write(sessionIDBytes); err != nil {
		return err
	}

	// Start time (8 bytes, Unix nano)
	if err := binary.Write(r.writer, binary.BigEndian, r.startTime.UnixNano()); err != nil {
		return err
	}

	r.bytesWriten.Add(30)
	return nil
}

// WriteFrame records a desktop frame
func (r *Recording) WriteFrame(codecType int, x, y, width, height int, data []byte) error {
	if r.closed.Load() {
		return ErrRecordingClosed
	}

	// Check size limit
	if r.config.MaxFileSize > 0 && r.bytesWriten.Load()+int64(len(data)+20) > r.config.MaxFileSize {
		return ErrRecordingTooLarge
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Record byte offset for indexing
	frameNum := r.frameCount.Load()
	if r.config.IndexEvery > 0 && int(frameNum)%r.config.IndexEvery == 0 {
		r.frameIndex = append(r.frameIndex, r.bytesWriten.Load())
	}

	// Timestamp (8 bytes) - milliseconds since start
	elapsed := time.Since(r.startTime).Milliseconds()
	if err := binary.Write(r.writer, binary.BigEndian, elapsed); err != nil {
		return err
	}

	// Type (1 byte)
	if err := r.writer.WriteByte(RecordTypeFrame); err != nil {
		return err
	}

	// Sub-type (1 byte)
	subType := byte(FrameSubTypeJPEG)
	switch codecType {
	case 0:
		subType = FrameSubTypeRAW
	case 1:
		subType = FrameSubTypeJPEG
	case 4:
		subType = FrameSubTypeVP8
	case 5:
		subType = FrameSubTypeVP9
	case 6:
		subType = FrameSubTypeH264
	case 7:
		subType = FrameSubTypePNG
	}
	if err := r.writer.WriteByte(subType); err != nil {
		return err
	}

	// Length (4 bytes)
	recordLen := uint32(8 + len(data)) // x,y,w,h (2 each) + data
	if err := binary.Write(r.writer, binary.BigEndian, recordLen); err != nil {
		return err
	}

	// Position and dimensions (2 bytes each)
	if err := binary.Write(r.writer, binary.BigEndian, uint16(x)); err != nil {
		return err
	}
	if err := binary.Write(r.writer, binary.BigEndian, uint16(y)); err != nil {
		return err
	}
	if err := binary.Write(r.writer, binary.BigEndian, uint16(width)); err != nil {
		return err
	}
	if err := binary.Write(r.writer, binary.BigEndian, uint16(height)); err != nil {
		return err
	}

	// Image data
	if _, err := r.writer.Write(data); err != nil {
		return err
	}

	r.frameCount.Add(1)
	r.bytesWriten.Add(int64(14 + len(data)))

	return nil
}

// WriteInput records an input event
func (r *Recording) WriteInput(inputType int, eventData []byte) error {
	if r.closed.Load() {
		return ErrRecordingClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Timestamp
	elapsed := time.Since(r.startTime).Milliseconds()
	if err := binary.Write(r.writer, binary.BigEndian, elapsed); err != nil {
		return err
	}

	// Type
	if err := r.writer.WriteByte(RecordTypeInput); err != nil {
		return err
	}

	// Sub-type
	subType := byte(InputSubTypeMouse)
	switch inputType {
	case 0:
		subType = InputSubTypeMouse
	case 1:
		subType = InputSubTypeKeyboard
	case 2:
		subType = InputSubTypeClipboard
	case 3:
		subType = InputSubTypeScroll
	}
	if err := r.writer.WriteByte(subType); err != nil {
		return err
	}

	// Length
	if err := binary.Write(r.writer, binary.BigEndian, uint32(len(eventData))); err != nil {
		return err
	}

	// Data
	if _, err := r.writer.Write(eventData); err != nil {
		return err
	}

	r.bytesWriten.Add(int64(14 + len(eventData)))
	return nil
}

// WriteResolution records a resolution change event
func (r *Recording) WriteResolution(width, height int) error {
	if r.closed.Load() {
		return ErrRecordingClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Timestamp
	elapsed := time.Since(r.startTime).Milliseconds()
	if err := binary.Write(r.writer, binary.BigEndian, elapsed); err != nil {
		return err
	}

	// Type
	if err := r.writer.WriteByte(RecordTypeResolution); err != nil {
		return err
	}

	// Reserved sub-type
	if err := r.writer.WriteByte(0); err != nil {
		return err
	}

	// Length (4 bytes for width + height)
	if err := binary.Write(r.writer, binary.BigEndian, uint32(4)); err != nil {
		return err
	}

	// Resolution
	if err := binary.Write(r.writer, binary.BigEndian, uint16(width)); err != nil {
		return err
	}
	if err := binary.Write(r.writer, binary.BigEndian, uint16(height)); err != nil {
		return err
	}

	r.bytesWriten.Add(18)
	return nil
}

// Flush writes buffered data to disk
func (r *Recording) Flush() error {
	if r.closed.Load() {
		return ErrRecordingClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	return r.writer.Flush()
}

// Close finishes and closes the recording
func (r *Recording) Close() error {
	if r.closed.Swap(true) {
		return ErrRecordingClosed
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Flush buffer
	if err := r.writer.Flush(); err != nil {
		r.file.Close()
		return err
	}

	// Write index trailer (optional, for seeking support)
	if len(r.frameIndex) > 0 {
		// Index marker
		if err := binary.Write(r.file, binary.BigEndian, uint32(0xFFFFFFFF)); err != nil {
			r.file.Close()
			return err
		}
		// Number of index entries
		if err := binary.Write(r.file, binary.BigEndian, uint32(len(r.frameIndex))); err != nil {
			r.file.Close()
			return err
		}
		// Index entries
		for _, offset := range r.frameIndex {
			if err := binary.Write(r.file, binary.BigEndian, offset); err != nil {
				r.file.Close()
				return err
			}
		}
	}

	return r.file.Close()
}

// Stats returns recording statistics
func (r *Recording) Stats() map[string]interface{} {
	return map[string]interface{}{
		"session_id":    r.config.SessionID,
		"frame_count":   r.frameCount.Load(),
		"bytes_written": r.bytesWriten.Load(),
		"duration_ms":   time.Since(r.startTime).Milliseconds(),
		"closed":        r.closed.Load(),
	}
}

// RecordingManager manages multiple recording sessions
type RecordingManager struct {
	recordings sync.Map // map[sessionID]*Recording
	outputPath string
}

// Global recording manager (disabled by default)
var globalRecordingManager *RecordingManager

// InitRecordingManager initializes the global recording manager
func InitRecordingManager(outputPath string) {
	if outputPath == "" {
		return
	}
	globalRecordingManager = &RecordingManager{
		outputPath: outputPath,
	}
}

// GetRecordingManager returns the global manager (may be nil)
func GetRecordingManager() *RecordingManager {
	return globalRecordingManager
}

// StartRecording starts recording a session
func (m *RecordingManager) StartRecording(sessionID string, metadata map[string]string) (*Recording, error) {
	if _, loaded := m.recordings.Load(sessionID); loaded {
		return nil, ErrRecordingExists
	}

	config := DefaultRecordingConfig(m.outputPath, sessionID)
	config.Metadata = metadata

	r, err := NewRecording(config)
	if err != nil {
		return nil, err
	}

	m.recordings.Store(sessionID, r)
	return r, nil
}

// GetRecording returns an active recording
func (m *RecordingManager) GetRecording(sessionID string) (*Recording, bool) {
	r, ok := m.recordings.Load(sessionID)
	if !ok {
		return nil, false
	}
	return r.(*Recording), true
}

// StopRecording stops and closes a recording
func (m *RecordingManager) StopRecording(sessionID string) error {
	r, ok := m.recordings.LoadAndDelete(sessionID)
	if !ok {
		return ErrRecordingNotFound
	}
	return r.(*Recording).Close()
}

// ==================== RECORDING READER (PLAYBACK) ====================

// RecordingReader reads recorded sessions for playback
type RecordingReader struct {
	file       *os.File
	reader     *bufio.Reader
	sessionID  string
	startTime  int64
	frameIndex []int64
}

// OpenRecording opens a recording file for playback
func OpenRecording(path string) (*RecordingReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	r := &RecordingReader{
		file:   file,
		reader: reader,
	}

	// Read and validate header
	if err := r.readHeader(); err != nil {
		file.Close()
		return nil, err
	}

	return r, nil
}

func (r *RecordingReader) readHeader() error {
	// Magic
	var magic uint32
	if err := binary.Read(r.reader, binary.BigEndian, &magic); err != nil {
		return err
	}
	if magic != RecordingMagic {
		return ErrRecordingCorrupt
	}

	// Version
	var version uint16
	if err := binary.Read(r.reader, binary.BigEndian, &version); err != nil {
		return err
	}
	if version != RecordingVersion {
		return ErrRecordingCorrupt
	}

	// Session ID
	sessionIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(r.reader, sessionIDBytes); err != nil {
		return err
	}
	r.sessionID = string(sessionIDBytes)

	// Start time
	if err := binary.Read(r.reader, binary.BigEndian, &r.startTime); err != nil {
		return err
	}

	return nil
}

// Record represents a single recorded event
type Record struct {
	Timestamp int64 // Milliseconds since recording start
	Type      byte
	SubType   byte
	Data      []byte
}

// ReadRecord reads the next record from the recording
func (r *RecordingReader) ReadRecord() (*Record, error) {
	rec := &Record{}

	// Timestamp
	if err := binary.Read(r.reader, binary.BigEndian, &rec.Timestamp); err != nil {
		return nil, err
	}

	// Check for index marker
	if rec.Timestamp == -1 {
		return nil, io.EOF
	}

	// Type
	var err error
	rec.Type, err = r.reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// Sub-type
	rec.SubType, err = r.reader.ReadByte()
	if err != nil {
		return nil, err
	}

	// Length
	var length uint32
	if err := binary.Read(r.reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	// Data
	rec.Data = make([]byte, length)
	if _, err := io.ReadFull(r.reader, rec.Data); err != nil {
		return nil, err
	}

	return rec, nil
}

// Close closes the recording reader
func (r *RecordingReader) Close() error {
	return r.file.Close()
}

// SessionID returns the recorded session ID
func (r *RecordingReader) SessionID() string {
	return r.sessionID
}
