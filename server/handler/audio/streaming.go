package audio

import (
	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/utils/melody"
	"Rocket/utils/cmap"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var streamTracer = otel.Tracer("rocket-server/audio-streaming")

// AudioStream represents an active audio streaming session from a client
type AudioStream struct {
	UUID         string
	DeviceID     string
	StartTime    time.Time
	LastPacket   time.Time
	PacketCount  uint64
	BytesWritten uint64
	File         *os.File
	FilePath     string
	mu           sync.Mutex
}

var (
	audioStreams = cmap.New[*AudioStream]()
	streamsMutex sync.RWMutex
)

func init() {
	// Create audio recordings directory if it doesn't exist
	if err := os.MkdirAll("./logs/audio", 0755); err != nil {
		fmt.Printf("[WARN] Failed to create audio recordings directory: %v\n", err)
	}
}

// HandleAudioData processes AUDIO_DATA packets from clients
// This is called when a client sends audio data packets via any transport
func HandleAudioData(pack modules.Packet, uuid string) error {
	ctx, span := streamTracer.Start(context.Background(), "audio.handle_data")
	defer span.End()
	_ = ctx // Unused but kept for future middleware integration

	// Extract audio UUID
	audioUUID, ok := pack.Data["uuid"].(string)
	if !ok {
		span.RecordError(fmt.Errorf("missing audio UUID"))
		span.SetStatus(codes.Error, "missing audio UUID")
		return fmt.Errorf("missing audio UUID in packet")
	}

	// Extract base64 encoded data
	dataStr, ok := pack.Data["data"].(string)
	if !ok {
		span.RecordError(fmt.Errorf("missing audio data"))
		span.SetStatus(codes.Error, "missing audio data")
		return fmt.Errorf("missing audio data in packet")
	}

	// Extract metadata
	seq, _ := pack.Data["seq"].(float64)
	timestamp, _ := pack.Data["timestamp"].(float64)
	size, _ := pack.Data["size"].(float64)

	span.SetAttributes(
		attribute.String("audio.uuid", audioUUID),
		attribute.String("device.uuid", uuid),
		attribute.Int64("packet.seq", int64(seq)),
		attribute.Int64("packet.timestamp", int64(timestamp)),
		attribute.Int64("packet.size", int64(size)),
	)

	// Decode base64 data
	audioData, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "base64 decode failed")
		common.Warn(nil, "AUDIO_DECODE_FAILED", uuid, err.Error(), map[string]any{
			"audio_uuid": audioUUID,
		})
		return fmt.Errorf("failed to decode audio data: %w", err)
	}

	// Get or create audio stream
	stream := getOrCreateStream(audioUUID, uuid)
	if stream == nil {
		err := fmt.Errorf("failed to create audio stream")
		span.RecordError(err)
		span.SetStatus(codes.Error, "stream creation failed")
		return err
	}

	// Write audio data to file
	if err := stream.WriteData(audioData); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "write failed")
		common.Warn(nil, "AUDIO_WRITE_FAILED", uuid, err.Error(), map[string]any{
			"audio_uuid": audioUUID,
			"file_path":  stream.FilePath,
		})
		return fmt.Errorf("failed to write audio data: %w", err)
	}

	// Forward raw Opus packets to any connected browser audio sessions for this uuid.
	broadcastAudioPacket(audioUUID, audioData)

	// Log every 100th packet to avoid spam
	if int64(seq)%100 == 0 {
		common.Debug(nil, "AUDIO_DATA_RECEIVED", uuid, "", map[string]any{
			"audio_uuid":    audioUUID,
			"seq":           int64(seq),
			"size":          len(audioData),
			"total_packets": stream.PacketCount,
			"total_bytes":   stream.BytesWritten,
		})
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

func broadcastAudioPacket(audioUUID string, packet []byte) {
	if audioUUID == "" || len(packet) == 0 {
		return
	}
	audioSessions.IterSessions(func(_ string, session *melody.Session) bool {
		val, ok := session.Get(`Audio`)
		if !ok {
			return true
		}
		a, ok := val.(*audio)
		if !ok || a == nil || a.uuid != audioUUID {
			return true
		}
		_ = session.WriteBinary(packet)
		return true
	})
}

// getOrCreateStream gets an existing audio stream or creates a new one
func getOrCreateStream(audioUUID, deviceUUID string) *AudioStream {
	if stream, ok := audioStreams.Get(audioUUID); ok {
		return stream
	}

	streamsMutex.Lock()
	defer streamsMutex.Unlock()

	// Double-check after acquiring lock
	if stream, ok := audioStreams.Get(audioUUID); ok {
		return stream
	}

	// Get device info
	device, ok := common.Devices.Get(deviceUUID)
	if !ok {
		return nil
	}

	// Create new stream
	now := time.Now()
	filename := fmt.Sprintf("audio_%s_%s_%s.opus",
		device.ID,
		audioUUID[:8],
		now.Format("20060102_150405"))
	filepath := filepath.Join("./logs/audio", filename)

	file, err := os.Create(filepath)
	if err != nil {
		common.Warn(nil, "AUDIO_FILE_CREATE_FAILED", deviceUUID, err.Error(), map[string]any{
			"file_path": filepath,
		})
		return nil
	}

	stream := &AudioStream{
		UUID:      audioUUID,
		DeviceID:  device.ID,
		StartTime: now,
		LastPacket: now,
		File:      file,
		FilePath:  filepath,
	}

	audioStreams.Set(audioUUID, stream)

	common.Info(nil, "AUDIO_STREAM_STARTED", deviceUUID, "", map[string]any{
		"audio_uuid": audioUUID,
		"device_id":  device.ID,
		"file_path":  filepath,
	})

	// Start cleanup timer (close file after 30 seconds of inactivity)
	go stream.startCleanupTimer()

	return stream
}

// WriteData writes audio data to the stream file
func (s *AudioStream) WriteData(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.File == nil {
		return fmt.Errorf("stream file is closed")
	}

	n, err := s.File.Write(data)
	if err != nil {
		return err
	}

	s.BytesWritten += uint64(n)
	s.PacketCount++
	s.LastPacket = time.Now()

	return nil
}

// startCleanupTimer starts a timer to close the stream after inactivity
func (s *AudioStream) startCleanupTimer() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		inactive := time.Since(s.LastPacket)
		s.mu.Unlock()

		if inactive > 30*time.Second {
			s.Close()
			audioStreams.Remove(s.UUID)
			return
		}
	}
}

// Close closes the audio stream and its file
func (s *AudioStream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.File != nil {
		s.File.Close()
		s.File = nil

		duration := time.Since(s.StartTime)
		common.Info(nil, "AUDIO_STREAM_CLOSED", "", "", map[string]any{
			"audio_uuid":   s.UUID,
			"device_id":    s.DeviceID,
			"file_path":    s.FilePath,
			"duration_sec": duration.Seconds(),
			"packets":      s.PacketCount,
			"bytes":        s.BytesWritten,
		})
	}
}

// CloseStream manually closes an audio stream
func CloseStream(audioUUID string) {
	if stream, ok := audioStreams.Get(audioUUID); ok {
		stream.Close()
		audioStreams.Remove(audioUUID)
	}
}

// GetActiveStreams returns the number of active audio streams
func GetActiveStreams() int {
	return audioStreams.Count()
}

// ListActiveStreams returns information about all active streams
func ListActiveStreams() []map[string]any {
	var streams []map[string]any

	audioStreams.IterCb(func(uuid string, stream *AudioStream) bool {
		stream.mu.Lock()
		info := map[string]any{
			"uuid":       stream.UUID,
			"device_id":  stream.DeviceID,
			"file_path":  stream.FilePath,
			"start_time": stream.StartTime.Format(time.RFC3339),
			"duration":   time.Since(stream.StartTime).Seconds(),
			"packets":    stream.PacketCount,
			"bytes":      stream.BytesWritten,
		}
		stream.mu.Unlock()

		streams = append(streams, info)
		return true
	})

	return streams
}
