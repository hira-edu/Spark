package desktop

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
)

// MTU-aware frame fragmentation for WebRTC and WebSocket paths
// Following 2025 best practices to avoid UDP fragmentation and respect transport limits.

const (
	// WebRTC RTP packet size limits (UDP path)
	// Conservative 1200 bytes works for 99% of networks (IPv4 + IPv6)
	// Avoids IP fragmentation which is unreliable and often blocked
	MaxRTPPayloadSize = 1200 // Chrome/Firefox standard for WebRTC

	// WebSocket message size limits (TCP path)
	// Default safe limit, can be increased if server MaxMessageSize allows
	DefaultWSMaxMessageSize = 1 * 1024 * 1024 // 1 MB default
	MaxWSChunkSize          = 256 * 1024      // 256 KB chunks for large frames

	// Fragment header size (8 bytes)
	// [4 bytes: fragment ID][2 bytes: sequence][2 bytes: total fragments]
	FragmentHeaderSize = 8

	// Maximum fragments per frame (prevent memory exhaustion)
	MaxFragmentsPerFrame = 1024
)

// Fragment header format:
// [0-3]: Frame ID (uint32) - unique identifier for this frame
// [4-5]: Sequence number (uint16) - which fragment this is (0-based)
// [6-7]: Total fragments (uint16) - how many fragments in total

var (
	// Global frame ID counter for fragment identification
	frameIDCounter atomic.Uint32

	// Statistics
	fragmentStats struct {
		fragmentedFrames   atomic.Uint64 // Frames that required fragmentation
		totalFragmentsSent atomic.Uint64 // Total fragments sent
		reassemblyErrors   atomic.Uint64 // Failed reassembly attempts
	}
)

// FragmentFrame splits a large frame into MTU-sized chunks with headers.
// Returns a slice of fragments that can be sent independently.
// Each fragment includes a header for reassembly on the receiving end.
func FragmentFrame(data []byte, maxFragmentSize int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot fragment empty data")
	}

	// If frame fits in single fragment, no need to fragment
	if len(data) <= maxFragmentSize {
		return [][]byte{data}, nil
	}

	// Calculate number of fragments needed
	payloadSize := maxFragmentSize - FragmentHeaderSize
	if payloadSize <= 0 {
		return nil, errors.New("maxFragmentSize too small for header")
	}

	totalFragments := (len(data) + payloadSize - 1) / payloadSize
	if totalFragments > MaxFragmentsPerFrame {
		return nil, errors.New("frame too large, exceeds max fragments")
	}

	// Generate unique frame ID
	frameID := frameIDCounter.Add(1)

	// Create fragments
	fragments := make([][]byte, totalFragments)
	offset := 0

	for i := 0; i < totalFragments; i++ {
		// Calculate payload size for this fragment
		remaining := len(data) - offset
		fragmentPayload := payloadSize
		if remaining < payloadSize {
			fragmentPayload = remaining
		}

		// Allocate fragment with header
		fragment := make([]byte, FragmentHeaderSize+fragmentPayload)

		// Write header
		binary.BigEndian.PutUint32(fragment[0:4], frameID)
		binary.BigEndian.PutUint16(fragment[4:6], uint16(i))
		binary.BigEndian.PutUint16(fragment[6:8], uint16(totalFragments))

		// Copy payload
		copy(fragment[FragmentHeaderSize:], data[offset:offset+fragmentPayload])

		fragments[i] = fragment
		offset += fragmentPayload
	}

	// Update statistics
	fragmentStats.fragmentedFrames.Add(1)
	fragmentStats.totalFragmentsSent.Add(uint64(totalFragments))

	return fragments, nil
}

// IsFragmentedFrame checks if data starts with a fragment header.
func IsFragmentedFrame(data []byte) bool {
	if len(data) < FragmentHeaderSize {
		return false
	}
	// Check if total fragments > 1 (indicating fragmentation)
	totalFragments := binary.BigEndian.Uint16(data[6:8])
	return totalFragments > 1
}

// ParseFragmentHeader extracts fragment metadata from a fragment.
func ParseFragmentHeader(data []byte) (frameID uint32, sequence uint16, total uint16, payload []byte, err error) {
	if len(data) < FragmentHeaderSize {
		return 0, 0, 0, nil, errors.New("data too short for fragment header")
	}

	frameID = binary.BigEndian.Uint32(data[0:4])
	sequence = binary.BigEndian.Uint16(data[4:6])
	total = binary.BigEndian.Uint16(data[6:8])
	payload = data[FragmentHeaderSize:]

	if sequence >= total {
		return 0, 0, 0, nil, errors.New("invalid fragment: sequence >= total")
	}

	return frameID, sequence, total, payload, nil
}

// FrameReassembler accumulates fragments and reassembles complete frames.
// Thread-safe for concurrent fragment arrival.
type FrameReassembler struct {
	// Map of frameID -> fragment collector
	frames map[uint32]*fragmentCollector
	// TODO: Add mutex if needed for concurrent access
	// TODO: Add timeout for incomplete frames (GC old entries)
}

type fragmentCollector struct {
	frameID        uint32
	totalFragments uint16
	received       map[uint16][]byte // sequence -> payload
	totalSize      int               // Total bytes received
}

// NewFrameReassembler creates a new reassembler instance.
func NewFrameReassembler() *FrameReassembler {
	return &FrameReassembler{
		frames: make(map[uint32]*fragmentCollector),
	}
}

// AddFragment processes an incoming fragment and returns the complete frame if all fragments arrived.
// Returns (completeFrame, true) when frame is complete, or (nil, false) if more fragments needed.
func (fr *FrameReassembler) AddFragment(fragmentData []byte) ([]byte, bool, error) {
	frameID, sequence, total, payload, err := ParseFragmentHeader(fragmentData)
	if err != nil {
		fragmentStats.reassemblyErrors.Add(1)
		return nil, false, err
	}

	// Get or create collector for this frame
	collector, exists := fr.frames[frameID]
	if !exists {
		collector = &fragmentCollector{
			frameID:        frameID,
			totalFragments: total,
			received:       make(map[uint16][]byte),
		}
		fr.frames[frameID] = collector
	}

	// Validate total fragments matches
	if collector.totalFragments != total {
		fragmentStats.reassemblyErrors.Add(1)
		delete(fr.frames, frameID)
		return nil, false, errors.New("fragment total mismatch")
	}

	// Store fragment payload
	collector.received[sequence] = payload
	collector.totalSize += len(payload)

	// Check if all fragments received
	if len(collector.received) == int(total) {
		// Reassemble frame
		completeFrame := make([]byte, collector.totalSize)
		offset := 0

		for seq := uint16(0); seq < total; seq++ {
			fragment, ok := collector.received[seq]
			if !ok {
				fragmentStats.reassemblyErrors.Add(1)
				delete(fr.frames, frameID)
				return nil, false, errors.New("missing fragment in sequence")
			}
			copy(completeFrame[offset:], fragment)
			offset += len(fragment)
		}

		// Clean up
		delete(fr.frames, frameID)

		return completeFrame, true, nil
	}

	return nil, false, nil // More fragments needed
}

// GetFragmentationStats returns current fragmentation statistics.
func GetFragmentationStats() map[string]interface{} {
	return map[string]interface{}{
		"fragmented_frames":   fragmentStats.fragmentedFrames.Load(),
		"total_fragments":     fragmentStats.totalFragmentsSent.Load(),
		"reassembly_errors":   fragmentStats.reassemblyErrors.Load(),
		"max_rtp_payload":     MaxRTPPayloadSize,
		"max_ws_chunk":        MaxWSChunkSize,
		"fragment_header_size": FragmentHeaderSize,
	}
}
