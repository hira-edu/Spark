package desktop

import (
	"sync/atomic"
	"time"
)

// AdaptiveQualityManager dynamically adjusts encoding parameters based on network conditions.
// Implements best practices from WebRTC ABR algorithms and VNC/RDP adaptive streaming (2025).
//
// Key Metrics:
// - RTT (Round Trip Time): <50ms ideal, <150ms acceptable, >200ms degraded
// - Packet Loss: <1% ideal, <5% acceptable, >5% degraded
// - Queue Depth: Monitors pending bytes to detect network congestion
// - Frame Size: Enforces maximum to prevent transport fragmentation
//
// Quality Tiers (following industry standards):
// - High:   1200 kbps, JPEG quality 85-90
// - Medium:  600 kbps, JPEG quality 70-75
// - Low:     300 kbps, JPEG quality 50-60
type AdaptiveQualityManager struct {
	// Network metrics (atomic for lock-free reads)
	rttMs           atomic.Int64  // Current RTT in milliseconds
	packetLossRate  atomic.Uint32 // Packet loss as percentage * 100 (e.g., 150 = 1.5%)
	queueDepthBytes atomic.Int64  // Pending bytes in send queue

	// REMB (Receiver Estimated Maximum Bitrate) from RTCP feedback
	// This is the most reliable bandwidth estimate from the receiver
	rembBitrate   atomic.Int64 // REMB bitrate in bps (0 = not received)
	rembUpdatedAt atomic.Int64 // Unix nano timestamp of last REMB update

	// Quality parameters (atomic for lock-free updates)
	currentJPEGQuality atomic.Int32 // Current JPEG quality (1-100)
	currentBitrate     atomic.Int32 // Current bitrate in bps
	maxFrameSize       atomic.Int64 // Maximum allowed frame size in bytes

	// Adaptation state
	lastAdjustment atomic.Int64 // Unix nano timestamp of last quality change
	adaptationMode atomic.Int32 // 0=auto, 1=fixed high, 2=fixed low

	// Statistics
	qualityUpgrades   atomic.Uint64 // Count of quality increases
	qualityDowngrades atomic.Uint64 // Count of quality decreases
	droppedFrames     atomic.Uint64 // Frames dropped due to size/backpressure
	rembDowngrades    atomic.Uint64 // Count of downgrades due to REMB limit
}

// Quality tier constants based on 2025 ABR best practices
const (
	// Bitrate tiers (bits per second)
	BitrateHigh   = 1200000 // 1.2 Mbps
	BitrateMedium = 600000  // 600 kbps
	BitrateLow    = 300000  // 300 kbps

	// JPEG quality tiers (1-100)
	JPEGQualityHigh   = 85
	JPEGQualityMedium = 70
	JPEGQualityLow    = 55

	// Network condition thresholds (based on research)
	RTTIdealMs      = 50  // <50ms: ideal conditions
	RTTAcceptableMs = 150 // <150ms: acceptable
	RTTDegradedMs   = 200 // >200ms: degrade quality

	PacketLossIdeal      = 100 // <1% (stored as percentage * 100)
	PacketLossAcceptable = 500 // <5%

	QueueDepthWarning  = 512 * 1024  // 512 KB - start reducing quality
	QueueDepthCritical = 1024 * 1024 // 1 MB - aggressive reduction

	// Frame size limits (prevent fragmentation)
	// NOTE: Rocket's desktop WS path already chunks frames into ~65KB WebSocket messages.
	// The max-frame size here is therefore an *aggregate pacing/backpressure* hint (not an MTU limit).
	// If this is set too low, initial keyframes (DESKTOP_INIT/SHOT) get split into many sub-frames,
	// which shows up as slow/patchy "tile filling" during startup.
	MaxFrameSizeDefault = 1024 * 1024 // 1 MB default limit (keyframes should fit without excessive splitting)
	MaxFrameSizeMin     = 128 * 1024  // 128 KB minimum (extreme congestion)

	// Adaptation timing (prevent oscillation)
	MinAdaptationInterval = 2 * time.Second // Don't adjust more frequently than 2s
)

// NewAdaptiveQualityManager creates a new quality manager with default settings.
func NewAdaptiveQualityManager() *AdaptiveQualityManager {
	aqm := &AdaptiveQualityManager{}

	// Initialize to high quality (optimistic start)
	aqm.currentJPEGQuality.Store(JPEGQualityHigh)
	aqm.currentBitrate.Store(BitrateHigh)
	aqm.maxFrameSize.Store(MaxFrameSizeDefault)
	aqm.adaptationMode.Store(0) // Auto mode

	return aqm
}

// UpdateNetworkMetrics updates the current network condition metrics.
// Should be called periodically (e.g., every second) with current measurements.
func (aqm *AdaptiveQualityManager) UpdateNetworkMetrics(rttMs int64, packetLossPercent float64, queueBytes int64) {
	aqm.rttMs.Store(rttMs)
	aqm.packetLossRate.Store(uint32(packetLossPercent * 100))
	aqm.queueDepthBytes.Store(queueBytes)
}

// UpdateQueueDepth updates just the queue depth (called frequently during sending).
func (aqm *AdaptiveQualityManager) UpdateQueueDepth(queueBytes int64) {
	aqm.queueDepthBytes.Store(queueBytes)
}

// UpdateREMB updates the Receiver Estimated Maximum Bitrate from RTCP feedback.
// This is the most reliable bandwidth estimate and should be used to cap the bitrate.
func (aqm *AdaptiveQualityManager) UpdateREMB(bitrateBps int64) {
	aqm.rembBitrate.Store(bitrateBps)
	aqm.rembUpdatedAt.Store(time.Now().UnixNano())
}

// GetREMB returns the current REMB value and whether it's still valid (updated within 5s).
func (aqm *AdaptiveQualityManager) GetREMB() (bitrateBps int64, valid bool) {
	bitrateBps = aqm.rembBitrate.Load()
	if bitrateBps == 0 {
		return 0, false
	}
	updatedAt := aqm.rembUpdatedAt.Load()
	age := time.Duration(time.Now().UnixNano() - updatedAt)
	return bitrateBps, age < 5*time.Second
}

// Adapt analyzes current network conditions and adjusts quality parameters if needed.
// Returns true if quality was changed. Uses hysteresis to prevent oscillation.
func (aqm *AdaptiveQualityManager) Adapt() bool {
	// Skip if in fixed mode
	if aqm.adaptationMode.Load() != 0 {
		return false
	}

	// Enforce minimum time between adaptations (prevent oscillation)
	now := time.Now().UnixNano()
	lastAdj := aqm.lastAdjustment.Load()
	if lastAdj != 0 && time.Duration(now-lastAdj) < MinAdaptationInterval {
		return false
	}

	// Gather current metrics
	rtt := aqm.rttMs.Load()
	lossRate := aqm.packetLossRate.Load()
	queueDepth := aqm.queueDepthBytes.Load()

	// Calculate network score (0-100, higher is better)
	score := aqm.calculateNetworkScore(rtt, lossRate, queueDepth)

	// Get current quality tier
	currentQuality := aqm.currentJPEGQuality.Load()
	_ = aqm.currentBitrate.Load() // Keep for future use

	var newQuality int32
	var newBitrate int32
	var changed bool

	// Check REMB (receiver-estimated max bitrate) first - this is the most reliable signal
	rembBps, rembValid := aqm.GetREMB()
	var rembCappedTier int32 = -1 // -1 means no cap
	if rembValid && rembBps > 0 {
		// Determine max quality tier allowed by REMB
		if rembBps >= BitrateHigh {
			rembCappedTier = JPEGQualityHigh
		} else if rembBps >= BitrateMedium {
			rembCappedTier = JPEGQualityMedium
		} else {
			rembCappedTier = JPEGQualityLow
		}
	}

	// Determine target tier based on score with hysteresis
	// Upgrade threshold: 70+ (avoid premature upgrades)
	// Downgrade threshold: 40- (quick response to degradation)
	if score >= 70 && currentQuality < JPEGQualityHigh {
		// Upgrade to high quality (if REMB allows)
		if rembCappedTier < 0 || rembCappedTier >= JPEGQualityHigh {
			newQuality = JPEGQualityHigh
			newBitrate = BitrateHigh
			aqm.qualityUpgrades.Add(1)
			changed = true
		} else if rembCappedTier >= JPEGQualityMedium && currentQuality < JPEGQualityMedium {
			// REMB caps us at medium, but we can still upgrade from low
			newQuality = JPEGQualityMedium
			newBitrate = BitrateMedium
			aqm.qualityUpgrades.Add(1)
			aqm.rembDowngrades.Add(1) // Count as REMB-capped
			changed = true
		}
	} else if score >= 50 && score < 70 {
		// Medium quality range
		if currentQuality != JPEGQualityMedium {
			newQuality = JPEGQualityMedium
			newBitrate = BitrateMedium
			if currentQuality > JPEGQualityMedium {
				aqm.qualityDowngrades.Add(1)
			} else {
				aqm.qualityUpgrades.Add(1)
			}
			changed = true
		}
	} else if score < 40 && currentQuality > JPEGQualityLow {
		// Downgrade to low quality
		newQuality = JPEGQualityLow
		newBitrate = BitrateLow
		aqm.qualityDowngrades.Add(1)
		changed = true
	}

	// Apply REMB cap even if score-based logic didn't trigger a change
	if !changed && rembCappedTier >= 0 && currentQuality > rembCappedTier {
		// REMB says we're sending too fast - downgrade
		if rembCappedTier >= JPEGQualityMedium {
			newQuality = JPEGQualityMedium
			newBitrate = BitrateMedium
		} else {
			newQuality = JPEGQualityLow
			newBitrate = BitrateLow
		}
		aqm.rembDowngrades.Add(1)
		changed = true
	}

	if changed {
		aqm.currentJPEGQuality.Store(newQuality)
		aqm.currentBitrate.Store(newBitrate)
		aqm.lastAdjustment.Store(now)

		// Adjust max frame size based on quality tier
		if newQuality >= JPEGQualityHigh {
			aqm.maxFrameSize.Store(MaxFrameSizeDefault)
		} else if newQuality >= JPEGQualityMedium {
			aqm.maxFrameSize.Store(MaxFrameSizeDefault * 3 / 4) // 192 KB
		} else {
			aqm.maxFrameSize.Store(MaxFrameSizeDefault / 2) // 128 KB
		}
	}

	return changed
}

// calculateNetworkScore returns a score from 0 (worst) to 100 (best) based on network metrics.
// Uses weighted scoring: RTT 40%, packet loss 40%, queue depth 20%.
func (aqm *AdaptiveQualityManager) calculateNetworkScore(rtt int64, lossRate uint32, queueDepth int64) int32 {
	// RTT score (40% weight): 100 at 0ms, 80 at 50ms, 40 at 150ms, 0 at 200ms+
	var rttScore int32
	if rtt < RTTIdealMs {
		rttScore = 100
	} else if rtt < RTTAcceptableMs {
		// Linear interpolation: 100 at 0ms -> 40 at 150ms
		rttScore = 100 - int32((rtt*60)/RTTAcceptableMs)
	} else if rtt < RTTDegradedMs {
		// 40 at 150ms -> 0 at 200ms
		rttScore = 40 - int32(((rtt-RTTAcceptableMs)*40)/(RTTDegradedMs-RTTAcceptableMs))
	} else {
		rttScore = 0
	}

	// Packet loss score (40% weight): 100 at 0%, 80 at 1%, 20 at 5%, 0 at 10%+
	var lossScore int32
	lossPercent := float64(lossRate) / 100.0
	if lossPercent < 1.0 {
		lossScore = 100 - int32(lossPercent*20) // 100 at 0%, 80 at 1%
	} else if lossPercent < 5.0 {
		lossScore = 80 - int32((lossPercent-1.0)*15) // 80 at 1%, 20 at 5%
	} else if lossPercent < 10.0 {
		lossScore = 20 - int32((lossPercent-5.0)*4) // 20 at 5%, 0 at 10%
	} else {
		lossScore = 0
	}

	// Queue depth score (20% weight): 100 at 0KB, 50 at 512KB, 0 at 1MB+
	var queueScore int32
	if queueDepth < QueueDepthWarning {
		queueScore = 100 - int32((queueDepth*50)/QueueDepthWarning)
	} else if queueDepth < QueueDepthCritical {
		queueScore = 50 - int32(((queueDepth-QueueDepthWarning)*50)/(QueueDepthCritical-QueueDepthWarning))
	} else {
		queueScore = 0
	}

	// Weighted average
	totalScore := (rttScore*40 + lossScore*40 + queueScore*20) / 100

	if totalScore < 0 {
		totalScore = 0
	} else if totalScore > 100 {
		totalScore = 100
	}

	return totalScore
}

// GetCurrentJPEGQuality returns the current recommended JPEG quality (1-100).
func (aqm *AdaptiveQualityManager) GetCurrentJPEGQuality() int {
	return int(aqm.currentJPEGQuality.Load())
}

// GetCurrentBitrate returns the current recommended bitrate in bps.
func (aqm *AdaptiveQualityManager) GetCurrentBitrate() int {
	return int(aqm.currentBitrate.Load())
}

// GetMaxFrameSize returns the current maximum allowed frame size in bytes.
func (aqm *AdaptiveQualityManager) GetMaxFrameSize() int64 {
	return aqm.maxFrameSize.Load()
}

// ShouldDropFrame returns true if the given frame size exceeds current limits.
func (aqm *AdaptiveQualityManager) ShouldDropFrame(frameSize int64) bool {
	maxSize := aqm.maxFrameSize.Load()
	if frameSize > maxSize {
		aqm.droppedFrames.Add(1)
		return true
	}
	return false
}

// SetFixedQuality disables adaptive mode and sets a fixed quality level.
// quality: JPEG quality 1-100, bitrate: bps (or 0 to auto-calculate)
func (aqm *AdaptiveQualityManager) SetFixedQuality(quality int32, bitrate int32) {
	aqm.adaptationMode.Store(1) // Fixed mode
	aqm.currentJPEGQuality.Store(quality)
	if bitrate == 0 {
		// Auto-calculate bitrate based on quality
		if quality >= 80 {
			bitrate = BitrateHigh
		} else if quality >= 65 {
			bitrate = BitrateMedium
		} else {
			bitrate = BitrateLow
		}
	}
	aqm.currentBitrate.Store(bitrate)
}

// EnableAutoAdaptation re-enables automatic quality adaptation.
func (aqm *AdaptiveQualityManager) EnableAutoAdaptation() {
	aqm.adaptationMode.Store(0)
}

// GetStatistics returns current quality manager statistics.
func (aqm *AdaptiveQualityManager) GetStatistics() map[string]interface{} {
	return map[string]interface{}{
		"jpeg_quality":       aqm.currentJPEGQuality.Load(),
		"bitrate_bps":        aqm.currentBitrate.Load(),
		"max_frame_size":     aqm.maxFrameSize.Load(),
		"rtt_ms":             aqm.rttMs.Load(),
		"packet_loss_pct":    float64(aqm.packetLossRate.Load()) / 100.0,
		"queue_depth_bytes":  aqm.queueDepthBytes.Load(),
		"quality_upgrades":   aqm.qualityUpgrades.Load(),
		"quality_downgrades": aqm.qualityDowngrades.Load(),
		"dropped_frames":     aqm.droppedFrames.Load(),
		"adaptation_mode":    aqm.adaptationMode.Load(),
	}
}
