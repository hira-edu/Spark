package desktop

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// DesktopSessionMetrics describes queue health for a single client session.
type DesktopSessionMetrics struct {
	SessionUUID        string  `json:"session_uuid"`
	ChannelLen         int     `json:"channel_len"`
	ChannelCap         int     `json:"channel_cap"`
	ChannelUtilization float64 `json:"channel_utilization"`
	HighWater          uint64  `json:"high_water"`
	FramesDropped      uint64  `json:"frames_dropped"`
	FramesDelivered    uint64  `json:"frames_delivered"`
	DeliveryRate       float64 `json:"delivery_rate"`
}

// LatencyHistogram tracks latency distribution in Prometheus-style buckets.
// Buckets: 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1000ms, 5000ms
type LatencyHistogram struct {
	buckets [8]atomic.Uint64 // Count per bucket
	sum     atomic.Int64     // Sum of all observations (for avg calculation)
	count   atomic.Uint64    // Total count
}

// Bucket boundaries in milliseconds
var latencyBuckets = []int64{10, 25, 50, 100, 250, 500, 1000, 5000}

// Observe records a latency observation in the histogram.
func (h *LatencyHistogram) Observe(latencyMs int64) {
	h.sum.Add(latencyMs)
	h.count.Add(1)

	// Find bucket and increment
	for i, boundary := range latencyBuckets {
		if latencyMs <= boundary {
			h.buckets[i].Add(1)
			return
		}
	}
	// Greater than largest bucket - goes in last bucket
	h.buckets[len(latencyBuckets)-1].Add(1)
}

// Snapshot returns current histogram values.
func (h *LatencyHistogram) Snapshot() map[string]any {
	bucketCounts := make(map[string]uint64)
	for i, boundary := range latencyBuckets {
		bucketCounts[fmt.Sprintf("le_%d", boundary)] = h.buckets[i].Load()
	}

	count := h.count.Load()
	var avg float64
	if count > 0 {
		avg = float64(h.sum.Load()) / float64(count)
	}

	return map[string]any{
		"buckets": bucketCounts,
		"sum":     h.sum.Load(),
		"count":   count,
		"avg_ms":  avg,
	}
}

// DesktopLatencyMetrics tracks various latency metrics.
var desktopLatencyMetrics = struct {
	frameDelivery  LatencyHistogram // Frame relay latency
	wsRoundTrip    LatencyHistogram // WebSocket ping/pong RTT
	handshake      LatencyHistogram // Handshake completion time
}{}

// RecordFrameDeliveryLatency records frame delivery latency.
func RecordFrameDeliveryLatency(latencyMs int64) {
	desktopLatencyMetrics.frameDelivery.Observe(latencyMs)
}

// RecordWSRoundTrip records WebSocket round-trip time.
func RecordWSRoundTrip(latencyMs int64) {
	desktopLatencyMetrics.wsRoundTrip.Observe(latencyMs)
}

// RecordHandshakeLatency records desktop handshake latency.
func RecordHandshakeLatency(latencyMs int64) {
	desktopLatencyMetrics.handshake.Observe(latencyMs)
}

// GetLatencyMetrics returns all latency histogram snapshots.
func GetLatencyMetrics() map[string]any {
	return map[string]any{
		"frame_delivery": desktopLatencyMetrics.frameDelivery.Snapshot(),
		"ws_round_trip":  desktopLatencyMetrics.wsRoundTrip.Snapshot(),
		"handshake":      desktopLatencyMetrics.handshake.Snapshot(),
	}
}

// DesktopMetricsEnvelope groups recent metrics for a desktop UUID/device.
type DesktopMetricsEnvelope struct {
	DeviceID    string                  `json:"device"`
	DesktopUUID string                  `json:"desktop_uuid"`
	GeneratedAt int64                   `json:"generated_at"`
	Sessions    []DesktopSessionMetrics `json:"sessions"`
}

var metricsStore = struct {
	sync.RWMutex
	data map[string]DesktopMetricsEnvelope
}{
	data: make(map[string]DesktopMetricsEnvelope),
}

func storeDesktopMetrics(envelope DesktopMetricsEnvelope) {
	metricsStore.Lock()
	defer metricsStore.Unlock()
	metricsStore.data[envelope.DesktopUUID] = envelope
}

func getDesktopMetrics(desktopUUID string) (DesktopMetricsEnvelope, bool) {
	metricsStore.RLock()
	defer metricsStore.RUnlock()
	envelope, ok := metricsStore.data[desktopUUID]
	return envelope, ok
}
