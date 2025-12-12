package desktop

import "sync"

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
