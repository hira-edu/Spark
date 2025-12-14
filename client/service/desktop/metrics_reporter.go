package desktop

import (
	"time"

	"Rocket/modules"
)

// sessionMetricsSnapshot captures the health of a desktop session queue.
type sessionMetricsSnapshot struct {
	SessionUUID        string  `json:"session_uuid"`
	ChannelLen         int     `json:"channel_len"`
	ChannelCap         int     `json:"channel_cap"`
	ChannelUtilization float64 `json:"channel_utilization"`
	HighWater          uint64  `json:"high_water"`
	FramesDropped      uint64  `json:"frames_dropped"`
	FramesDelivered    uint64  `json:"frames_delivered"`
	DeliveryRate       float64 `json:"delivery_rate"`
}

func init() {
	go metricsReporterLoop()
}

func metricsReporterLoop() {
	defer func() {
		if r := recover(); r != nil {
			recordRecoveredPanic("metricsReporterLoop", r)
			time.Sleep(500 * time.Millisecond)
			go metricsReporterLoop()
		}
	}()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		func() {
			defer func() {
				if r := recover(); r != nil {
					recordRecoveredPanic("publishDesktopMetrics", r)
				}
			}()
			publishDesktopMetrics()
		}()
	}
}

func publishDesktopMetrics() {
	snapshots := collectSessionSnapshots()
	if len(snapshots) == 0 {
		return
	}

	payload := map[string]any{
		"sessions":     snapshots,
		"generated_at": time.Now().Unix(),
	}

	sendDesktopPacket(modules.Packet{
		Act:  "DESKTOP_METRICS",
		Data: payload,
	}, nil)
}

func collectSessionSnapshots() []sessionMetricsSnapshot {
	out := make([]sessionMetricsSnapshot, 0)
	sessions.IterCb(func(uuid string, sess *session) bool {
		if snapshot, ok := buildSessionSnapshot(uuid, sess); ok {
			out = append(out, snapshot)
		}
		return true
	})
	return out
}

func buildSessionSnapshot(uuid string, sess *session) (sessionMetricsSnapshot, bool) {
	sess.lock.Lock()
	defer sess.lock.Unlock()

	if sess.channel == nil {
		return sessionMetricsSnapshot{}, false
	}

	channelLen := len(sess.channel)
	channelCap := cap(sess.channel)

	util := float64(0)
	if channelCap > 0 {
		util = float64(channelLen) / float64(channelCap) * 100
	}

	dropped := sess.framesDropped.Load()
	delivered := sess.framesDelivered.Load()
	total := dropped + delivered
	deliveryRate := float64(100)
	if total > 0 {
		deliveryRate = float64(delivered) / float64(total) * 100
	}

	return sessionMetricsSnapshot{
		SessionUUID:        uuid,
		ChannelLen:         channelLen,
		ChannelCap:         channelCap,
		ChannelUtilization: util,
		HighWater:          sess.channelHighWater.Load(),
		FramesDropped:      dropped,
		FramesDelivered:    delivered,
		DeliveryRate:       deliveryRate,
	}, true
}
