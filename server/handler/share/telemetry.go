package share

import (
	"Rocket/server/common"
	"sync/atomic"
)

var sharePolicyCounters struct {
	viewOnlyBlocks atomic.Uint64
	rateLimited    atomic.Uint64
	expiredKilled  atomic.Uint64
}

// recordShareViewOnlyBlock logs when a view-only guest attempts a blocked action
// ctx can be *gin.Context, *melody.Session, or nil for background operations
func recordShareViewOnlyBlock(ctx any, act, shareID string) {
	sharePolicyCounters.viewOnlyBlocks.Add(1)
	common.Warn(ctx, "SHARE_POLICY_VIEW_ONLY", "blocked", "view-only guest attempted control action", map[string]any{
		"action":   act,
		"share_id": shortShareID(shareID),
	})
}

// recordShareRateLimit logs when input events are rate limited
func recordShareRateLimit(ctx any, shareID string, tokens int64) {
	sharePolicyCounters.rateLimited.Add(1)
	common.Warn(ctx, "SHARE_POLICY_RATE_LIMIT", "triggered", "input rate limited", map[string]any{
		"share_id":         shortShareID(shareID),
		"remaining_tokens": tokens,
	})
}

// recordShareExpirationEnforcement logs when a session is terminated due to expiration
func recordShareExpirationEnforcement(ctx any, shareID string, reason string) {
	sharePolicyCounters.expiredKilled.Add(1)
	common.Warn(ctx, "SHARE_POLICY_EXPIRED", "terminated", "session terminated due to expiration", map[string]any{
		"share_id": shortShareID(shareID),
		"reason":   reason,
	})
}

// GetSharePolicyCounters returns the current policy enforcement counters for Prometheus
func GetSharePolicyCounters() map[string]uint64 {
	return map[string]uint64{
		"view_only_blocks": sharePolicyCounters.viewOnlyBlocks.Load(),
		"rate_limited":     sharePolicyCounters.rateLimited.Load(),
		"expired_killed":   sharePolicyCounters.expiredKilled.Load(),
	}
}

func shortShareID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "..."
}
