package desktop

import (
	"testing"
	"time"
)

func TestWebRTCControllerStateFlow(t *testing.T) {
	ctrl := newWebRTCController(500 * time.Millisecond)
	desktopID := "desk-123"

	// Record browser offer.
	ctrl.recordOffer(desktopID)
	snap := ctrl.snapshot(desktopID)
	if snap.LastOfferAt.IsZero() {
		t.Fatalf("expected LastOfferAt to be set")
	}
	if snap.AgentReady {
		t.Fatalf("agent should not be ready after offer")
	}

	// Record agent answer.
	ctrl.recordAnswer(desktopID)
	snap = ctrl.snapshot(desktopID)
	if snap.LastAnswerAt.IsZero() {
		t.Fatalf("expected LastAnswerAt to be set")
	}
	if !snap.AgentReady {
		t.Fatalf("agent should be ready after answer")
	}

	// Record candidate.
	ctrl.recordCandidate(desktopID)
	snap = ctrl.snapshot(desktopID)
	if snap.LastCandidate.IsZero() {
		t.Fatalf("expected LastCandidate to be set")
	}

	// Mark browser ready.
	ctrl.markBrowserReady(desktopID)
	snap = ctrl.snapshot(desktopID)
	if !snap.BrowserReady {
		t.Fatalf("browser should be marked ready")
	}

	// Ensure TTL extend later than now.
	if time.Until(snap.ExpiresAt) <= 0 {
		t.Fatalf("expected future expiry")
	}

	// Touch again to extend TTL and ensure snapshot returns same desktop.
	ctrl.touch(desktopID)
	snap2 := ctrl.snapshot(desktopID)
	if !snap2.ExpiresAt.After(snap.ExpiresAt) {
		t.Fatalf("expected expiry to extend after touch")
	}
}

func TestWebRTCControllerCandidateQueue(t *testing.T) {
	ctrl := newWebRTCController(time.Second)
	desktopID := "desk-queue"
	ctrl.recordOffer(desktopID)

	candidate := map[string]any{"candidate": "cand1"}
	if queued := ctrl.queueAgentCandidate(desktopID, candidate); !queued {
		t.Fatalf("expected candidate to be queued before browser ready")
	}

	ctrl.recordAnswer(desktopID)
	queued := ctrl.markBrowserReady(desktopID)
	if len(queued) != 1 {
		t.Fatalf("expected queued candidate to flush, got %d", len(queued))
	}
	if queued[0]["candidate"] != "cand1" {
		t.Fatalf("unexpected candidate payload: %v", queued[0])
	}

	// Now that browser is ready, subsequent candidates should not queue.
	if queued := ctrl.queueAgentCandidate(desktopID, map[string]any{"candidate": "cand2"}); queued {
		t.Fatalf("did not expect candidate to queue after browser ready")
	}
}
