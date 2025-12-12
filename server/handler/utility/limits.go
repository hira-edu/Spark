// Package utility provides shared constants and helpers for request validation.
//
// This file centralizes security-critical payload limits that were previously
// duplicated across desktop.go, share.go, webrtc.go, webcam.go, and audio.go.
// All handlers should import these constants to ensure consistent validation.
//
// Reference: REMOTE_DESKTOP_PIPELINE_AUDIT.md - Payload Constant Centralization
package utility

const (
	// WebRTC signaling limits
	// These constrain SDP and ICE candidate payloads to prevent memory exhaustion.
	// Based on practical SDP sizes: typical offers are 2-4KB, complex ones up to 16KB.
	MaxSDPLength       = 1 << 15 // 32 KiB - accommodates large multi-codec SDPs
	MaxCandidateLength = 4096    // 4 KiB - typical ICE candidate is ~200 bytes

	// Clipboard payload limit
	// Prevents clipboard-based DoS while allowing reasonable text/image transfers.
	// Reference: RustDesk uses 2MB, noVNC uses 1MB, we use 64KB for conservative default.
	MaxClipboardBytes = 64 * 1024 // 64 KiB

	// File drop limits
	// Constrains metadata-only file drop notifications (actual transfer is separate).
	MaxFileDropEntries = 5   // Max files per drop event
	MaxFileNameLength  = 255 // POSIX NAME_MAX

	// Input batching limit
	// Prevents input event flooding while allowing smooth mouse movement.
	// 32 events at 60fps = ~500ms of buffered input.
	MaxDesktopInputBatch = 32

	// Cursor image limits
	// Prevents memory exhaustion from malicious cursor data.
	// 256x256 RGBA = 256KB raw, ~340KB base64 encoded.
	MaxCursorWidth  = 256
	MaxCursorHeight = 256
	// MaxCursorDataSize accounts for base64 encoding overhead (~1.33x)
	MaxCursorDataSize = MaxCursorWidth * MaxCursorHeight * 4 * 4 / 3

	// Audio payload limits (for WebRTC audio signaling)
	MaxAudioSDPLength       = MaxSDPLength
	MaxAudioCandidateLength = MaxCandidateLength
)

// ValidateSDPLength checks if SDP payload is within acceptable bounds.
func ValidateSDPLength(sdp string) bool {
	return len(sdp) > 0 && len(sdp) <= MaxSDPLength
}

// ValidateCandidateLength checks if ICE candidate is within acceptable bounds.
// Empty candidates are valid (signals end-of-candidates).
func ValidateCandidateLength(candidate string) bool {
	return len(candidate) <= MaxCandidateLength
}

// ValidateClipboardLength checks if clipboard payload is within bounds.
func ValidateClipboardLength(text string) bool {
	return len(text) <= MaxClipboardBytes
}

// TruncateClipboard returns clipboard text truncated to max length.
func TruncateClipboard(text string) string {
	if len(text) > MaxClipboardBytes {
		return text[:MaxClipboardBytes]
	}
	return text
}

// TruncateFileName returns filename truncated to max length.
func TruncateFileName(name string) string {
	if len(name) > MaxFileNameLength {
		return name[:MaxFileNameLength]
	}
	return name
}
