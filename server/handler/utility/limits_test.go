package utility

import (
	"strings"
	"testing"
)

func TestValidateSDPLength(t *testing.T) {
	valid := strings.Repeat("v", MaxSDPLength)
	if !ValidateSDPLength(valid) {
		t.Fatalf("expected SDP with length %d to be accepted", len(valid))
	}

	tooLong := strings.Repeat("x", MaxSDPLength+1)
	if ValidateSDPLength(tooLong) {
		t.Fatalf("expected SDP length %d to be rejected", len(tooLong))
	}
}

func TestValidateCandidateLength(t *testing.T) {
	valid := strings.Repeat("c", MaxCandidateLength)
	if !ValidateCandidateLength(valid) {
		t.Fatalf("expected ICE candidate length %d to be accepted", len(valid))
	}

	tooLong := strings.Repeat("c", MaxCandidateLength+1)
	if ValidateCandidateLength(tooLong) {
		t.Fatalf("expected ICE candidate length %d to be rejected", len(tooLong))
	}
}

func TestClipboardLimits(t *testing.T) {
	if !ValidateClipboardLength("short text") {
		t.Fatal("expected short clipboard payload to be valid")
	}

	long := strings.Repeat("a", MaxClipboardBytes+1)
	if ValidateClipboardLength(long) {
		t.Fatal("expected clipboard payload larger than limit to be rejected")
	}

	truncated := TruncateClipboard(long)
	if len(truncated) != MaxClipboardBytes {
		t.Fatalf("expected truncated clipboard length %d, got %d", MaxClipboardBytes, len(truncated))
	}
}

func TestTruncateFileName(t *testing.T) {
	name := strings.Repeat("n", MaxFileNameLength+5)
	truncated := TruncateFileName(name)
	if len(truncated) != MaxFileNameLength {
		t.Fatalf("expected filename to be truncated to %d, got %d", MaxFileNameLength, len(truncated))
	}

	if TruncateFileName("abc") != "abc" {
		t.Fatal("expected short filenames to remain unchanged")
	}
}
