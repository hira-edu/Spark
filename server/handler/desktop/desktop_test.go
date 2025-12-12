package desktop

import (
	"strings"
	"testing"

	"Rocket/server/handler/utility"
)

func TestNormalizeCursorRejectsInvalidDimensions(t *testing.T) {
	payload := map[string]any{
		"width":  utility.MaxCursorWidth + 1,
		"height": 10,
		"data":   "AAAA",
	}
	if _, ok := normalizeCursor(payload); ok {
		t.Fatal("expected normalizeCursor to reject width over limit")
	}

	payload = map[string]any{
		"width":  10,
		"height": 0,
		"data":   "AAAA",
	}
	if _, ok := normalizeCursor(payload); ok {
		t.Fatal("expected normalizeCursor to reject zero height")
	}
}

func TestNormalizeCursorRejectsOversizedData(t *testing.T) {
	payload := map[string]any{
		"width":  32,
		"height": 32,
		"data":   strings.Repeat("A", utility.MaxCursorDataSize+1),
	}
	if _, ok := normalizeCursor(payload); ok {
		t.Fatal("expected normalizeCursor to reject cursor payloads exceeding MaxCursorDataSize")
	}
}

func TestNormalizeCursorAcceptsValidPayload(t *testing.T) {
	validData := map[string]any{
		"width":   32,
		"height":  32,
		"x":       100.0, // float to exercise coercion
		"y":       200,
		"hotX":    5,
		"hotY":    6,
		"hash":    123456,
		"visible": true,
		"format":  "ARGB32",
		"data":    strings.Repeat("b", utility.MaxCursorDataSize),
	}
	result, ok := normalizeCursor(validData)
	if !ok {
		t.Fatal("expected normalizeCursor to accept payload within limits")
	}

	if width, _ := result["width"].(int64); width != 32 {
		t.Fatalf("expected width 32, got %#v", result["width"])
	}
	if x, _ := result["x"].(int64); x != 100 {
		t.Fatalf("expected coerced x to equal 100, got %#v", result["x"])
	}
	if visible, _ := result["visible"].(bool); !visible {
		t.Fatalf("expected visible=true, got %#v", result["visible"])
	}
	if format, _ := result["format"].(string); format != "ARGB32" {
		t.Fatalf("expected format to be preserved, got %#v", format)
	}
	if data, _ := result["data"].(string); len(data) != utility.MaxCursorDataSize {
		t.Fatalf("expected cursor data length %d, got %d", utility.MaxCursorDataSize, len(data))
	}
}

func TestNormalizeConfigMonitorSelection(t *testing.T) {
	payload, ok := normalizeConfig(map[string]any{
		"fps":     float64(40),
		"quality": float64(75),
		"monitor": float32(2),
	})
	if !ok {
		t.Fatal("expected normalizeConfig to succeed with monitor specified")
	}
	if payload["fps"] != int64(40) {
		t.Fatalf("expected fps 40, got %#v", payload["fps"])
	}
	if payload["quality"] != int64(75) {
		t.Fatalf("expected quality 75, got %#v", payload["quality"])
	}
	if payload["monitor"] != int64(2) {
		t.Fatalf("expected monitor coerced to 2, got %#v", payload["monitor"])
	}

	payload, ok = normalizeConfig(map[string]any{
		"display":      float64(3),
		"codec":        " H264 ",
		"allowControl": true,
	})
	if !ok {
		t.Fatal("expected normalizeConfig to accept display alias")
	}
	if payload["monitor"] != int64(3) {
		t.Fatalf("expected display alias to map to monitor=3, got %#v", payload["monitor"])
	}
	if payload["codec"] != "h264" {
		t.Fatalf("expected codec to be normalized to lowercase, got %#v", payload["codec"])
	}
	if allow, _ := payload["allowControl"].(bool); !allow {
		t.Fatalf("expected allowControl to be true, got %#v", payload["allowControl"])
	}
}
