package ipc

import (
	"bytes"
	"io"
	"testing"
)

type shortWriter struct {
	w   io.Writer
	max int
}

func (s *shortWriter) Write(p []byte) (int, error) {
	if s.max > 0 && len(p) > s.max {
		p = p[:s.max]
	}
	return s.w.Write(p)
}

func TestWriteMessageHandlesShortWrites(t *testing.T) {
	var buf bytes.Buffer
	sw := &shortWriter{w: &buf, max: 3}

	payload := bytes.Repeat([]byte{0xAB}, 100)
	if err := WriteMessage(sw, &Message{Type: 42, Payload: payload}); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	msg, err := ReadMessage(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if msg.Type != 42 {
		t.Fatalf("Type mismatch: got %d want %d", msg.Type, 42)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Fatalf("Payload mismatch: got %d bytes want %d", len(msg.Payload), len(payload))
	}
}

