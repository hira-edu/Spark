package pipeline

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4/pkg/media"
)

type fakeCapturer struct {
	seq      atomic.Uint64
	released atomic.Uint64
}

func (f *fakeCapturer) Capture() (*CaptureFrame, error) {
	seq := f.seq.Add(1)
	return &CaptureFrame{
		Timestamp: time.Now(),
		FrameSeq:  seq,
		Release: func() {
			f.released.Add(1)
		},
	}, nil
}

func (f *fakeCapturer) Release() {}

type fakeEncoder struct {
	calls atomic.Uint64
}

func (f *fakeEncoder) Encode(frame *CaptureFrame, duration time.Duration) (media.Sample, error) {
	f.calls.Add(1)
	return media.Sample{Data: []byte{1, 2, 3}, Duration: duration}, nil
}

func (f *fakeEncoder) Close() error { return nil }

type fakeSender struct {
	calls atomic.Uint64
	fail  atomic.Bool
}

func (f *fakeSender) SendSample(sample media.Sample) error {
	f.calls.Add(1)
	if f.fail.Load() {
		return errors.New("send failed")
	}
	return nil
}

func TestPipelineCaptureDropOldest(t *testing.T) {
	capturer := &fakeCapturer{}
	encoder := &fakeEncoder{}
	sender := &fakeSender{}

	p := New(capturer, encoder, sender, Config{
		TargetFPS:       30,
		CaptureQueueLen: 1,
		EncodeQueueLen:  1,
	})

	p.captureFrame()
	p.captureFrame()

	if got := p.droppedCapture.Load(); got != 1 {
		t.Fatalf("droppedCapture=%d, want 1", got)
	}
	if got := capturer.released.Load(); got != 1 {
		t.Fatalf("released=%d, want 1 (oldest frame released)", got)
	}

	// Drain remaining queued frame(s) to avoid leaks.
	for {
		select {
		case frame := <-p.captureQueue:
			if frame != nil && frame.Release != nil {
				frame.Release()
			}
		default:
			return
		}
	}
}

func TestPipelineEncodeDropWhenQueueFull(t *testing.T) {
	capturer := &fakeCapturer{}
	encoder := &fakeEncoder{}
	sender := &fakeSender{}

	p := New(capturer, encoder, sender, Config{
		TargetFPS:       30,
		CaptureQueueLen: 2,
		EncodeQueueLen:  1,
	})

	// Fill encode queue so encodeLoop must drop.
	p.encodeQueue <- media.Sample{Data: []byte{9}, Duration: time.Second / 30}

	done := make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer close(done)
		p.encodeLoop()
	}()

	// Push a frame into the capture queue for encodeLoop to process.
	frame, _ := capturer.Capture()
	p.captureQueue <- frame

	deadline := time.NewTimer(1 * time.Second)
	defer deadline.Stop()

	for {
		if p.encodedFrames.Load() > 0 || p.droppedEncode.Load() > 0 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("timeout waiting for encodeLoop to process frame")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	p.cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("encodeLoop did not exit after cancel")
	}

	if got := p.droppedEncode.Load(); got != 1 {
		t.Fatalf("droppedEncode=%d, want 1", got)
	}
	if got := capturer.released.Load(); got != 1 {
		t.Fatalf("released=%d, want 1 (frame released after encode attempt)", got)
	}
}

func TestPipelineStartStop(t *testing.T) {
	capturer := &fakeCapturer{}
	encoder := &fakeEncoder{}
	sender := &fakeSender{}

	p := New(capturer, encoder, sender, Config{
		TargetFPS:       120,
		CaptureQueueLen: 3,
		EncodeQueueLen:  2,
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Start()
		time.Sleep(25 * time.Millisecond)
		p.Stop()
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pipeline Start/Stop timed out")
	}
}
