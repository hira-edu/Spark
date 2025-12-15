package desktop

import (
	"sync"
)

// HWFrameListener consumes GPU-backed capture frames. Callers must invoke
// frame.Release() when finished so COM references and other resources are
// returned to the pool.
type HWFrameListener func(frame *GPUFrame)

type hwFrameBroadcaster struct {
	mu        sync.RWMutex
	listeners map[uint64]HWFrameListener
	nextID    uint64
}

func newHWFrameBroadcaster() *hwFrameBroadcaster {
	return &hwFrameBroadcaster{
		listeners: make(map[uint64]HWFrameListener),
	}
}

// Register installs a listener and returns a function that removes it.
func (b *hwFrameBroadcaster) Register(listener HWFrameListener) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.nextID
	b.nextID++
	b.listeners[id] = listener
	return func() {
		b.mu.Lock()
		delete(b.listeners, id)
		b.mu.Unlock()
	}
}

func (b *hwFrameBroadcaster) HasListeners() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.listeners) > 0
}

// Dispatch clones the GPU frame (if present) and delivers it to all listeners.
// Each listener receives an independent AddRef'd resource and must call Release().
func (b *hwFrameBroadcaster) Dispatch(frame *CaptureFrame) {
	if frame == nil || frame.GPU == nil {
		return
	}

	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.listeners) == 0 {
		return
	}

	for _, listener := range b.listeners {
		cloned := cloneGPUFrame(frame.GPU)
		if cloned == nil {
			continue
		}
		listener(cloned)
	}
}

var globalHWFrameBroadcaster = newHWFrameBroadcaster()

// cloneGPUFrame duplicates metadata and adds a COM reference when possible.
func cloneGPUFrame(src *GPUFrame) *GPUFrame {
	if src == nil || src.Resource == nil {
		return nil
	}

	clone := *src

	// Special-case NV12 texture leases: keep the texture alive and prevent pool
	// reuse until every consumer releases it.
	if tex, ok := src.Resource.(*iD3D11Texture2D); ok && tex != nil {
		if release := retainNV12Lease(tex); release != nil {
			clone.Release = release
			return &clone
		}
	}

	// If the resource is a COM object, bump AddRef so listeners own the handle.
	type comObject interface {
		AddRef() uint32
		Release() uint32
	}
	if obj, ok := src.Resource.(comObject); ok {
		obj.AddRef()
		clone.Release = func() {
			obj.Release()
		}
	} else if src.Release != nil {
		clone.Release = src.Release
	}

	return &clone
}
