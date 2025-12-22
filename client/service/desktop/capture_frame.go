package desktop

import "image"

// CaptureFrame wraps the CPU/GPU data returned by a screen capture backend.
// CPU callers should read Image (if non-nil) while GPU-aware codecs can inspect
// GPU to leverage zero-copy pipelines.
type CaptureFrame struct {
	Image         *image.RGBA
	GPU           *GPUFrame
	CaptureTimeNs int64
}

// GPUFrame carries metadata about a GPU surface returned by a capture backend.
// Resource's concrete type is backend-dependent (e.g., *d3d11.ID3D11Texture2D).
type GPUFrame struct {
	Backend  string
	Width    int
	Height   int
	Format   string
	Stride   int
	Resource interface{}
	Release  func()
}

// Close releases GPU resources if provided. Always safe to call.
func (f *CaptureFrame) Close() {
	if f == nil || f.GPU == nil || f.GPU.Release == nil {
		return
	}
	f.GPU.Release()
	f.GPU.Release = nil
}
