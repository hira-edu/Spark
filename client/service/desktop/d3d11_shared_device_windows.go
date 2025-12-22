//go:build windows

package desktop

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// captureD3D11Device holds an AddRef'd ID3D11Device from the active capture
// backend (DXGI NV12). Encoders may request an AddRef'd copy for zero-copy
// Media Foundation pipelines.
var captureD3D11Device atomic.Value // *iD3D11Device

func setCaptureD3D11Device(dev *iD3D11Device) {
	var prev *iD3D11Device
	if v := captureD3D11Device.Load(); v != nil {
		prev, _ = v.(*iD3D11Device)
	}

	if dev != nil {
		dev.AddRef()
		captureD3D11Device.Store(dev)
	} else {
		captureD3D11Device.Store((*iD3D11Device)(nil))
	}

	if prev != nil {
		prev.Release()
	}
}

func getCaptureD3D11Device() *iD3D11Device {
	if v := captureD3D11Device.Load(); v != nil {
		if dev, ok := v.(*iD3D11Device); ok && dev != nil {
			dev.AddRef()
			return dev
		}
	}
	return nil
}

// NV12ReadbackContext holds resources for reading GPU NV12 textures back to CPU.
type NV12ReadbackContext struct {
	device     *iD3D11Device
	deviceCtx  *iD3D11DeviceContextExt
	stagingTex *iD3D11Texture2D
	surface    *iDXGISurface
	width      int
	height     int
	mu         sync.Mutex
}

// iD3D11DeviceContextExt extends iD3D11DeviceContext with CopyResource
type iD3D11DeviceContextExt struct {
	vtbl *iD3D11DeviceContextExtVtbl
}

type iD3D11DeviceContextExtVtbl struct {
	QueryInterface                uintptr // 0
	AddRef                        uintptr // 1
	Release                       uintptr // 2
	GetDevice                     uintptr // 3
	GetPrivateData                uintptr // 4
	SetPrivateData                uintptr // 5
	SetPrivateDataInterface       uintptr // 6
	VSSetConstantBuffers          uintptr // 7
	PSSetShaderResources          uintptr // 8
	PSSetShader                   uintptr // 9
	PSSetSamplers                 uintptr // 10
	VSSetShader                   uintptr // 11
	DrawIndexed                   uintptr // 12
	Draw                          uintptr // 13
	Map                           uintptr // 14
	Unmap                         uintptr // 15
	PSSetConstantBuffers          uintptr // 16
	IASetInputLayout              uintptr // 17
	IASetVertexBuffers            uintptr // 18
	IASetIndexBuffer              uintptr // 19
	DrawIndexedInstanced          uintptr // 20
	DrawInstanced                 uintptr // 21
	GSSetConstantBuffers          uintptr // 22
	GSSetShader                   uintptr // 23
	IASetPrimitiveTopology        uintptr // 24
	VSSetShaderResources          uintptr // 25
	VSSetSamplers                 uintptr // 26
	Begin                         uintptr // 27
	End                           uintptr // 28
	GetData                       uintptr // 29
	SetPredication                uintptr // 30
	GSSetShaderResources          uintptr // 31
	GSSetSamplers                 uintptr // 32
	OMSetRenderTargets            uintptr // 33
	OMSetRenderTargetsAndUAVs     uintptr // 34
	OMSetBlendState               uintptr // 35
	OMSetDepthStencilState        uintptr // 36
	SOSetTargets                  uintptr // 37
	DrawAuto                      uintptr // 38
	DrawIndexedInstancedIndirect  uintptr // 39
	DrawInstancedIndirect         uintptr // 40
	Dispatch                      uintptr // 41
	DispatchIndirect              uintptr // 42
	RSSetState                    uintptr // 43
	RSSetViewports                uintptr // 44
	RSSetScissorRects             uintptr // 45
	CopySubresourceRegion         uintptr // 46
	CopyResource                  uintptr // 47
	UpdateSubresource             uintptr // 48
	CopyStructureCount            uintptr // 49
	ClearRenderTargetView         uintptr // 50
	ClearUnorderedAccessViewUint  uintptr // 51
	ClearUnorderedAccessViewFloat uintptr // 52
	ClearDepthStencilView         uintptr // 53
	GenerateMips                  uintptr // 54
	SetResourceMinLOD             uintptr // 55
	GetResourceMinLOD             uintptr // 56
	ResolveSubresource            uintptr // 57
	ExecuteCommandList            uintptr // 58
	HSSetShaderResources          uintptr // 59
	HSSetShader                   uintptr // 60
	HSSetSamplers                 uintptr // 61
	HSSetConstantBuffers          uintptr // 62
	DSSetShaderResources          uintptr // 63
	DSSetShader                   uintptr // 64
	DSSetSamplers                 uintptr // 65
	DSSetConstantBuffers          uintptr // 66
	CSSetShaderResources          uintptr // 67
	CSSetUnorderedAccessViews     uintptr // 68
	CSSetShader                   uintptr // 69
	CSSetSamplers                 uintptr // 70
	CSSetConstantBuffers          uintptr // 71
	VSGetConstantBuffers          uintptr // 72
	PSGetShaderResources          uintptr // 73
	PSGetShader                   uintptr // 74
	PSGetSamplers                 uintptr // 75
	VSGetShader                   uintptr // 76
	PSGetConstantBuffers          uintptr // 77
	IAGetInputLayout              uintptr // 78
	IAGetVertexBuffers            uintptr // 79
	IAGetIndexBuffer              uintptr // 80
	GSGetConstantBuffers          uintptr // 81
	GSGetShader                   uintptr // 82
	IAGetPrimitiveTopology        uintptr // 83
	VSGetShaderResources          uintptr // 84
	VSGetSamplers                 uintptr // 85
	GetPredication                uintptr // 86
	GSGetShaderResources          uintptr // 87
	GSGetSamplers                 uintptr // 88
	OMGetRenderTargets            uintptr // 89
	OMGetRenderTargetsAndUAVs     uintptr // 90
	OMGetBlendState               uintptr // 91
	OMGetDepthStencilState        uintptr // 92
	SOGetTargets                  uintptr // 93
	RSGetState                    uintptr // 94
	RSGetViewports                uintptr // 95
	RSGetScissorRects             uintptr // 96
	HSGetShaderResources          uintptr // 97
	HSGetShader                   uintptr // 98
	HSGetSamplers                 uintptr // 99
	HSGetConstantBuffers          uintptr // 100
	DSGetShaderResources          uintptr // 101
	DSGetShader                   uintptr // 102
	DSGetSamplers                 uintptr // 103
	DSGetConstantBuffers          uintptr // 104
	CSGetShaderResources          uintptr // 105
	CSGetUnorderedAccessViews     uintptr // 106
	CSGetShader                   uintptr // 107
	CSGetSamplers                 uintptr // 108
	CSGetConstantBuffers          uintptr // 109
	ClearState                    uintptr // 110
	Flush                         uintptr // 111
	GetType                       uintptr // 112
	GetContextFlags               uintptr // 113
	FinishCommandList             uintptr // 114
}

func (c *iD3D11DeviceContextExt) Release() {
	if c == nil || c.vtbl == nil {
		return
	}
	syscall.SyscallN(c.vtbl.Release, uintptr(unsafe.Pointer(c)))
}

func (c *iD3D11DeviceContextExt) QueryInterface(iid *windows.GUID) (unsafe.Pointer, error) {
	if c == nil || c.vtbl == nil {
		return nil, fmt.Errorf("nil device context")
	}
	var result unsafe.Pointer
	r0, _, _ := syscall.SyscallN(
		c.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(c)),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&result)),
	)
	if err := hresultError(r0, "QueryInterface"); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *iD3D11DeviceContextExt) CopyResource(dst, src unsafe.Pointer) {
	if c == nil || c.vtbl == nil {
		return
	}
	syscall.SyscallN(c.vtbl.CopyResource,
		uintptr(unsafe.Pointer(c)),
		uintptr(dst),
		uintptr(src),
	)
}

func (c *iD3D11DeviceContextExt) Flush() {
	if c == nil || c.vtbl == nil || c.vtbl.Flush == 0 {
		return
	}
	syscall.SyscallN(c.vtbl.Flush, uintptr(unsafe.Pointer(c)))
}

// dxgiMappedRect matches DXGI_MAPPED_RECT for surface mapping
type dxgiMappedRect struct {
	Pitch int32
	Bits  *byte
}

const dxgiMapRead = 1

// Map maps the surface for CPU read access.
func (s *iDXGISurface) Map(rect *dxgiMappedRect, flags uint32) error {
	r0, _, _ := syscall.SyscallN(s.vtbl.Map,
		uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(rect)),
		uintptr(flags),
	)
	return hresultError(r0, "IDXGISurface.Map")
}

// Unmap unmaps a previously mapped surface.
func (s *iDXGISurface) Unmap() {
	if s == nil || s.vtbl == nil {
		return
	}
	syscall.SyscallN(s.vtbl.Unmap, uintptr(unsafe.Pointer(s)))
}

// NewNV12ReadbackContext creates a context for reading NV12 GPU textures to CPU.
func NewNV12ReadbackContext(device *iD3D11Device) (*NV12ReadbackContext, error) {
	if envIsTruthy("SPARK_H264_HW_ONLY") {
		return nil, fmt.Errorf("NV12ReadbackContext is disabled in hardware-only mode (SPARK_H264_HW_ONLY)")
	}
	if device == nil {
		return nil, fmt.Errorf("nil device")
	}

	// Ensure GUIDs are initialized
	initDXGINV12GUIDs()

	// Get immediate context
	var ctx *iD3D11DeviceContextExt
	syscall.SyscallN(device.vtbl.GetImmediateContext,
		uintptr(unsafe.Pointer(device)),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ctx == nil {
		return nil, fmt.Errorf("failed to get immediate context")
	}

	// D3D11 immediate contexts are not thread-safe by default. In this codebase, capture and
	// encoder readback can happen on different locked OS threads. Enable multithread protection
	// so CopyResource/Map do not race the video processor blit, avoiding DXGI_ERROR_DEVICE_REMOVED.
	if err := enableD3D11MultithreadProtection(ctx); err != nil {
		fmt.Printf("[DXGI] failed to enable D3D11 multithread protection (readback): %v\n", err)
	}

	device.AddRef()
	return &NV12ReadbackContext{
		device:    device,
		deviceCtx: ctx,
	}, nil
}

// d3d11Texture2DDescReadback matches D3D11_TEXTURE2D_DESC for creating staging textures
type d3d11Texture2DDescReadback struct {
	Width          uint32
	Height         uint32
	MipLevels      uint32
	ArraySize      uint32
	Format         uint32
	SampleDesc     struct{ Count, Quality uint32 }
	Usage          uint32
	BindFlags      uint32
	CPUAccessFlags uint32
	MiscFlags      uint32
}

const (
	d3d11UsageStaging   = 3
	d3d11CPUAccessRead  = 0x20000
	dxgiFormatNV12Local = 103
)

// ensureStaging creates or resizes the staging texture for the given dimensions.
func (rc *NV12ReadbackContext) ensureStaging(width, height int) error {
	if rc.stagingTex != nil && rc.width == width && rc.height == height {
		return nil
	}

	// Release old resources
	if rc.surface != nil {
		rc.surface.Release()
		rc.surface = nil
	}
	if rc.stagingTex != nil {
		rc.stagingTex.Release()
		rc.stagingTex = nil
	}

	// Create staging texture
	desc := d3d11Texture2DDescReadback{
		Width:          uint32(width),
		Height:         uint32(height),
		MipLevels:      1,
		ArraySize:      1,
		Format:         dxgiFormatNV12Local,
		SampleDesc:     struct{ Count, Quality uint32 }{1, 0},
		Usage:          d3d11UsageStaging,
		BindFlags:      0,
		CPUAccessFlags: d3d11CPUAccessRead,
		MiscFlags:      0,
	}

	var tex *iD3D11Texture2D
	r0, _, _ := syscall.SyscallN(
		rc.device.vtbl.CreateTexture2D,
		uintptr(unsafe.Pointer(rc.device)),
		uintptr(unsafe.Pointer(&desc)),
		0,
		uintptr(unsafe.Pointer(&tex)),
	)
	if err := hresultError(r0, "CreateTexture2D(staging)"); err != nil {
		return err
	}

	// Query IDXGISurface for mapping
	var surface *iDXGISurface
	r0, _, _ = syscall.SyscallN(
		tex.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(tex)),
		uintptr(unsafe.Pointer(&iidIDXGISurface)),
		uintptr(unsafe.Pointer(&surface)),
	)
	if err := hresultError(r0, "QueryInterface(IDXGISurface)"); err != nil {
		tex.Release()
		return err
	}

	rc.stagingTex = tex
	rc.surface = surface
	rc.width = width
	rc.height = height
	return nil
}

// ReadbackNV12 reads an NV12 GPU texture to a CPU buffer.
// The buffer must be at least width*height*3/2 bytes.
func (rc *NV12ReadbackContext) ReadbackNV12(gpuTex *iD3D11Texture2D, width, height int, buf []byte) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if gpuTex == nil {
		return fmt.Errorf("nil GPU texture")
	}

	expectedSize := width * height * 3 / 2
	if len(buf) < expectedSize {
		return fmt.Errorf("buffer too small: need %d, got %d", expectedSize, len(buf))
	}

	if err := rc.ensureStaging(width, height); err != nil {
		return err
	}

	// Copy GPU texture to staging
	rc.deviceCtx.CopyResource(unsafe.Pointer(rc.stagingTex), unsafe.Pointer(gpuTex))
	// Ensure the copy is submitted before we map the staging texture.
	rc.deviceCtx.Flush()

	// Map staging texture
	var mapped dxgiMappedRect
	if err := rc.surface.Map(&mapped, dxgiMapRead); err != nil {
		return err
	}
	defer rc.surface.Unmap()

	pitch := int(mapped.Pitch)
	srcPtr := unsafe.Pointer(mapped.Bits)

	// Copy Y plane (height rows, each row is width bytes, but pitch may differ)
	yPlaneSize := width * height
	if pitch == width {
		// Fast path: pitch matches width
		copy(buf[:yPlaneSize], unsafe.Slice((*byte)(srcPtr), yPlaneSize))
	} else {
		// Row-by-row copy
		for y := 0; y < height; y++ {
			srcRow := unsafe.Add(srcPtr, y*pitch)
			dstOffset := y * width
			copy(buf[dstOffset:dstOffset+width], unsafe.Slice((*byte)(srcRow), width))
		}
	}

	// Copy UV plane (height/2 rows, each row is width bytes)
	uvSrcStart := unsafe.Add(srcPtr, pitch*height)
	uvHeight := height / 2
	if pitch == width {
		uvSize := width * uvHeight
		copy(buf[yPlaneSize:], unsafe.Slice((*byte)(uvSrcStart), uvSize))
	} else {
		for y := 0; y < uvHeight; y++ {
			srcRow := unsafe.Add(uvSrcStart, y*pitch)
			dstOffset := yPlaneSize + y*width
			copy(buf[dstOffset:dstOffset+width], unsafe.Slice((*byte)(srcRow), width))
		}
	}

	return nil
}

// Release frees resources.
func (rc *NV12ReadbackContext) Release() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.surface != nil {
		rc.surface.Release()
		rc.surface = nil
	}
	if rc.stagingTex != nil {
		rc.stagingTex.Release()
		rc.stagingTex = nil
	}
	if rc.deviceCtx != nil {
		rc.deviceCtx.Release()
		rc.deviceCtx = nil
	}
	if rc.device != nil {
		rc.device.Release()
		rc.device = nil
	}
}

// ---- NV12 Upload Context ----
// For uploading CPU NV12 data (with perf marker) to GPU texture for hardware encoding.

const (
	d3d11CPUAccessWrite   = 0x10000
	d3d11BindVideoEncoder = 0x200000 // D3D11_BIND_VIDEO_ENCODER
	dxgiMapWrite          = 2
	dxgiMapWriteDiscard   = 4
)

// NV12UploadContext holds resources for uploading CPU NV12 data to GPU textures.
type NV12UploadContext struct {
	device     *iD3D11Device
	deviceCtx  *iD3D11DeviceContextExt
	stagingTex *iD3D11Texture2D
	surface    *iDXGISurface
	defaultTex *iD3D11Texture2D // DEFAULT usage texture for encoder input
	width      int
	height     int
	mu         sync.Mutex
}

// NewNV12UploadContext creates a context for uploading CPU NV12 data to GPU textures.
func NewNV12UploadContext(device *iD3D11Device) (*NV12UploadContext, error) {
	if device == nil {
		return nil, fmt.Errorf("nil device")
	}

	initDXGINV12GUIDs()

	var ctx *iD3D11DeviceContextExt
	syscall.SyscallN(device.vtbl.GetImmediateContext,
		uintptr(unsafe.Pointer(device)),
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ctx == nil {
		return nil, fmt.Errorf("failed to get immediate context")
	}

	if err := enableD3D11MultithreadProtection(ctx); err != nil {
		fmt.Printf("[DXGI] failed to enable D3D11 multithread protection (upload): %v\n", err)
	}

	device.AddRef()
	return &NV12UploadContext{
		device:    device,
		deviceCtx: ctx,
	}, nil
}

// ensureTextures creates or resizes the staging and default textures.
func (uc *NV12UploadContext) ensureTextures(width, height int) error {
	if uc.stagingTex != nil && uc.width == width && uc.height == height {
		return nil
	}

	// Release old resources
	if uc.surface != nil {
		uc.surface.Release()
		uc.surface = nil
	}
	if uc.stagingTex != nil {
		uc.stagingTex.Release()
		uc.stagingTex = nil
	}
	if uc.defaultTex != nil {
		uc.defaultTex.Release()
		uc.defaultTex = nil
	}

	// Create staging texture (CPU writable)
	stagingDesc := d3d11Texture2DDescReadback{
		Width:          uint32(width),
		Height:         uint32(height),
		MipLevels:      1,
		ArraySize:      1,
		Format:         dxgiFormatNV12Local,
		SampleDesc:     struct{ Count, Quality uint32 }{1, 0},
		Usage:          d3d11UsageStaging,
		BindFlags:      0,
		CPUAccessFlags: d3d11CPUAccessWrite,
		MiscFlags:      0,
	}

	var staging *iD3D11Texture2D
	r0, _, _ := syscall.SyscallN(
		uc.device.vtbl.CreateTexture2D,
		uintptr(unsafe.Pointer(uc.device)),
		uintptr(unsafe.Pointer(&stagingDesc)),
		0,
		uintptr(unsafe.Pointer(&staging)),
	)
	if err := hresultError(r0, "CreateTexture2D(staging-write)"); err != nil {
		return err
	}

	// Query IDXGISurface for mapping
	var surface *iDXGISurface
	r0, _, _ = syscall.SyscallN(
		staging.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(staging)),
		uintptr(unsafe.Pointer(&iidIDXGISurface)),
		uintptr(unsafe.Pointer(&surface)),
	)
	if err := hresultError(r0, "QueryInterface(IDXGISurface)"); err != nil {
		staging.Release()
		return err
	}

	// Create DEFAULT texture (for encoder input via DXGI)
	// NOTE: D3D11_BIND_VIDEO_ENCODER is not valid for NV12 textures on all GPUs.
	// Use no bind flags - hardware encoders should accept DEFAULT NV12 textures via DXGI.
	defaultDesc := d3d11Texture2DDescReadback{
		Width:          uint32(width),
		Height:         uint32(height),
		MipLevels:      1,
		ArraySize:      1,
		Format:         dxgiFormatNV12Local,
		SampleDesc:     struct{ Count, Quality uint32 }{1, 0},
		Usage:          d3d11UsageDefault,
		BindFlags:      0,
		CPUAccessFlags: 0,
		MiscFlags:      0,
	}

	var defaultTex *iD3D11Texture2D
	r0, _, _ = syscall.SyscallN(
		uc.device.vtbl.CreateTexture2D,
		uintptr(unsafe.Pointer(uc.device)),
		uintptr(unsafe.Pointer(&defaultDesc)),
		0,
		uintptr(unsafe.Pointer(&defaultTex)),
	)
	if err := hresultError(r0, "CreateTexture2D(default)"); err != nil {
		surface.Release()
		staging.Release()
		return err
	}

	uc.stagingTex = staging
	uc.surface = surface
	uc.defaultTex = defaultTex
	uc.width = width
	uc.height = height
	return nil
}

// UploadNV12 uploads CPU NV12 data to a GPU texture suitable for DXGI-based encoding.
// Returns the DEFAULT texture that can be used with DXGIDeviceManager.CreateSampleFromTexture.
func (uc *NV12UploadContext) UploadNV12(buf []byte, width, height int) (*iD3D11Texture2D, error) {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	expectedSize := width * height * 3 / 2
	if len(buf) < expectedSize {
		return nil, fmt.Errorf("buffer too small: need %d, got %d", expectedSize, len(buf))
	}

	if err := uc.ensureTextures(width, height); err != nil {
		return nil, err
	}

	// Map staging texture for write
	var mapped dxgiMappedRect
	if err := uc.surface.Map(&mapped, dxgiMapWrite); err != nil {
		return nil, err
	}

	pitch := int(mapped.Pitch)
	dstPtr := unsafe.Pointer(mapped.Bits)

	// Copy Y plane
	yPlaneSize := width * height
	if pitch == width {
		copy(unsafe.Slice((*byte)(dstPtr), yPlaneSize), buf[:yPlaneSize])
	} else {
		for y := 0; y < height; y++ {
			dstRow := unsafe.Add(dstPtr, y*pitch)
			srcOffset := y * width
			copy(unsafe.Slice((*byte)(dstRow), width), buf[srcOffset:srcOffset+width])
		}
	}

	// Copy UV plane
	uvDstStart := unsafe.Add(dstPtr, pitch*height)
	uvHeight := height / 2
	if pitch == width {
		uvSize := width * uvHeight
		copy(unsafe.Slice((*byte)(uvDstStart), uvSize), buf[yPlaneSize:yPlaneSize+uvSize])
	} else {
		for y := 0; y < uvHeight; y++ {
			dstRow := unsafe.Add(uvDstStart, y*pitch)
			srcOffset := yPlaneSize + y*width
			copy(unsafe.Slice((*byte)(dstRow), width), buf[srcOffset:srcOffset+width])
		}
	}

	uc.surface.Unmap()

	// Copy staging to default texture
	uc.deviceCtx.CopyResource(unsafe.Pointer(uc.defaultTex), unsafe.Pointer(uc.stagingTex))
	uc.deviceCtx.Flush()

	return uc.defaultTex, nil
}

// Release frees resources.
func (uc *NV12UploadContext) Release() {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if uc.surface != nil {
		uc.surface.Release()
		uc.surface = nil
	}
	if uc.stagingTex != nil {
		uc.stagingTex.Release()
		uc.stagingTex = nil
	}
	if uc.defaultTex != nil {
		uc.defaultTex.Release()
		uc.defaultTex = nil
	}
	if uc.deviceCtx != nil {
		uc.deviceCtx.Release()
		uc.deviceCtx = nil
	}
	if uc.device != nil {
		uc.device.Release()
		uc.device = nil
	}
}

// ---- D3D11 multithread protection ----

var (
	iidID3D11Multithread windows.GUID
	mtGUIDOnce           sync.Once
	mtGUIDErr            error
)

func initMultithreadGUID() error {
	mtGUIDOnce.Do(func() {
		// ID3D11Multithread: enables runtime locking for cross-thread D3D11 usage.
		// This differs from ID3D10Multithread (9B7E4C0F-...) and is defined in d3d11_4.h.
		iidID3D11Multithread, mtGUIDErr = windows.GUIDFromString("{9B7E4E00-342C-4106-A19F-4F2704F689F0}")
	})
	return mtGUIDErr
}

type iD3D11Multithread struct {
	vtbl *iD3D11MultithreadVtbl
}

type iD3D11MultithreadVtbl struct {
	QueryInterface          uintptr
	AddRef                  uintptr
	Release                 uintptr
	Enter                   uintptr
	Leave                   uintptr
	SetMultithreadProtected uintptr
	GetMultithreadProtected uintptr
}

func (m *iD3D11Multithread) Release() {
	if m == nil || m.vtbl == nil {
		return
	}
	syscall.SyscallN(m.vtbl.Release, uintptr(unsafe.Pointer(m)))
}

func (m *iD3D11Multithread) SetMultithreadProtected(enabled bool) error {
	if m == nil || m.vtbl == nil || m.vtbl.SetMultithreadProtected == 0 {
		return fmt.Errorf("nil multithread interface")
	}
	var flag uintptr
	if enabled {
		flag = 1
	}
	r0, _, _ := syscall.SyscallN(
		m.vtbl.SetMultithreadProtected,
		uintptr(unsafe.Pointer(m)),
		flag,
	)
	return hresultError(r0, "ID3D11Multithread.SetMultithreadProtected")
}

func enableD3D11MultithreadProtection(ctx interface {
	QueryInterface(*windows.GUID) (unsafe.Pointer, error)
}) error {
	if ctx == nil {
		return nil
	}
	if err := initMultithreadGUID(); err != nil {
		return err
	}
	ptr, err := ctx.QueryInterface(&iidID3D11Multithread)
	if err != nil {
		return err
	}
	mt := (*iD3D11Multithread)(ptr)
	defer mt.Release()
	return mt.SetMultithreadProtected(true)
}
