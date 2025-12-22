//go:build windows

package desktop

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// D3D11VideoProcessor wraps ID3D11VideoProcessor for GPU color conversion.
//
// **Purpose**: Convert BGRA (Desktop Duplication output) → NV12 (H.264 input)
// **Performance**: ~1ms on GPU vs 15-20ms on CPU
//
// Architecture:
//   1. Create video processor enumerator (describes capabilities)
//   2. Create video processor (actual GPU converter)
//   3. Configure input/output streams (BGRA→NV12)
//   4. Blit operation: GPU shader converts format
//
// References:
//   - https://docs.microsoft.com/en-us/windows/win32/medfound/direct3d-11-video-apis
//   - https://docs.microsoft.com/en-us/windows/win32/api/d3d11/nf-d3d11-id3d11videocontext-videoprocessorblt

var (
	// Video processor GUIDs
	iidID3D11VideoProcessorEnumerator windows.GUID
	iidID3D11VideoProcessorInputView  windows.GUID
	iidID3D11VideoProcessorOutputView windows.GUID

	vpGUIDOnce sync.Once
)

func initVideoProcessorGUIDs() {
	vpGUIDOnce.Do(func() {
		iidID3D11VideoProcessorEnumerator, _ = windows.GUIDFromString("{31627037-53AB-4200-9061-05FAA9AB45F9}")
		iidID3D11VideoProcessorInputView, _ = windows.GUIDFromString("{11EC5A5F-51DC-4945-AB34-6E8C21300EA5}")
		iidID3D11VideoProcessorOutputView, _ = windows.GUIDFromString("{A048285E-25A9-4527-BD93-D68B68C44254}")
	})
}

// D3D11_VIDEO_PROCESSOR_CONTENT_DESC describes the video stream.
type d3d11VideoProcessorContentDesc struct {
	InputFrameFormat uint32 // D3D11_VIDEO_FRAME_FORMAT (0=progressive, 1=interlaced)
	InputFrameRate   struct{ Numerator, Denominator uint32 }
	InputWidth       uint32
	InputHeight      uint32
	OutputFrameRate  struct{ Numerator, Denominator uint32 }
	OutputWidth      uint32
	OutputHeight     uint32
	Usage            uint32 // D3D11_VIDEO_USAGE (0=playback, 1=optimal speed)
}

// D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC describes input view.
type d3d11VideoProcessorInputViewDesc struct {
	FourCC        uint32
	ViewDimension uint32 // D3D11_VPIV_DIMENSION (0=texture2D)
	Texture2D     struct{ MipSlice, ArraySlice uint32 }
}

// D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC describes output view.
type d3d11VideoProcessorOutputViewDesc struct {
	ViewDimension uint32 // D3D11_VPOV_DIMENSION (0=texture2D)
	Texture2D     struct{ MipSlice uint32 }
}

// D3D11_VIDEO_PROCESSOR_STREAM describes a video stream for blit.
type d3d11VideoProcessorStream struct {
	Enable                int32 // BOOL
	OutputIndex           uint32
	InputFrameOrField     uint32
	PastFrames            uint32
	FutureFrames          uint32
	ppPastSurfaces        uintptr // **ID3D11VideoProcessorInputView (not used)
	pInputSurface         uintptr // *ID3D11VideoProcessorInputView
	ppFutureSurfaces      uintptr // **ID3D11VideoProcessorInputView (not used)
	ppPastSurfacesRight   uintptr // (stereo, not used)
	pInputSurfaceRight    uintptr
	ppFutureSurfacesRight uintptr
}

// VideoProcessor manages D3D11 video processing for color conversion.
type VideoProcessor struct {
	device       *iD3D11Device
	deviceCtx    *iD3D11DeviceContext
	videoDevice  *iD3D11VideoDevice
	videoContext *iD3D11VideoContext

	// Processor objects
	processorEnum *iD3D11VideoProcessorEnumerator
	processor     *iD3D11VideoProcessor

	// Configuration
	inputWidth   int
	inputHeight  int
	outputWidth  int
	outputHeight int

	// Texture pool for NV12 output (reuse to avoid allocation overhead)
	nv12TexPool   []*iD3D11Texture2D
	nv12PoolMutex sync.Mutex

	mu sync.Mutex
}

// NewVideoProcessor creates a video processor for BGRA→NV12 conversion.
func NewVideoProcessor(device *iD3D11Device, deviceCtx *iD3D11DeviceContext,
	videoDevice *iD3D11VideoDevice, videoContext *iD3D11VideoContext,
	inputWidth, inputHeight int, outputWidth, outputHeight int) (*VideoProcessor, error) {

	initVideoProcessorGUIDs()

	if outputWidth <= 0 {
		outputWidth = inputWidth
	}
	if outputHeight <= 0 {
		outputHeight = inputHeight
	}

	vp := &VideoProcessor{
		device:       device,
		deviceCtx:    deviceCtx,
		videoDevice:  videoDevice,
		videoContext: videoContext,
		inputWidth:   inputWidth,
		inputHeight:  inputHeight,
		outputWidth:  outputWidth,
		outputHeight: outputHeight,
		nv12TexPool:  make([]*iD3D11Texture2D, 0, 3), // Pool of 3 textures
	}

	if err := vp.createProcessor(); err != nil {
		vp.Release()
		return nil, err
	}

	return vp, nil
}

// createProcessor creates the video processor enumerator and processor.
func (vp *VideoProcessor) createProcessor() error {
	// Create enumerator (describes processor capabilities)
	desc := d3d11VideoProcessorContentDesc{
		InputFrameFormat: 0, // Progressive (not interlaced)
		InputFrameRate:   struct{ Numerator, Denominator uint32 }{30, 1},
		InputWidth:       uint32(vp.inputWidth),
		InputHeight:      uint32(vp.inputHeight),
		OutputFrameRate:  struct{ Numerator, Denominator uint32 }{30, 1},
		OutputWidth:      uint32(vp.outputWidth),
		OutputHeight:     uint32(vp.outputHeight),
		Usage:            0, // Playback normal (widest driver support)
	}

	var enumerator *iD3D11VideoProcessorEnumerator
	r0, _, _ := syscall.SyscallN(
		vp.videoDevice.vtbl.CreateVideoProcessorEnumerator,
		uintptr(unsafe.Pointer(vp.videoDevice)),
		uintptr(unsafe.Pointer(&desc)),
		uintptr(unsafe.Pointer(&enumerator)),
	)
	if err := hresultError(r0, "CreateVideoProcessorEnumerator"); err != nil {
		return err
	}
	vp.processorEnum = enumerator

	// Create processor (index 0 = default/fastest)
	var processor *iD3D11VideoProcessor
	r0, _, _ = syscall.SyscallN(
		vp.videoDevice.vtbl.CreateVideoProcessor,
		uintptr(unsafe.Pointer(vp.videoDevice)),
		uintptr(unsafe.Pointer(vp.processorEnum)),
		0, // RateConversionIndex (0 = default)
		uintptr(unsafe.Pointer(&processor)),
	)
	if err := hresultError(r0, "CreateVideoProcessor"); err != nil {
		return err
	}
	vp.processor = processor

	return nil
}

// ConvertBGRAToNV12 converts a BGRA texture to NV12 using GPU video processor.
//
// **Performance**: ~1ms on GPU (vs 15-20ms on CPU)
//
// Steps:
//  1. Create NV12 output texture (or reuse from pool)
//  2. Create input/output views
//  3. VideoProcessorBlt (GPU shader converts BGRA→NV12)
//  4. Return NV12 texture
func (vp *VideoProcessor) ConvertBGRAToNV12(bgraTex *iD3D11Texture2D) (*iD3D11Texture2D, error) {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	if vp.processor == nil {
		return nil, fmt.Errorf("video processor not initialized")
	}

	// Get or create NV12 output texture
	nv12Tex, err := vp.getOrCreateNV12Texture()
	if err != nil {
		return nil, err
	}

	// Create input view (BGRA)
	inputViewDesc := d3d11VideoProcessorInputViewDesc{
		FourCC:        0, // 0 = use texture format
		ViewDimension: 1, // D3D11_VPIV_DIMENSION_TEXTURE2D
		Texture2D:     struct{ MipSlice, ArraySlice uint32 }{0, 0},
	}

	var inputView *iD3D11VideoProcessorInputView
	r0, _, _ := syscall.SyscallN(
		vp.videoDevice.vtbl.CreateVideoProcessorInputView,
		uintptr(unsafe.Pointer(vp.videoDevice)),
		uintptr(unsafe.Pointer(bgraTex)),
		uintptr(unsafe.Pointer(vp.processorEnum)),
		uintptr(unsafe.Pointer(&inputViewDesc)),
		uintptr(unsafe.Pointer(&inputView)),
	)
	if err := hresultError(r0, "CreateVideoProcessorInputView"); err != nil {
		return nil, err
	}
	defer inputView.Release()

	// Create output view (NV12)
	outputViewDesc := d3d11VideoProcessorOutputViewDesc{
		ViewDimension: 1, // D3D11_VPOV_DIMENSION_TEXTURE2D
		Texture2D:     struct{ MipSlice uint32 }{0},
	}

	var outputView *iD3D11VideoProcessorOutputView
	r0, _, _ = syscall.SyscallN(
		vp.videoDevice.vtbl.CreateVideoProcessorOutputView,
		uintptr(unsafe.Pointer(vp.videoDevice)),
		uintptr(unsafe.Pointer(nv12Tex)),
		uintptr(unsafe.Pointer(vp.processorEnum)),
		uintptr(unsafe.Pointer(&outputViewDesc)),
		uintptr(unsafe.Pointer(&outputView)),
	)
	if err := hresultError(r0, "CreateVideoProcessorOutputView"); err != nil {
		return nil, err
	}
	defer outputView.Release()

	// Configure stream
	stream := d3d11VideoProcessorStream{
		Enable:            1, // TRUE
		OutputIndex:       0,
		InputFrameOrField: 0,
		PastFrames:        0,
		FutureFrames:      0,
		pInputSurface:     uintptr(unsafe.Pointer(inputView)),
	}

	// Perform blit (GPU BGRA→NV12 conversion, ~1ms)
	r0, _, _ = syscall.SyscallN(
		vp.videoContext.vtbl.VideoProcessorBlt,
		uintptr(unsafe.Pointer(vp.videoContext)),
		uintptr(unsafe.Pointer(vp.processor)),
		uintptr(unsafe.Pointer(outputView)),
		0, // OutputFrame
		1, // StreamCount
		uintptr(unsafe.Pointer(&stream)),
	)
	if err := hresultError(r0, "VideoProcessorBlt"); err != nil {
		return nil, err
	}

	ctx := (*iD3D11DeviceContextExt)(unsafe.Pointer(vp.deviceCtx))
	ctx.Flush()
	return nv12Tex, nil
}

// getOrCreateNV12Texture gets a texture from pool or creates a new one.
func (vp *VideoProcessor) getOrCreateNV12Texture() (*iD3D11Texture2D, error) {
	vp.nv12PoolMutex.Lock()
	defer vp.nv12PoolMutex.Unlock()

	// DISABLED: Texture pooling disabled for debugging AMD encoder issues.
	// The encoder might hold references to textures, causing issues when we reuse them.
	// TODO: Re-enable pooling once AMD encoding is fixed.
	/*
	// Try to get from pool
	if len(vp.nv12TexPool) > 0 {
		tex := vp.nv12TexPool[len(vp.nv12TexPool)-1]
		vp.nv12TexPool = vp.nv12TexPool[:len(vp.nv12TexPool)-1]
		return tex, nil
	}
	*/

	// Create new NV12 texture
	// D3D11_BIND_RENDER_TARGET (0x20) is required for video processor output.
	// D3D11_BIND_VIDEO_ENCODER (0x200000) is preferred for hardware encoder input.
	// D3D11_RESOURCE_MISC_SHARED (0x2) allows sharing across D3D11 contexts (required by some AMD encoders).
	// Some GPUs don't support VIDEO_ENCODER with RENDER_TARGET, so we fall back if needed.
	const d3d11ResourceMiscShared = 0x2
	desc := d3d11Texture2DDesc{
		Width:          uint32(vp.outputWidth),
		Height:         uint32(vp.outputHeight),
		MipLevels:      1,
		ArraySize:      1,
		Format:         dxgiFormatNV12, // 103
		SampleDesc:     struct{ Count, Quality uint32 }{1, 0},
		Usage:          d3d11UsageDefault,
		BindFlags:      d3d11BindRenderTarget | d3d11BindVideoEncoder,
		CPUAccessFlags: d3d11CPUAccessNone,
		MiscFlags:      d3d11ResourceMiscShared,
	}

	var tex *iD3D11Texture2D
	r0, _, _ := syscall.SyscallN(
		vp.device.vtbl.CreateTexture2D,
		uintptr(unsafe.Pointer(vp.device)),
		uintptr(unsafe.Pointer(&desc)),
		0, // pInitialData (nil)
		uintptr(unsafe.Pointer(&tex)),
	)
	if hresultError(r0, "") != nil {
		// Fallback: some GPUs don't support VIDEO_ENCODER + RENDER_TARGET combination.
		// Try with just RENDER_TARGET.
		desc.BindFlags = d3d11BindRenderTarget
		r0, _, _ = syscall.SyscallN(
			vp.device.vtbl.CreateTexture2D,
			uintptr(unsafe.Pointer(vp.device)),
			uintptr(unsafe.Pointer(&desc)),
			0,
			uintptr(unsafe.Pointer(&tex)),
		)
		if err := hresultError(r0, "CreateTexture2D(NV12) fallback"); err != nil {
			return nil, err
		}
	}

	return tex, nil
}

// ReturnTexture returns an NV12 texture to the pool (for reuse).
func (vp *VideoProcessor) ReturnTexture(tex *iD3D11Texture2D) {
	if tex == nil {
		return
	}

	// DISABLED: Pooling disabled for debugging AMD encoder issues.
	// Always release textures immediately instead of pooling.
	tex.Release()

	/*
	vp.nv12PoolMutex.Lock()
	defer vp.nv12PoolMutex.Unlock()

	// Add to pool if not full
	if len(vp.nv12TexPool) < cap(vp.nv12TexPool) {
		vp.nv12TexPool = append(vp.nv12TexPool, tex)
	} else {
		// Pool full, release texture
		tex.Release()
	}
	*/
}

// Release cleans up video processor resources.
func (vp *VideoProcessor) Release() {
	vp.mu.Lock()
	defer vp.mu.Unlock()

	// Release pooled textures
	vp.nv12PoolMutex.Lock()
	for _, tex := range vp.nv12TexPool {
		if tex != nil {
			tex.Release()
		}
	}
	vp.nv12TexPool = nil
	vp.nv12PoolMutex.Unlock()

	if vp.processor != nil {
		vp.processor.Release()
		vp.processor = nil
	}

	if vp.processorEnum != nil {
		vp.processorEnum.Release()
		vp.processorEnum = nil
	}
}

// d3d11Texture2DDesc describes a 2D texture.
type d3d11Texture2DDesc struct {
	Width          uint32
	Height         uint32
	MipLevels      uint32
	ArraySize      uint32
	Format         uint32 // DXGI_FORMAT
	SampleDesc     struct{ Count, Quality uint32 }
	Usage          uint32 // D3D11_USAGE
	BindFlags      uint32
	CPUAccessFlags uint32
	MiscFlags      uint32
}

// COM interface definitions (extended from capture_dxgi_nv12.go)

type iD3D11VideoProcessorEnumerator struct {
	vtbl *iD3D11VideoProcessorEnumeratorVtbl
}

type iD3D11VideoProcessorEnumeratorVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetDevice      uintptr
	// ... (abbreviated, ~20 methods)
}

func (e *iD3D11VideoProcessorEnumerator) Release() {
	if e == nil || e.vtbl == nil {
		return
	}
	syscall.SyscallN(e.vtbl.Release, uintptr(unsafe.Pointer(e)))
}

type iD3D11VideoProcessorInputView struct {
	vtbl *iD3D11VideoProcessorInputViewVtbl
}

type iD3D11VideoProcessorInputViewVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetDevice      uintptr
	GetResource    uintptr
	GetDesc        uintptr
}

func (v *iD3D11VideoProcessorInputView) Release() {
	if v == nil || v.vtbl == nil {
		return
	}
	syscall.SyscallN(v.vtbl.Release, uintptr(unsafe.Pointer(v)))
}

type iD3D11VideoProcessorOutputView struct {
	vtbl *iD3D11VideoProcessorOutputViewVtbl
}

type iD3D11VideoProcessorOutputViewVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetDevice      uintptr
	GetResource    uintptr
	GetDesc        uintptr
}

func (v *iD3D11VideoProcessorOutputView) Release() {
	if v == nil || v.vtbl == nil {
		return
	}
	syscall.SyscallN(v.vtbl.Release, uintptr(unsafe.Pointer(v)))
}

// Extended vtables for video device/context
// Method order from Windows SDK d3d11.h - MUST match exactly for COM vtable calls

// ID3D11VideoDevice vtable (inherits from IUnknown).
// Reference: Windows SDK `d3d11.h` interface definition order.
type iD3D11VideoDeviceVtbl struct {
	// IUnknown methods (0-2)
	QueryInterface uintptr // 0
	AddRef         uintptr // 1
	Release        uintptr // 2

	// ID3D11VideoDevice methods (3-19)
	CreateVideoDecoder             uintptr // 3
	CreateVideoProcessor           uintptr // 4 - creates processor
	CreateAuthenticatedChannel     uintptr // 5
	CreateCryptoSession            uintptr // 6
	CreateVideoDecoderOutputView   uintptr // 7
	CreateVideoProcessorInputView  uintptr // 8 - creates input view for blit
	CreateVideoProcessorOutputView uintptr // 9 - creates output view for blit
	CreateVideoProcessorEnumerator uintptr // 10 - creates enumerator
	GetVideoDecoderProfileCount    uintptr // 11
	GetVideoDecoderProfile         uintptr // 12
	CheckVideoDecoderFormat        uintptr // 13
	GetVideoDecoderConfigCount     uintptr // 14
	GetVideoDecoderConfig          uintptr // 15
	GetContentProtectionCaps       uintptr // 16
	CheckCryptoKeyExchange         uintptr // 17
	SetPrivateData                 uintptr // 18
	SetPrivateDataInterface        uintptr // 19
}

// ID3D11VideoContext vtable (inherits from ID3D11DeviceChild)
// Reference: https://docs.microsoft.com/en-us/windows/win32/api/d3d11/nn-d3d11-id3d11videocontext
// This interface has ~60 methods - we only define what we need plus padding
type iD3D11VideoContextVtbl struct {
	// IUnknown methods (0-2)
	QueryInterface uintptr // 0
	AddRef         uintptr // 1
	Release        uintptr // 2

	// ID3D11DeviceChild methods (3-6)
	GetDevice               uintptr // 3
	GetPrivateData          uintptr // 4
	SetPrivateData          uintptr // 5
	SetPrivateDataInterface uintptr // 6

	// ID3D11VideoContext methods (7-59)
	GetDecoderBuffer                        uintptr // 7
	ReleaseDecoderBuffer                    uintptr // 8
	DecoderBeginFrame                       uintptr // 9
	DecoderEndFrame                         uintptr // 10
	SubmitDecoderBuffers                    uintptr // 11
	DecoderExtension                        uintptr // 12
	VideoProcessorSetOutputTargetRect       uintptr // 13
	VideoProcessorSetOutputBackgroundColor  uintptr // 14
	VideoProcessorSetOutputColorSpace       uintptr // 15
	VideoProcessorSetOutputAlphaFillMode    uintptr // 16
	VideoProcessorSetOutputConstriction     uintptr // 17
	VideoProcessorSetOutputStereoMode       uintptr // 18
	VideoProcessorSetOutputExtension        uintptr // 19
	VideoProcessorGetOutputTargetRect       uintptr // 20
	VideoProcessorGetOutputBackgroundColor  uintptr // 21
	VideoProcessorGetOutputColorSpace       uintptr // 22
	VideoProcessorGetOutputAlphaFillMode    uintptr // 23
	VideoProcessorGetOutputConstriction     uintptr // 24
	VideoProcessorGetOutputStereoMode       uintptr // 25
	VideoProcessorGetOutputExtension        uintptr // 26
	VideoProcessorSetStreamFrameFormat      uintptr // 27
	VideoProcessorSetStreamColorSpace       uintptr // 28
	VideoProcessorSetStreamOutputRate       uintptr // 29
	VideoProcessorSetStreamSourceRect       uintptr // 30
	VideoProcessorSetStreamDestRect         uintptr // 31
	VideoProcessorSetStreamAlpha            uintptr // 32
	VideoProcessorSetStreamPalette          uintptr // 33
	VideoProcessorSetStreamPixelAspectRatio uintptr // 34
	VideoProcessorSetStreamLumaKey          uintptr // 35
	VideoProcessorSetStreamStereoFormat     uintptr // 36
	VideoProcessorSetStreamAutoProcessing   uintptr // 37
	VideoProcessorSetStreamFilter           uintptr // 38
	VideoProcessorSetStreamExtension        uintptr // 39
	VideoProcessorGetStreamFrameFormat      uintptr // 40
	VideoProcessorGetStreamColorSpace       uintptr // 41
	VideoProcessorGetStreamOutputRate       uintptr // 42
	VideoProcessorGetStreamSourceRect       uintptr // 43
	VideoProcessorGetStreamDestRect         uintptr // 44
	VideoProcessorGetStreamAlpha            uintptr // 45
	VideoProcessorGetStreamPalette          uintptr // 46
	VideoProcessorGetStreamPixelAspectRatio uintptr // 47
	VideoProcessorGetStreamLumaKey          uintptr // 48
	VideoProcessorGetStreamStereoFormat     uintptr // 49
	VideoProcessorGetStreamAutoProcessing   uintptr // 50
	VideoProcessorGetStreamFilter           uintptr // 51
	VideoProcessorGetStreamExtension        uintptr // 52
	VideoProcessorBlt                       uintptr // 53 - IMPORTANT: performs color conversion
	NegotiateCryptoSessionKeyExchange       uintptr // 54
	EncryptionBlt                           uintptr // 55
	DecryptionBlt                           uintptr // 56
	StartSessionKeyRefresh                  uintptr // 57
	FinishSessionKeyRefresh                 uintptr // 58
	GetEncryptionBltKey                     uintptr // 59
}

// Extended iD3D11Texture2D vtbl
type iD3D11DeviceVtbl struct {
	QueryInterface                       uintptr
	AddRef                               uintptr
	Release                              uintptr
	CreateBuffer                         uintptr
	CreateTexture1D                      uintptr
	CreateTexture2D                      uintptr // ← This is what we need
	CreateTexture3D                      uintptr
	CreateShaderResourceView             uintptr
	CreateUnorderedAccessView            uintptr
	CreateRenderTargetView               uintptr
	CreateDepthStencilView               uintptr
	CreateInputLayout                    uintptr
	CreateVertexShader                   uintptr
	CreateGeometryShader                 uintptr
	CreateGeometryShaderWithStreamOutput uintptr
	CreatePixelShader                    uintptr
	CreateHullShader                     uintptr
	CreateDomainShader                   uintptr
	CreateComputeShader                  uintptr
	CreateClassLinkage                   uintptr
	CreateBlendState                     uintptr
	CreateDepthStencilState              uintptr
	CreateRasterizerState                uintptr
	CreateSamplerState                   uintptr
	CreateQuery                          uintptr
	CreatePredicate                      uintptr
	CreateCounter                        uintptr
	CreateDeferredContext                uintptr
	OpenSharedResource                   uintptr
	CheckFormatSupport                   uintptr
	CheckMultisampleQualityLevels        uintptr
	CheckCounterInfo                     uintptr
	CheckCounter                         uintptr
	CheckFeatureSupport                  uintptr
	GetPrivateData                       uintptr
	SetPrivateData                       uintptr
	SetPrivateDataInterface              uintptr
	GetFeatureLevel                      uintptr
	GetCreationFlags                     uintptr
	GetDeviceRemovedReason               uintptr
	GetImmediateContext                  uintptr
	SetExceptionMode                     uintptr
	GetExceptionMode                     uintptr
}
