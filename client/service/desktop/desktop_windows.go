package desktop

import (
	"Rocket/client/config"
	"Rocket/client/telemetry"
	"errors"
	"fmt"
	"image"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/kbinani/screenshot"
	"github.com/kirides/go-d3d"
	"github.com/kirides/go-d3d/d3d11"
	"github.com/kirides/go-d3d/dxgi"
	"github.com/kirides/go-d3d/outputduplication/swizzle"
	winDXGI "github.com/kirides/go-d3d/win"
	winGDI "github.com/lxn/win"
	"golang.org/x/sys/windows"
)

// D3D11 bind flags (not exported by go-d3d library)
const (
	d3d11BindShaderResource uint32 = 0x8 // D3D11_BIND_SHADER_RESOURCE
)

var (
	libUser32, _               = syscall.LoadLibrary("user32.dll")
	funcGetDesktopWindow, _    = syscall.GetProcAddress(syscall.Handle(libUser32), "GetDesktopWindow")
	funcEnumDisplayMonitors, _ = syscall.GetProcAddress(syscall.Handle(libUser32), "EnumDisplayMonitors")
	funcGetMonitorInfo, _      = syscall.GetProcAddress(syscall.Handle(libUser32), "GetMonitorInfoW")
	funcEnumDisplaySettings, _ = syscall.GetProcAddress(syscall.Handle(libUser32), "EnumDisplaySettingsW")
)

// Capture statistics for Windows platforms (NVFBC/DXGI/GDI)
var (
	captureCount      atomic.Uint64
	captureErrors     atomic.Uint64
	captureLatency    atomic.Int64  // nanoseconds (last capture)
	dxgiFallbackCount atomic.Uint64 // times GDI was used due to DXGI failure
	nvfbcProbeOnce    sync.Once
	nvfbcAvailable    atomic.Bool
)

// CaptureStats returns capture telemetry for Windows platforms.
func CaptureStats() map[string]interface{} {
	return map[string]interface{}{
		"captures_total":  captureCount.Load(),
		"errors_total":    captureErrors.Load(),
		"last_latency_us": captureLatency.Load() / 1000, // microseconds
		"platform":        runtime.GOOS,
		"arch":            runtime.GOARCH,
		"backend":         getActiveCaptureBackend(),
		"dxgi_fallbacks":  dxgiFallbackCount.Load(),
	}
}

const (
	minDXGICaptureTimeoutMS = 5
	maxDXGICaptureTimeoutMS = 100
)

func dxgiCaptureTimeoutMillis() int {
	fps := clampFPSValue(configFPS.Load())
	if fps <= 0 {
		fps = fpsDefault
	}
	frameDuration := time.Second / time.Duration(fps)
	timeout := frameDuration / 2
	if timeout < time.Duration(minDXGICaptureTimeoutMS)*time.Millisecond {
		timeout = time.Duration(minDXGICaptureTimeoutMS) * time.Millisecond
	}
	if timeout > time.Duration(maxDXGICaptureTimeoutMS)*time.Millisecond {
		timeout = time.Duration(maxDXGICaptureTimeoutMS) * time.Millisecond
	}
	return int(timeout / time.Millisecond)
}

func backendPreferenceOrder(desired CaptureBackendMode) []CaptureBackendMode {
	order := getFallbackOrder()
	final := make([]CaptureBackendMode, 0, len(order)+4)
	appendMode := func(mode CaptureBackendMode) {
		if mode == CaptureBackendAuto || !isBackendSelectable(mode) {
			return
		}
		for _, existing := range final {
			if existing == mode {
				return
			}
		}
		final = append(final, mode)
	}

	if desired != CaptureBackendAuto {
		appendMode(desired)
	}

	if len(order) > 0 {
		for _, mode := range order {
			appendMode(mode)
		}
	} else if isSharedSurfaceEnabled() && desired == CaptureBackendAuto {
		appendMode(CaptureBackendSharedSurface)
	}

	appendMode(CaptureBackendNVFBC)
	// In bridge mode (user-session helper process), DXGI initialization can be flaky/hang
	// depending on GPU/session state. Prefer GDI first so we always have a working
	// capture path and keep DXGI as an optional upgrade when explicitly selected.
	if IsBridgeMode() {
		appendMode(CaptureBackendGDI)
		appendMode(CaptureBackendDXGI)
	} else {
		appendMode(CaptureBackendDXGI)
		appendMode(CaptureBackendGDI)
	}

	if len(final) == 0 {
		return []CaptureBackendMode{CaptureBackendGDI}
	}
	return final
}

// preferGDIOverDXGI reorders a fallback list so the GDI backend is attempted
// before DXGI when both are present. This is a pragmatic safety valve for
// bridge mode where DXGI init can hang on some systems, leading to 0fps/black.
func preferGDIOverDXGI(order []CaptureBackendMode) []CaptureBackendMode {
	dxgiIdx := -1
	gdiIdx := -1
	for i, mode := range order {
		switch mode {
		case CaptureBackendDXGI:
			dxgiIdx = i
		case CaptureBackendGDI:
			gdiIdx = i
		}
	}
	if dxgiIdx == -1 || gdiIdx == -1 || gdiIdx < dxgiIdx {
		return order
	}

	out := make([]CaptureBackendMode, 0, len(order))
	for i, mode := range order {
		if i == gdiIdx {
			continue
		}
		if i == dxgiIdx {
			out = append(out, CaptureBackendGDI)
		}
		out = append(out, mode)
	}
	return out
}

func nvfbcSupported() bool {
	nvfbcProbeOnce.Do(func() {
		dlls := []string{"NvFBC64.dll", "NvFBC.dll"}
		for _, name := range dlls {
			dll := windows.NewLazySystemDLL(name)
			if err := dll.Load(); err == nil {
				nvfbcAvailable.Store(true)
				telemetry.LogStructured("INFO", "NVFBC runtime detected", map[string]interface{}{
					"dll": name,
				})
				return
			}
		}
		nvfbcAvailable.Store(false)
		telemetry.LogStructured("DEBUG", "NVFBC runtime not detected", nil)
	})
	return nvfbcAvailable.Load()
}

type Screen struct {
	screen          ScreenCapture
	overrideBackend CaptureBackendMode
}
type ScreenCapture interface {
	Init(uint, image.Rectangle) error
	Capture() (*CaptureFrame, error)
	Release()
}
type ScreenNVFBC struct {
	rect image.Rectangle
}
type ScreenSharedSurface struct {
	rect         image.Rectangle
	displayIndex uint
	ctx          uintptr
	buffer       []byte
}
type pointerInfo struct {
	pos            dxgi.POINT
	size           dxgi.POINT
	shapeInBuffer  []byte
	shapeOutBuffer *image.RGBA
	visible        bool
}

type ScreenDXGI struct {
	rect      image.Rectangle
	device    *d3d11.ID3D11Device
	deviceCtx *d3d11.ID3D11DeviceContext

	duplicator *dxgi.IDXGIOutputDuplication
	stagedTex  *d3d11.ID3D11Texture2D
	surface    *dxgi.IDXGISurface
	mappedRect dxgi.DXGI_MAPPED_RECT
	size       dxgi.POINT

	pointerInfo       pointerInfo
	shouldDrawPointer bool
	dirtyRects        []dxgi.RECT
	movedRects        []dxgi.DXGI_OUTDUPL_MOVE_RECT
	needsSwizzle      bool

	gpuTex *d3d11.ID3D11Texture2D
}
type ScreenGDI struct {
	rect           image.Rectangle
	width          int
	height         int
	hwnd           winGDI.HWND
	hdc            winGDI.HDC
	memoryDevice   winGDI.HDC
	bitmap         winGDI.HBITMAP
	bitmapInfo     winGDI.BITMAPINFOHEADER
	bitmapDataSize uintptr
	hmem           winGDI.HGLOBAL
	memptr         unsafe.Pointer
}

// ScreenGDICompat performs GDI capture using per-call resources instead of
// keeping persistent device contexts. This is slower than ScreenGDI but avoids
// init-time hangs seen on some Windows environments.
type ScreenGDICompat struct {
	rect image.Rectangle
}

func (s *ScreenGDICompat) Init(_ uint, rect image.Rectangle) error {
	s.rect = rect
	return nil
}

func (s *ScreenGDICompat) Capture() (*CaptureFrame, error) {
	width := s.rect.Dx()
	height := s.rect.Dy()
	if width <= 0 || height <= 0 {
		return nil, errors.New("invalid capture bounds")
	}

	hwnd := getDesktopWindow()
	hdc := winGDI.GetDC(hwnd)
	if hdc == 0 {
		return nil, errors.New("GetDC failed")
	}
	defer winGDI.ReleaseDC(hwnd, hdc)

	memoryDevice := winGDI.CreateCompatibleDC(hdc)
	if memoryDevice == 0 {
		return nil, errors.New("CreateCompatibleDC failed")
	}
	defer winGDI.DeleteDC(memoryDevice)

	bitmap := winGDI.CreateCompatibleBitmap(hdc, int32(width), int32(height))
	if bitmap == 0 {
		return nil, errors.New("CreateCompatibleBitmap failed")
	}
	defer winGDI.DeleteObject(winGDI.HGDIOBJ(bitmap))

	const hgdiError = winGDI.HGDIOBJ(^uintptr(0))
	old := winGDI.SelectObject(memoryDevice, winGDI.HGDIOBJ(bitmap))
	if old == 0 || old == hgdiError {
		return nil, errors.New("SelectObject failed")
	}
	defer winGDI.SelectObject(memoryDevice, old)

	if !winGDI.BitBlt(memoryDevice, 0, 0, int32(width), int32(height), hdc, int32(s.rect.Min.X), int32(s.rect.Min.Y), winGDI.SRCCOPY|winGDI.CAPTUREBLT) {
		return nil, errors.New("BitBlt failed")
	}

	var header winGDI.BITMAPINFOHEADER
	header.BiSize = uint32(unsafe.Sizeof(header))
	header.BiPlanes = 1
	header.BiBitCount = 32
	header.BiWidth = int32(width)
	header.BiHeight = -int32(height)
	header.BiCompression = winGDI.BI_RGB
	header.BiSizeImage = 0

	bitmapDataSize := uintptr(((int64(width)*int64(header.BiBitCount) + 31) / 32) * 4 * int64(height))
	hmem := winGDI.GlobalAlloc(winGDI.GMEM_MOVEABLE, bitmapDataSize)
	if hmem == 0 {
		return nil, errors.New("GlobalAlloc failed")
	}
	defer winGDI.GlobalFree(hmem)
	memptr := winGDI.GlobalLock(hmem)
	if memptr == nil {
		return nil, errors.New("GlobalLock failed")
	}
	defer winGDI.GlobalUnlock(hmem)

	if winGDI.GetDIBits(memoryDevice, bitmap, 0, uint32(height), (*uint8)(memptr), (*winGDI.BITMAPINFO)(unsafe.Pointer(&header)), winGDI.DIB_RGB_COLORS) == 0 {
		return nil, errors.New("GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	imageBytes := ((*[1 << 30]byte)(unsafe.Pointer(memptr)))[:bitmapDataSize:bitmapDataSize]
	copy(img.Pix[:bitmapDataSize], imageBytes)
	swizzle.BGRA(img.Pix)

	return &CaptureFrame{Image: img}, nil
}

func (s *ScreenGDICompat) Release() {}

// ScreenScreenshot is a last-resort fallback that uses github.com/kbinani/screenshot
// to capture pixels when all Windows-specific backends fail to initialize.
//
// This is slower than DXGI, but prevents "0 FPS / black screen" regressions when
// the bridge is running in a constrained session environment.
type ScreenScreenshot struct {
	rect         image.Rectangle
	displayIndex uint
}

func (s *ScreenScreenshot) Init(displayIndex uint, rect image.Rectangle) error {
	s.displayIndex = displayIndex
	s.rect = rect
	return nil
}

func (s *ScreenScreenshot) Capture() (*CaptureFrame, error) {
	img, err := screenshot.CaptureRect(s.rect)
	if err != nil {
		return nil, err
	}
	return &CaptureFrame{Image: img}, nil
}

func (s *ScreenScreenshot) Release() {}

type dxgiAdapterDesc1 struct {
	Description           [128]uint16
	VendorID              uint32
	DeviceID              uint32
	SubSysID              uint32
	Revision              uint32
	DedicatedVideoMemory  uintptr
	DedicatedSystemMemory uintptr
	SharedSystemMemory    uintptr
	AdapterLuid           windows.LUID
	Flags                 uint32
}

type dxgiOutputDesc struct {
	DeviceName         [32]uint16
	DesktopCoordinates dxgi.RECT
	AttachedToDesktop  uint32
	Rotation           uint32
	Monitor            winGDI.HMONITOR
}

func (s *ScreenNVFBC) Init(_ uint, rect image.Rectangle) error {
	s.rect = rect
	return errors.New("NVFBC backend not yet implemented")
}

func (s *ScreenNVFBC) Capture() (*CaptureFrame, error) {
	return nil, errors.New("NVFBC backend inactive")
}

func (s *ScreenNVFBC) Release() {}

func (s *ScreenSharedSurface) Init(displayIndex uint, rect image.Rectangle) error {
	if !isSharedSurfaceEnabled() {
		return errors.New("shared surface capture disabled")
	}
	if err := sharedSurface.loadAndBind(); err != nil {
		return fmt.Errorf("shared surface load failed: %w", err)
	}
	ctx, err := sharedSurface.init(config.Config.Capture.AdapterLUID)
	if err != nil {
		return fmt.Errorf("shared surface init failed: %w", err)
	}
	if err := sharedSurface.start(ctx, uint32(displayIndex)); err != nil {
		sharedSurface.shutdown(ctx)
		return fmt.Errorf("shared surface start failed: %w", err)
	}
	s.ctx = ctx
	s.rect = rect
	s.displayIndex = displayIndex
	return nil
}

func (s *ScreenSharedSurface) Capture() (*CaptureFrame, error) {
	if s.ctx == 0 {
		return nil, errors.New("shared surface inactive")
	}

	width := s.rect.Dx()
	height := s.rect.Dy()
	if width <= 0 || height <= 0 {
		return nil, errors.New("invalid capture bounds")
	}

	bytesNeeded := width * height * 4
	if len(s.buffer) < bytesNeeded {
		s.buffer = make([]byte, bytesNeeded)
	}

	frame := captureFrame{
		Data:   uintptr(unsafe.Pointer(&s.buffer[0])),
		Size:   uint32(len(s.buffer)),
		Width:  uint32(width),
		Height: uint32(height),
		Stride: uint32(width * 4),
	}

	status, err := sharedSurface.nextFrame(s.ctx, &frame)
	if err != nil {
		return nil, err
	}
	if status == 1 {
		return nil, errNoImage
	}
	if status != 0 {
		return nil, fmt.Errorf("shared surface frame error (%d)", status)
	}

	if frame.Width > 0 {
		width = int(frame.Width)
	}
	if frame.Height > 0 {
		height = int(frame.Height)
	}
	stride := int(frame.Stride)
	if stride <= 0 {
		stride = width * 4
	}

	bytesAvailable := int(frame.Size)
	if bytesAvailable <= 0 || bytesAvailable > len(s.buffer) {
		bytesAvailable = len(s.buffer)
	}

	dataPtr := frame.Data
	if dataPtr == 0 {
		dataPtr = uintptr(unsafe.Pointer(&s.buffer[0]))
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), bytesAvailable)

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	rowBytes := width * 4
	for y := 0; y < height; y++ {
		srcOffset := y * stride
		dstOffset := y * img.Stride
		if srcOffset+rowBytes > len(src) || dstOffset+rowBytes > len(img.Pix) {
			break
		}
		copy(img.Pix[dstOffset:dstOffset+rowBytes], src[srcOffset:srcOffset+rowBytes])
	}

	return &CaptureFrame{Image: img}, nil
}

func (s *ScreenSharedSurface) Release() {
	if s.ctx != 0 {
		sharedSurface.stop(s.ctx)
		sharedSurface.shutdown(s.ctx)
		s.ctx = 0
	}
	s.buffer = nil
}

func (s *ScreenDXGI) initDuplicator(displayIndex uint) error {
	var hr int32
	var dxgiDevice1 *dxgi.IDXGIDevice1
	hr = s.device.QueryInterface(dxgi.IID_IDXGIDevice1, &dxgiDevice1)
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("dxgi device query failed: %w", d3d.HRESULT(hr))
	}
	defer dxgiDevice1.Release()

	var adapterPtr unsafe.Pointer
	hr = dxgiDevice1.GetParent(dxgi.IID_IDXGIAdapter1, &adapterPtr)
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("dxgi device parent query failed: %w", d3d.HRESULT(hr))
	}
	dxgiAdapter := (*dxgi.IDXGIAdapter1)(adapterPtr)
	defer dxgiAdapter.Release()

	var dxgiOutput *dxgi.IDXGIOutput
	hr = int32(dxgiAdapter.EnumOutputs(displayIndex, &dxgiOutput))
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("dxgi enum outputs failed: %w", d3d.HRESULT(hr))
	}
	defer dxgiOutput.Release()

	logDXGIAdapterInfo(dxgiAdapter, dxgiOutput, displayIndex)

	var dxgiOutput5 *dxgi.IDXGIOutput5
	hr = dxgiOutput.QueryInterface(dxgi.IID_IDXGIOutput5, &dxgiOutput5)
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("dxgi output5 query failed: %w", d3d.HRESULT(hr))
	}
	defer dxgiOutput5.Release()

	var dup *dxgi.IDXGIOutputDuplication
	formats := []dxgi.DXGI_FORMAT{
		dxgi.DXGI_FORMAT_R8G8B8A8_UNORM,
	}
	hr = dxgiOutput5.DuplicateOutput1(dxgiDevice1, 0, formats, &dup)
	s.needsSwizzle = false
	if d3d.HRESULT(hr).Failed() {
		s.needsSwizzle = true
		var dxgiOutput1 *dxgi.IDXGIOutput1
		hr = dxgiOutput.QueryInterface(dxgi.IID_IDXGIOutput1, &dxgiOutput1)
		if d3d.HRESULT(hr).Failed() {
			return fmt.Errorf("dxgi output1 query failed: %w", d3d.HRESULT(hr))
		}
		defer dxgiOutput1.Release()
		hr = dxgiOutput1.DuplicateOutput(dxgiDevice1, &dup)
		if d3d.HRESULT(hr).Failed() {
			return fmt.Errorf("dxgi duplicate output failed: %w", d3d.HRESULT(hr))
		}
	}

	s.duplicator = dup
	s.shouldDrawPointer = true
	return nil
}

func (s *ScreenDXGI) ensureStage(texture *d3d11.ID3D11Texture2D) error {
	desc := d3d11.D3D11_TEXTURE2D_DESC{}
	if hr := texture.GetDesc(&desc); d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("stage texture GetDesc failed: %w", d3d.HRESULT(hr))
	}

	desc.Usage = d3d11.D3D11_USAGE_STAGING
	desc.CPUAccessFlags = d3d11.D3D11_CPU_ACCESS_READ
	desc.BindFlags = 0
	desc.MipLevels = 1
	desc.ArraySize = 1
	desc.MiscFlags = 0
	desc.SampleDesc.Count = 1

	if s.stagedTex != nil {
		var current d3d11.D3D11_TEXTURE2D_DESC
		if hr := s.stagedTex.GetDesc(&current); !d3d.HRESULT(hr).Failed() &&
			current.Width == desc.Width && current.Height == desc.Height {
			s.size = dxgi.POINT{X: int32(desc.Width), Y: int32(desc.Height)}
			return nil
		}
		s.stagedTex.Release()
		s.stagedTex = nil
	}
	if s.surface != nil {
		s.surface.Release()
		s.surface = nil
	}

	if hr := s.device.CreateTexture2D(&desc, &s.stagedTex); d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("create staging texture failed: %w", d3d.HRESULT(hr))
	}
	if hr := s.stagedTex.QueryInterface(dxgi.IID_IDXGISurface, &s.surface); d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("query IDXGISurface failed: %w", d3d.HRESULT(hr))
	}
	s.size = dxgi.POINT{X: int32(desc.Width), Y: int32(desc.Height)}
	return nil
}

func (s *ScreenDXGI) ensureGPUTexture(desc *d3d11.D3D11_TEXTURE2D_DESC) error {
	if desc == nil {
		return errors.New("nil texture description")
	}
	if s.gpuTex != nil {
		var current d3d11.D3D11_TEXTURE2D_DESC
		if hr := s.gpuTex.GetDesc(&current); !d3d.HRESULT(hr).Failed() &&
			current.Width == desc.Width && current.Height == desc.Height && current.Format == desc.Format {
			return nil
		}
		s.gpuTex.Release()
		s.gpuTex = nil
	}
	gpuDesc := *desc
	gpuDesc.Usage = d3d11.D3D11_USAGE_DEFAULT
	gpuDesc.CPUAccessFlags = 0
	gpuDesc.BindFlags = d3d11BindShaderResource
	gpuDesc.MiscFlags = 0

	if hr := s.device.CreateTexture2D(&gpuDesc, &s.gpuTex); d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("create gpu texture failed: %w", d3d.HRESULT(hr))
	}
	return nil
}

func (s *ScreenDXGI) updatePointer(info *dxgi.DXGI_OUTDUPL_FRAME_INFO) error {
	if info.LastMouseUpdateTime == 0 {
		return nil
	}
	s.pointerInfo.visible = info.PointerPosition.Visible != 0
	s.pointerInfo.pos = info.PointerPosition.Position

	if info.PointerShapeBufferSize == 0 {
		return nil
	}

	if len(s.pointerInfo.shapeInBuffer) < int(info.PointerShapeBufferSize) {
		s.pointerInfo.shapeInBuffer = make([]byte, info.PointerShapeBufferSize)
	}
	var required uint32
	var shapeInfo dxgi.DXGI_OUTDUPL_POINTER_SHAPE_INFO
	hr := s.duplicator.GetFramePointerShape(info.PointerShapeBufferSize, s.pointerInfo.shapeInBuffer, &required, &shapeInfo)
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("get frame pointer shape failed: %w", d3d.HRESULT(hr))
	}

	switch shapeInfo.Type {
	case dxgi.DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME:
		s.pointerInfo.size = dxgi.POINT{X: int32(shapeInfo.Width), Y: int32(shapeInfo.Height)}
		xorOffset := shapeInfo.Pitch * (shapeInfo.Height / 2)
		andMap := s.pointerInfo.shapeInBuffer
		xorMap := s.pointerInfo.shapeInBuffer[:xorOffset]
		if s.pointerInfo.shapeOutBuffer == nil || s.pointerInfo.shapeOutBuffer.Rect.Dx()*s.pointerInfo.shapeOutBuffer.Rect.Dy() < int(shapeInfo.Width*shapeInfo.Height) {
			s.pointerInfo.shapeOutBuffer = image.NewRGBA(image.Rect(0, 0, int(shapeInfo.Width), int(shapeInfo.Height)/2))
		}
		out := s.pointerInfo.shapeOutBuffer.Pix
		widthBytes := (shapeInfo.Width + 7) / 8
		imgHeight := shapeInfo.Height / 2
		for j := 0; j < int(imgHeight); j++ {
			bit := byte(0x80)
			for i := 0; i < int(shapeInfo.Width); i++ {
				andByte := andMap[j*int(widthBytes)+i/8]
				xorByte := xorMap[j*int(widthBytes)+i/8]
				andBit := (andByte & bit) != 0
				xorBit := (xorByte & bit) != 0
				idx := j*int(shapeInfo.Width)*4 + i*4
				switch {
				case !andBit && !xorBit:
					out[idx+0], out[idx+1], out[idx+2], out[idx+3] = 0, 0, 0, 0
				case !andBit && xorBit:
					out[idx+0], out[idx+1], out[idx+2], out[idx+3] = 0xFF, 0xFF, 0xFF, 0xFF
				case andBit && xorBit:
					out[idx+0], out[idx+1], out[idx+2], out[idx+3] = 0, 0, 0, 0xFF
				default:
					out[idx+0], out[idx+1], out[idx+2], out[idx+3] = 0, 0, 0, 0
				}
				if bit == 0x01 {
					bit = 0x80
				} else {
					bit >>= 1
				}
			}
		}
	case dxgi.DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR, dxgi.DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR:
		s.pointerInfo.size = dxgi.POINT{X: int32(shapeInfo.Width), Y: int32(shapeInfo.Height)}
		if s.pointerInfo.shapeOutBuffer == nil || s.pointerInfo.shapeOutBuffer.Rect.Dx()*s.pointerInfo.shapeOutBuffer.Rect.Dy() < int(shapeInfo.Width*shapeInfo.Height) {
			s.pointerInfo.shapeOutBuffer = image.NewRGBA(image.Rect(0, 0, int(shapeInfo.Width), int(shapeInfo.Height)))
		}
		out := s.pointerInfo.shapeOutBuffer.Pix
		in := s.pointerInfo.shapeInBuffer
		for j := 0; j < int(shapeInfo.Height); j++ {
			dst := out[j*int(shapeInfo.Pitch):]
			src := in[j*int(shapeInfo.Pitch):]
			copy(dst, src[:shapeInfo.Pitch])
		}
	default:
		s.pointerInfo.size = dxgi.POINT{}
	}
	return nil
}

func (s *ScreenDXGI) drawPointer(img *image.RGBA) {
	if !s.shouldDrawPointer || s.pointerInfo.shapeOutBuffer == nil || !s.pointerInfo.visible {
		return
	}
	for j := 0; j < int(s.pointerInfo.size.Y); j++ {
		for i := 0; i < int(s.pointerInfo.size.X); i++ {
			col := s.pointerInfo.shapeOutBuffer.At(i, j)
			_, _, _, a := col.RGBA()
			if a == 0 {
				continue
			}
			x := int(s.pointerInfo.pos.X) + i
			y := int(s.pointerInfo.pos.Y) + j
			if x < 0 || y < 0 || x >= img.Bounds().Dx() || y >= img.Bounds().Dy() {
				continue
			}
			img.Set(x, y, col)
		}
	}
}

func (s *Screen) Init(displayIndex uint, rect image.Rectangle) {
	defer func() {
		if r := recover(); r != nil {
			telemetry.LogStructured("ERROR", "Panic during desktop capture initialization", map[string]interface{}{
				"panic":   r,
				"display": displayIndex,
			})
			if s.screen != nil {
				s.screen.Release()
			}
			s.screen = nil
		}
	}()

	// Reset active backend state for this initialization attempt.
	setActiveCaptureBackend("unknown")

	tryInit := func(name string, init func() error, release func()) (err error) {
		defer func() {
			if r := recover(); r != nil {
				telemetry.LogStructured("ERROR", "Panic during capture backend init", map[string]interface{}{
					"backend": name,
					"panic":   r,
					"display": displayIndex,
				})
				if release != nil {
					release()
				}
				err = fmt.Errorf("panic in %s init: %v", name, r)
			}
		}()
		err = init()
		if err != nil && release != nil {
			release()
		}
		return err
	}

	tryInitWithTimeout := func(name string, init func() error, release func(), timeout time.Duration) error {
		done := make(chan error, 1)
		go func() {
			done <- tryInit(name, init, release)
		}()
		select {
		case err := <-done:
			return err
		case <-time.After(timeout):
			telemetry.LogStructured("WARN", "Capture backend init timed out", map[string]interface{}{
				"backend":    name,
				"display":    displayIndex,
				"timeout_ms": timeout.Milliseconds(),
				"is_bridge":  IsBridgeMode(),
			})
			return errors.New("capture init timeout")
		}
	}

	desired := getConfiguredCaptureBackend()
	if s.overrideBackend != CaptureBackendAuto {
		desired = s.overrideBackend
	}
	order := backendPreferenceOrder(desired)
	var (
		initSuccess bool
		dxgiFailed  bool
	)

	for _, backend := range order {
		switch backend {
		case CaptureBackendSharedSurface:
			if !isSharedSurfaceEnabled() {
				telemetry.LogStructured("DEBUG", "Shared surface backend skipped (disabled)", map[string]interface{}{
					"display": displayIndex,
				})
				continue
			}
			shared := &ScreenSharedSurface{}
			if err := tryInitWithTimeout("shared_surface", func() error { return shared.Init(displayIndex, rect) }, shared.Release, 2*time.Second); err != nil {
				telemetry.LogStructured("WARN", "Shared surface initialization failed, falling back", map[string]interface{}{
					"display": displayIndex,
					"error":   err.Error(),
				})
				continue
			}
			s.screen = shared
			setActiveCaptureBackend("shared_surface")
			initSuccess = true

		case CaptureBackendNVFBC:
			if !nvfbcSupported() {
				if desired == CaptureBackendNVFBC {
					telemetry.LogStructured("ERROR", "NVFBC requested but not available", map[string]interface{}{
						"display": displayIndex,
					})
				} else {
					telemetry.LogStructured("DEBUG", "NVFBC skipped - driver/runtime missing", map[string]interface{}{
						"display": displayIndex,
					})
				}
				continue
			}
			nvfbc := &ScreenNVFBC{}
			if err := tryInitWithTimeout("nvfbc", func() error { return nvfbc.Init(displayIndex, rect) }, nvfbc.Release, 2*time.Second); err != nil {
				telemetry.LogStructured("WARN", "NVFBC initialization failed, falling back", map[string]interface{}{
					"display": displayIndex,
					"error":   err.Error(),
				})
				continue
			}
			s.screen = nvfbc
			setActiveCaptureBackend("nvfbc")
			initSuccess = true

		case CaptureBackendDXGI:
			dxgi := &ScreenDXGI{}
			if err := tryInitWithTimeout("dxgi", func() error { return dxgi.Init(displayIndex, rect) }, dxgi.Release, 2*time.Second); err != nil {
				dxgiFailed = true
				telemetry.LogStructured("WARN", "DXGI initialization failed, falling back", map[string]interface{}{
					"display": displayIndex,
					"error":   err.Error(),
				})
				continue
			}
			s.screen = dxgi
			setActiveCaptureBackend("dxgi")
			initSuccess = true
			dxgiFailed = false

		case CaptureBackendGDI:
			var gdi ScreenCapture
			if IsBridgeMode() {
				gdi = &ScreenGDICompat{}
			} else {
				gdi = &ScreenGDI{}
			}
			if err := tryInitWithTimeout("gdi", func() error { return gdi.Init(displayIndex, rect) }, gdi.Release, 2*time.Second); err != nil {
				telemetry.LogStructured("ERROR", "GDI initialization failed", map[string]interface{}{
					"display": displayIndex,
					"error":   err.Error(),
				})
				continue
			}
			if dxgiFailed {
				dxgiFallbackCount.Add(1)
			}
			s.screen = gdi
			setActiveCaptureBackend("gdi")
			initSuccess = true
			dxgiFailed = false
		}

		if initSuccess {
			telemetry.LogStructured("INFO", "Desktop capture initialized", map[string]interface{}{
				"display":           displayIndex,
				"rect":              rect.String(),
				"backend":           getActiveCaptureBackend(),
				"requested_backend": captureBackendName(desired),
			})
			break
		}
	}

	// Last-resort fallback: use screenshot library if all optimized backends fail.
	if !initSuccess {
		var fallback ScreenCapture
		fallbackName := "screenshot"
		if IsBridgeMode() {
			// In bridge mode, prefer the pure-GDI compat path over kbinani/screenshot
			// to avoid known hangs around GetDIBits on some systems.
			fallback = &ScreenGDICompat{}
			fallbackName = "gdi"
		} else {
			fallback = &ScreenScreenshot{}
		}
		if err := fallback.Init(displayIndex, rect); err == nil {
			s.screen = fallback
			setActiveCaptureBackend(fallbackName)
			initSuccess = true
			telemetry.LogStructured("WARN", "Falling back to capture backend", map[string]interface{}{
				"backend":           fallbackName,
				"display":           displayIndex,
				"rect":              rect.String(),
				"requested_backend": captureBackendName(desired),
			})
		}
	}

	// Avoid doing a synchronous test capture here: certain Win32 capture backends can
	// hang inside Capture(), which would block the worker from ever starting.
	if !initSuccess {
		telemetry.LogStructured("ERROR", "Failed to initialize any capture backend", map[string]interface{}{
			"display":           displayIndex,
			"requested_backend": captureBackendName(desired),
		})
	}
}

func (s *Screen) Capture() (*CaptureFrame, error) {
	if s.screen == nil {
		captureCount.Add(1)
		captureErrors.Add(1)
		if captureErrors.Load()%10 == 1 {
			telemetry.LogStructured("ERROR", "Capture called with no initialized backend", map[string]interface{}{
				"backend": getActiveCaptureBackend(),
			})
		}
		return nil, errors.New("capture backend not initialized")
	}

	start := time.Now()
	frame, err := s.screen.Capture()
	latency := time.Since(start)

	captureLatency.Store(latency.Nanoseconds())
	captureCount.Add(1)

	if err != nil && err != errNoImage {
		captureErrors.Add(1)
		if captureErrors.Load()%100 == 1 {
			telemetry.LogStructured("WARN", "Capture error", map[string]interface{}{
				"error":         err.Error(),
				"error_count":   captureErrors.Load(),
				"capture_count": captureCount.Load(),
				"backend":       getActiveCaptureBackend(),
			})
		}
	}

	return frame, err
}

func (s *Screen) Release() {
	if s.screen != nil {
		s.screen.Release()
	}
	telemetry.LogStructured("INFO", "Desktop capture released", map[string]interface{}{
		"platform":       runtime.GOOS,
		"backend":        getActiveCaptureBackend(),
		"total_captures": captureCount.Load(),
		"total_errors":   captureErrors.Load(),
		"dxgi_fallbacks": dxgiFallbackCount.Load(),
	})
}

func (s *ScreenDXGI) Init(displayIndex uint, rect image.Rectangle) (err error) {
	// Panic-safe cleanup: release resources on any panic
	defer func() {
		if r := recover(); r != nil {
			s.Release()
			err = errors.New("DXGI init panic recovered")
		}
	}()

	s.rect = rect
	if !winDXGI.IsValidDpiAwarenessContext(winDXGI.DpiAwarenessContextPerMonitorAwareV2) {
		return errors.New("no valid DPI awareness context")
	}
	_, err = winDXGI.SetThreadDpiAwarenessContext(winDXGI.DpiAwarenessContextPerMonitorAwareV2)
	if err != nil {
		return err
	}

	s.device, s.deviceCtx, err = d3d11.NewD3D11Device()
	if err != nil {
		s.Release()
		return err
	}

	if err := s.initDuplicator(displayIndex); err != nil {
		s.Release()
		return err
	}
	return nil
}
func (s *ScreenDXGI) Capture() (*CaptureFrame, error) {
	if s.duplicator == nil {
		return nil, errors.New("dxgi duplicator not initialized")
	}

	timeout := dxgiCaptureTimeoutMillis()
	var frameInfo dxgi.DXGI_OUTDUPL_FRAME_INFO
	var desktopResource *dxgi.IDXGIResource

	s.duplicator.ReleaseFrame()
	hr := s.duplicator.AcquireNextFrame(uint(timeout), &frameInfo, &desktopResource)
	if d3d.HRESULT(hr) == d3d.DXGI_ERROR_WAIT_TIMEOUT {
		return nil, errNoImage
	}
	if d3d.HRESULT(hr).Failed() {
		return nil, fmt.Errorf("dxgi acquire frame failed: %w", d3d.HRESULT(hr))
	}
	defer s.duplicator.ReleaseFrame()
	defer desktopResource.Release()

	if frameInfo.AccumulatedFrames == 0 {
		return nil, errNoImage
	}

	if err := s.updatePointer(&frameInfo); err != nil {
		telemetry.LogStructured("WARN", "dxgi pointer update failed", map[string]interface{}{
			"error": err.Error(),
		})
	}

	var desktopTex *d3d11.ID3D11Texture2D
	if hr := desktopResource.QueryInterface(d3d11.IID_ID3D11Texture2D, &desktopTex); d3d.HRESULT(hr).Failed() {
		return nil, fmt.Errorf("desktop QueryInterface failed: %w", d3d.HRESULT(hr))
	}
	defer desktopTex.Release()

	if err := s.ensureStage(desktopTex); err != nil {
		return nil, err
	}

	desc := d3d11.D3D11_TEXTURE2D_DESC{}
	if hr := desktopTex.GetDesc(&desc); d3d.HRESULT(hr).Failed() {
		return nil, fmt.Errorf("texture GetDesc failed: %w", d3d.HRESULT(hr))
	}
	if err := s.ensureGPUTexture(&desc); err != nil {
		telemetry.LogStructured("WARN", "dxgi gpu texture allocation failed", map[string]interface{}{
			"error": err.Error(),
		})
	}

	s.deviceCtx.CopyResource2D(s.stagedTex, desktopTex)

	if hr := s.surface.Map(&s.mappedRect, dxgi.DXGI_MAP_READ); d3d.HRESULT(hr).Failed() {
		return nil, fmt.Errorf("surface map failed: %w", d3d.HRESULT(hr))
	}
	defer s.surface.Unmap()

	width := int(s.size.X)
	height := int(s.size.Y)
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	pitch := int(s.mappedRect.Pitch)
	for y := 0; y < height; y++ {
		src := ((*[1 << 30]byte)(unsafe.Pointer(s.mappedRect.PBits)))[y*pitch:]
		dst := img.Pix[y*img.Stride:]
		copy(dst[:img.Stride], src[:img.Stride])
	}
	if s.needsSwizzle {
		swizzle.BGRA(img.Pix)
	}
	s.drawPointer(img)

	return &CaptureFrame{Image: img}, nil
}
func (s *ScreenDXGI) Release() {
	if s.duplicator != nil {
		s.duplicator.Release()
		s.duplicator = nil
	}
	if s.surface != nil {
		s.surface.Release()
		s.surface = nil
	}
	if s.stagedTex != nil {
		s.stagedTex.Release()
		s.stagedTex = nil
	}
	if s.gpuTex != nil {
		s.gpuTex.Release()
		s.gpuTex = nil
	}
	if s.device != nil {
		s.device.Release()
		s.device = nil
	}
	if s.deviceCtx != nil {
		s.deviceCtx.Release()
		s.deviceCtx = nil
	}
}

func logDXGIAdapterInfo(adapter *dxgi.IDXGIAdapter1, output *dxgi.IDXGIOutput, displayIndex uint) {
	if adapter == nil {
		return
	}

	adapterDesc, err := queryDXGIAdapterDesc(adapter)
	if err != nil {
		telemetry.LogStructured("WARN", "DXGI adapter query failed", map[string]interface{}{
			"display": displayIndex,
			"error":   err.Error(),
		})
		return
	}

	payload := map[string]interface{}{
		"display":                displayIndex,
		"adapter":                windows.UTF16ToString(adapterDesc.Description[:]),
		"vendor_id":              fmt.Sprintf("0x%04X", adapterDesc.VendorID),
		"device_id":              fmt.Sprintf("0x%04X", adapterDesc.DeviceID),
		"subsys_id":              fmt.Sprintf("0x%04X", adapterDesc.SubSysID),
		"revision":               adapterDesc.Revision,
		"adapter_luid":           formatLUID(adapterDesc.AdapterLuid),
		"dedicated_vram_mb":      uint64(adapterDesc.DedicatedVideoMemory) / (1024 * 1024),
		"dedicated_system_mb":    uint64(adapterDesc.DedicatedSystemMemory) / (1024 * 1024),
		"shared_system_mb":       uint64(adapterDesc.SharedSystemMemory) / (1024 * 1024),
		"adapter_flags":          adapterDesc.Flags,
		"backend":                "dxgi",
		"active_capture_backend": getActiveCaptureBackend(),
	}

	if output != nil {
		if outputDesc, err := queryDXGIOutputDesc(output); err == nil {
			rect := outputDesc.DesktopCoordinates
			width := int(rect.Right - rect.Left)
			height := int(rect.Bottom - rect.Top)
			payload["output"] = windows.UTF16ToString(outputDesc.DeviceName[:])
			payload["desktop_rect"] = fmt.Sprintf("%dx%d@(%d,%d)", width, height, rect.Left, rect.Top)
			payload["attached_to_desktop"] = outputDesc.AttachedToDesktop != 0
			payload["rotation"] = outputDesc.Rotation
		} else {
			telemetry.LogStructured("WARN", "DXGI output query failed", map[string]interface{}{
				"display": displayIndex,
				"error":   err.Error(),
			})
		}
	}

	telemetry.LogStructured("INFO", "DXGI adapter capabilities", payload)
}

func queryDXGIAdapterDesc(adapter *dxgi.IDXGIAdapter1) (*dxgiAdapterDesc1, error) {
	if adapter == nil {
		return nil, errors.New("nil adapter")
	}
	vtbl := *(**dxgi.IDXGIAdapter1Vtbl)(unsafe.Pointer(adapter))
	var desc dxgiAdapterDesc1
	hr, _, _ := syscall.Syscall(
		vtbl.GetDesc1,
		2,
		uintptr(unsafe.Pointer(adapter)),
		uintptr(unsafe.Pointer(&desc)),
		0,
	)
	if d3d.HRESULT(hr).Failed() {
		return nil, fmt.Errorf("GetDesc1 failed: %w", d3d.HRESULT(hr))
	}
	return &desc, nil
}

func queryDXGIOutputDesc(output *dxgi.IDXGIOutput) (*dxgiOutputDesc, error) {
	if output == nil {
		return nil, errors.New("nil output")
	}
	vtbl := *(**dxgi.IDXGIOutputVtbl)(unsafe.Pointer(output))
	var desc dxgiOutputDesc
	hr, _, _ := syscall.Syscall(
		vtbl.GetDesc,
		2,
		uintptr(unsafe.Pointer(output)),
		uintptr(unsafe.Pointer(&desc)),
		0,
	)
	if d3d.HRESULT(hr).Failed() {
		return nil, fmt.Errorf("GetDesc failed: %w", d3d.HRESULT(hr))
	}
	return &desc, nil
}

func formatLUID(luid windows.LUID) string {
	return fmt.Sprintf("%08x:%08x", uint32(luid.HighPart), luid.LowPart)
}

func (s *ScreenGDI) Init(_ uint, rect image.Rectangle) (err error) {
	// Panic-safe cleanup: release resources on any panic
	defer func() {
		if r := recover(); r != nil {
			s.Release()
			err = errors.New("GDI init panic recovered")
		}
	}()

	s.rect = rect
	s.width = rect.Dx()
	s.height = rect.Dy()

	s.hwnd = getDesktopWindow()
	s.hdc = winGDI.GetDC(s.hwnd)
	if s.hdc == 0 {
		s.Release()
		return errors.New("GetDC failed")
	}
	s.memoryDevice = winGDI.CreateCompatibleDC(s.hdc)
	if s.memoryDevice == 0 {
		s.Release()
		return errors.New("CreateCompatibleDC failed")
	}
	s.bitmap = winGDI.CreateCompatibleBitmap(s.hdc, int32(s.width), int32(s.height))
	if s.bitmap == 0 {
		s.Release()
		return errors.New("CreateCompatibleBitmap failed")
	}

	s.bitmapInfo = winGDI.BITMAPINFOHEADER{}
	s.bitmapInfo.BiSize = uint32(unsafe.Sizeof(s.bitmapInfo))
	s.bitmapInfo.BiPlanes = 1
	s.bitmapInfo.BiBitCount = 32
	s.bitmapInfo.BiWidth = int32(s.width)
	s.bitmapInfo.BiHeight = -int32(s.height)
	s.bitmapInfo.BiCompression = winGDI.BI_RGB
	s.bitmapInfo.BiSizeImage = uint32(s.width * s.height * 4)

	s.bitmapDataSize = uintptr(((int64(s.width)*int64(s.bitmapInfo.BiBitCount) + 31) / 32) * 4 * int64(s.height))
	s.hmem = winGDI.GlobalAlloc(winGDI.GMEM_MOVEABLE, s.bitmapDataSize)
	if s.hmem == 0 {
		s.Release()
		return errors.New("GlobalAlloc failed")
	}
	s.memptr = winGDI.GlobalLock(s.hmem)
	if s.memptr == nil {
		s.Release()
		return errors.New("GlobalLock failed")
	}
	return nil
}
func (s *ScreenGDI) Capture() (*CaptureFrame, error) {
	const hgdiError = winGDI.HGDIOBJ(^uintptr(0))

	old := winGDI.SelectObject(s.memoryDevice, winGDI.HGDIOBJ(s.bitmap))
	if old == 0 || old == hgdiError {
		return nil, errors.New("SelectObject failed")
	}
	defer winGDI.SelectObject(s.memoryDevice, old)

	if !winGDI.BitBlt(s.memoryDevice, 0, 0, int32(s.width), int32(s.height), s.hdc, int32(s.rect.Min.X), int32(s.rect.Min.Y), winGDI.SRCCOPY|winGDI.CAPTUREBLT) {
		return nil, errors.New("BitBlt failed")
	}

	if winGDI.GetDIBits(s.memoryDevice, s.bitmap, 0, uint32(s.height), (*uint8)(s.memptr), (*winGDI.BITMAPINFO)(unsafe.Pointer(&s.bitmapInfo)), winGDI.DIB_RGB_COLORS) == 0 {
		return nil, errors.New("GetDIBits failed")
	}

	img := image.NewRGBA(image.Rect(0, 0, s.width, s.height))
	imageBytes := ((*[1 << 30]byte)(unsafe.Pointer(s.memptr)))[:s.bitmapDataSize:s.bitmapDataSize]
	copy(img.Pix[:s.bitmapDataSize], imageBytes)
	swizzle.BGRA(img.Pix)

	return &CaptureFrame{Image: img}, nil
}
func (s *ScreenGDI) Release() {
	if s.hdc != 0 {
		winGDI.ReleaseDC(s.hwnd, s.hdc)
		s.hdc = 0
	}
	if s.memoryDevice != 0 {
		winGDI.DeleteDC(s.memoryDevice)
		s.memoryDevice = 0
	}
	if s.bitmap != 0 {
		winGDI.DeleteObject(winGDI.HGDIOBJ(s.bitmap))
		s.bitmap = 0
	}
	if s.hmem != 0 {
		winGDI.GlobalUnlock(s.hmem)
		winGDI.GlobalFree(s.hmem)
		s.hmem = 0
	}
}
func getDesktopWindow() winGDI.HWND {
	ret, _, _ := syscall.SyscallN(funcGetDesktopWindow)
	return winGDI.HWND(ret)
}
