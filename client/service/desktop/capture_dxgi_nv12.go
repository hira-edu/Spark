//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
	"math"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"Rocket/client/telemetry"

	"github.com/kirides/go-d3d"
	"github.com/kirides/go-d3d/d3d11"
	"github.com/kirides/go-d3d/dxgi"
	winDXGI "github.com/kirides/go-d3d/win"
	"golang.org/x/sys/windows"
)

// DXGI NV12 capture: Desktop Duplication (GPU BGRA/RGBA texture) + D3D11 video
// processor conversion (GPU NV12 texture). The CaptureFrame contains only a GPU
// texture (no CPU pixels).

const (
	// Shared constants used by the D3D11 video processor implementation.
	dxgiFormatNV12         = 103 // DXGI_FORMAT_NV12
	d3d11UsageDefault      = 0
	d3d11BindRenderTarget  = 0x00000020
	d3d11CPUAccessNone     = 0
	d3d11SDKVersion        = 7
	d3dDriverTypeUnknown   = 0
	d3dDriverTypeHardware  = 1
	d3dFeatureLevel_11_1   = 0xb100
	d3dFeatureLevel_11_0   = 0xb000
	d3d11CreateDeviceVideo = 0x00000800 // D3D11_CREATE_DEVICE_VIDEO_SUPPORT
	d3d11CreateDeviceBGRA  = 0x00000020 // D3D11_CREATE_DEVICE_BGRA_SUPPORT
)

var (
	d3d11DLL              = windows.NewLazySystemDLL("d3d11.dll")
	procD3D11CreateDevice = d3d11DLL.NewProc("D3D11CreateDevice")

	// Shared GUIDs used across the GPU pipeline.
	iidIDXGISurface       windows.GUID // used by mf_dxgi_manager.go
	iidID3D11VideoDevice  windows.GUID
	iidID3D11VideoContext windows.GUID

	dxgiNV12InitOnce sync.Once
	dxgiNV12InitErr  error
)

func initDXGINV12GUIDs() {
	dxgiNV12InitOnce.Do(func() {
		var err error
		iidIDXGISurface, err = windows.GUIDFromString("{cafcb56c-6ac3-4889-bf47-9e23bbd260ec}")
		if err != nil {
			dxgiNV12InitErr = err
			return
		}
		iidID3D11VideoDevice, err = windows.GUIDFromString("{10EC4D5B-975A-4689-B9E4-D0AAC30FE333}")
		if err != nil {
			dxgiNV12InitErr = err
			return
		}
		iidID3D11VideoContext, err = windows.GUIDFromString("{61F21C45-3C0E-4a74-9CEA-67100D9AD5E4}")
		if err != nil {
			dxgiNV12InitErr = err
			return
		}
	})
}

// DXGINV12Capturer captures the desktop and returns an NV12 GPU texture.
type DXGINV12Capturer struct {
	displayIndex uint
	bounds       image.Rectangle

	mu sync.Mutex

	device         *iD3D11Device
	deviceCtx      *iD3D11DeviceContext
	videoDevice    *iD3D11VideoDevice
	videoContext   *iD3D11VideoContext
	videoProcessor *VideoProcessor
	outputDup      *dxgi.IDXGIOutputDuplication

	adapterIndex uint
	outputIndex  uint

	srcWidth  int
	srcHeight int
	vpWidth   int
	vpHeight  int

	lastFrameTime time.Time
	frameCount    atomic.Uint64
	errorCount    atomic.Uint64
}

func computeNV12OutputSize(srcW, srcH int) (int, int) {
	maxW := parseEnvOptionalInt(envWebRTCMaxWidth, webRTCDefaultMaxW)
	maxH := parseEnvOptionalInt(envWebRTCMaxHeight, webRTCDefaultMaxH)
	if maxW <= 0 && maxH <= 0 {
		return srcW, srcH
	}

	scale := 1.0
	if maxW > 0 {
		scale = math.Min(scale, float64(maxW)/float64(srcW))
	}
	if maxH > 0 {
		scale = math.Min(scale, float64(maxH)/float64(srcH))
	}
	if !(scale > 0) || scale >= 1 {
		return srcW, srcH
	}
	outW := int(math.Round(float64(srcW) * scale))
	outH := int(math.Round(float64(srcH) * scale))
	if outW%2 == 1 {
		outW--
	}
	if outH%2 == 1 {
		outH--
	}
	// H.264 encoders commonly require 16x16 macroblock alignment.
	if outW >= 16 {
		outW &^= 15
	}
	if outH >= 16 {
		outH &^= 15
	}
	if outW < 2 {
		outW = 2
	}
	if outH < 2 {
		outH = 2
	}
	if outW > srcW {
		outW = srcW
	}
	if outH > srcH {
		outH = srcH
	}
	return outW, outH
}

// NewDXGINV12Capturer creates a GPU-accelerated screen capturer (NV12 output).
func NewDXGINV12Capturer(displayIndex uint, bounds image.Rectangle) (*DXGINV12Capturer, error) {
	initDXGINV12GUIDs()
	if dxgiNV12InitErr != nil {
		return nil, fmt.Errorf("DXGI NV12 init failed: %w", dxgiNV12InitErr)
	}

	c := &DXGINV12Capturer{
		displayIndex: displayIndex,
		bounds:       bounds,
	}

	if err := c.initialize(); err != nil {
		c.Release()
		return nil, err
	}

	return c, nil
}

func (c *DXGINV12Capturer) initialize() error {
	if c.bounds.Dx() <= 0 || c.bounds.Dy() <= 0 {
		return fmt.Errorf("invalid bounds: %v", c.bounds)
	}

	if winDXGI.IsValidDpiAwarenessContext(winDXGI.DpiAwarenessContextPerMonitorAwareV2) {
		_, _ = winDXGI.SetThreadDpiAwarenessContext(winDXGI.DpiAwarenessContextPerMonitorAwareV2)
	}

	sel, _ := findDXGIOutputForRect(c.bounds)
	var adapter *dxgi.IDXGIAdapter1
	if sel != nil {
		var output *dxgi.IDXGIOutput
		var err error
		adapter, output, err = openDXGIAdapterOutput(sel)
		if err != nil {
			adapter = nil
			sel = nil
		} else if output != nil {
			output.Release()
		}
	}

	device, deviceCtx, err := createD3D11DeviceWithVideoSupport(adapter)
	if adapter != nil {
		adapter.Release()
	}
	if err != nil {
		return err
	}
	c.device = device
	c.deviceCtx = deviceCtx

	videoDevicePtr, err := c.device.QueryInterface(&iidID3D11VideoDevice)
	if err != nil {
		return fmt.Errorf("QueryInterface(ID3D11VideoDevice): %w", err)
	}
	c.videoDevice = (*iD3D11VideoDevice)(videoDevicePtr)

	videoContextPtr, err := c.deviceCtx.QueryInterface(&iidID3D11VideoContext)
	if err != nil {
		return fmt.Errorf("QueryInterface(ID3D11VideoContext): %w", err)
	}
	c.videoContext = (*iD3D11VideoContext)(videoContextPtr)

	if sel != nil {
		c.adapterIndex = sel.AdapterIndex
		c.outputIndex = sel.OutputIndex
		if err := c.setupDesktopDuplicationSelected(sel); err != nil {
			return err
		}
	} else {
		if err := c.setupDesktopDuplicationLegacy(); err != nil {
			return err
		}
	}

	baseRect := c.bounds
	if sel != nil && sel.OutputDesc != nil {
		baseRect = rectFromDXGI(sel.OutputDesc.DesktopCoordinates)
	}

	width := baseRect.Dx()
	height := baseRect.Dy()
	if width%2 == 1 {
		width--
	}
	if height%2 == 1 {
		height--
	}
	if width <= 0 || height <= 0 {
		return fmt.Errorf("invalid NV12 size: %dx%d", width, height)
	}
	c.srcWidth = width
	c.srcHeight = height
	outW, outH := computeNV12OutputSize(width, height)
	c.vpWidth = outW
	c.vpHeight = outH

	vp, err := NewVideoProcessor(c.device, c.deviceCtx, c.videoDevice, c.videoContext, width, height, outW, outH)
	if err != nil {
		telemetryLog("WARN", "Failed to create D3D11 video processor (DXGI NV12 capture unavailable)", map[string]interface{}{
			"error":  err.Error(),
			"width":  width,
			"height": height,
		})
		return err
	}
	c.videoProcessor = vp

	telemetryLog("INFO", "DXGI NV12 capture initialized", map[string]interface{}{
		"display": c.displayIndex,
		"width":   outW,
		"height":  outH,
	})

	return nil
}

func (c *DXGINV12Capturer) setupDesktopDuplicationSelected(sel *dxgiOutputSelection) error {
	if sel == nil {
		return errors.New("nil selection")
	}

	d3dDevice := (*d3d11.ID3D11Device)(unsafe.Pointer(c.device))

	var dxgiDevice1 *dxgi.IDXGIDevice1
	hr := d3dDevice.QueryInterface(dxgi.IID_IDXGIDevice1, &dxgiDevice1)
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("dxgi device query failed: %w", d3d.HRESULT(hr))
	}
	defer dxgiDevice1.Release()

	adapter, output, err := openDXGIAdapterOutput(sel)
	if err != nil {
		return err
	}
	defer output.Release()
	defer adapter.Release()

	logDXGIAdapterInfo(adapter, output, c.displayIndex)

	dup, err := duplicateOutput(dxgiDevice1, output, []dxgi.DXGI_FORMAT{
		dxgi.DXGI_FORMAT_B8G8R8A8_UNORM,
		dxgi.DXGI_FORMAT_R8G8B8A8_UNORM,
	})
	if err != nil {
		return err
	}

	c.outputDup = dup
	return nil
}

func (c *DXGINV12Capturer) setupDesktopDuplicationLegacy() error {
	d3dDevice := (*d3d11.ID3D11Device)(unsafe.Pointer(c.device))

	var dxgiDevice1 *dxgi.IDXGIDevice1
	hr := d3dDevice.QueryInterface(dxgi.IID_IDXGIDevice1, &dxgiDevice1)
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
	hr = int32(dxgiAdapter.EnumOutputs(c.displayIndex, &dxgiOutput))
	if d3d.HRESULT(hr).Failed() {
		return fmt.Errorf("dxgi enum outputs failed: %w", d3d.HRESULT(hr))
	}
	defer dxgiOutput.Release()

	logDXGIAdapterInfo(dxgiAdapter, dxgiOutput, c.displayIndex)

	dup, err := duplicateOutput(dxgiDevice1, dxgiOutput, []dxgi.DXGI_FORMAT{
		dxgi.DXGI_FORMAT_B8G8R8A8_UNORM,
		dxgi.DXGI_FORMAT_R8G8B8A8_UNORM,
	})
	if err != nil {
		return err
	}
	c.outputDup = dup
	return nil
}

func duplicateOutput(dxgiDevice1 *dxgi.IDXGIDevice1, output *dxgi.IDXGIOutput, formats []dxgi.DXGI_FORMAT) (*dxgi.IDXGIOutputDuplication, error) {
	if dxgiDevice1 == nil || output == nil {
		return nil, errors.New("nil dxgi device/output")
	}
	var dup *dxgi.IDXGIOutputDuplication
	var hr int32

	var output5 *dxgi.IDXGIOutput5
	hr = output.QueryInterface(dxgi.IID_IDXGIOutput5, &output5)
	if !d3d.HRESULT(hr).Failed() {
		defer output5.Release()
		hr = output5.DuplicateOutput1(dxgiDevice1, 0, formats, &dup)
	}

	if dup == nil || d3d.HRESULT(hr).Failed() {
		var output1 *dxgi.IDXGIOutput1
		hr = output.QueryInterface(dxgi.IID_IDXGIOutput1, &output1)
		if d3d.HRESULT(hr).Failed() {
			return nil, fmt.Errorf("dxgi output1 query failed: %w", d3d.HRESULT(hr))
		}
		defer output1.Release()
		hr = output1.DuplicateOutput(dxgiDevice1, &dup)
		if d3d.HRESULT(hr).Failed() {
			return nil, fmt.Errorf("dxgi duplicate output failed: %w", d3d.HRESULT(hr))
		}
	}

	return dup, nil
}

func shouldResetDXGI(hr d3d.HRESULT) bool {
	switch hr {
	case d3d.DXGI_ERROR_ACCESS_LOST,
		d3d.DXGI_ERROR_DEVICE_REMOVED,
		d3d.DXGI_ERROR_DEVICE_RESET,
		d3d.DXGI_ERROR_DEVICE_HUNG,
		d3d.DXGI_ERROR_DRIVER_INTERNAL_ERROR,
		d3d.DXGI_ERROR_SESSION_DISCONNECTED,
		d3d.DXGI_ERROR_MODE_CHANGE_IN_PROGRESS,
		d3d.DXGI_ERROR_NOT_CURRENTLY_AVAILABLE:
		return true
	default:
		return false
	}
}

func (c *DXGINV12Capturer) resetLocked(reason d3d.HRESULT) error {
	telemetryLog("WARN", "DXGI NV12 capture reset", map[string]interface{}{
		"display": c.displayIndex,
		"reason":  fmt.Sprintf("0x%08X", uint32(reason)),
	})

	full := reason == d3d.DXGI_ERROR_DEVICE_REMOVED ||
		reason == d3d.DXGI_ERROR_DEVICE_RESET ||
		reason == d3d.DXGI_ERROR_DEVICE_HUNG ||
		reason == d3d.DXGI_ERROR_DRIVER_INTERNAL_ERROR

	if c.outputDup != nil {
		c.outputDup.Release()
		c.outputDup = nil
	}

	if full {
		if c.videoProcessor != nil {
			c.videoProcessor.Release()
			c.videoProcessor = nil
		}
		if c.videoContext != nil {
			c.videoContext.Release()
			c.videoContext = nil
		}
		if c.videoDevice != nil {
			c.videoDevice.Release()
			c.videoDevice = nil
		}
		if c.deviceCtx != nil {
			c.deviceCtx.Release()
			c.deviceCtx = nil
		}
		if c.device != nil {
			c.device.Release()
			c.device = nil
		}
		err := c.initialize()
		if err == nil && getActiveCaptureBackend() == "dxgi_nv12" {
			setCaptureD3D11Device(c.device)
		}
		return err
	}

	if sel, err := findDXGIOutputForRect(c.bounds); err == nil && sel != nil {
		if sel.AdapterIndex != c.adapterIndex {
			return c.initialize()
		}
		c.outputIndex = sel.OutputIndex
		return c.setupDesktopDuplicationSelected(sel)
	}

	return c.setupDesktopDuplicationLegacy()
}

// Capture returns a frame as NV12 GPU texture (zero CPU copy).
func (c *DXGINV12Capturer) Capture() (*CaptureFrame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if winDXGI.IsValidDpiAwarenessContext(winDXGI.DpiAwarenessContextPerMonitorAwareV2) {
		_, _ = winDXGI.SetThreadDpiAwarenessContext(winDXGI.DpiAwarenessContextPerMonitorAwareV2)
	}

	if c.outputDup == nil {
		return nil, errors.New("output duplication not initialized")
	}
	if c.videoProcessor == nil {
		return nil, errors.New("video processor not initialized")
	}

	timeout := dxgiCaptureTimeoutMillis()
	var frameInfo dxgi.DXGI_OUTDUPL_FRAME_INFO
	var desktopResource *dxgi.IDXGIResource

	c.outputDup.ReleaseFrame()
	hr := c.outputDup.AcquireNextFrame(uint(timeout), &frameInfo, &desktopResource)
	if d3d.HRESULT(hr) == d3d.DXGI_ERROR_WAIT_TIMEOUT {
		return nil, errNoImage
	}
	if d3d.HRESULT(hr).Failed() {
		c.errorCount.Add(1)
		if shouldResetDXGI(d3d.HRESULT(hr)) {
			_ = c.resetLocked(d3d.HRESULT(hr))
			return nil, errNoImage
		}
		return nil, fmt.Errorf("dxgi acquire frame failed: %w", d3d.HRESULT(hr))
	}
	defer c.outputDup.ReleaseFrame()
	defer desktopResource.Release()

	if frameInfo.AccumulatedFrames == 0 {
		return nil, errNoImage
	}

	var desktopTex *d3d11.ID3D11Texture2D
	if hr := desktopResource.QueryInterface(d3d11.IID_ID3D11Texture2D, &desktopTex); d3d.HRESULT(hr).Failed() {
		c.errorCount.Add(1)
		return nil, fmt.Errorf("desktop QueryInterface failed: %w", d3d.HRESULT(hr))
	}
	defer desktopTex.Release()

	var texDesc d3d11.D3D11_TEXTURE2D_DESC
	if hr := desktopTex.GetDesc(&texDesc); !d3d.HRESULT(hr).Failed() {
		newW := int(texDesc.Width)
		newH := int(texDesc.Height)
		if newW > 0 && newH > 0 {
			if newW%2 == 1 {
				newW--
			}
			if newH%2 == 1 {
				newH--
			}
			if newW > 0 && newH > 0 && (newW != c.srcWidth || newH != c.srcHeight) {
				outW, outH := computeNV12OutputSize(newW, newH)
				telemetryLog("INFO", "DXGI NV12 capture resizing video processor", map[string]interface{}{
					"display":     c.displayIndex,
					"input_from":  fmt.Sprintf("%dx%d", c.srcWidth, c.srcHeight),
					"input_to":    fmt.Sprintf("%dx%d", newW, newH),
					"output_from": fmt.Sprintf("%dx%d", c.vpWidth, c.vpHeight),
					"output_to":   fmt.Sprintf("%dx%d", outW, outH),
				})
				if c.videoProcessor != nil {
					c.videoProcessor.Release()
					c.videoProcessor = nil
				}
				c.srcWidth = newW
				c.srcHeight = newH
				c.vpWidth = outW
				c.vpHeight = outH
				vp, err := NewVideoProcessor(c.device, c.deviceCtx, c.videoDevice, c.videoContext, newW, newH, outW, outH)
				if err != nil {
					return nil, err
				}
				c.videoProcessor = vp
				return nil, errNoImage
			}
		}
	}

	bgraTexture := (*iD3D11Texture2D)(unsafe.Pointer(desktopTex))
	nv12Texture, err := c.videoProcessor.ConvertBGRAToNV12(bgraTexture)
	if err != nil {
		c.errorCount.Add(1)
		// Treat common DXGI reset scenarios as recoverable: reset the duplication + device
		// and return errNoImage so the worker doesn't trip its circuit breaker.
		var mfErr mfError
		if errors.As(err, &mfErr) {
			reason := d3d.HRESULT(int32(mfErr.hr))
			if shouldResetDXGI(reason) {
				_ = c.resetLocked(reason)
				return nil, errNoImage
			}
		}
		return nil, err
	}

	release := acquireNV12Lease(c.videoProcessor.ReturnTexture, nv12Texture)

	c.frameCount.Add(1)
	c.lastFrameTime = time.Now()

	width := c.vpWidth
	height := c.vpHeight
	stride := width

	frame := &CaptureFrame{
		Image: nil,
		GPU: &GPUFrame{
			Backend:  "dxgi_nv12",
			Width:    width,
			Height:   height,
			Format:   "NV12",
			Stride:   stride,
			Resource: nv12Texture,
			Release: func() {
				// Ref-counted lease prevents reusing the texture until all clones are done.
				release()
			},
		},
	}
	return frame, nil
}

func (c *DXGINV12Capturer) Release() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.outputDup != nil {
		c.outputDup.Release()
		c.outputDup = nil
	}
	if c.videoProcessor != nil {
		c.videoProcessor.Release()
		c.videoProcessor = nil
	}
	if c.videoContext != nil {
		c.videoContext.Release()
		c.videoContext = nil
	}
	if c.videoDevice != nil {
		c.videoDevice.Release()
		c.videoDevice = nil
	}
	if c.deviceCtx != nil {
		c.deviceCtx.Release()
		c.deviceCtx = nil
	}
	if c.device != nil {
		c.device.Release()
		c.device = nil
	}
}

func (c *DXGINV12Capturer) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"backend":     "dxgi_nv12",
		"frame_count": c.frameCount.Load(),
		"error_count": c.errorCount.Load(),
	}
	if !c.lastFrameTime.IsZero() {
		stats["last_capture"] = c.lastFrameTime.Format(time.RFC3339Nano)
	}
	return stats
}

func createD3D11DeviceWithVideoSupport(adapter *dxgi.IDXGIAdapter1) (*iD3D11Device, *iD3D11DeviceContext, error) {
	featureLevels := []uint32{
		d3dFeatureLevel_11_1,
		d3dFeatureLevel_11_0,
	}

	var selected uint32
	var device *iD3D11Device
	var deviceCtx *iD3D11DeviceContext

	flags := uint32(d3d11CreateDeviceVideo | d3d11CreateDeviceBGRA)
	adapterPtr := uintptr(0)
	driverType := uintptr(d3dDriverTypeHardware)
	if adapter != nil {
		adapterPtr = uintptr(unsafe.Pointer(adapter))
		driverType = uintptr(d3dDriverTypeUnknown)
	}
	r0, _, _ := procD3D11CreateDevice.Call(
		adapterPtr,
		driverType,
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(&featureLevels[0])),
		uintptr(len(featureLevels)),
		uintptr(d3d11SDKVersion),
		uintptr(unsafe.Pointer(&device)),
		uintptr(unsafe.Pointer(&selected)),
		uintptr(unsafe.Pointer(&deviceCtx)),
	)
	if err := hresultError(r0, "D3D11CreateDevice"); err != nil {
		return nil, nil, err
	}
	if device == nil || deviceCtx == nil {
		return nil, nil, fmt.Errorf("D3D11CreateDevice returned nil device/context")
	}
	// D3D11 immediate contexts are not thread-safe by default. Capture and encoder readback may
	// touch the immediate context from different locked OS threads. Enable multithread protection
	// to avoid DXGI_ERROR_DEVICE_REMOVED and stale readbacks under concurrent use.
	if err := enableD3D11MultithreadProtection(deviceCtx); err != nil {
		fmt.Printf("[DXGI] failed to enable D3D11 multithread protection (capture): %v\n", err)
	}
	return device, deviceCtx, nil
}

func telemetryLog(level, msg string, data map[string]interface{}) {
	telemetry.LogStructured(level, msg, data)
}

// ---- COM definitions required by D3D11 video processor / MF DXGI manager ----

type iD3D11Device struct {
	vtbl *iD3D11DeviceVtbl
}

func (d *iD3D11Device) AddRef() uint32 {
	if d == nil || d.vtbl == nil {
		return 0
	}
	ret, _, _ := syscall.SyscallN(d.vtbl.AddRef, uintptr(unsafe.Pointer(d)))
	return uint32(ret)
}

func (d *iD3D11Device) Release() {
	if d == nil || d.vtbl == nil {
		return
	}
	syscall.SyscallN(d.vtbl.Release, uintptr(unsafe.Pointer(d)))
}

func (d *iD3D11Device) QueryInterface(iid *windows.GUID) (unsafe.Pointer, error) {
	var result unsafe.Pointer
	r0, _, _ := syscall.SyscallN(
		d.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&result)),
	)
	if err := hresultError(r0, "QueryInterface"); err != nil {
		return nil, err
	}
	return result, nil
}

// GetDeviceRemovedReason returns the reason code if the device has been removed.
// Returns 0 (S_OK) if the device is operating normally.
func (d *iD3D11Device) GetDeviceRemovedReason() int32 {
	if d == nil || d.vtbl == nil {
		return -1
	}
	r0, _, _ := syscall.SyscallN(d.vtbl.GetDeviceRemovedReason, uintptr(unsafe.Pointer(d)))
	return int32(r0)
}

type iD3D11DeviceContext struct {
	vtbl *iD3D11DeviceContextVtbl
}

type iD3D11DeviceContextVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

func (c *iD3D11DeviceContext) Release() {
	if c == nil || c.vtbl == nil {
		return
	}
	syscall.SyscallN(c.vtbl.Release, uintptr(unsafe.Pointer(c)))
}

func (c *iD3D11DeviceContext) QueryInterface(iid *windows.GUID) (unsafe.Pointer, error) {
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

type iD3D11Texture2D struct {
	vtbl *iD3D11Texture2DVtbl
}

type iD3D11Texture2DVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

func (t *iD3D11Texture2D) AddRef() uint32 {
	if t == nil || t.vtbl == nil {
		return 0
	}
	ret, _, _ := syscall.SyscallN(t.vtbl.AddRef, uintptr(unsafe.Pointer(t)))
	return uint32(ret)
}

func (t *iD3D11Texture2D) Release() uint32 {
	if t == nil || t.vtbl == nil {
		return 0
	}
	ret, _, _ := syscall.SyscallN(t.vtbl.Release, uintptr(unsafe.Pointer(t)))
	return uint32(ret)
}

type iD3D11VideoDevice struct {
	vtbl *iD3D11VideoDeviceVtbl
}

func (v *iD3D11VideoDevice) Release() {
	if v == nil || v.vtbl == nil {
		return
	}
	syscall.SyscallN(v.vtbl.Release, uintptr(unsafe.Pointer(v)))
}

type iD3D11VideoContext struct {
	vtbl *iD3D11VideoContextVtbl
}

func (v *iD3D11VideoContext) Release() {
	if v == nil || v.vtbl == nil {
		return
	}
	syscall.SyscallN(v.vtbl.Release, uintptr(unsafe.Pointer(v)))
}

type iD3D11VideoProcessor struct {
	vtbl *iD3D11VideoProcessorVtbl
}

type iD3D11VideoProcessorVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

func (v *iD3D11VideoProcessor) Release() {
	if v == nil || v.vtbl == nil {
		return
	}
	syscall.SyscallN(v.vtbl.Release, uintptr(unsafe.Pointer(v)))
}

type iUnknown struct {
	vtbl *iUnknownVtbl
}

type iUnknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

func (u *iUnknown) QueryInterface(iid *windows.GUID) (unsafe.Pointer, error) {
	var result unsafe.Pointer
	r0, _, _ := syscall.SyscallN(
		u.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(u)),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&result)),
	)
	if err := hresultError(r0, "QueryInterface"); err != nil {
		return nil, err
	}
	return result, nil
}
