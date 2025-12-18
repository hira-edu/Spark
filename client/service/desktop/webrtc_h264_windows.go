//go:build windows

package desktop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"Rocket/client/service/desktop/colorconv"

	"github.com/kirides/go-d3d"
	"github.com/pion/webrtc/v4/pkg/media"
	"golang.org/x/sys/windows"
)

const (
	mfVersion           = 0x00020070
	mfStartupFull       = 0
	clsctxInprocServer  = 1
	mftSetTypeTestOnly  = 0x00000001
	mfInterlaceProgress = 2 // MFVideoInterlace_Progressive
)

const (
	mftMessageCommandFlush         = 0x00000000
	mftMessageCommandDrain         = 0x00000001
	mftMessageNotifyBeginStreaming = 0x10000000
	mftMessageNotifyStartOfStream  = 0x10000003
)

const (
	mftOutputStreamProvidesSamples = 0x00000100
)

const mfETransformTypeNotSet = 0xC00D6D60
const mfENotAccepting = 0xC00D36B5
const mfETransformNeedMoreInput = 0xC00D6D72
const mfETransformStreamChange = 0xC00D6D61

func envIsTruthy(name string) bool {
	val := strings.TrimSpace(os.Getenv(name))
	if val == "" {
		return false
	}
	switch strings.ToLower(val) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

var (
	mfplat                = windows.NewLazySystemDLL("mfplat.dll")
	procMFStartup         = mfplat.NewProc("MFStartup")
	procMFTEnumEx         = mfplat.NewProc("MFTEnumEx")
	procMFCreateMediaType = mfplat.NewProc("MFCreateMediaType")
	procMFCreateSample    = mfplat.NewProc("MFCreateSample")
	procMFCreateMemoryBuf = mfplat.NewProc("MFCreateMemoryBuffer")

	ole32                = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procCoTaskMemFree    = ole32.NewProc("CoTaskMemFree")

	mfOnce     sync.Once
	mfInitErr  error
	mfGUIDOnce sync.Once
	mfGUIDErr  error

	clsidCMSH264EncoderMFT     windows.GUID
	iidIMFTransform            windows.GUID
	mftCategoryVideoEncoder    windows.GUID
	mftTransformClsidAttribute windows.GUID

	mfMTMajorType             windows.GUID
	mfMTSubtype               windows.GUID
	mfMTFrameSize             windows.GUID
	mfMTFrameRate             windows.GUID
	mfMTInterlace             windows.GUID
	mfMTPixelAspect           windows.GUID
	mfMTAvgBitrate            windows.GUID
	mfMTProfile               windows.GUID
	mfMTDefaultStride         windows.GUID
	mfMTSampleSize            windows.GUID
	mfMTFixedSizeSamples      windows.GUID
	mfMTAllSamplesIndependent windows.GUID

	mfMediaTypeVideo windows.GUID
	mfVideoNV12      windows.GUID
	mfVideoH264      windows.GUID
)

func initMFGuids() {
	mfGUIDOnce.Do(func() {
		clsidCMSH264EncoderMFT, mfGUIDErr = parseGUID("6CA50344-051A-4DED-9779-A43305165E35")
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse CLSID_CMSH264EncoderMFT: %w", mfGUIDErr)
			return
		}
		iidIMFTransform, mfGUIDErr = parseGUID("BF94C121-5B05-4E6F-8000-BA598961414D")
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse IID_IMFTransform: %w", mfGUIDErr)
			return
		}
		mftCategoryVideoEncoder, mfGUIDErr = parseGUID("F79EAC7D-E545-4387-BDEE-D647D7BDE42A") // MFT_CATEGORY_VIDEO_ENCODER
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MFT_CATEGORY_VIDEO_ENCODER: %w", mfGUIDErr)
			return
		}
		mftTransformClsidAttribute, mfGUIDErr = parseGUID("6821C42B-65A4-4E82-99BC-9A88205ECD0C") // MFT_TRANSFORM_CLSID_Attribute
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MFT_TRANSFORM_CLSID_Attribute: %w", mfGUIDErr)
			return
		}

		mfMTMajorType, mfGUIDErr = parseGUID("48EBA18E-F8C9-4687-BF11-0A74C9F96A8F") // MF_MT_MAJOR_TYPE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_MAJOR_TYPE: %w", mfGUIDErr)
			return
		}
		mfMTSubtype, mfGUIDErr = parseGUID("F7E34C9A-42E8-4714-B74B-CB29D72C35E5") // MF_MT_SUBTYPE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_SUBTYPE: %w", mfGUIDErr)
			return
		}
		mfMTFrameSize, mfGUIDErr = parseGUID("1652C33D-D6B2-4012-B834-72030849A37D") // MF_MT_FRAME_SIZE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_FRAME_SIZE: %w", mfGUIDErr)
			return
		}
		mfMTFrameRate, mfGUIDErr = parseGUID("C459A2E8-3D2C-4E44-B132-FEE5156C7BB0") // MF_MT_FRAME_RATE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_FRAME_RATE: %w", mfGUIDErr)
			return
		}
		mfMTInterlace, mfGUIDErr = parseGUID("E2724BB8-E676-4806-B4B2-A8D6EFb44CCD") // MF_MT_INTERLACE_MODE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_INTERLACE_MODE: %w", mfGUIDErr)
			return
		}
		mfMTPixelAspect, mfGUIDErr = parseGUID("C6376A1E-8D0A-4027-BE45-6D9A0AD39BB6") // MF_MT_PIXEL_ASPECT_RATIO
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_PIXEL_ASPECT_RATIO: %w", mfGUIDErr)
			return
		}
		mfMTAvgBitrate, mfGUIDErr = parseGUID("20332624-FB0D-4D9E-BD0D-CBF6786C102E") // MF_MT_AVG_BITRATE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_AVG_BITRATE: %w", mfGUIDErr)
			return
		}
		mfMTProfile, mfGUIDErr = parseGUID("AD76A802-2D5C-4E0B-B375-64A1F4BF5B53") // MF_MT_MPEG2_PROFILE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_MPEG2_PROFILE: %w", mfGUIDErr)
			return
		}
		mfMTDefaultStride, mfGUIDErr = parseGUID("644B4E48-1E02-4516-B0EB-C01CA9D49AC6") // MF_MT_DEFAULT_STRIDE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_DEFAULT_STRIDE: %w", mfGUIDErr)
			return
		}
		mfMTSampleSize, mfGUIDErr = parseGUID("DAD3AB78-1990-408B-BCE2-EB3A9D1D3341") // MF_MT_SAMPLE_SIZE
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_SAMPLE_SIZE: %w", mfGUIDErr)
			return
		}
		mfMTFixedSizeSamples, mfGUIDErr = parseGUID("B8EBEFAF-B718-4E04-B0A9-116775E3321B") // MF_MT_FIXED_SIZE_SAMPLES
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_FIXED_SIZE_SAMPLES: %w", mfGUIDErr)
			return
		}
		mfMTAllSamplesIndependent, mfGUIDErr = parseGUID("C9173739-5E56-461C-B713-46FB995CB95F") // MF_MT_ALL_SAMPLES_INDEPENDENT
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MF_MT_ALL_SAMPLES_INDEPENDENT: %w", mfGUIDErr)
			return
		}

		mfMediaTypeVideo, mfGUIDErr = parseGUID("73646976-0000-0010-8000-00AA00389B71") // MFMediaType_Video
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MFMediaType_Video: %w", mfGUIDErr)
			return
		}
		mfVideoNV12, mfGUIDErr = parseGUID("3231564E-0000-0010-8000-00AA00389B71") // MFVideoFormat_NV12
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MFVideoFormat_NV12: %w", mfGUIDErr)
			return
		}
		mfVideoH264, mfGUIDErr = parseGUID("34363248-0000-0010-8000-00AA00389B71") // MFVideoFormat_H264
		if mfGUIDErr != nil {
			mfGUIDErr = fmt.Errorf("parse MFVideoFormat_H264: %w", mfGUIDErr)
			return
		}
	})
}

func parseGUID(s string) (windows.GUID, error) {
	if g, err := windows.GUIDFromString(s); err == nil {
		return g, nil
	}
	if strings.HasPrefix(s, "{") {
		return windows.GUIDFromString(s)
	}
	return windows.GUIDFromString("{" + s + "}")
}

func ensureMediaFoundation() error {
	initMFGuids()
	if mfGUIDErr != nil {
		return mfGUIDErr
	}
	mfOnce.Do(func() {
		r0, _, _ := procMFStartup.Call(uintptr(mfVersion), uintptr(mfStartupFull))
		if err := hresultError(r0, "MFStartup"); err != nil {
			mfInitErr = err
		}
	})
	return mfInitErr
}

func hresultError(hr uintptr, name string) error {
	if int32(hr) >= 0 {
		return nil
	}
	return mfError{name: name, hr: uint32(hr)}
}

type mfError struct {
	name string
	hr   uint32
}

func (e mfError) Error() string {
	return fmt.Sprintf("%s failed: HRESULT=0x%08X", e.name, e.hr)
}

func mfHasHRESULT(err error, hr uint32) bool {
	var e mfError
	if errors.As(err, &e) {
		return e.hr == hr
	}
	return false
}

var h264SoftwareCaptureFallbackOnce atomic.Bool

func downgradeCaptureBackendForSoftwareH264(reason string) {
	// Only auto mode should be adapted automatically.
	if getConfiguredCaptureBackend() != CaptureBackendAuto {
		return
	}
	// Only meaningful when we're currently running the NV12 GPU backend.
	if getActiveCaptureBackend() != "dxgi_nv12" {
		return
	}
	if !h264SoftwareCaptureFallbackOnce.CompareAndSwap(false, true) {
		return
	}

	prev := setConfiguredCaptureBackend(CaptureBackendDXGI)
	bumpCaptureConfigEpoch()
	setCaptureD3D11Device(nil)

	fmt.Printf("[H264_CAPTURE] switching capture backend %s -> %s (reason=%s)\n",
		captureBackendName(prev), captureBackendName(CaptureBackendDXGI), reason)
}

type perfMarkerOverlayConfig struct {
	enabled  bool
	debug    bool
	x        int
	y        int
	pad      int
	cell     int
	gap      int
	cols     int
	rows     int
	monitorW int
	monitorH int
}

var perfMarkerOverlayLastLogMs atomic.Int64

func loadPerfMarkerOverlayConfig() perfMarkerOverlayConfig {
	raw := strings.TrimSpace(os.Getenv("SPARK_PERF_MARKER_OVERLAY"))
	enabled := false
	if raw != "" {
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			enabled = true
		}
	}
	if !enabled {
		return perfMarkerOverlayConfig{}
	}

	debug := false
	if rawDebug := strings.TrimSpace(os.Getenv("SPARK_PERF_MARKER_OVERLAY_DEBUG")); rawDebug != "" {
		switch strings.ToLower(rawDebug) {
		case "1", "true", "yes", "on":
			debug = true
		}
	}

	x := parseEnvOptionalInt("PERF_MARKER_X", 0)
	y := parseEnvOptionalInt("PERF_MARKER_Y", 0)
	pad := parseEnvOptionalInt("PERF_MARKER_PAD", 8)
	cell := parseEnvOptionalInt("PERF_MARKER_SIZE", 24)
	gap := parseEnvOptionalInt("PERF_MARKER_GAP", 2)

	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	if pad < 0 {
		pad = 0
	}
	if cell < 2 {
		cell = 2
	}
	if gap < 0 {
		gap = 0
	}

	monitorW := 0
	monitorH := 0
	if b, err := getDisplayBoundsForMonitor(configMonitor.Load()); err == nil {
		if w := b.Dx(); w > 0 {
			monitorW = w
		}
		if h := b.Dy(); h > 0 {
			monitorH = h
		}
	}

	return perfMarkerOverlayConfig{
		enabled:  true,
		debug:    debug,
		x:        x,
		y:        y,
		pad:      pad,
		cell:     cell,
		gap:      gap,
		cols:     6,
		rows:     4,
		monitorW: monitorW,
		monitorH: monitorH,
	}
}

func applyPerfMarkerOverlayNV12(nv12 []byte, width, height int, cfg perfMarkerOverlayConfig) {
	if !cfg.enabled {
		return
	}
	if width <= 0 || height <= 0 {
		return
	}
	nowMs := time.Now().UnixMilli()
	need := width * height * 3 / 2
	if len(nv12) < need {
		return
	}

	// Determine scaling from captured display bounds -> encoded frame dimensions.
	monitorW := width
	monitorH := height
	if cfg.monitorW > 0 {
		monitorW = cfg.monitorW
	}
	if cfg.monitorH > 0 {
		monitorH = cfg.monitorH
	}
	if monitorW <= 0 {
		monitorW = width
	}
	if monitorH <= 0 {
		monitorH = height
	}

	scaleX := float64(width) / float64(monitorW)
	scaleY := float64(height) / float64(monitorH)
	scale := math.Min(scaleX, scaleY)
	if !(scale > 0) || math.IsNaN(scaleX) || math.IsNaN(scaleY) || math.IsInf(scaleX, 0) || math.IsInf(scaleY, 0) {
		return
	}

	x := int(math.Round(float64(cfg.x) * scaleX))
	y := int(math.Round(float64(cfg.y) * scaleY))
	pad := int(math.Round(float64(cfg.pad) * scale))
	cell := int(math.Round(float64(cfg.cell) * scale))
	gap := int(math.Round(float64(cfg.gap) * scale))
	if pad < 0 {
		pad = 0
	}
	if cell < 2 {
		cell = 2
	}
	if gap < 0 {
		gap = 0
	}

	left := x + pad
	top := y + pad
	gridW := cfg.cols*cell + (cfg.cols-1)*gap
	gridH := cfg.rows*cell + (cfg.rows-1)*gap
	if left < 0 || top < 0 || gridW <= 0 || gridH <= 0 {
		return
	}
	if left+gridW > width || top+gridH > height {
		return
	}

	// Lower 24 bits of unix millis, matching perfmarker.exe and the Playwright decoder.
	ts24 := uint32(nowMs) & 0x00FFFFFF

	if cfg.debug {
		const everyMs = int64(1000)
		prev := perfMarkerOverlayLastLogMs.Load()
		if prev == 0 || nowMs-prev >= everyMs {
			if perfMarkerOverlayLastLogMs.CompareAndSwap(prev, nowMs) {
				fmt.Printf("[PERF_OVERLAY] nowMs=%d ts24=0x%06X frame=%dx%d monitor=%dx%d scaleX=%.4f scaleY=%.4f pad=%d cell=%d gap=%d left=%d top=%d grid=%dx%d\n",
					nowMs, ts24, width, height, monitorW, monitorH, scaleX, scaleY, pad, cell, gap, left, top, gridW, gridH)
			}
		}
	}

	yPlane := nv12[:width*height]
	uvPlane := nv12[width*height : need]

	// Fill background for stable detection (mid gray).
	fillNV12YRect(yPlane, width, height, left, top, gridW, gridH, 128)
	fillNV12UVRect(uvPlane, width, height, left, top, gridW, gridH, 128, 128)

	for bit := 0; bit < cfg.cols*cfg.rows; bit++ {
		col := bit % cfg.cols
		row := bit / cfg.cols
		mask := uint32(1) << uint((cfg.cols*cfg.rows-1)-bit)
		on := (ts24 & mask) != 0
		var yVal byte
		if on {
			yVal = 255
		} else {
			yVal = 0
		}
		x0 := left + col*(cell+gap)
		y0 := top + row*(cell+gap)
		fillNV12YRect(yPlane, width, height, x0, y0, cell, cell, yVal)
		fillNV12UVRect(uvPlane, width, height, x0, y0, cell, cell, 128, 128)
	}
}

func fillNV12YRect(yPlane []byte, width, height int, x, y, w, h int, value byte) {
	if yPlane == nil || width <= 0 || height <= 0 || w <= 0 || h <= 0 {
		return
	}
	if x < 0 || y < 0 || x+w > width || y+h > height {
		return
	}
	for row := 0; row < h; row++ {
		start := (y+row)*width + x
		end := start + w
		for i := start; i < end; i++ {
			yPlane[i] = value
		}
	}
}

func fillNV12UVRect(uvPlane []byte, width, height int, x, y, w, h int, u, v byte) {
	if uvPlane == nil || width <= 0 || height <= 0 || w <= 0 || h <= 0 {
		return
	}
	if x < 0 || y < 0 || x+w > width || y+h > height {
		return
	}
	uvHeight := height / 2
	if uvHeight <= 0 {
		return
	}
	uvY0 := y / 2
	uvY1 := (y + h + 1) / 2
	if uvY1 > uvHeight {
		uvY1 = uvHeight
	}
	uvX0 := x &^ 1
	uvX1 := (x + w + 1) &^ 1
	if uvX0 < 0 {
		uvX0 = 0
	}
	if uvX1 > width {
		uvX1 = width
	}
	for row := uvY0; row < uvY1; row++ {
		base := row * width
		for col := uvX0; col < uvX1; col += 2 {
			idx := base + col
			if idx+1 >= len(uvPlane) {
				return
			}
			uvPlane[idx] = u
			uvPlane[idx+1] = v
		}
	}
}

type imfTransform struct {
	vtbl *imfTransformVtbl
}

type imfTransformVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr

	GetStreamLimits           uintptr
	GetStreamCount            uintptr
	GetStreamIDs              uintptr
	GetInputStreamInfo        uintptr
	GetOutputStreamInfo       uintptr
	GetAttributes             uintptr
	GetInputStreamAttributes  uintptr
	GetOutputStreamAttributes uintptr
	DeleteInputStream         uintptr
	AddInputStreams           uintptr
	GetInputAvailableType     uintptr
	GetOutputAvailableType    uintptr
	SetInputType              uintptr
	SetOutputType             uintptr
	GetInputCurrentType       uintptr
	GetOutputCurrentType      uintptr
	GetInputStatus            uintptr
	GetOutputStatus           uintptr
	SetOutputBounds           uintptr
	ProcessEvent              uintptr
	ProcessMessage            uintptr
	ProcessInput              uintptr
	ProcessOutput             uintptr
}

func (t *imfTransform) Release() uint32 {
	ret, _, _ := syscall.SyscallN(t.vtbl.Release, uintptr(unsafe.Pointer(t)))
	return uint32(ret)
}

func (t *imfTransform) SetInputType(streamID uint32, mt *imfMediaType, flags uint32) error {
	r0, _, _ := syscall.SyscallN(
		t.vtbl.SetInputType,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(unsafe.Pointer(mt)),
		uintptr(flags),
	)
	return hresultError(r0, "IMFTransform.SetInputType")
}

func (t *imfTransform) SetOutputType(streamID uint32, mt *imfMediaType, flags uint32) error {
	r0, _, _ := syscall.SyscallN(
		t.vtbl.SetOutputType,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(unsafe.Pointer(mt)),
		uintptr(flags),
	)
	return hresultError(r0, "IMFTransform.SetOutputType")
}

const mfENoMoreTypes = 0xC00D36B9

func (t *imfTransform) GetInputAvailableType(streamID uint32, typeIndex uint32) (*imfMediaType, error) {
	var mt *imfMediaType
	r0, _, _ := syscall.SyscallN(
		t.vtbl.GetInputAvailableType,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(typeIndex),
		uintptr(unsafe.Pointer(&mt)),
	)
	if uint32(r0) == mfENoMoreTypes {
		return nil, syscall.Errno(r0)
	}
	if err := hresultError(r0, "IMFTransform.GetInputAvailableType"); err != nil {
		return nil, err
	}
	return mt, nil
}

func (t *imfTransform) GetOutputAvailableType(streamID uint32, typeIndex uint32) (*imfMediaType, error) {
	var mt *imfMediaType
	r0, _, _ := syscall.SyscallN(
		t.vtbl.GetOutputAvailableType,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(typeIndex),
		uintptr(unsafe.Pointer(&mt)),
	)
	if uint32(r0) == mfENoMoreTypes {
		return nil, syscall.Errno(r0)
	}
	if err := hresultError(r0, "IMFTransform.GetOutputAvailableType"); err != nil {
		return nil, err
	}
	return mt, nil
}

type mftOutputStreamInfo struct {
	Flags     uint32
	Size      uint32
	Alignment uint32
}

func (t *imfTransform) GetOutputStreamInfo(streamID uint32, info *mftOutputStreamInfo) error {
	r0, _, _ := syscall.SyscallN(
		t.vtbl.GetOutputStreamInfo,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(unsafe.Pointer(info)),
	)
	return hresultError(r0, "IMFTransform.GetOutputStreamInfo")
}

// MFT_INPUT_STATUS_ACCEPT_DATA indicates the stream can accept input data
const mftInputStatusAcceptData = 0x00000001

func (t *imfTransform) GetInputStatus(streamID uint32) (uint32, error) {
	var flags uint32
	r0, _, _ := syscall.SyscallN(
		t.vtbl.GetInputStatus,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(unsafe.Pointer(&flags)),
	)
	if err := hresultError(r0, "IMFTransform.GetInputStatus"); err != nil {
		return 0, err
	}
	return flags, nil
}

func (t *imfTransform) ProcessMessage(msg uint32, param uintptr) error {
	r0, _, _ := syscall.SyscallN(
		t.vtbl.ProcessMessage,
		uintptr(unsafe.Pointer(t)),
		uintptr(msg),
		param,
	)
	return hresultError(r0, "IMFTransform.ProcessMessage")
}

func (t *imfTransform) ProcessInput(streamID uint32, sample *imfSample, flags uint32) error {
	r0, _, _ := syscall.SyscallN(
		t.vtbl.ProcessInput,
		uintptr(unsafe.Pointer(t)),
		uintptr(streamID),
		uintptr(unsafe.Pointer(sample)),
		uintptr(flags),
	)
	return hresultError(r0, "IMFTransform.ProcessInput")
}

type mftOutputDataBuffer struct {
	StreamID uint32
	Sample   *imfSample
	Status   uint32
	Events   unsafe.Pointer
}

func (t *imfTransform) ProcessOutput(flags uint32, out *mftOutputDataBuffer, status *uint32) error {
	r0, _, _ := syscall.SyscallN(
		t.vtbl.ProcessOutput,
		uintptr(unsafe.Pointer(t)),
		uintptr(flags),
		uintptr(1),
		uintptr(unsafe.Pointer(out)),
		uintptr(unsafe.Pointer(status)),
	)
	// MF_E_TRANSFORM_NEED_MORE_INPUT is expected when no output is ready yet.
	if uint32(r0) == mfETransformNeedMoreInput {
		return syscall.Errno(r0)
	}
	return hresultError(r0, "IMFTransform.ProcessOutput")
}

// QueryInterface for IMFMediaEventGenerator to support async MFT event model
func (t *imfTransform) QueryEventGenerator() (*iMFMediaEventGenerator, error) {
	iidIMFMediaEventGenerator, _ := windows.GUIDFromString("{2CD0BD52-BCD5-4B89-B62C-EADC0C031E7D}")
	var eventGen *iMFMediaEventGenerator
	r0, _, _ := syscall.SyscallN(
		t.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(t)),
		uintptr(unsafe.Pointer(&iidIMFMediaEventGenerator)),
		uintptr(unsafe.Pointer(&eventGen)),
	)
	if err := hresultError(r0, "QueryInterface(IMFMediaEventGenerator)"); err != nil {
		return nil, err
	}
	return eventGen, nil
}

// Async MFT event types
const (
	// Values from Windows SDK: MediaEventType (mfobjects.h)
	// METransformUnknown = 600
	// METransformNeedInput = 601
	// METransformHaveOutput = 602
	// METransformDrainComplete = 603
	// METransformMarker = 604
	meTransformNeedInput     = 601
	meTransformHaveOutput    = 602
	meTransformDrainComplete = 603
	meTransformMarker        = 604
)

// IMFMediaEventGenerator interface for async MFT events
type iMFMediaEventGenerator struct {
	vtbl *iMFMediaEventGeneratorVtbl
}

type iMFMediaEventGeneratorVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	GetEvent       uintptr
	BeginGetEvent  uintptr
	EndGetEvent    uintptr
	QueueEvent     uintptr
}

func (g *iMFMediaEventGenerator) Release() {
	if g == nil || g.vtbl == nil {
		return
	}
	syscall.SyscallN(g.vtbl.Release, uintptr(unsafe.Pointer(g)))
}

// GetEvent retrieves the next event from the event generator.
// flags: 0 = blocking, MF_EVENT_FLAG_NO_WAIT (0x1) = non-blocking
func (g *iMFMediaEventGenerator) GetEvent(flags uint32) (*iMFMediaEvent, error) {
	var event *iMFMediaEvent
	r0, _, _ := syscall.SyscallN(
		g.vtbl.GetEvent,
		uintptr(unsafe.Pointer(g)),
		uintptr(flags),
		uintptr(unsafe.Pointer(&event)),
	)
	if err := hresultError(r0, "IMFMediaEventGenerator.GetEvent"); err != nil {
		return nil, err
	}
	return event, nil
}

// IMFMediaEvent interface
type iMFMediaEvent struct {
	vtbl *iMFMediaEventVtbl
}

type iMFMediaEventVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	// IMFAttributes methods (inherited)
	GetItem            uintptr
	GetItemType        uintptr
	CompareItem        uintptr
	Compare            uintptr
	GetUINT32          uintptr
	GetUINT64          uintptr
	GetDouble          uintptr
	GetGUID            uintptr
	GetStringLength    uintptr
	GetString          uintptr
	GetAllocatedString uintptr
	GetBlobSize        uintptr
	GetBlob            uintptr
	GetAllocatedBlob   uintptr
	GetUnknown         uintptr
	SetItem            uintptr
	DeleteItem         uintptr
	DeleteAllItems     uintptr
	SetUINT32          uintptr
	SetUINT64          uintptr
	SetDouble          uintptr
	SetGUID            uintptr
	SetString          uintptr
	SetBlob            uintptr
	SetUnknown         uintptr
	LockStore          uintptr
	UnlockStore        uintptr
	GetCount           uintptr
	GetItemByIndex     uintptr
	CopyAllItems       uintptr
	// IMFMediaEvent methods
	GetType         uintptr // index 34
	GetExtendedType uintptr
	GetStatus       uintptr
	GetValue        uintptr
}

func (e *iMFMediaEvent) Release() {
	if e == nil || e.vtbl == nil {
		return
	}
	syscall.SyscallN(e.vtbl.Release, uintptr(unsafe.Pointer(e)))
}

func (e *iMFMediaEvent) GetType() (uint32, error) {
	var eventType uint32
	r0, _, _ := syscall.SyscallN(
		e.vtbl.GetType,
		uintptr(unsafe.Pointer(e)),
		uintptr(unsafe.Pointer(&eventType)),
	)
	if err := hresultError(r0, "IMFMediaEvent.GetType"); err != nil {
		return 0, err
	}
	return eventType, nil
}

func (e *iMFMediaEvent) GetStatus() error {
	var status int32
	r0, _, _ := syscall.SyscallN(
		e.vtbl.GetStatus,
		uintptr(unsafe.Pointer(e)),
		uintptr(unsafe.Pointer(&status)),
	)
	if err := hresultError(r0, "IMFMediaEvent.GetStatus"); err != nil {
		return err
	}
	// Check the event's status (HRESULT stored in the event)
	if status < 0 {
		return fmt.Errorf("event status: HRESULT=0x%08x", uint32(status))
	}
	return nil
}

type imfMediaType struct {
	vtbl *imfMediaTypeVtbl
}

type imfMediaTypeVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr

	GetItem            uintptr
	GetItemType        uintptr
	CompareItem        uintptr
	Compare            uintptr
	GetUINT32          uintptr
	GetUINT64          uintptr
	GetDouble          uintptr
	GetGUID            uintptr
	GetStringLength    uintptr
	GetString          uintptr
	GetAllocatedString uintptr
	GetBlobSize        uintptr
	GetBlob            uintptr
	GetAllocatedBlob   uintptr
	GetUnknown         uintptr
	SetItem            uintptr
	DeleteItem         uintptr
	DeleteAllItems     uintptr
	SetUINT32          uintptr
	SetUINT64          uintptr
	SetDouble          uintptr
	SetGUID            uintptr
	SetString          uintptr
	SetBlob            uintptr
	SetUnknown         uintptr
	LockStore          uintptr
	UnlockStore        uintptr
	GetCount           uintptr
	GetItemByIndex     uintptr
	CopyAllItems       uintptr

	GetMajorType       uintptr
	IsCompressedFormat uintptr
	IsEqual            uintptr
	GetRepresentation  uintptr
	FreeRepresentation uintptr
}

func (mt *imfMediaType) Release() uint32 {
	ret, _, _ := syscall.SyscallN(mt.vtbl.Release, uintptr(unsafe.Pointer(mt)))
	return uint32(ret)
}

func (mt *imfMediaType) SetGUID(key, value *windows.GUID) error {
	r0, _, _ := syscall.SyscallN(
		mt.vtbl.SetGUID,
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(value)),
	)
	return hresultError(r0, "IMFMediaType.SetGUID")
}

func (mt *imfMediaType) GetGUID(key *windows.GUID) (windows.GUID, error) {
	var out windows.GUID
	r0, _, _ := syscall.SyscallN(
		mt.vtbl.GetGUID,
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(&out)),
	)
	return out, hresultError(r0, "IMFMediaType.GetGUID")
}

func (mt *imfMediaType) SetUINT32(key *windows.GUID, value uint32) error {
	r0, _, _ := syscall.SyscallN(
		mt.vtbl.SetUINT32,
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(value),
	)
	return hresultError(r0, "IMFMediaType.SetUINT32")
}

func (mt *imfMediaType) SetUINT64(key *windows.GUID, value uint64) error {
	r0, _, _ := syscall.SyscallN(
		mt.vtbl.SetUINT64,
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(value),
	)
	return hresultError(r0, "IMFMediaType.SetUINT64")
}

func mfCreateMediaType() (*imfMediaType, error) {
	var mt *imfMediaType
	r0, _, _ := procMFCreateMediaType.Call(uintptr(unsafe.Pointer(&mt)))
	if err := hresultError(r0, "MFCreateMediaType"); err != nil {
		return nil, err
	}
	return mt, nil
}

func mfSetAttributeSize(mt *imfMediaType, key *windows.GUID, width, height uint32) error {
	// MFSetAttributeSize is a convenience wrapper that is not guaranteed to be
	// exported in all mfplat builds. Set the attribute via the canonical UINT64
	// packing (high=width, low=height).
	if mt == nil {
		return errors.New("nil media type")
	}
	return mt.SetUINT64(key, (uint64(width)<<32)|uint64(height))
}

func mfSetAttributeRatio(mt *imfMediaType, key *windows.GUID, num, den uint32) error {
	// MFSetAttributeRatio is a convenience wrapper; set via UINT64 packing
	// (high=numerator, low=denominator).
	if mt == nil {
		return errors.New("nil media type")
	}
	return mt.SetUINT64(key, (uint64(num)<<32)|uint64(den))
}

func mfApproxFPS(d time.Duration) uint32 {
	if d <= 0 {
		return 30
	}
	fps := (time.Second + d/2) / d
	if fps < 1 {
		return 1
	}
	if fps > 240 {
		return 240
	}
	return uint32(fps)
}

func mfConfigureNV12Type(mt *imfMediaType, w, h int, fps uint32, includeBufferAttrs bool) error {
	// Minimal NV12 type: only essential attributes.
	// Many encoders infer or ignore optional attributes like interlace mode.
	if err := mt.SetGUID(&mfMTMajorType, &mfMediaTypeVideo); err != nil {
		return err
	}
	if err := mt.SetGUID(&mfMTSubtype, &mfVideoNV12); err != nil {
		return err
	}
	if err := mfSetAttributeSize(mt, &mfMTFrameSize, uint32(w), uint32(h)); err != nil {
		return err
	}
	if err := mfSetAttributeRatio(mt, &mfMTFrameRate, fps, 1); err != nil {
		return err
	}
	// Interlace mode is required by some encoders
	if err := mt.SetUINT32(&mfMTInterlace, mfInterlaceProgress); err != nil {
		return err
	}
	// Software encoders often require these buffer attributes
	if includeBufferAttrs {
		// NV12 stride is typically the width (Y plane)
		if err := mt.SetUINT32(&mfMTDefaultStride, uint32(w)); err != nil {
			return err
		}
		// NV12 sample size: Y plane (w*h) + UV plane (w*h/2)
		sampleSize := uint32(w*h + (w*h)/2)
		if err := mt.SetUINT32(&mfMTSampleSize, sampleSize); err != nil {
			return err
		}
		// Mark samples as fixed size
		if err := mt.SetUINT32(&mfMTFixedSizeSamples, 1); err != nil {
			return err
		}
		// All samples are independent (no temporal compression on input)
		if err := mt.SetUINT32(&mfMTAllSamplesIndependent, 1); err != nil {
			return err
		}
	}
	return nil
}

func mfConfigureH264Type(mt *imfMediaType, w, h int, fps uint32, targetBitRate int) error {
	if err := mt.SetGUID(&mfMTMajorType, &mfMediaTypeVideo); err != nil {
		return err
	}
	if err := mt.SetGUID(&mfMTSubtype, &mfVideoH264); err != nil {
		return err
	}
	if err := mfSetAttributeSize(mt, &mfMTFrameSize, uint32(w), uint32(h)); err != nil {
		return err
	}
	if err := mfSetAttributeRatio(mt, &mfMTFrameRate, fps, 1); err != nil {
		return err
	}
	if err := mt.SetUINT32(&mfMTAvgBitrate, uint32(targetBitRate)); err != nil {
		return err
	}
	// Interlace mode is required by some encoders
	if err := mt.SetUINT32(&mfMTInterlace, mfInterlaceProgress); err != nil {
		return err
	}
	// Baseline profile: maximizes browser compatibility and disallows B-frames.
	if err := mt.SetUINT32(&mfMTProfile, 66); err != nil {
		return err
	}
	return nil
}

func mfConfigureH264TypeNoProfile(mt *imfMediaType, w, h int, fps uint32, targetBitRate int) error {
	if err := mt.SetGUID(&mfMTMajorType, &mfMediaTypeVideo); err != nil {
		return err
	}
	if err := mt.SetGUID(&mfMTSubtype, &mfVideoH264); err != nil {
		return err
	}
	if err := mfSetAttributeSize(mt, &mfMTFrameSize, uint32(w), uint32(h)); err != nil {
		return err
	}
	if err := mfSetAttributeRatio(mt, &mfMTFrameRate, fps, 1); err != nil {
		return err
	}
	if err := mt.SetUINT32(&mfMTAvgBitrate, uint32(targetBitRate)); err != nil {
		return err
	}
	// Interlace mode is required by some encoders
	if err := mt.SetUINT32(&mfMTInterlace, mfInterlaceProgress); err != nil {
		return err
	}
	return nil
}

func mfClearTypes(transform *imfTransform) {
	if transform == nil {
		return
	}
	_ = transform.SetInputType(0, nil, 0)
	_ = transform.SetOutputType(0, nil, 0)
}

func mfSetTypes(transform *imfTransform, it, ot *imfMediaType) error {
	if transform == nil {
		return errors.New("nil transform")
	}
	if it == nil || ot == nil {
		return errors.New("nil media type")
	}

	// Best-effort test-only pass to let the MFT pre-validate/normalize types.
	// Some transforms return MF_E_TRANSFORM_TYPE_NOT_SET until both types are provided.
	mfClearTypes(transform)
	if err := transform.SetOutputType(0, ot, mftSetTypeTestOnly); err != nil && !mfHasHRESULT(err, mfETransformTypeNotSet) {
		return fmt.Errorf("test output type: %w", err)
	}
	if err := transform.SetInputType(0, it, mftSetTypeTestOnly); err != nil && !mfHasHRESULT(err, mfETransformTypeNotSet) {
		return fmt.Errorf("test input type: %w", err)
	}

	var lastErr error
	tryCommit := func(outputFirst bool) bool {
		mfClearTypes(transform)
		if outputFirst {
			if err := transform.SetOutputType(0, ot, 0); err != nil {
				lastErr = fmt.Errorf("commit output: %w", err)
				return false
			}
			if err := transform.SetInputType(0, it, 0); err != nil {
				lastErr = fmt.Errorf("commit input: %w", err)
				return false
			}
			return true
		}
		if err := transform.SetInputType(0, it, 0); err != nil {
			lastErr = fmt.Errorf("commit input: %w", err)
			return false
		}
		if err := transform.SetOutputType(0, ot, 0); err != nil {
			lastErr = fmt.Errorf("commit output: %w", err)
			return false
		}
		return true
	}

	// Try both commit orders; different encoder MFTs have different requirements.
	if tryCommit(true) || tryCommit(false) {
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("failed to commit media types")
}

func mfTrySelectAvailableType(
	transform *imfTransform,
	isInput bool,
	w, h int,
	fps uint32,
	targetBitRate int,
	includeInputBufferAttrs bool,
) (*imfMediaType, error) {
	var lastErr error
	for idx := uint32(0); ; idx++ {
		var (
			mt  *imfMediaType
			err error
		)
		if isInput {
			mt, err = transform.GetInputAvailableType(0, idx)
		} else {
			mt, err = transform.GetOutputAvailableType(0, idx)
		}
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && uint32(errno) == mfENoMoreTypes {
				break
			}
			return nil, err
		}
		if mt == nil {
			continue
		}

		sub, subErr := mt.GetGUID(&mfMTSubtype)
		if subErr != nil {
			mt.Release()
			lastErr = subErr
			continue
		}
		if isInput && sub != mfVideoNV12 {
			mt.Release()
			continue
		}
		if !isInput && sub != mfVideoH264 {
			mt.Release()
			continue
		}

		if isInput {
			err = mfConfigureNV12Type(mt, w, h, fps, includeInputBufferAttrs)
		} else {
			err = mfConfigureH264Type(mt, w, h, fps, targetBitRate)
		}
		if err != nil {
			mt.Release()
			lastErr = err
			continue
		}

		// Validate and keep the first type that the transform accepts.
		if isInput {
			err = transform.SetInputType(0, mt, mftSetTypeTestOnly)
		} else {
			err = transform.SetOutputType(0, mt, mftSetTypeTestOnly)
		}
		if err != nil && !mfHasHRESULT(err, mfETransformTypeNotSet) {
			mt.Release()
			lastErr = err
			continue
		}
		return mt, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	if isInput {
		return nil, errors.New("no compatible NV12 input media types found")
	}
	return nil, errors.New("no compatible H264 output media types found")
}

type imfSample struct {
	vtbl *imfSampleVtbl
}

// imfSampleVtbl is the vtable for IMFSample which inherits from IMFAttributes.
// The full inheritance chain is: IUnknown -> IMFAttributes -> IMFSample.
type imfSampleVtbl struct {
	// IUnknown (3 methods)
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr

	// IMFAttributes (31 methods)
	GetItem            uintptr
	GetItemType        uintptr
	CompareItem        uintptr
	Compare            uintptr
	GetUINT32          uintptr
	GetUINT64          uintptr
	GetDouble          uintptr
	GetGUID            uintptr
	GetStringLength    uintptr
	GetString          uintptr
	GetAllocatedString uintptr
	GetBlobSize        uintptr
	GetBlob            uintptr
	GetAllocatedBlob   uintptr
	GetUnknown         uintptr
	SetItem            uintptr
	DeleteItem         uintptr
	DeleteAllItems     uintptr
	SetUINT32          uintptr
	SetUINT64          uintptr
	SetDouble          uintptr
	SetGUID            uintptr
	SetString          uintptr
	SetBlob            uintptr
	SetUnknown         uintptr
	LockStore          uintptr
	UnlockStore        uintptr
	GetCount           uintptr
	GetItemByIndex     uintptr
	CopyAllItems       uintptr

	// IMFSample methods (14 methods)
	GetSampleFlags            uintptr
	SetSampleFlags            uintptr
	GetSampleTime             uintptr
	SetSampleTime             uintptr
	GetSampleDuration         uintptr
	SetSampleDuration         uintptr
	GetBufferCount            uintptr
	GetBufferByIndex          uintptr
	ConvertToContiguousBuffer uintptr
	AddBuffer                 uintptr
	RemoveBufferByIndex       uintptr
	RemoveAllBuffers          uintptr
	GetTotalLength            uintptr
	CopyToBuffer              uintptr
}

func (s *imfSample) Release() uint32 {
	ret, _, _ := syscall.SyscallN(s.vtbl.Release, uintptr(unsafe.Pointer(s)))
	return uint32(ret)
}

func (s *imfSample) AddBuffer(buf *imfMediaBuffer) error {
	r0, _, _ := syscall.SyscallN(
		s.vtbl.AddBuffer,
		uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(buf)),
	)
	return hresultError(r0, "IMFSample.AddBuffer")
}

func (s *imfSample) SetSampleTime(t int64) error {
	r0, _, _ := syscall.SyscallN(
		s.vtbl.SetSampleTime,
		uintptr(unsafe.Pointer(s)),
		uintptr(t),
	)
	return hresultError(r0, "IMFSample.SetSampleTime")
}

func (s *imfSample) SetSampleDuration(d int64) error {
	r0, _, _ := syscall.SyscallN(
		s.vtbl.SetSampleDuration,
		uintptr(unsafe.Pointer(s)),
		uintptr(d),
	)
	return hresultError(r0, "IMFSample.SetSampleDuration")
}

func (s *imfSample) ConvertToContiguousBuffer() (*imfMediaBuffer, error) {
	if s == nil || s.vtbl == nil || s.vtbl.ConvertToContiguousBuffer == 0 {
		return nil, errors.New("IMFSample.ConvertToContiguousBuffer unavailable")
	}
	var buf *imfMediaBuffer
	r0, _, _ := syscall.SyscallN(
		s.vtbl.ConvertToContiguousBuffer,
		uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(&buf)),
	)
	if err := hresultError(r0, "IMFSample.ConvertToContiguousBuffer"); err != nil {
		return nil, err
	}
	if buf == nil {
		return nil, errors.New("IMFSample.ConvertToContiguousBuffer returned nil buffer")
	}
	return buf, nil
}

func mfCreateSample() (*imfSample, error) {
	var sample *imfSample
	r0, _, _ := procMFCreateSample.Call(uintptr(unsafe.Pointer(&sample)))
	if err := hresultError(r0, "MFCreateSample"); err != nil {
		return nil, err
	}
	return sample, nil
}

type imfMediaBuffer struct {
	vtbl *imfMediaBufferVtbl
}

type imfMediaBufferVtbl struct {
	QueryInterface   uintptr
	AddRef           uintptr
	Release          uintptr
	Lock             uintptr
	Unlock           uintptr
	GetCurrentLength uintptr
	SetCurrentLength uintptr
	GetMaxLength     uintptr
}

func (b *imfMediaBuffer) Release() uint32 {
	ret, _, _ := syscall.SyscallN(b.vtbl.Release, uintptr(unsafe.Pointer(b)))
	return uint32(ret)
}

func (b *imfMediaBuffer) Lock() (ptr unsafe.Pointer, maxLen, curLen uint32, err error) {
	var p uintptr
	var max, cur uint32
	r0, _, _ := syscall.SyscallN(
		b.vtbl.Lock,
		uintptr(unsafe.Pointer(b)),
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&max)),
		uintptr(unsafe.Pointer(&cur)),
	)
	if e := hresultError(r0, "IMFMediaBuffer.Lock"); e != nil {
		return nil, 0, 0, e
	}
	return unsafe.Pointer(p), max, cur, nil
}

func (b *imfMediaBuffer) Unlock() error {
	r0, _, _ := syscall.SyscallN(b.vtbl.Unlock, uintptr(unsafe.Pointer(b)))
	return hresultError(r0, "IMFMediaBuffer.Unlock")
}

func (b *imfMediaBuffer) SetCurrentLength(length uint32) error {
	r0, _, _ := syscall.SyscallN(
		b.vtbl.SetCurrentLength,
		uintptr(unsafe.Pointer(b)),
		uintptr(length),
	)
	return hresultError(r0, "IMFMediaBuffer.SetCurrentLength")
}

func mfCreateMemoryBuffer(size uint32) (*imfMediaBuffer, error) {
	var buf *imfMediaBuffer
	r0, _, _ := procMFCreateMemoryBuf.Call(uintptr(size), uintptr(unsafe.Pointer(&buf)))
	if err := hresultError(r0, "MFCreateMemoryBuffer"); err != nil {
		return nil, err
	}
	return buf, nil
}

type mftRegisterTypeInfo struct {
	MajorType windows.GUID
	Subtype   windows.GUID
}

const (
	mftEnumFlagSyncMFT       = 0x00000001
	mftEnumFlagAsyncMFT      = 0x00000002
	mftEnumFlagHardware      = 0x00000004
	mftEnumFlagSortAndFilter = 0x00000040
)

// iMFActivate extends iMFAttributes with ActivateObject for hardware MFTs.
// Hardware MFTs must be activated through IMFActivate to preserve device bindings.
type iMFActivate struct {
	vtbl *iMFActivateVtbl
}

type iMFActivateVtbl struct {
	// IMFAttributes methods (inherited) - indices 0-33
	QueryInterface     uintptr
	AddRef             uintptr
	Release            uintptr
	GetItem            uintptr
	GetItemType        uintptr
	CompareItem        uintptr
	Compare            uintptr
	GetUINT32          uintptr
	GetUINT64          uintptr
	GetDouble          uintptr
	GetGUID            uintptr
	GetStringLength    uintptr
	GetString          uintptr
	GetAllocatedString uintptr
	GetBlobSize        uintptr
	GetBlob            uintptr
	GetAllocatedBlob   uintptr
	GetUnknown         uintptr
	SetItem            uintptr
	DeleteItem         uintptr
	DeleteAllItems     uintptr
	SetUINT32          uintptr
	SetUINT64          uintptr
	SetDouble          uintptr
	SetGUID            uintptr
	SetString          uintptr
	SetBlob            uintptr
	SetUnknown         uintptr
	LockStore          uintptr
	UnlockStore        uintptr
	GetCount           uintptr
	GetItemByIndex     uintptr
	CopyAllItems       uintptr
	// IMFActivate methods - indices 34-36
	ActivateObject uintptr // index 34
	ShutdownObject uintptr // index 35
	DetachObject   uintptr // index 36
}

func (a *iMFActivate) Release() {
	if a == nil || a.vtbl == nil {
		return
	}
	syscall.SyscallN(a.vtbl.Release, uintptr(unsafe.Pointer(a)))
}

func (a *iMFActivate) ActivateObject(iid *windows.GUID) (unsafe.Pointer, error) {
	var obj unsafe.Pointer
	r0, _, _ := syscall.SyscallN(
		a.vtbl.ActivateObject,
		uintptr(unsafe.Pointer(a)),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&obj)),
	)
	return obj, hresultError(r0, "IMFActivate.ActivateObject")
}

func (a *iMFActivate) GetGUID(key *windows.GUID) (windows.GUID, error) {
	var out windows.GUID
	r0, _, _ := syscall.SyscallN(
		a.vtbl.GetGUID,
		uintptr(unsafe.Pointer(a)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(&out)),
	)
	return out, hresultError(r0, "IMFActivate.GetGUID")
}

func (a *iMFAttributes) GetGUID(key *windows.GUID) (windows.GUID, error) {
	var out windows.GUID
	r0, _, _ := syscall.SyscallN(
		a.vtbl.GetGUID,
		uintptr(unsafe.Pointer(a)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(&out)),
	)
	return out, hresultError(r0, "IMFAttributes.GetGUID")
}

func coCreateH264TransformFromEnum(flags uint32) (*imfTransform, error) {
	in := mftRegisterTypeInfo{MajorType: mfMediaTypeVideo, Subtype: mfVideoNV12}
	out := mftRegisterTypeInfo{MajorType: mfMediaTypeVideo, Subtype: mfVideoH264}

	// MFTEnumEx returns an array of IMFActivate pointers, not IMFAttributes.
	// Hardware MFTs must be activated through IMFActivate::ActivateObject to
	// preserve D3D11 device bindings required for zero-copy encoding.
	var activates **iMFActivate
	var count uint32
	r0, _, _ := procMFTEnumEx.Call(
		uintptr(unsafe.Pointer(&mftCategoryVideoEncoder)),
		uintptr(flags),
		uintptr(unsafe.Pointer(&in)),
		uintptr(unsafe.Pointer(&out)),
		uintptr(unsafe.Pointer(&activates)),
		uintptr(unsafe.Pointer(&count)),
	)
	if err := hresultError(r0, "MFTEnumEx"); err != nil {
		return nil, err
	}
	if activates == nil || count == 0 {
		return nil, errors.New("no video encoders matched")
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(activates)))

	var firstErr error
	for _, act := range unsafe.Slice(activates, count) {
		if act == nil {
			continue
		}
		// Use IMFActivate::ActivateObject instead of CoCreateInstance.
		// This is critical for hardware MFTs as it preserves device bindings.
		obj, err := act.ActivateObject(&iidIMFTransform)
		act.Release() // Release activate object after activation attempt
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		transform := (*imfTransform)(obj)
		if transform != nil {
			// NOTE: DXGI manager is configured AFTER media types are set (in reinitCore)
			return transform, nil
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("no usable video encoders matched")
}

func coCreateH264TransformCLSID() (*imfTransform, error) {
	var transform *imfTransform
	r0, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidCMSH264EncoderMFT)),
		0,
		uintptr(clsctxInprocServer),
		uintptr(unsafe.Pointer(&iidIMFTransform)),
		uintptr(unsafe.Pointer(&transform)),
	)
	if err := hresultError(r0, "CoCreateInstance(CMSH264EncoderMFT)"); err != nil {
		return nil, err
	}
	// NOTE: DXGI manager is configured AFTER media types are set (in reinitCore)
	return transform, nil
}

func coCreateH264Transform() (*imfTransform, error) {
	// Best practice: pick the system's preferred video encoder MFT for NV12->H264,
	// preferring hardware implementations when available.
	// Prefer synchronous MFTs first; some async encoder MFTs are unreliable when unlocked.
	if t, err := coCreateH264TransformFromEnum(mftEnumFlagHardware | mftEnumFlagSortAndFilter | mftEnumFlagSyncMFT); err == nil {
		return t, nil
	}
	if t, err := coCreateH264TransformFromEnum(mftEnumFlagHardware | mftEnumFlagSortAndFilter | mftEnumFlagSyncMFT | mftEnumFlagAsyncMFT); err == nil {
		return t, nil
	}
	if t, err := coCreateH264TransformFromEnum(mftEnumFlagSortAndFilter | mftEnumFlagSyncMFT); err == nil {
		return t, nil
	}
	if t, err := coCreateH264TransformFromEnum(mftEnumFlagSortAndFilter | mftEnumFlagSyncMFT | mftEnumFlagAsyncMFT); err == nil {
		return t, nil
	}
	return coCreateH264TransformCLSID()
}

// unlockAsyncMFT unlocks an async MFT for synchronous use.
// Hardware encoders returned by MFTEnumEx are typically async MFTs that must be
// unlocked before they can accept D3D11 device manager configuration.
// Returns true if the MFT was async and successfully unlocked.
func unlockAsyncMFT(transform *imfTransform) (bool, error) {
	if transform == nil {
		return false, nil
	}

	// Get attributes from transform
	var attrs *iMFAttributes
	r0, _, _ := syscall.SyscallN(
		transform.vtbl.GetAttributes,
		uintptr(unsafe.Pointer(transform)),
		uintptr(unsafe.Pointer(&attrs)),
	)
	if err := hresultError(r0, "GetAttributes"); err != nil {
		// Some MFTs don't support GetAttributes - not an error
		return false, nil
	}
	if attrs == nil {
		return false, nil
	}
	defer attrs.Release()

	// MF_TRANSFORM_ASYNC: {F81A699A-649A-497D-8C73-29F8FED6AD7A}
	guidMFTransformAsync, _ := windows.GUIDFromString("{f81a699a-649a-497d-8c73-29f8fed6ad7a}")

	// Check if MFT is async
	var isAsync uint32
	asyncKnown := true
	r0, _, _ = syscall.SyscallN(
		attrs.vtbl.GetUINT32,
		uintptr(unsafe.Pointer(attrs)),
		uintptr(unsafe.Pointer(&guidMFTransformAsync)),
		uintptr(unsafe.Pointer(&isAsync)),
	)
	if hresultError(r0, "") != nil {
		// Some MFTs don't expose MF_TRANSFORM_ASYNC but still require unlock to attach DXGI.
		asyncKnown = false
		isAsync = 0
	} else if isAsync == 0 {
		// Synchronous MFT: nothing to unlock.
		return false, nil
	}

	// MF_TRANSFORM_ASYNC_UNLOCK: {E5666D6B-3422-4EB6-A421-DA7DB1F8E207}
	guidMFTransformAsyncUnlock, _ := windows.GUIDFromString("{e5666d6b-3422-4eb6-a421-da7db1f8e207}")

	// Unlock the async MFT for synchronous use
	r0, _, _ = syscall.SyscallN(
		attrs.vtbl.SetUINT32,
		uintptr(unsafe.Pointer(attrs)),
		uintptr(unsafe.Pointer(&guidMFTransformAsyncUnlock)),
		uintptr(1), // TRUE
	)
	if err := hresultError(r0, "SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK)"); err != nil {
		// If we know the MFT is async, this is fatal for sync usage.
		if asyncKnown {
			return false, err
		}
		// Otherwise, treat as best-effort: caller will fall back if DXGI attach fails.
		return false, nil
	}

	// Return true to indicate we successfully applied the unlock attribute.
	// This also covers the "async attribute not exposed" case.
	return true, nil
}

type h264Encoder struct {
	baseBitRate      int
	keyFrameInterval int
	aqm              *AdaptiveQualityManager
	forceKeyFrame    atomic.Bool
	captureDevice    *iD3D11Device
	seq              atomic.Uint64

	mu          sync.Mutex
	workerOnce  sync.Once
	frameQueue  chan h264Request
	resultQueue chan h264Result
	closed      bool
	wg          sync.WaitGroup
}

type h264Request struct {
	img        *image.RGBA
	gpuTexture *iD3D11Texture2D
	gpuWidth   int
	gpuHeight  int
	isGPU      bool
	duration   time.Duration
	seq        uint64
}

type h264Result struct {
	sample media.Sample
	err    error
	seq    uint64
}

// NewH264Encoder builds a Media Foundation backed H.264 encoder (Windows 10+).
func NewH264Encoder(cfg WebRTCEncoderConfig) (WebRTCEncoder, error) {
	bitRate := cfg.BitRate
	if bitRate <= 0 {
		bitRate = 900_000
	}
	keyInterval := cfg.KeyFrameInterval
	if keyInterval <= 0 {
		keyInterval = 60
	}
	return &h264Encoder{
		baseBitRate:      bitRate,
		keyFrameInterval: keyInterval,
		captureDevice:    getCaptureD3D11Device(),
	}, nil
}

func (e *h264Encoder) EnableAdaptiveQuality(aqm *AdaptiveQualityManager) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.aqm = aqm
}

func (e *h264Encoder) RequestKeyFrame() {
	if e == nil {
		return
	}
	e.forceKeyFrame.Store(true)
}

func (e *h264Encoder) startWorkerLocked() {
	e.workerOnce.Do(func() {
		e.frameQueue = make(chan h264Request, 2)
		e.resultQueue = make(chan h264Result, 1)
		e.wg.Add(1)
		go e.encodeLoop()
	})
}

func (e *h264Encoder) Encode(img *image.RGBA, duration time.Duration) (media.Sample, error) {
	if img == nil {
		return media.Sample{}, errors.New("nil frame")
	}
	if duration <= 0 {
		duration = time.Second / 30
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return media.Sample{}, errors.New("encoder closed")
	}
	e.startWorkerLocked()
	frameQueue := e.frameQueue
	resultQueue := e.resultQueue
	e.mu.Unlock()

	seq := e.seq.Add(1)
	select {
	case frameQueue <- h264Request{img: img, duration: duration, seq: seq}:
	default:
		// Drop frame if encoder is backed up.
		return media.Sample{}, nil
	}

	timer := time.NewTimer(1250 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case res := <-resultQueue:
			if res.seq != seq {
				continue
			}
			return res.sample, res.err
		case <-timer.C:
			return media.Sample{}, ErrWebRTCEncoderTimeout
		}
	}
}

func (e *h264Encoder) EncodeFrame(frame *CaptureFrame, duration time.Duration) (media.Sample, error) {
	if frame == nil {
		return media.Sample{}, errors.New("nil frame")
	}
	if frame.Image != nil {
		return e.Encode(frame.Image, duration)
	}
	if frame.GPU == nil || frame.GPU.Resource == nil {
		return media.Sample{}, errors.New("frame has no CPU image or GPU texture")
	}
	if frame.GPU.Backend != "dxgi_nv12" {
		return media.Sample{}, errors.New("unsupported GPU backend")
	}
	tex, ok := frame.GPU.Resource.(*iD3D11Texture2D)
	if !ok || tex == nil {
		return media.Sample{}, errors.New("GPU resource is not D3D11 texture")
	}
	if duration <= 0 {
		duration = time.Second / 30
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return media.Sample{}, errors.New("encoder closed")
	}
	e.startWorkerLocked()
	frameQueue := e.frameQueue
	resultQueue := e.resultQueue
	e.mu.Unlock()

	seq := e.seq.Add(1)
	req := h264Request{
		gpuTexture: tex,
		gpuWidth:   frame.GPU.Width,
		gpuHeight:  frame.GPU.Height,
		isGPU:      true,
		duration:   duration,
		seq:        seq,
	}

	select {
	case frameQueue <- req:
	default:
		return media.Sample{}, nil
	}

	timer := time.NewTimer(1250 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case res := <-resultQueue:
			if res.seq != seq {
				continue
			}
			return res.sample, res.err
		case <-timer.C:
			return media.Sample{}, ErrWebRTCEncoderTimeout
		}
	}
}

func (e *h264Encoder) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	if e.frameQueue != nil {
		close(e.frameQueue)
	}
	e.mu.Unlock()
	e.wg.Wait()
	if e.captureDevice != nil {
		e.captureDevice.Release()
		e.captureDevice = nil
	}
	return nil
}

func (e *h264Encoder) encodeLoop() {
	defer e.wg.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Ensure COM is initialized on this thread.
	if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil && err != syscall.Errno(windows.S_FALSE) {
		e.sendResult(h264Result{err: err})
		return
	}
	defer windows.CoUninitialize()

	if err := ensureMediaFoundation(); err != nil {
		e.sendResult(h264Result{err: err})
		return
	}

	dxgiInputEnabled := envIsTruthy("SPARK_WEBRTC_H264_DXGI")
	fmt.Printf("[H264_INIT] DXGI direct input enabled=%t (env SPARK_WEBRTC_H264_DXGI)\n", dxgiInputEnabled)

	var (
		transform       *imfTransform
		eventGen        *iMFMediaEventGenerator // For async MFT event model (hardware encoders)
		isAsyncMFT      bool                    // True if using async event model
		codecAPI        *iCodecAPI
		inType          *imfMediaType
		outType         *imfMediaType
		inSample        *imfSample
		inBuf           *imfMediaBuffer
		outSample       *imfSample
		outBuf          *imfMediaBuffer
		dxgiMgr         *DXGIDeviceManager
		ownedDev        *iD3D11Device
		nv12ReadbackCtx *NV12ReadbackContext // For software fallback with GPU frames
		width           int
		height          int
		bitRate         int
		fps             uint32
		frameSeq        int
		encodeBuf       []byte
	)

	releaseTransformState := func() {
		if eventGen != nil {
			eventGen.Release()
			eventGen = nil
		}
		isAsyncMFT = false
		if codecAPI != nil {
			codecAPI.Release()
			codecAPI = nil
		}
		if outBuf != nil {
			outBuf.Release()
			outBuf = nil
		}
		if outSample != nil {
			outSample.Release()
			outSample = nil
		}
		if inBuf != nil {
			inBuf.Release()
			inBuf = nil
		}
		if inSample != nil {
			inSample.Release()
			inSample = nil
		}
		if outType != nil {
			outType.Release()
			outType = nil
		}
		if inType != nil {
			inType.Release()
			inType = nil
		}
		if transform != nil {
			transform.Release()
			transform = nil
		}
		width, height, bitRate, fps, frameSeq = 0, 0, 0, 0, 0
		encodeBuf = nil
	}
	var nv12UploadCtx *NV12UploadContext // For perf overlay + hardware encoder path

	defer func() {
		releaseTransformState()
		if nv12ReadbackCtx != nil {
			nv12ReadbackCtx.Release()
			nv12ReadbackCtx = nil
		}
		if nv12UploadCtx != nil {
			nv12UploadCtx.Release()
			nv12UploadCtx = nil
		}
		if dxgiMgr != nil {
			dxgiMgr.Release()
			dxgiMgr = nil
		}
		if ownedDev != nil {
			ownedDev.Release()
			ownedDev = nil
		}
	}()

	if e.captureDevice != nil {
		mgr, err := NewDXGIDeviceManager(e.captureDevice)
		if err == nil {
			dxgiMgr = mgr
		}
	}

	// needKeyframe tracks whether the next frame should be an IDR/keyframe.
	needKeyframe := true

	// reinitCore performs the actual encoder initialization.
	// For hardware encoding, DXGI manager should be attached FIRST (before any types).
	reinitCore := func(w, h int, targetBitRate int, targetFPS uint32, includeInputBufferAttrs bool, useHardwareMFT bool, useDXGIMgr *DXGIDeviceManager) error {
		releaseTransformState()

		fmt.Printf("[H264_INIT] creating MFT w=%d h=%d fps=%d bitrate=%d hw=%t dxgi=%t bufAttrs=%t\n", w, h, targetFPS, targetBitRate, useHardwareMFT, useDXGIMgr != nil, includeInputBufferAttrs)

		var t *imfTransform
		var err error

		if useHardwareMFT {
			// Use enumeration to find a hardware encoder (when available).
			t, err = coCreateH264Transform()
			if err != nil {
				fmt.Printf("[H264_INIT] coCreateH264Transform failed: %v\n", err)
				return err
			}
			fmt.Printf("[H264_INIT] hardware MFT created (via enumeration)\n")

			// Unlock async MFT for synchronous use.
			// This is required for DXGI attachment to work and allows ProcessInput/ProcessOutput calls.
			wasAsync, err := unlockAsyncMFT(t)
			if err != nil {
				fmt.Printf("[H264_INIT] failed to unlock async MFT: %v\n", err)
				t.Release()
				return fmt.Errorf("unlock async MFT: %w", err)
			}
			isAsyncMFT = false
			if wasAsync {
				fmt.Printf("[H264_INIT] async MFT unlocked for synchronous use\n")
				if eg, err := t.QueryEventGenerator(); err == nil && eg != nil {
					eventGen = eg
					isAsyncMFT = true
					fmt.Printf("[H264_INIT] async MFT: event generator enabled\n")
				} else if err != nil {
					fmt.Printf("[H264_INIT] async MFT: QueryEventGenerator unavailable: %v\n", err)
				}
			}

			// For hardware encoders, attach DXGI manager BEFORE setting media types.
			// This is required by Microsoft documentation for hardware video encoders.
			if useDXGIMgr != nil {
				fmt.Printf("[H264_INIT] attaching DXGI manager FIRST (before types)\n")
				if err := useDXGIMgr.ConfigureTransform(t); err != nil {
					fmt.Printf("[H264_INIT] DXGI ConfigureTransform failed: %v\n", err)
					t.Release()
					return fmt.Errorf("configure DXGI before types: %w", err)
				}
				fmt.Printf("[H264_INIT] DXGI manager attached successfully\n")
			}
		} else {
			// For software encoding: use Microsoft's software encoder directly
			// This avoids getting a hardware encoder that requires DXGI
			t, err = coCreateH264TransformCLSID()
			if err != nil {
				fmt.Printf("[H264_INIT] coCreateH264TransformCLSID failed: %v\n", err)
				return err
			}
			fmt.Printf("[H264_INIT] software MFT created (CMSH264EncoderMFT)\n")
		}
		transform = t
		if api, err := mfTryInitCodecAPI(transform); err == nil {
			codecAPI = api
			mfConfigureCodecAPIForH264(codecAPI, targetBitRate, e.keyFrameInterval)
			fmt.Printf("[H264_CODECAPI] configured low-latency settings\n")
		} else {
			codecAPI = nil
			fmt.Printf("[H264_CODECAPI] unavailable: %v\n", err)
		}

		ot, err := mfCreateMediaType()
		if err != nil {
			return err
		}
		if err := mfConfigureH264Type(ot, w, h, targetFPS, targetBitRate); err != nil {
			ot.Release()
			return err
		}

		// MFT encoders require output type to be COMMITTED before they accept input types.
		// Try to commit output type directly; if that fails, try with minimal attrs.
		outputCommitted := false
		if err := transform.SetOutputType(0, ot, 0); err == nil {
			outputCommitted = true
			fmt.Printf("[H264_INIT] SetOutputType with profile SUCCESS\n")
		} else {
			fmt.Printf("[H264_INIT] SetOutputType with profile failed: %v\n", err)
			// Some encoders reject an explicit profile; retry with minimal output attrs.
			ot.Release()
			ot, err = mfCreateMediaType()
			if err != nil {
				return err
			}
			if err := mfConfigureH264TypeNoProfile(ot, w, h, targetFPS, targetBitRate); err != nil {
				ot.Release()
				return err
			}
			if err := transform.SetOutputType(0, ot, 0); err == nil {
				outputCommitted = true
				fmt.Printf("[H264_INIT] SetOutputType without profile SUCCESS\n")
			} else {
				fmt.Printf("[H264_INIT] SetOutputType without profile failed: %v\n", err)
				// Try enumerating available types.
				ot.Release()
				ot, err = mfTrySelectAvailableType(transform, false, w, h, targetFPS, targetBitRate, false)
				if err != nil {
					fmt.Printf("[H264_INIT] mfTrySelectAvailableType for output failed: %v\n", err)
					return fmt.Errorf("validate output type: %w", err)
				}
				if err := transform.SetOutputType(0, ot, 0); err != nil {
					fmt.Printf("[H264_INIT] final SetOutputType failed: %v\n", err)
					ot.Release()
					return fmt.Errorf("set output type: %w", err)
				}
				outputCommitted = true
				fmt.Printf("[H264_INIT] SetOutputType from available types SUCCESS\n")
			}
		}
		_ = outputCommitted // always true at this point

		// Now set input type (output type committed, DXGI attached if hardware).
		it, err := mfCreateMediaType()
		if err != nil {
			ot.Release()
			return err
		}
		if err := mfConfigureNV12Type(it, w, h, targetFPS, includeInputBufferAttrs); err != nil {
			it.Release()
			ot.Release()
			return err
		}
		// Directly commit input type (output is already set).
		if err := transform.SetInputType(0, it, 0); err != nil {
			fmt.Printf("[H264_INIT] SetInputType failed: %v\n", err)
			firstErr := err
			it.Release()
			fmt.Printf("[H264_INIT] trying mfTrySelectAvailableType for input\n")
			it, err = mfTrySelectAvailableType(transform, true, w, h, targetFPS, targetBitRate, includeInputBufferAttrs)
			if err != nil {
				fmt.Printf("[H264_INIT] mfTrySelectAvailableType for input failed: %v\n", err)
				ot.Release()
				return fmt.Errorf("validate input type: %w (fallback err=%v)", firstErr, err)
			}
			fmt.Printf("[H264_INIT] found available input type, setting\n")
			if err := transform.SetInputType(0, it, 0); err != nil {
				fmt.Printf("[H264_INIT] final SetInputType failed: %v\n", err)
				it.Release()
				ot.Release()
				return fmt.Errorf("set input type: %w", err)
			}
			fmt.Printf("[H264_INIT] SetInputType from available types SUCCESS\n")
		} else {
			fmt.Printf("[H264_INIT] SetInputType SUCCESS\n")
		}

		inType = it
		outType = ot

		// DXGI manager already attached BEFORE setting types for hardware encoders.

		// Allocate reusable input sample/buffer (NV12).
		inSize := uint32(w*h + (w*h)/2)
		inS, err := mfCreateSample()
		if err != nil {
			return err
		}
		inSample = inS
		inB, err := mfCreateMemoryBuffer(inSize)
		if err != nil {
			return err
		}
		inBuf = inB
		if err := inSample.AddBuffer(inBuf); err != nil {
			return err
		}
		encodeBuf = make([]byte, inSize)

		// Allocate reusable output sample/buffer.
		var outInfo mftOutputStreamInfo
		if err := transform.GetOutputStreamInfo(0, &outInfo); err != nil {
			return err
		}
		providesSamples := (outInfo.Flags & mftOutputStreamProvidesSamples) != 0
		fmt.Printf("[H264_INIT] output stream info flags=0x%08x size=%d provides_samples=%t\n", outInfo.Flags, outInfo.Size, providesSamples)
		if providesSamples {
			// Some hardware encoders insist on allocating output samples themselves.
			// In that case, callers must pass a nil sample pointer to ProcessOutput.
			outSample = nil
			outBuf = nil
		} else {
			outS, err := mfCreateSample()
			if err != nil {
				return err
			}
			outSample = outS
			outB, err := mfCreateMemoryBuffer(outInfo.Size)
			if err != nil {
				return err
			}
			outBuf = outB
			if err := outSample.AddBuffer(outBuf); err != nil {
				return err
			}
		}

		// Reset and begin streaming.
		_ = transform.ProcessMessage(mftMessageCommandFlush, 0)
		// Not all encoder MFTs support/require these messages; treat as best-effort.
		_ = transform.ProcessMessage(mftMessageNotifyBeginStreaming, 0)
		_ = transform.ProcessMessage(mftMessageNotifyStartOfStream, 0)

		if useHardwareMFT {
			if isAsyncMFT && eventGen != nil {
				fmt.Printf("[H264_INIT] hardware MFT: async event model enabled\n")
			} else {
				fmt.Printf("[H264_INIT] hardware MFT: using sync model\n")
			}
		}

		width, height, bitRate, fps, frameSeq, needKeyframe = w, h, targetBitRate, targetFPS, 0, true
		return nil
	}

	var usingSoftwareFallback atomic.Bool
	var pendingOutput []media.Sample // Buffer for drained frames that couldn't be delivered

	perfOverlay := loadPerfMarkerOverlayConfig()

	// reinit tries DXGI-accelerated encoding first, falls back to software if that fails.
	reinit := func(w, h int, targetBitRate int, targetFPS uint32) error {
		if perfOverlay.enabled || usingSoftwareFallback.Load() {
			// Perf overlay requires CPU-accessible NV12 so we can draw the marker.
			// Software fallback is set when hardware encoder ProcessInput fails.
			// Use software encoder directly - hardware encoders with DXGI + CPU roundtrip
			// are unreliable across different GPU vendors.
			reason := "perf overlay enabled"
			if usingSoftwareFallback.Load() && !perfOverlay.enabled {
				reason = "software fallback active"
			}
			usingSoftwareFallback.Store(true)
			fmt.Printf("[H264_REINIT] %s: using software encoder\n", reason)
			err := reinitCore(w, h, targetBitRate, targetFPS, true, false, nil)
			if err != nil {
				fmt.Printf("[H264_REINIT] software encoder FAILED: %v\n", err)
			} else {
				fmt.Printf("[H264_REINIT] software encoder SUCCESS\n")
			}
			return err
		}

		// Prefer hardware encoding. Enable direct DXGI surface input only when explicitly
		// requested; some driver/MFT combinations hang with DXGI-backed samples.
		useDXGIInput := dxgiInputEnabled && dxgiMgr != nil
		var mgr *DXGIDeviceManager
		if useDXGIInput {
			mgr = dxgiMgr
		}
		// Keep input buffer attributes enabled even for DXGI samples; several hardware MFTs
		// still rely on stride/sample-size hints when validating NV12 inputs.
		includeBufferAttrs := true
		fmt.Printf("[H264_REINIT] trying hardware encoder w=%d h=%d bitrate=%d fps=%d dxgi_input=%t bufAttrs=%t\n", w, h, targetBitRate, targetFPS, useDXGIInput, includeBufferAttrs)
		if err := reinitCore(w, h, targetBitRate, targetFPS, includeBufferAttrs, true, mgr); err == nil {
			usingSoftwareFallback.Store(false)
			fmt.Printf("[H264_REINIT] hardware encoder SUCCESS\n")
			return nil // Hardware encoder working
		} else {
			fmt.Printf("[H264_REINIT] hardware encoder FAILED: %v\n", err)
		}

		// Software encoder path (no DXGI, include buffer attrs for software MFT).
		fmt.Printf("[H264_REINIT] trying software encoder w=%d h=%d bitrate=%d fps=%d\n", w, h, targetBitRate, targetFPS)
		usingSoftwareFallback.Store(true)
		err := reinitCore(w, h, targetBitRate, targetFPS, true, false, nil)
		if err != nil {
			fmt.Printf("[H264_REINIT] software encoder FAILED: %v\n", err)
		} else {
			fmt.Printf("[H264_REINIT] software encoder SUCCESS\n")
		}
		return err
	}

	frameCounter := 0
	emptyOutputCount := 0
	outputCount := 0
	var lastFrameLog time.Time

	// File-based debug log for Windows GUI apps
	debugLog := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		fmt.Print(msg) // Also print to stdout
		if f, err := os.OpenFile("logs/h264_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, "[%s] %s", time.Now().Format("15:04:05.000"), msg)
			f.Close()
		}
	}

	var asyncNeedInputPending bool
	var asyncHaveOutputPending bool

	drainAsyncEvents := func() {
		if eventGen == nil {
			return
		}
		for {
			event, err := eventGen.GetEvent(1) // MF_EVENT_FLAG_NO_WAIT
			if err != nil {
				return
			}
			eventType, _ := event.GetType()
			event.Release()
			switch eventType {
			case meTransformNeedInput:
				asyncNeedInputPending = true
			case meTransformHaveOutput:
				asyncHaveOutputPending = true
			}
		}
	}

	waitForNeedInput := func(timeout time.Duration) bool {
		if !isAsyncMFT || eventGen == nil {
			return true
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			drainAsyncEvents()
			if asyncNeedInputPending {
				return true
			}
			time.Sleep(2 * time.Millisecond)
		}
		drainAsyncEvents()
		return asyncNeedInputPending
	}

	waitForHaveOutput := func(timeout time.Duration) bool {
		if !isAsyncMFT || eventGen == nil {
			return true
		}
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			drainAsyncEvents()
			if asyncHaveOutputPending {
				return true
			}
			time.Sleep(2 * time.Millisecond)
		}
		drainAsyncEvents()
		return asyncHaveOutputPending
	}

	for req := range e.frameQueue {
		frameCounter++
		// Log first 20 frames, every 100th, or every 5 seconds
		shouldLog := frameCounter <= 20 || frameCounter%100 == 0 || time.Since(lastFrameLog) > 5*time.Second
		if shouldLog {
			lastFrameLog = time.Now()
			debugLog("[H264_FRAME] frame=%d isGPU=%v hasImg=%v gpuW=%d gpuH=%d pendingOut=%d emptyOuts=%d outputs=%d swFallback=%v\n",
				frameCounter, req.isGPU, req.img != nil, req.gpuWidth, req.gpuHeight, len(pendingOutput), emptyOutputCount, outputCount, usingSoftwareFallback.Load())
		}

		// Return pending output from previous drain first
		if len(pendingOutput) > 0 {
			sample := pendingOutput[0]
			pendingOutput = pendingOutput[1:]
			e.sendResult(h264Result{sample: sample, seq: req.seq})
			continue
		}
		if !req.isGPU && req.img == nil {
			e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
			continue
		}
		w := req.gpuWidth
		h := req.gpuHeight
		if !req.isGPU {
			w = req.img.Bounds().Dx()
			h = req.img.Bounds().Dy()
		}
		if w <= 0 || h <= 0 {
			e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
			continue
		}
		// NV12 requires even dimensions (4:2:0).
		if w%2 != 0 || h%2 != 0 {
			e.sendResult(h264Result{err: fmt.Errorf("h264 requires even dimensions, got %dx%d", w, h), seq: req.seq})
			continue
		}

		targetBitRate := e.baseBitRate
		e.mu.Lock()
		if e.aqm != nil {
			targetBitRate = e.aqm.GetCurrentBitrate()
		}
		e.mu.Unlock()

		// Only try to create DXGI manager if hardware encoding hasn't permanently failed.
		// If usingSoftwareFallback is true, GPU frames will be dropped gracefully below.
		if req.isGPU && dxgiMgr == nil && !perfOverlay.enabled && !usingSoftwareFallback.Load() {
			if e.captureDevice == nil && ownedDev == nil {
				ownedDev = getCaptureD3D11Device()
			}
			if e.captureDevice != nil {
				if mgr, err := NewDXGIDeviceManager(e.captureDevice); err == nil {
					dxgiMgr = mgr
				}
			} else if ownedDev != nil {
				if mgr, err := NewDXGIDeviceManager(ownedDev); err == nil {
					dxgiMgr = mgr
				}
			}
			// Force reinit with DXGI manager attached.
			if dxgiMgr != nil {
				releaseTransformState()
			}
		}

		targetFPS := mfApproxFPS(req.duration)
		// Only reinit for dimension or FPS changes, not bitrate changes.
		// Bitrate changes during streaming cause an 8-frame stall, which hurts FPS.
		// The encoder will continue at the original bitrate until resolution changes.
		needReinit := transform == nil || w != width || h != height || targetFPS != fps
		if needReinit {
			// Use current bitrate if already initialized, otherwise use target
			reinitBitRate := targetBitRate
			if bitRate > 0 {
				reinitBitRate = bitRate
			}
			if err := reinit(w, h, reinitBitRate, targetFPS); err != nil {
				e.sendResult(h264Result{err: err, seq: req.seq})
				continue
			}
			pendingOutput = nil // Clear pending output from old encoder state
			// Note: reinitCore already sends BeginStreaming/StartOfStream messages
		}

		frameSeq++
		forceKeyframe := needKeyframe
		if e.forceKeyFrame.Swap(false) {
			forceKeyframe = true
		}
		if !forceKeyframe && e.keyFrameInterval > 0 && frameSeq >= e.keyFrameInterval {
			forceKeyframe = true
			frameSeq = 0
		}
		if forceKeyframe {
			needKeyframe = false
			frameSeq = 0
			if codecAPI != nil {
				_ = codecAPI.SetValue(&codecapiAVEncVideoForceKeyFrame, ptrVariant(variantUI4Value(1)))
			} else if transform != nil {
				// Fallback: flush-based keyframe requests (may add latency).
				_ = transform.ProcessMessage(mftMessageCommandFlush, 0)
				_ = transform.ProcessMessage(mftMessageNotifyBeginStreaming, 0)
				_ = transform.ProcessMessage(mftMessageNotifyStartOfStream, 0)
			}
		}

		if req.isGPU {
			// Prefer direct DXGI surface input when enabled for this encoder; otherwise
			// fall back to GPU readback -> CPU NV12 buffers -> encoder MFT.
			useDirectDXGI := dxgiInputEnabled && dxgiMgr != nil && !perfOverlay.enabled && !usingSoftwareFallback.Load() && req.gpuTexture != nil

			if useDirectDXGI {
				// Diagnostic: verify device relationship on first frame
				if frameCounter == 1 {
					mgrDev := dxgiMgr.GetDevice()
					capDev := e.captureDevice
					debugLog("[H264_HW_DIAG] dxgiMgr.device=%p captureDevice=%p match=%t\n",
						unsafe.Pointer(mgrDev), unsafe.Pointer(capDev), mgrDev == capDev)
					debugLog("[H264_HW_DIAG] texture=%p w=%d h=%d\n", unsafe.Pointer(req.gpuTexture), w, h)
				}

				if frameCounter <= 3 {
					debugLog("[H264_HW] frame=%d creating DXGI sample\n", frameCounter)
				}
				sample, err := dxgiMgr.CreateSampleFromTexture(req.gpuTexture, w, h)
				if err != nil {
					fmt.Printf("[H264_HW] frame=%d CreateSampleFromTexture failed: %v\n", frameCounter, err)
					e.sendResult(h264Result{err: err, seq: req.seq})
					continue
				}
				if frameCounter <= 3 {
					debugLog("[H264_HW] frame=%d DXGI sample created\n", frameCounter)
				}

				// Set sample time/duration (100ns units). Some hardware MFTs require this to produce output.
				sampleTime := int64(frameCounter-1) * int64(req.duration/100)
				sampleDuration := int64(req.duration / 100)
				_ = sample.SetSampleTime(sampleTime)
				_ = sample.SetSampleDuration(sampleDuration)

				// For async MFTs, best-effort wait for METransformNeedInput before ProcessInput.
				if isAsyncMFT && eventGen != nil && frameCounter <= 3 {
					if waitForNeedInput(250 * time.Millisecond) {
						asyncNeedInputPending = false
					} else {
						debugLog("[H264_HW] frame=%d no METransformNeedInput within timeout, trying ProcessInput anyway\n", frameCounter)
					}
				} else if !isAsyncMFT {
					// Synchronous MFT: check input status
					inputStatus, statusErr := transform.GetInputStatus(0)
					if frameCounter <= 3 {
						if statusErr != nil {
							debugLog("[H264_HW] frame=%d GetInputStatus failed: %v\n", frameCounter, statusErr)
						} else {
							canAccept := (inputStatus & mftInputStatusAcceptData) != 0
							debugLog("[H264_HW] frame=%d GetInputStatus=0x%x canAccept=%t tex=%p\n", frameCounter, inputStatus, canAccept, unsafe.Pointer(req.gpuTexture))
						}
					}
					// If MFT reports it cannot accept input, try draining output first
					if statusErr == nil && (inputStatus&mftInputStatusAcceptData) == 0 {
						debugLog("[H264_HW] frame=%d MFT not accepting input, trying to drain output first\n", frameCounter)
						for drainAttempt := 0; drainAttempt < 3; drainAttempt++ {
							var drainStatus uint32
							drainOut := mftOutputDataBuffer{StreamID: 0, Sample: nil}
							drainErr := transform.ProcessOutput(0, &drainOut, &drainStatus)
							if drainErr != nil {
								if errno, ok := drainErr.(syscall.Errno); ok && uint32(errno) == 0xC00D6D72 {
									debugLog("[H264_HW] frame=%d drain attempt %d: NEED_MORE_INPUT (expected)\n", frameCounter, drainAttempt)
									break
								}
								debugLog("[H264_HW] frame=%d drain attempt %d failed: %v\n", frameCounter, drainAttempt, drainErr)
								break
							}
							debugLog("[H264_HW] frame=%d drain attempt %d: got output\n", frameCounter, drainAttempt)
							if drainOut.Sample != nil {
								drainOut.Sample.Release()
							}
						}
						// Re-check input status after drain
						inputStatus, _ = transform.GetInputStatus(0)
						debugLog("[H264_HW] frame=%d after drain: GetInputStatus=0x%x\n", frameCounter, inputStatus)
					}
				}
				inputErr := error(nil)
				for inputAttempt := 0; inputAttempt < 3; inputAttempt++ {
					if isAsyncMFT && eventGen != nil {
						if waitForNeedInput(75 * time.Millisecond) {
							asyncNeedInputPending = false
						}
					}
					inputErr = transform.ProcessInput(0, sample, 0)
					if inputErr == nil {
						break
					}
					if !mfHasHRESULT(inputErr, mfENotAccepting) {
						break
					}
					// MF_E_NOTACCEPTING: drain pending output then retry.
					if frameCounter <= 3 {
						debugLog("[H264_HW] frame=%d ProcessInput NOT_ACCEPTING, draining+retry attempt=%d\n", frameCounter, inputAttempt)
					}
					for drainAttempt := 0; drainAttempt < 3; drainAttempt++ {
						var drainStatus uint32
						drainOut := mftOutputDataBuffer{StreamID: 0, Sample: outSample}
						drainErr := transform.ProcessOutput(0, &drainOut, &drainStatus)
						if drainErr != nil {
							if errno, ok := drainErr.(syscall.Errno); ok && uint32(errno) == mfETransformNeedMoreInput {
								break
							}
							break
						}
						if drainOut.Sample != nil && drainOut.Sample != outSample {
							drainOut.Sample.Release()
						}
					}
				}

				if inputErr != nil {
					if mfHasHRESULT(inputErr, mfENotAccepting) {
						fmt.Printf("[H264_HW] frame=%d ProcessInput NOT_ACCEPTING after retries, disabling DXGI direct input\n", frameCounter)
					} else if errno, ok := inputErr.(syscall.Errno); ok {
						fmt.Printf("[H264_HW] frame=%d ProcessInput FAILED: %v (0x%08x), disabling DXGI direct input\n", frameCounter, inputErr, uint32(errno))
					} else {
						fmt.Printf("[H264_HW] frame=%d ProcessInput FAILED: %v, disabling DXGI direct input\n", frameCounter, inputErr)
					}
					sample.Release()

					// Some hardware encoder MFTs accept NV12 input types but refuse DXGI-backed input samples
					// (MF_E_NOTACCEPTING). In that case, keep hardware encoding enabled, but fall back to
					// system-memory samples (NV12 readback -> ProcessInput) instead of switching to the
					// software H.264 encoder (which adds significant pipeline buffering).
					dxgiInputEnabled = false
					if reinitErr := reinit(w, h, targetBitRate, fps); reinitErr != nil {
						fmt.Printf("[H264_HW] fallback reinit failed: %v\n", reinitErr)
						e.sendResult(h264Result{err: reinitErr, seq: req.seq})
						continue
					}
					fmt.Printf("[H264_HW] switched away from DXGI direct input, dropping current frame\n")
					e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
					continue
				}

				if frameCounter <= 3 {
					debugLog("[H264_HW] frame=%d ProcessInput OK\n", frameCounter)
				}
				sample.Release()
			} else {
				// Need to read back GPU texture to CPU for marker overlay, software encoding, or when
				// DXGI-backed input samples are disabled/unavailable.
				if req.gpuTexture == nil {
					fmt.Printf("[H264_READBACK] GPU frame but nil texture\n")
					e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
					continue
				}

				// Initialize readback context if needed.
				if nv12ReadbackCtx == nil {
					fmt.Printf("[H264_READBACK] creating readback context\n")
					dev := e.captureDevice
					fmt.Printf("[H264_READBACK] e.captureDevice=%v\n", dev != nil)
					if dev == nil {
						dev = getCaptureD3D11Device()
						fmt.Printf("[H264_READBACK] getCaptureD3D11Device=%v\n", dev != nil)
						if dev != nil {
							defer dev.Release()
						}
					}
					if dev != nil {
						fmt.Printf("[H264_READBACK] calling NewNV12ReadbackContext\n")
						if ctx, err := NewNV12ReadbackContext(dev); err == nil {
							nv12ReadbackCtx = ctx
							fmt.Printf("[H264_READBACK] readback context created successfully\n")
						} else {
							fmt.Printf("[H264_ENCODE] failed to create NV12 readback context: %v\n", err)
						}
					} else {
						fmt.Printf("[H264_READBACK] no D3D11 device available\n")
					}
				}

				if nv12ReadbackCtx == nil {
					// No readback context - drop frame.
					e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
					continue
				}

				// Read back NV12 texture to CPU buffer.
				nv12Size := w * h * 3 / 2
				if cap(encodeBuf) < nv12Size {
					encodeBuf = make([]byte, nv12Size)
				}
				encodeBuf = encodeBuf[:nv12Size]

				if frameCounter <= 3 {
					fmt.Printf("[H264_READBACK] frame=%d reading NV12 texture w=%d h=%d size=%d tex=%v\n",
						frameCounter, w, h, nv12Size, req.gpuTexture != nil)
				}
				if err := nv12ReadbackCtx.ReadbackNV12(req.gpuTexture, w, h, encodeBuf); err != nil {
					fmt.Printf("[H264_ENCODE] NV12 readback failed: %v\n", err)
					var mfErr mfError
					if errors.As(err, &mfErr) {
						reason := d3d.HRESULT(int32(mfErr.hr))
						if shouldResetDXGI(reason) {
							nv12ReadbackCtx.Release()
							nv12ReadbackCtx = nil
							if e.captureDevice != nil {
								e.captureDevice.Release()
								e.captureDevice = nil
							}
							downgradeCaptureBackendForSoftwareH264("nv12 readback failed")
						}
					}
					e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
					continue
				}
				if frameCounter <= 3 {
					fmt.Printf("[H264_READBACK] frame=%d readback successful\n", frameCounter)
				}

				applyPerfMarkerOverlayNV12(encodeBuf, w, h, perfOverlay)

				// Feed NV12 data to the encoder MFT (hardware or software).
				ptr, maxLen, _, lockErr := inBuf.Lock()
				if lockErr != nil {
					fmt.Printf("[H264_ENCODE] inBuf.Lock failed: %v\n", lockErr)
					e.sendResult(h264Result{err: lockErr, seq: req.seq})
					continue
				}
				if uint32(len(encodeBuf)) > maxLen {
					fmt.Printf("[H264_ENCODE] input buffer too small: need %d have %d\n", len(encodeBuf), maxLen)
					_ = inBuf.Unlock()
					e.sendResult(h264Result{err: errors.New("input buffer too small"), seq: req.seq})
					continue
				}
				copy(unsafe.Slice((*byte)(ptr), len(encodeBuf)), encodeBuf)
				_ = inBuf.Unlock()
				_ = inBuf.SetCurrentLength(uint32(len(encodeBuf)))

				// Set sample time and duration (required by some MFTs).
				sampleTime := int64(frameCounter-1) * int64(req.duration/100)
				sampleDuration := int64(req.duration / 100)
				_ = inSample.SetSampleTime(sampleTime)
				_ = inSample.SetSampleDuration(sampleDuration)

				// For hardware MFTs: check input status and drain if needed before ProcessInput.
				// This handles MF_E_NOTACCEPTING by draining pending output first.
				if !usingSoftwareFallback.Load() {
					inputStatus, statusErr := transform.GetInputStatus(0)
					if statusErr == nil && (inputStatus&mftInputStatusAcceptData) == 0 {
						if frameCounter <= 3 {
							debugLog("[H264_ENCODE] frame=%d MFT not accepting, draining output\n", frameCounter)
						}
						for drainAttempt := 0; drainAttempt < 3; drainAttempt++ {
							var drainStatus uint32
							drainOut := mftOutputDataBuffer{StreamID: 0, Sample: nil}
							drainErr := transform.ProcessOutput(0, &drainOut, &drainStatus)
							if drainErr != nil {
								break
							}
							if drainOut.Sample != nil {
								drainOut.Sample.Release()
							}
						}
					}
				}

				// ProcessInput with retry and drain on MF_E_NOTACCEPTING
				if frameCounter <= 3 {
					fmt.Printf("[H264_ENCODE] frame=%d calling ProcessInput\n", frameCounter)
				}
				inputErr := error(nil)
				for inputAttempt := 0; inputAttempt < 3; inputAttempt++ {
					if isAsyncMFT && eventGen != nil {
						if waitForNeedInput(75 * time.Millisecond) {
							asyncNeedInputPending = false
						}
					}
					inputErr = transform.ProcessInput(0, inSample, 0)
					if inputErr == nil {
						break
					}
					if !mfHasHRESULT(inputErr, mfENotAccepting) {
						break
					}
					// MF_E_NOTACCEPTING: drain output and retry
					if frameCounter <= 3 {
						debugLog("[H264_ENCODE] frame=%d ProcessInput NOTACCEPTING, draining (attempt %d)\n", frameCounter, inputAttempt)
					}
					var drainStatus uint32
					drainOut := mftOutputDataBuffer{StreamID: 0, Sample: nil}
					drainErr := transform.ProcessOutput(0, &drainOut, &drainStatus)
					if drainErr != nil {
						if errno, ok := drainErr.(syscall.Errno); ok && uint32(errno) == 0xC00D6D72 {
							// NEED_MORE_INPUT - no output available, wait briefly
							time.Sleep(5 * time.Millisecond)
						}
					} else if drainOut.Sample != nil {
						drainOut.Sample.Release()
					}
				}
				if inputErr != nil {
					fmt.Printf("[H264_ENCODE] ProcessInput failed: %v\n", inputErr)
					// Hardware MFTs may claim NV12 input support but still reject CPU-backed samples.
					// If that happens, fall back to the known-good software encoder.
					if !usingSoftwareFallback.Load() && !dxgiInputEnabled {
						usingSoftwareFallback.Store(true)
						if err := reinit(w, h, targetBitRate, targetFPS); err == nil {
							e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
							continue
						}
					}
					e.sendResult(h264Result{err: inputErr, seq: req.seq})
					continue
				}
				if frameCounter <= 3 {
					fmt.Printf("[H264_ENCODE] frame=%d ProcessInput succeeded\n", frameCounter)
				}
			}
		} else {
			if err := colorconv.RGBAToNV12(req.img, encodeBuf, w, h); err != nil {
				e.sendResult(h264Result{err: err, seq: req.seq})
				continue
			}

			applyPerfMarkerOverlayNV12(encodeBuf, w, h, perfOverlay)

			ptr, maxLen, _, lockErr := inBuf.Lock()
			if lockErr != nil {
				e.sendResult(h264Result{err: lockErr, seq: req.seq})
				continue
			}
			if uint32(len(encodeBuf)) > maxLen {
				_ = inBuf.Unlock()
				e.sendResult(h264Result{err: errors.New("input buffer too small"), seq: req.seq})
				continue
			}
			copy(unsafe.Slice((*byte)(ptr), len(encodeBuf)), encodeBuf)
			_ = inBuf.Unlock()
			_ = inBuf.SetCurrentLength(uint32(len(encodeBuf)))

			// Set sample time and duration (required by software encoder)
			// Use 100ns units (Media Foundation standard)
			sampleTime := int64(frameCounter-1) * int64(req.duration/100) // Convert to 100ns
			sampleDuration := int64(req.duration / 100)                   // Convert to 100ns
			_ = inSample.SetSampleTime(sampleTime)
			_ = inSample.SetSampleDuration(sampleDuration)

			// Software encoder (RGBA path) - direct ProcessInput
			if procErr := transform.ProcessInput(0, inSample, 0); procErr != nil {
				e.sendResult(h264Result{err: procErr, seq: req.seq})
				continue
			}
		}

		// Reset output buffer length before ProcessOutput
		// Note: Codec API low-latency settings (AVEncCommonLowLatency, CBR, etc.) configured in
		// mfConfigureCodecAPIForH264 ensure immediate output without needing drain/restart cycles.
		// With low-latency settings, we typically get 0 or 1 outputs per input, so 2 attempts is sufficient.
		var outputs []media.Sample
		maxAttempts := 2
		asyncRetryDelay := time.Duration(0)
		if isAsyncMFT && eventGen != nil {
			// Some async hardware encoder MFTs only produce output a few milliseconds after ProcessInput.
			// Poll briefly to avoid premature fallback and to keep the pipeline flowing.
			maxAttempts = 20
			asyncRetryDelay = 3 * time.Millisecond
		}
		for attempt := 0; attempt < maxAttempts; attempt++ {
			if isAsyncMFT && eventGen != nil {
				// Async MFT contract: call ProcessOutput when the MFT signals METransformHaveOutput.
				// Avoid hammering ProcessOutput (can yield E_UNEXPECTED).
				if !asyncHaveOutputPending {
					if !waitForHaveOutput(75 * time.Millisecond) {
						break
					}
				}
				asyncHaveOutputPending = false
			}

			if outBuf != nil {
				_ = outBuf.SetCurrentLength(0)
			}

			var outStatus uint32
			out := mftOutputDataBuffer{StreamID: 0, Sample: outSample}
			if frameCounter <= 3 {
				debugLog("[H264_HW] frame=%d ProcessOutput attempt=%d outSampleNil=%t\n", frameCounter, attempt, out.Sample == nil)
			}
			outErr := transform.ProcessOutput(0, &out, &outStatus)
			if outErr != nil {
				if mfHasHRESULT(outErr, mfETransformStreamChange) {
					if frameCounter <= 3 {
						debugLog("[H264_HW] frame=%d ProcessOutput STREAM_CHANGE, renegotiating output type\n", frameCounter)
					}
					newType, err := mfTrySelectAvailableType(transform, false, w, h, fps, bitRate, false)
					if err != nil {
						fmt.Printf("[H264_ENCODE] stream change renegotiation failed: %v\n", err)
						e.sendResult(h264Result{err: err, seq: req.seq})
						goto nextReq
					}
					if err := transform.SetOutputType(0, newType, 0); err != nil {
						newType.Release()
						fmt.Printf("[H264_ENCODE] SetOutputType after stream change failed: %v\n", err)
						e.sendResult(h264Result{err: err, seq: req.seq})
						goto nextReq
					}
					if outType != nil {
						outType.Release()
					}
					outType = newType

					if outBuf != nil {
						outBuf.Release()
						outBuf = nil
					}
					if outSample != nil {
						outSample.Release()
						outSample = nil
					}

					var outInfo mftOutputStreamInfo
					if err := transform.GetOutputStreamInfo(0, &outInfo); err != nil {
						e.sendResult(h264Result{err: err, seq: req.seq})
						goto nextReq
					}
					providesSamples := (outInfo.Flags & mftOutputStreamProvidesSamples) != 0
					if !providesSamples {
						outS, err := mfCreateSample()
						if err != nil {
							e.sendResult(h264Result{err: err, seq: req.seq})
							goto nextReq
						}
						outB, err := mfCreateMemoryBuffer(outInfo.Size)
						if err != nil {
							outS.Release()
							e.sendResult(h264Result{err: err, seq: req.seq})
							goto nextReq
						}
						if err := outS.AddBuffer(outB); err != nil {
							outB.Release()
							outS.Release()
							e.sendResult(h264Result{err: err, seq: req.seq})
							goto nextReq
						}
						outSample = outS
						outBuf = outB
					}

					asyncHaveOutputPending = false
					continue
				}
				// MF_E_TRANSFORM_NEED_MORE_INPUT is normal for encoders; it just means no output yet.
				if errno, ok := outErr.(syscall.Errno); ok && uint32(errno) == 0xC00D6D72 {
					if frameCounter <= 3 {
						debugLog("[H264_HW] frame=%d ProcessOutput NEED_MORE_INPUT\n", frameCounter)
					}
					break
				}
				// Async hardware encoder MFTs can return E_UNEXPECTED when polled before they have output ready.
				// Retry briefly instead of treating it as fatal.
				if isAsyncMFT && eventGen != nil && mfHasHRESULT(outErr, 0x8000FFFF) {
					if frameCounter <= 3 {
						debugLog("[H264_HW] frame=%d ProcessOutput E_UNEXPECTED (async, retry)\n", frameCounter)
					}
					if attempt+1 < maxAttempts && asyncRetryDelay > 0 {
						time.Sleep(asyncRetryDelay)
						continue
					}
					break
				}
				fmt.Printf("[H264_ENCODE] ProcessOutput failed: %v\n", outErr)
				e.sendResult(h264Result{err: outErr, seq: req.seq})
				goto nextReq
			}
			if frameCounter <= 3 {
				debugLog("[H264_HW] frame=%d ProcessOutput OK status=0x%08x hasSample=%t\n", frameCounter, outStatus, out.Sample != nil)
			}

			sample := out.Sample
			if sample == nil {
				continue
			}
			buf, err := sample.ConvertToContiguousBuffer()
			if err != nil {
				fmt.Printf("[H264_ENCODE] ConvertToContiguousBuffer failed: %v\n", err)
				e.sendResult(h264Result{err: err, seq: req.seq})
				if sample != outSample {
					sample.Release()
				}
				goto nextReq
			}
			outPtr, _, curLen, lockErr := buf.Lock()
			if lockErr != nil {
				buf.Release()
				e.sendResult(h264Result{err: lockErr, seq: req.seq})
				if sample != outSample {
					sample.Release()
				}
				goto nextReq
			}
			var encoded []byte
			if curLen > 0 {
				encoded = make([]byte, curLen)
				copy(encoded, unsafe.Slice((*byte)(outPtr), int(curLen)))
			}
			_ = buf.Unlock()
			buf.Release()
			if sample != outSample {
				sample.Release()
			}
			if len(encoded) > 0 {
				encoded = ensureAnnexB(encoded)
				if e.aqm == nil || !e.aqm.ShouldDropFrame(int64(len(encoded))) {
					outputs = append(outputs, media.Sample{Data: encoded, Duration: req.duration})
				}
			}
		}

		if len(outputs) == 0 {
			emptyOutputCount++
			if shouldLog {
				debugLog("[H264_FRAME] frame=%d no output produced (need more input?), emptyOuts=%d outputs=%d\n", frameCounter, emptyOutputCount, outputCount)
			}
			e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}, seq: req.seq})
			continue
		}

		outputCount++
		if shouldLog || outputCount <= 5 {
			debugLog("[H264_OUTPUT] frame=%d output produced, len=%d outputCount=%d\n", frameCounter, len(outputs[0].Data), outputCount)
		}
		e.sendResult(h264Result{sample: outputs[0], seq: req.seq})
		if len(outputs) > 1 {
			pendingOutput = append(pendingOutput, outputs[1:]...)
		}
	nextReq:
	}
}

func (e *h264Encoder) sendResult(res h264Result) {
	e.mu.Lock()
	ch := e.resultQueue
	closed := e.closed
	e.mu.Unlock()
	if closed || ch == nil {
		return
	}
	select {
	case ch <- res:
	default:
	}
}

var annexBLogCount atomic.Uint64

func logNALTypes(buf []byte, frameNum uint64) {
	nalTypes := []int{}
	for i := 0; i < len(buf)-4; i++ {
		// Look for 4-byte start codes (00 00 00 01) only to avoid double counting
		if buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x01 && i+4 < len(buf) {
			nalType := int(buf[i+4] & 0x1F)
			nalTypes = append(nalTypes, nalType)

			// Log SPS details for first frame (NAL type 7 = SPS)
			if nalType == 7 && frameNum == 1 && i+7 < len(buf) {
				// SPS starts after start code + NAL header
				// Bytes after NAL header: profile_idc, constraint_set_flags, level_idc
				profileIDC := buf[i+5]
				constraintFlags := buf[i+6]
				levelIDC := buf[i+7]
				fmt.Printf("[SPS_PROFILE] profile_idc=0x%02X constraint_flags=0x%02X level_idc=0x%02X (profile-level-id=%02x%02x%02x)\n",
					profileIDC, constraintFlags, levelIDC, profileIDC, constraintFlags, levelIDC)
			}
		}
		if len(nalTypes) >= 20 {
			break // Limit to first 20 NAL units
		}
	}
	fmt.Printf("[ANNEXB_NAL] frame=%d nal_types=%v\n", frameNum, nalTypes)
}

func ensureAnnexB(buf []byte) []byte {
	count := annexBLogCount.Add(1)
	if count <= 5 && len(buf) >= 8 {
		fmt.Printf("[ANNEXB] frame=%d in_bytes=%02x%02x%02x%02x%02x%02x%02x%02x len=%d\n",
			count, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], len(buf))
	}

	if len(buf) >= 4 && buf[0] == 0x00 && buf[1] == 0x00 && (buf[2] == 0x01 || (buf[2] == 0x00 && buf[3] == 0x01)) {
		if count <= 5 {
			fmt.Printf("[ANNEXB] frame=%d already annexb\n", count)
			logNALTypes(buf, count)
		}
		return buf
	}
	converted, ok := avccToAnnexB(buf)
	if ok {
		if count <= 5 && len(converted) >= 8 {
			fmt.Printf("[ANNEXB] frame=%d converted_bytes=%02x%02x%02x%02x%02x%02x%02x%02x len=%d\n",
				count, converted[0], converted[1], converted[2], converted[3], converted[4], converted[5], converted[6], converted[7], len(converted))
			logNALTypes(converted, count)
		}
		return converted
	}
	if count <= 5 {
		fmt.Printf("[ANNEXB] frame=%d conversion failed, returning raw\n", count)
	}
	return buf
}

func avccToAnnexB(buf []byte) ([]byte, bool) {
	if len(buf) < 4 {
		return nil, false
	}
	out := make([]byte, 0, len(buf)+len(buf)/4*4)
	for i := 0; i+4 <= len(buf); {
		n := int(binary.BigEndian.Uint32(buf[i : i+4]))
		i += 4
		if n <= 0 || i+n > len(buf) {
			return nil, false
		}
		out = append(out, 0x00, 0x00, 0x00, 0x01)
		out = append(out, buf[i:i+n]...)
		i += n
	}
	return out, true
}
