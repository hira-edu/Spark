//go:build windows

package desktop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"Rocket/client/service/desktop/colorconv"

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
	mftMessageNotifyBeginStreaming = 0x10000000
	mftMessageNotifyStartOfStream  = 0x10000003
)

var (
	mfplat                 = windows.NewLazySystemDLL("mfplat.dll")
	procMFStartup          = mfplat.NewProc("MFStartup")
	procMFCreateMediaType  = mfplat.NewProc("MFCreateMediaType")
	procMFCreateSample     = mfplat.NewProc("MFCreateSample")
	procMFCreateMemoryBuf  = mfplat.NewProc("MFCreateMemoryBuffer")
	procMFSetAttributeSize = mfplat.NewProc("MFSetAttributeSize")
	procMFSetAttributeRat  = mfplat.NewProc("MFSetAttributeRatio")

	ole32                = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")

	mfOnce     sync.Once
	mfInitErr  error
	mfGUIDOnce sync.Once

	clsidCMSH264EncoderMFT windows.GUID
	iidIMFTransform        windows.GUID

	mfMTMajorType   windows.GUID
	mfMTSubtype     windows.GUID
	mfMTFrameSize   windows.GUID
	mfMTFrameRate   windows.GUID
	mfMTInterlace   windows.GUID
	mfMTPixelAspect windows.GUID
	mfMTAvgBitrate  windows.GUID
	mfMTProfile     windows.GUID

	mfMediaTypeVideo windows.GUID
	mfVideoNV12      windows.GUID
	mfVideoH264      windows.GUID
)

func initMFGuids() {
	mfGUIDOnce.Do(func() {
		clsidCMSH264EncoderMFT = mustGUID("6CA50344-051A-4DED-9779-A43305165E35")
		iidIMFTransform = mustGUID("BF94C121-5B05-4E6F-8000-BA598961414D")

		mfMTMajorType = mustGUID("48EBA18E-F8C9-4687-BF11-0A74C9F96A8F")   // MF_MT_MAJOR_TYPE
		mfMTSubtype = mustGUID("F7E34C9A-42E8-4714-B74B-CB29D72C35E5")     // MF_MT_SUBTYPE
		mfMTFrameSize = mustGUID("1652C33D-D6B2-4012-B834-72030849A37D")   // MF_MT_FRAME_SIZE
		mfMTFrameRate = mustGUID("C459A2E8-3D2C-4E44-B132-FEE5156C7BB0")   // MF_MT_FRAME_RATE
		mfMTInterlace = mustGUID("E2724BB8-E676-4806-B4B2-A8D6EFb44CCD")   // MF_MT_INTERLACE_MODE
		mfMTPixelAspect = mustGUID("C6376A1E-8D0A-4027-BE45-6D9A0AD39BB6") // MF_MT_PIXEL_ASPECT_RATIO
		mfMTAvgBitrate = mustGUID("20332624-FB0D-4D9E-BD0D-CBF6786C102E")  // MF_MT_AVG_BITRATE
		mfMTProfile = mustGUID("AD76A802-2D5C-4E0B-B375-64A1F4BF5B53")     // MF_MT_MPEG2_PROFILE

		mfMediaTypeVideo = mustGUID("73646976-0000-0010-8000-00AA00389B71") // MFMediaType_Video
		mfVideoNV12 = mustGUID("3231564E-0000-0010-8000-00AA00389B71")      // MFVideoFormat_NV12
		mfVideoH264 = mustGUID("34363248-0000-0010-8000-00AA00389B71")      // MFVideoFormat_H264
	})
}

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return g
}

func ensureMediaFoundation() error {
	initMFGuids()
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
	return fmt.Errorf("%s failed: HRESULT=0x%08X", name, uint32(hr))
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
	// MF_E_TRANSFORM_NEED_MORE_INPUT (0xC00D6D72) is expected when no output is ready yet.
	if uint32(r0) == 0xC00D6D72 {
		return syscall.Errno(r0)
	}
	return hresultError(r0, "IMFTransform.ProcessOutput")
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

func (mt *imfMediaType) SetUINT32(key *windows.GUID, value uint32) error {
	r0, _, _ := syscall.SyscallN(
		mt.vtbl.SetUINT32,
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(value),
	)
	return hresultError(r0, "IMFMediaType.SetUINT32")
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
	r0, _, _ := procMFSetAttributeSize.Call(
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(width),
		uintptr(height),
	)
	return hresultError(r0, "MFSetAttributeSize")
}

func mfSetAttributeRatio(mt *imfMediaType, key *windows.GUID, num, den uint32) error {
	r0, _, _ := procMFSetAttributeRat.Call(
		uintptr(unsafe.Pointer(mt)),
		uintptr(unsafe.Pointer(key)),
		uintptr(num),
		uintptr(den),
	)
	return hresultError(r0, "MFSetAttributeRatio")
}

type imfSample struct {
	vtbl *imfSampleVtbl
}

type imfSampleVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr

	GetSampleFlags      uintptr
	SetSampleFlags      uintptr
	GetSampleTime       uintptr
	SetSampleTime       uintptr
	GetSampleDuration   uintptr
	SetSampleDuration   uintptr
	GetBufferCount      uintptr
	GetBufferByIndex    uintptr
	ConvertToContiguous uintptr
	AddBuffer           uintptr
	RemoveBufferByIndex uintptr
	RemoveAllBuffers    uintptr
	GetTotalLength      uintptr
	CopyToBuffer        uintptr
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

func coCreateH264Transform() (*imfTransform, error) {
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
	return transform, nil
}

type h264Encoder struct {
	baseBitRate      int
	keyFrameInterval int
	aqm              *AdaptiveQualityManager
	forceKeyFrame    atomic.Bool
	captureDevice    *iD3D11Device

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
}

type h264Result struct {
	sample media.Sample
	err    error
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

	select {
	case frameQueue <- h264Request{img: img, duration: duration}:
	default:
		// Drop frame if encoder is backed up.
		return media.Sample{}, nil
	}

	select {
	case res := <-resultQueue:
		return res.sample, res.err
	case <-time.After(150 * time.Millisecond):
		return media.Sample{}, errors.New("encoder timeout")
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

	req := h264Request{
		gpuTexture: tex,
		gpuWidth:   frame.GPU.Width,
		gpuHeight:  frame.GPU.Height,
		isGPU:      true,
		duration:   duration,
	}

	select {
	case frameQueue <- req:
	default:
		return media.Sample{}, nil
	}

	select {
	case res := <-resultQueue:
		return res.sample, res.err
	case <-time.After(150 * time.Millisecond):
		return media.Sample{}, errors.New("encoder timeout")
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

	var (
		transform *imfTransform
		inType    *imfMediaType
		outType   *imfMediaType
		inSample  *imfSample
		inBuf     *imfMediaBuffer
		outSample *imfSample
		outBuf    *imfMediaBuffer
		dxgiMgr   *DXGIDeviceManager
		ownedDev  *iD3D11Device
		width     int
		height    int
		bitRate   int
		frameSeq  int
		encodeBuf []byte
	)

	releaseTransformState := func() {
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
		width, height, bitRate, frameSeq = 0, 0, 0, 0
		encodeBuf = nil
	}
	defer func() {
		releaseTransformState()
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

	reinit := func(w, h int, targetBitRate int) error {
		releaseTransformState()

		t, err := coCreateH264Transform()
		if err != nil {
			return err
		}
		transform = t
		if dxgiMgr != nil {
			if err := dxgiMgr.ConfigureTransform(transform); err != nil {
				return err
			}
		}

		it, err := mfCreateMediaType()
		if err != nil {
			return err
		}
		inType = it
		if err := inType.SetGUID(&mfMTMajorType, &mfMediaTypeVideo); err != nil {
			return err
		}
		if err := inType.SetGUID(&mfMTSubtype, &mfVideoNV12); err != nil {
			return err
		}
		if err := mfSetAttributeSize(inType, &mfMTFrameSize, uint32(w), uint32(h)); err != nil {
			return err
		}
		if err := mfSetAttributeRatio(inType, &mfMTFrameRate, 30, 1); err != nil {
			return err
		}
		if err := mfSetAttributeRatio(inType, &mfMTPixelAspect, 1, 1); err != nil {
			return err
		}
		if err := inType.SetUINT32(&mfMTInterlace, mfInterlaceProgress); err != nil {
			return err
		}

		ot, err := mfCreateMediaType()
		if err != nil {
			return err
		}
		outType = ot
		if err := outType.SetGUID(&mfMTMajorType, &mfMediaTypeVideo); err != nil {
			return err
		}
		if err := outType.SetGUID(&mfMTSubtype, &mfVideoH264); err != nil {
			return err
		}
		if err := mfSetAttributeSize(outType, &mfMTFrameSize, uint32(w), uint32(h)); err != nil {
			return err
		}
		if err := mfSetAttributeRatio(outType, &mfMTFrameRate, 30, 1); err != nil {
			return err
		}
		if err := outType.SetUINT32(&mfMTAvgBitrate, uint32(targetBitRate)); err != nil {
			return err
		}
		// Baseline profile: maximizes browser compatibility and disallows B-frames.
		if err := outType.SetUINT32(&mfMTProfile, 66); err != nil {
			return err
		}

		// Validate types first (helps return a clearer HRESULT when unsupported).
		if err := transform.SetInputType(0, inType, mftSetTypeTestOnly); err != nil {
			return err
		}
		if err := transform.SetOutputType(0, outType, mftSetTypeTestOnly); err != nil {
			return err
		}
		if err := transform.SetInputType(0, inType, 0); err != nil {
			return err
		}
		if err := transform.SetOutputType(0, outType, 0); err != nil {
			return err
		}

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

		// Reset and begin streaming.
		_ = transform.ProcessMessage(mftMessageCommandFlush, 0)
		if err := transform.ProcessMessage(mftMessageNotifyBeginStreaming, 0); err != nil {
			return err
		}
		if err := transform.ProcessMessage(mftMessageNotifyStartOfStream, 0); err != nil {
			return err
		}

		width, height, bitRate, frameSeq = w, h, targetBitRate, 0
		return nil
	}

	for req := range e.frameQueue {
		if !req.isGPU && req.img == nil {
			continue
		}
		w := req.gpuWidth
		h := req.gpuHeight
		if !req.isGPU {
			w = req.img.Bounds().Dx()
			h = req.img.Bounds().Dy()
		}
		if w <= 0 || h <= 0 {
			continue
		}
		// NV12 requires even dimensions (4:2:0).
		if w%2 != 0 || h%2 != 0 {
			e.sendResult(h264Result{err: fmt.Errorf("h264 requires even dimensions, got %dx%d", w, h)})
			continue
		}

		targetBitRate := e.baseBitRate
		e.mu.Lock()
		if e.aqm != nil {
			targetBitRate = e.aqm.GetCurrentBitrate()
		}
		e.mu.Unlock()

		if req.isGPU && dxgiMgr == nil {
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
				transform = nil
				width, height, bitRate, frameSeq = 0, 0, 0, 0
			}
		}

		if transform == nil || w != width || h != height || targetBitRate != bitRate {
			if err := reinit(w, h, targetBitRate); err != nil {
				e.sendResult(h264Result{err: err})
				continue
			}
		}

		frameSeq++
		forceKeyframe := e.forceKeyFrame.Swap(false)
		if !forceKeyframe && e.keyFrameInterval > 0 && frameSeq >= e.keyFrameInterval {
			forceKeyframe = true
			frameSeq = 0
		}
		if forceKeyframe && transform != nil {
			_ = transform.ProcessMessage(mftMessageCommandFlush, 0)
			_ = transform.ProcessMessage(mftMessageNotifyBeginStreaming, 0)
			_ = transform.ProcessMessage(mftMessageNotifyStartOfStream, 0)
		}

		if req.isGPU {
			if dxgiMgr == nil {
				e.sendResult(h264Result{err: errors.New("DXGI device manager unavailable")})
				continue
			}
			if req.gpuTexture == nil {
				e.sendResult(h264Result{err: errors.New("nil GPU texture")})
				continue
			}
			sample, err := dxgiMgr.CreateSampleFromTexture(req.gpuTexture)
			if err != nil {
				e.sendResult(h264Result{err: err})
				continue
			}
			if err := transform.ProcessInput(0, sample, 0); err != nil {
				sample.Release()
				e.sendResult(h264Result{err: err})
				continue
			}
			sample.Release()
		} else {
			if err := colorconv.RGBAToNV12(req.img, encodeBuf, w, h); err != nil {
				e.sendResult(h264Result{err: err})
				continue
			}

			ptr, maxLen, _, lockErr := inBuf.Lock()
			if lockErr != nil {
				e.sendResult(h264Result{err: lockErr})
				continue
			}
			if uint32(len(encodeBuf)) > maxLen {
				_ = inBuf.Unlock()
				e.sendResult(h264Result{err: errors.New("input buffer too small")})
				continue
			}
			copy(unsafe.Slice((*byte)(ptr), len(encodeBuf)), encodeBuf)
			_ = inBuf.Unlock()
			_ = inBuf.SetCurrentLength(uint32(len(encodeBuf)))

			if procErr := transform.ProcessInput(0, inSample, 0); procErr != nil {
				e.sendResult(h264Result{err: procErr})
				continue
			}
		}

		var outStatus uint32
		out := mftOutputDataBuffer{StreamID: 0, Sample: outSample}
		outErr := transform.ProcessOutput(0, &out, &outStatus)
		if outErr != nil {
			// Need more input - treat as dropped frame.
			if errno, ok := outErr.(syscall.Errno); ok && uint32(errno) == 0xC00D6D72 {
				e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}})
				continue
			}
			e.sendResult(h264Result{err: outErr})
			continue
		}

		outPtr, _, curLen, err := outBuf.Lock()
		if err != nil {
			e.sendResult(h264Result{err: err})
			continue
		}
		encoded := make([]byte, curLen)
		copy(encoded, unsafe.Slice((*byte)(outPtr), int(curLen)))
		_ = outBuf.Unlock()

		encoded = ensureAnnexB(encoded)
		if e.aqm != nil && e.aqm.ShouldDropFrame(int64(len(encoded))) {
			e.sendResult(h264Result{sample: media.Sample{Duration: req.duration}})
			continue
		}

		e.sendResult(h264Result{sample: media.Sample{Data: encoded, Duration: req.duration}})
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

func ensureAnnexB(buf []byte) []byte {
	if len(buf) >= 4 && buf[0] == 0x00 && buf[1] == 0x00 && (buf[2] == 0x01 || (buf[2] == 0x00 && buf[3] == 0x01)) {
		return buf
	}
	converted, ok := avccToAnnexB(buf)
	if ok {
		return converted
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
