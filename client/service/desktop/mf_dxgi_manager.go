//go:build windows

package desktop

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/kirides/go-d3d/d3d11"
	"golang.org/x/sys/windows"
)

// MFDXGIDeviceManager wraps IMFDXGIDeviceManager for sharing D3D11 device
// between Desktop Duplication (DXGI) and Media Foundation (H.264 encoder).
//
// **Purpose**: Enable zero-copy GPU texture encoding
// **Performance**: Eliminates 10-15ms CPU download/upload overhead
//
// Architecture:
//   1. Create DXGI Device Manager (IMFDXGIDeviceManager)
//   2. Register D3D11 device with manager
//   3. Configure H.264 encoder to use DXGI manager
//   4. Pass GPU textures directly to encoder (IMFSample with D3D11 texture)
//
// References:
//   - https://docs.microsoft.com/en-us/windows/win32/api/mfobjects/nn-mfobjects-imfdxgidevicemanager
//   - https://docs.microsoft.com/en-us/windows/win32/medfound/supporting-direct3d-11-video-decoding-in-media-foundation

var (
	// DXGI Manager GUIDs
	iidIMFDXGIDeviceManager windows.GUID
	iidIMFDXGIBuffer        windows.GUID

	// Additional MF GUIDs
	mfSampleExtensionDecodeTimestamp windows.GUID

	mfDXGIOnce sync.Once
)

func initMFDXGIGUIDs() {
	mfDXGIOnce.Do(func() {
		iidIMFDXGIDeviceManager, _ = windows.GUIDFromString("{eb533d5d-2db6-40f8-97a9-494692014f07}")
		iidIMFDXGIBuffer, _ = windows.GUIDFromString("{e7174cfa-1c9e-48b1-8866-626226bfc258}")
		mfSampleExtensionDecodeTimestamp, _ = windows.GUIDFromString("{6698b84e-0afa-4330-aeb2-1c0a98d7a44d}")
	})
}

var (
	procMFCreateDXGIDeviceManager = mfplat.NewProc("MFCreateDXGIDeviceManager")
	procMFCreateDXGISurfaceBuffer = mfplat.NewProc("MFCreateDXGISurfaceBuffer")
	mfDXGIManagerInitOnce         sync.Once
	mfDXGIManagerInitErr          error
)

func ensureMFDXGIManager() error {
	mfDXGIManagerInitOnce.Do(func() {
		// MFStartup already called in ensureMediaFoundation()
		initMFDXGIGUIDs()
	})
	return mfDXGIManagerInitErr
}

// DXGIDeviceManager manages D3D11 device sharing for Media Foundation.
type DXGIDeviceManager struct {
	manager      *iMFDXGIDeviceManager
	device       *iD3D11Device
	resetToken   uint32
	mu           sync.Mutex
	refCount     atomic.Int32
	isConfigured atomic.Bool
}

// NewDXGIDeviceManager creates a DXGI device manager for the given D3D11 device.
func NewDXGIDeviceManager(device *iD3D11Device) (*DXGIDeviceManager, error) {
	if err := ensureMFDXGIManager(); err != nil {
		return nil, err
	}

	if device == nil {
		return nil, fmt.Errorf("nil D3D11 device")
	}

	dm := &DXGIDeviceManager{
		device: device,
	}

	if err := dm.initialize(); err != nil {
		dm.Release()
		return nil, err
	}

	return dm, nil
}

// initialize creates the IMFDXGIDeviceManager and registers the D3D11 device.
func (dm *DXGIDeviceManager) initialize() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Create DXGI Device Manager
	var manager *iMFDXGIDeviceManager
	var resetToken uint32

	r0, _, _ := procMFCreateDXGIDeviceManager.Call(
		uintptr(unsafe.Pointer(&resetToken)),
		uintptr(unsafe.Pointer(&manager)),
	)
	if err := hresultError(r0, "MFCreateDXGIDeviceManager"); err != nil {
		return err
	}

	dm.manager = manager
	dm.resetToken = resetToken

	// Register D3D11 device with manager
	r0, _, _ = syscall.SyscallN(
		dm.manager.vtbl.ResetDevice,
		uintptr(unsafe.Pointer(dm.manager)),
		uintptr(unsafe.Pointer(dm.device)),
		uintptr(resetToken),
	)
	if err := hresultError(r0, "IMFDXGIDeviceManager::ResetDevice"); err != nil {
		return err
	}

	dm.isConfigured.Store(true)
	dm.refCount.Store(1)

	return nil
}

// GetManager returns the IMFDXGIDeviceManager (for configuring MFT).
func (dm *DXGIDeviceManager) GetManager() *iMFDXGIDeviceManager {
	if dm == nil {
		return nil
	}
	return dm.manager
}

// LockDevice locks the device for exclusive access.
// Returns device handle and unlock function.
func (dm *DXGIDeviceManager) LockDevice() (uintptr, func(), error) {
	if dm == nil || dm.manager == nil {
		return 0, nil, fmt.Errorf("manager not initialized")
	}

	var deviceHandle uintptr
	r0, _, _ := syscall.SyscallN(
		dm.manager.vtbl.LockDevice,
		uintptr(unsafe.Pointer(dm.manager)),
		uintptr(unsafe.Pointer(&deviceHandle)),
		0, // fBlock (FALSE = don't block)
	)
	if err := hresultError(r0, "LockDevice"); err != nil {
		return 0, nil, err
	}

	unlock := func() {
		syscall.SyscallN(
			dm.manager.vtbl.UnlockDevice,
			uintptr(unsafe.Pointer(dm.manager)),
			deviceHandle,
			0, // fSaveState (FALSE)
		)
	}

	return deviceHandle, unlock, nil
}

// CreateSampleFromTexture creates an IMFSample backed by a D3D11 texture.
//
// **This is the key function for zero-copy encoding**:
//   - Wraps NV12 GPU texture in IMFSample
//   - No CPU download/upload
//   - Direct GPU → Encoder path
func (dm *DXGIDeviceManager) CreateSampleFromTexture(texture *iD3D11Texture2D) (*imfSample, error) {
	if dm == nil || dm.manager == nil {
		return nil, fmt.Errorf("manager not initialized")
	}

	if texture == nil {
		return nil, fmt.Errorf("nil texture")
	}

	// Create MF sample
	sample, err := mfCreateSample()
	if err != nil {
		return nil, err
	}

	// Create MF DXGI surface buffer from texture (zero-copy).
	// HRESULT MFCreateDXGISurfaceBuffer(REFIID riid, IUnknown *pSurface, UINT uSubresourceIndex,
	//                                  BOOL fBottomUpWhenLinear, IMFMediaBuffer **ppBuffer)
	var buf *imfMediaBuffer
	r0, _, _ := procMFCreateDXGISurfaceBuffer.Call(
		uintptr(unsafe.Pointer(&d3d11.IID_ID3D11Texture2D)),
		uintptr(unsafe.Pointer(texture)),
		0, // subresource
		0, // bottom-up
		uintptr(unsafe.Pointer(&buf)),
	)
	if err := hresultError(r0, "MFCreateDXGISurfaceBuffer"); err != nil {
		sample.Release()
		return nil, err
	}

	// Add buffer to sample
	if err := sample.AddBuffer(buf); err != nil {
		buf.Release()
		sample.Release()
		return nil, err
	}

	// Buffer is now owned by sample, release our reference
	buf.Release()

	return sample, nil
}

const mftMessageSetD3DManager = 0x0000000F

// ConfigureTransform configures an MFT (Media Foundation Transform) to use this DXGI manager.
func (dm *DXGIDeviceManager) ConfigureTransform(transform *imfTransform) error {
	if dm == nil || dm.manager == nil {
		return fmt.Errorf("manager not initialized")
	}

	if transform == nil {
		return fmt.Errorf("nil transform")
	}

	// Get IMFAttributes from transform
	var attributes *iMFAttributes
	r0, _, _ := syscall.SyscallN(
		transform.vtbl.GetAttributes,
		uintptr(unsafe.Pointer(transform)),
		uintptr(unsafe.Pointer(&attributes)),
	)
	if err := hresultError(r0, "GetAttributes"); err != nil {
		return err
	}
	defer attributes.Release()

	// Set MF_SA_D3D11_AWARE attribute
	guidD3D11Aware, _ := windows.GUIDFromString("{206b4fc8-fcf9-4c51-afe3-9764369e33a0}")
	r0, _, _ = syscall.SyscallN(
		attributes.vtbl.SetUINT32,
		uintptr(unsafe.Pointer(attributes)),
		uintptr(unsafe.Pointer(&guidD3D11Aware)),
		1, // TRUE
	)
	if err := hresultError(r0, "SetUINT32(MF_SA_D3D11_AWARE)"); err != nil {
		return err
	}

	// Attach DXGI manager (required for D3D11-backed IMFSamples).
	if err := transform.ProcessMessage(mftMessageSetD3DManager, uintptr(unsafe.Pointer(dm.manager))); err != nil {
		return err
	}

	return nil
}

// Release releases the DXGI device manager.
func (dm *DXGIDeviceManager) Release() {
	if dm == nil {
		return
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.manager != nil {
		dm.manager.Release()
		dm.manager = nil
	}

	dm.isConfigured.Store(false)
}

// COM interface definitions

type iMFDXGIDeviceManager struct {
	vtbl *iMFDXGIDeviceManagerVtbl
}

type iMFDXGIDeviceManagerVtbl struct {
	QueryInterface    uintptr
	AddRef            uintptr
	Release           uintptr
	CloseDeviceHandle uintptr
	GetVideoService   uintptr
	LockDevice        uintptr
	OpenDeviceHandle  uintptr
	ResetDevice       uintptr
	TestDevice        uintptr
	UnlockDevice      uintptr
}

func (m *iMFDXGIDeviceManager) Release() {
	if m == nil || m.vtbl == nil {
		return
	}
	syscall.SyscallN(m.vtbl.Release, uintptr(unsafe.Pointer(m)))
}

type iMFDXGIBuffer struct {
	vtbl *iMFDXGIBufferVtbl
}

type iMFDXGIBufferVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	Lock                uintptr
	Unlock              uintptr
	GetCurrentLength    uintptr
	SetCurrentLength    uintptr
	GetMaxLength        uintptr
	GetResource         uintptr
	GetSubresourceIndex uintptr
	GetUnknown          uintptr
	SetUnknown          uintptr
}

func (b *iMFDXGIBuffer) Release() {
	if b == nil || b.vtbl == nil {
		return
	}
	syscall.SyscallN(b.vtbl.Release, uintptr(unsafe.Pointer(b)))
}

type iMFAttributes struct {
	vtbl *iMFAttributesVtbl
}

type iMFAttributesVtbl struct {
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
}

func (a *iMFAttributes) Release() {
	if a == nil || a.vtbl == nil {
		return
	}
	syscall.SyscallN(a.vtbl.Release, uintptr(unsafe.Pointer(a)))
}

type iDXGISurface struct {
	vtbl *iDXGISurfaceVtbl
}

type iDXGISurfaceVtbl struct {
	QueryInterface          uintptr
	AddRef                  uintptr
	Release                 uintptr
	SetPrivateData          uintptr
	SetPrivateDataInterface uintptr
	GetPrivateData          uintptr
	GetParent               uintptr
	GetDevice               uintptr
	GetDesc                 uintptr
	Map                     uintptr
	Unmap                   uintptr
}

func (s *iDXGISurface) Release() {
	if s == nil || s.vtbl == nil {
		return
	}
	syscall.SyscallN(s.vtbl.Release, uintptr(unsafe.Pointer(s)))
}

func (s *iDXGISurface) QueryInterface(iid *windows.GUID) (unsafe.Pointer, error) {
	var result unsafe.Pointer
	r0, _, _ := syscall.SyscallN(
		s.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(s)),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&result)),
	)
	if err := hresultError(r0, "QueryInterface"); err != nil {
		return nil, err
	}
	return result, nil
}

// QueryInterface for iD3D11Texture2D (needed for surface conversion)
func (t *iD3D11Texture2D) QueryInterface(iid *windows.GUID) (unsafe.Pointer, error) {
	var result unsafe.Pointer
	r0, _, _ := syscall.SyscallN(
		t.vtbl.QueryInterface,
		uintptr(unsafe.Pointer(t)),
		uintptr(unsafe.Pointer(iid)),
		uintptr(unsafe.Pointer(&result)),
	)
	if err := hresultError(r0, "QueryInterface"); err != nil {
		return nil, err
	}
	return result, nil
}

// Extended imfTransform vtbl (add GetAttributes)
type imfTransformVtblExtended struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr

	GetStreamLimits           uintptr
	GetStreamCount            uintptr
	GetStreamIDs              uintptr
	GetInputStreamInfo        uintptr
	GetOutputStreamInfo       uintptr
	GetAttributes             uintptr // ← We need this!
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
