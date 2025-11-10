//go:build windows

package encoder

import (
	"errors"
	"fmt"
	"log"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dxgiErrorNotFound             = 0x887A0002
	d3dDriverTypeUnknown          = 0x0
	d3d11SdkVersion               = 7
	d3d11CreateDeviceVideoSupport = 0x00000200

	vendorNVIDIA = 0x10DE
	vendorAMD    = 0x1002
	vendorIntel  = 0x8086
)

var (
	modDXGI                = windows.NewLazySystemDLL("dxgi.dll")
	procCreateDXGIFactory1 = modDXGI.NewProc("CreateDXGIFactory1")

	modD3D11              = windows.NewLazySystemDLL("d3d11.dll")
	procD3D11CreateDevice = modD3D11.NewProc("D3D11CreateDevice")

	iidIDXGIFactory1 = windows.GUID{Data1: 0x770aae78, Data2: 0xf26f, Data3: 0x4dba, Data4: [8]byte{0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}}
)

type adapterCandidate struct {
	vendorID       uint32
	description    string
	videoSupported bool
}

func detectHardwareEncoders(m *Manager) {
	if m == nil {
		return
	}
	candidates, err := enumerateDXGIAdapters()
	if err != nil {
		log.Printf("encoder: hardware capability detection skipped: %v", err)
		return
	}
	registerHardwareStub(m, "NVENC", "nvenc-h264", "nvenc-hardware", "h264", selectAdapter(candidates, vendorNVIDIA))
	registerHardwareStub(m, "AMF", "amf-h264", "amf-hardware", "h264", selectAdapter(candidates, vendorAMD))
	registerHardwareStub(m, "QSV", "qsv-h264", "qsv-hardware", "h264", selectAdapter(candidates, vendorIntel))
}

func selectAdapter(list []adapterCandidate, vendor uint32) *adapterCandidate {
	for i := range list {
		if list[i].vendorID == vendor {
			return &list[i]
		}
	}
	return nil
}

func registerHardwareStub(m *Manager, label, name, capType, codec string, cand *adapterCandidate) {
	if m == nil || cand == nil {
		return
	}
	desc := fmt.Sprintf("%s hardware encoder (adapter: %s)", label, cand.description)
	reason := fmt.Sprintf("%s bindings not linked in this agent build", label)
	if !cand.videoSupported {
		reason += "; Direct3D 11 video support unavailable"
	}
	m.addCapability(Capability{
		Name:           name,
		Type:           capType,
		Codec:          codec,
		Lossless:       false,
		Hardware:       true,
		Experimental:   true,
		DefaultQuality: 80,
		Description:    desc,
		Disabled:       true,
		DisabledReason: reason,
	})
}

func enumerateDXGIAdapters() ([]adapterCandidate, error) {
	if err := procCreateDXGIFactory1.Find(); err != nil {
		return nil, fmt.Errorf("dxgi: CreateDXGIFactory1 unavailable: %w", err)
	}
	factory, err := createDXGIFactory1()
	if err != nil {
		return nil, err
	}
	defer factory.Release()
	adapters := make([]adapterCandidate, 0, 2)
	for idx := uint32(0); ; idx++ {
		adapter, hr := factory.enumAdapters1(idx)
		if hr == dxgiErrorNotFound {
			break
		}
		if hr != 0 {
			return adapters, hresultError(fmt.Sprintf("IDXGIFactory1::EnumAdapters1(%d)", idx), hr)
		}
		desc, err := adapter.describe()
		if err != nil {
			adapter.Release()
			return adapters, err
		}
		videoSupported := testD3D11VideoSupport(adapter)
		adapters = append(adapters, adapterCandidate{
			vendorID:       desc.VendorID,
			description:    windows.UTF16ToString(desc.Description[:]),
			videoSupported: videoSupported,
		})
		adapter.Release()
	}
	if len(adapters) == 0 {
		return nil, errors.New("dxgi: no adapters detected")
	}
	runtime.KeepAlive(factory)
	return adapters, nil
}

func createDXGIFactory1() (*idxgiFactory1, error) {
	var factory *idxgiFactory1
	hr, _, _ := procCreateDXGIFactory1.Call(
		uintptr(unsafe.Pointer(&iidIDXGIFactory1)),
		uintptr(unsafe.Pointer(&factory)),
	)
	if failedHRESULT(hr) {
		return nil, hresultError("CreateDXGIFactory1", uint32(hr))
	}
	return factory, nil
}

func testD3D11VideoSupport(adapter *idxgiAdapter1) bool {
	if adapter == nil {
		return false
	}
	if err := procD3D11CreateDevice.Find(); err != nil {
		return false
	}
	var device *iUnknown
	var context *iUnknown
	hr, _, _ := procD3D11CreateDevice.Call(
		uintptr(unsafe.Pointer(adapter)),
		uintptr(d3dDriverTypeUnknown),
		0,
		uintptr(d3d11CreateDeviceVideoSupport),
		0,
		0,
		uintptr(d3d11SdkVersion),
		uintptr(unsafe.Pointer(&device)),
		0,
		uintptr(unsafe.Pointer(&context)),
	)
	releaseIUnknown(device)
	releaseIUnknown(context)
	return !failedHRESULT(hr)
}

type idxgiFactory1 struct {
	lpVtbl *idxgiFactory1Vtbl
}

type idxgiFactory1Vtbl struct {
	QueryInterface          uintptr
	AddRef                  uintptr
	Release                 uintptr
	SetPrivateData          uintptr
	SetPrivateDataInterface uintptr
	GetPrivateData          uintptr
	GetParent               uintptr
	EnumAdapters            uintptr
	MakeWindowAssociation   uintptr
	GetWindowAssociation    uintptr
	CreateSwapChain         uintptr
	CreateSoftwareAdapter   uintptr
	EnumAdapters1           uintptr
	IsCurrent               uintptr
}

func (f *idxgiFactory1) enumAdapters1(index uint32) (*idxgiAdapter1, uint32) {
	var adapter *idxgiAdapter1
	hr, _, _ := syscall.Syscall(
		f.lpVtbl.EnumAdapters1,
		3,
		uintptr(unsafe.Pointer(f)),
		uintptr(index),
		uintptr(unsafe.Pointer(&adapter)),
	)
	code := uint32(hr)
	if code == dxgiErrorNotFound {
		return nil, code
	}
	if failedHRESULT(hr) {
		return nil, code
	}
	return adapter, 0
}

func (f *idxgiFactory1) Release() {
	if f == nil || f.lpVtbl == nil {
		return
	}
	syscall.Syscall(f.lpVtbl.Release, 1, uintptr(unsafe.Pointer(f)), 0, 0)
}

type idxgiAdapter1 struct {
	lpVtbl *idxgiAdapter1Vtbl
}

type idxgiAdapter1Vtbl struct {
	QueryInterface          uintptr
	AddRef                  uintptr
	Release                 uintptr
	SetPrivateData          uintptr
	SetPrivateDataInterface uintptr
	GetPrivateData          uintptr
	GetParent               uintptr
	EnumOutputs             uintptr
	GetDesc                 uintptr
	CheckInterfaceSupport   uintptr
	GetDesc1                uintptr
}

func (a *idxgiAdapter1) describe() (dxgiAdapterDesc1, error) {
	var desc dxgiAdapterDesc1
	hr, _, _ := syscall.Syscall(
		a.lpVtbl.GetDesc1,
		2,
		uintptr(unsafe.Pointer(a)),
		uintptr(unsafe.Pointer(&desc)),
		0,
	)
	if failedHRESULT(hr) {
		return dxgiAdapterDesc1{}, hresultError("IDXGIAdapter1::GetDesc1", uint32(hr))
	}
	return desc, nil
}

func (a *idxgiAdapter1) Release() {
	if a == nil || a.lpVtbl == nil {
		return
	}
	syscall.Syscall(a.lpVtbl.Release, 1, uintptr(unsafe.Pointer(a)), 0, 0)
}

type dxgiAdapterDesc1 struct {
	Description           [128]uint16
	VendorID              uint32
	DeviceID              uint32
	SubSysID              uint32
	Revision              uint32
	DedicatedVideoMemory  uint64
	DedicatedSystemMemory uint64
	SharedSystemMemory    uint64
	AdapterLuid           windows.LUID
	Flags                 uint32
}

type iUnknown struct {
	lpVtbl *iUnknownVtbl
}

type iUnknownVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
}

func releaseIUnknown(obj *iUnknown) {
	if obj == nil || obj.lpVtbl == nil {
		return
	}
	syscall.Syscall(obj.lpVtbl.Release, 1, uintptr(unsafe.Pointer(obj)), 0, 0)
}

func failedHRESULT(hr uintptr) bool {
	return int32(hr) < 0
}

func hresultError(op string, hr uint32) error {
	return fmt.Errorf("%s failed (HRESULT=0x%08X)", op, hr)
}
