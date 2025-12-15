//go:build windows

package desktop

import (
	"fmt"
	"unsafe"

	"github.com/kirides/go-d3d/d3d11"
	"github.com/kirides/go-d3d/dxgi"
)

func createD3D11DeviceForAdapter(adapter *dxgi.IDXGIAdapter1) (*d3d11.ID3D11Device, *d3d11.ID3D11DeviceContext, error) {
	featureLevels := []uint32{
		d3dFeatureLevel_11_1,
		d3dFeatureLevel_11_0,
	}

	var selected uint32
	var device *d3d11.ID3D11Device
	var deviceCtx *d3d11.ID3D11DeviceContext

	adapterPtr := uintptr(0)
	driverType := uintptr(d3dDriverTypeHardware)
	if adapter != nil {
		adapterPtr = uintptr(unsafe.Pointer(adapter))
		driverType = uintptr(d3dDriverTypeUnknown)
	}

	flags := uint32(d3d11CreateDeviceBGRA)
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
	return device, deviceCtx, nil
}
