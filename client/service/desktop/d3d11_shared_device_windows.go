//go:build windows

package desktop

import (
	"sync/atomic"
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
