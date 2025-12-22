//go:build windows

package desktop

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

type nv12Lease struct {
	release func(*iD3D11Texture2D)
	tex     *iD3D11Texture2D
	refs    atomic.Int32
}

var nv12Leases sync.Map // map[uintptr]*nv12Lease

func acquireNV12Lease(releaseFn func(*iD3D11Texture2D), tex *iD3D11Texture2D) func() {
	if releaseFn == nil || tex == nil {
		return func() {}
	}

	key := uintptr(unsafe.Pointer(tex))
	actual, loaded := nv12Leases.LoadOrStore(key, &nv12Lease{
		release: releaseFn,
		tex:     tex,
	})
	lease := actual.(*nv12Lease)
	if !loaded {
		lease.refs.Store(1)
	} else {
		lease.refs.Add(1)
	}

	return func() {
		if lease.refs.Add(-1) != 0 {
			return
		}
		nv12Leases.Delete(key)
		if lease.release != nil {
			lease.release(lease.tex)
		}
	}
}

func retainNV12Lease(tex *iD3D11Texture2D) func() {
	if tex == nil {
		return nil
	}
	key := uintptr(unsafe.Pointer(tex))
	actual, ok := nv12Leases.Load(key)
	if !ok {
		return nil
	}
	lease := actual.(*nv12Lease)
	lease.refs.Add(1)
	return func() {
		if lease.refs.Add(-1) != 0 {
			return
		}
		nv12Leases.Delete(key)
		if lease.release != nil {
			lease.release(lease.tex)
		}
	}
}
