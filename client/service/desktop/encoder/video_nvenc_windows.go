//go:build windows

package encoder

import "fmt"

type nvencFactory struct {
	description string
	base        VideoFactory
}

func newNVENCFactory(description string) VideoFactory {
	return &nvencFactory{
		description: description,
		base:        &mfH264Factory{},
	}
}

func (f *nvencFactory) Capability() Capability {
	desc := f.description
	if desc == "" {
		desc = "NVIDIA adapter"
	}
	return Capability{
		Name:         "nvenc-h264",
		Type:         "nvenc-hardware",
		Codec:        "h264",
		Hardware:     true,
		Experimental: true,
		Description:  fmt.Sprintf("NVENC H.264 encoder (%s)", desc),
	}
}

func (f *nvencFactory) Open(cfg VideoConfig) (VideoInstance, error) {
	if f == nil || f.base == nil {
		return nil, fmt.Errorf("nvenc: factory unavailable")
	}
	return f.base.Open(cfg)
}

func registerNVENCFactory(m *Manager, adapter *adapterCandidate) {
	if m == nil || adapter == nil {
		return
	}
	factory := newNVENCFactory(adapter.description)
	m.registerVideoFactory(factory, true)
}
