package encoder

import (
	"errors"
	"fmt"
	"image"
	"os"
	"strings"
	"sync"
)

// Capability describes an encoder/transport combination the agent can expose.
type Capability struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Codec          string `json:"codec,omitempty"`
	Lossless       bool   `json:"lossless"`
	Hardware       bool   `json:"hardware"`
	MaxWidth       int    `json:"maxWidth,omitempty"`
	MaxHeight      int    `json:"maxHeight,omitempty"`
	Description    string `json:"description,omitempty"`
	Experimental   bool   `json:"experimental,omitempty"`
	DefaultQuality int    `json:"defaultQuality,omitempty"`
	Disabled       bool   `json:"disabled,omitempty"`
	DisabledReason string `json:"disabledReason,omitempty"`
}

// Manager reports encoder capabilities. Today it only returns software JPEG,
// but the abstraction lets us plug in NVENC/AMF/QSV later.
type Manager struct {
	caps            []Capability
	encoders        map[string]blockEncoder
	defaultEncoder  blockEncoder
	defaultEncoderN string
	videoFactories  map[string]VideoFactory
	preferredVideo  string
}

// Request describes a block encode request.
type Request struct {
	Rect    image.Rectangle
	Frame   *image.RGBA
	Quality int
	Encoder string
}

type blockEncoder interface {
	Name() string
	Capability() Capability
	Encode(req Request) ([]byte, error)
}

var (
	managerOnce sync.Once
	managerInst *Manager

	errNoDefaultEncoder = errors.New("encoder: no default encoder available")
)

func (m *Manager) registerEncoder(enc blockEncoder, preferred bool) {
	if enc == nil {
		return
	}
	if m.encoders == nil {
		m.encoders = make(map[string]blockEncoder)
	}
	m.encoders[enc.Name()] = enc
	m.addCapability(enc.Capability())
	if preferred || m.defaultEncoder == nil {
		m.defaultEncoder = enc
		m.defaultEncoderN = enc.Name()
	}
}

func (m *Manager) addCapability(cap Capability) {
	if m == nil || cap.Name == "" {
		return
	}
	m.caps = append(m.caps, cap)
}

func (m *Manager) registerVideoFactory(factory VideoFactory, preferred bool) {
	if m == nil || factory == nil {
		return
	}
	cap := factory.Capability()
	if cap.Name == "" {
		return
	}
	if m.videoFactories == nil {
		m.videoFactories = make(map[string]VideoFactory)
	}
	m.videoFactories[cap.Name] = factory
	m.addCapability(cap)
	if preferred || m.preferredVideo == "" {
		m.preferredVideo = cap.Name
	}
}

// Instance returns the singleton encoder manager.
func Instance() *Manager {
	managerOnce.Do(func() {
		managerInst = &Manager{}
		managerInst.registerEncoder(newSoftwareJPEGEncoder(), true)
		registerMediaFoundationEncoder(managerInst)
		detectHardwareEncoders(managerInst)
		if enableExperimentalH264() {
			managerInst.caps = append(managerInst.caps, Capability{
				Name:         "h264-experimental",
				Type:         "software-h264",
				Codec:        "h264",
				Lossless:     false,
				Hardware:     false,
				Experimental: true,
				Description:  "Placeholder H.264 path (WebRTC beta)",
			})
		}
	})
	return managerInst
}

// Capabilities returns the list of encoders known to the manager.
func (m *Manager) Capabilities() []Capability {
	if m == nil {
		return nil
	}
	out := make([]Capability, len(m.caps))
	copy(out, m.caps)
	return out
}

// Encode encodes the requested region using the selected encoder.
func (m *Manager) Encode(req Request) ([]byte, error) {
	if m == nil {
		return nil, errNoDefaultEncoder
	}
	target := req.Encoder
	enc := m.defaultEncoder
	if target != "" {
		var ok bool
		enc, ok = m.encoders[target]
		if !ok {
			return nil, fmt.Errorf("encoder: %s not registered", target)
		}
	}
	if enc == nil {
		return nil, errNoDefaultEncoder
	}
	return enc.Encode(req)
}

// OpenVideoEncoder instantiates a video encoder by name using the provided config.
func (m *Manager) OpenVideoEncoder(name string, cfg VideoConfig) (VideoInstance, error) {
	if m == nil {
		return nil, fmt.Errorf("encoder: manager unavailable")
	}
	target := name
	if target == "" {
		target = cfg.Name
	}
	if target == "" {
		return nil, fmt.Errorf("encoder: video encoder name required")
	}
	factory, ok := m.videoFactories[target]
	if !ok {
		return nil, fmt.Errorf("encoder: video encoder %s not registered", target)
	}
	return factory.Open(cfg)
}

func (m *Manager) preferredVideoEncoder() string {
	if m == nil {
		return defaultVideoEncoderName
	}
	if m.preferredVideo != "" {
		return m.preferredVideo
	}
	return defaultVideoEncoderName
}

func enableExperimentalH264() bool {
	return strings.EqualFold(os.Getenv("SPARK_EXPERIMENTAL_WEBRTC_ENCODERS"), "1")
}
