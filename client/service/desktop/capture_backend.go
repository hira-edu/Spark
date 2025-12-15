package desktop

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// CaptureBackendMode represents the configured capture pipeline.
type CaptureBackendMode int32

// Supported capture backends. Additional values can be added as other
// platforms gain preferred GPU capture providers (PipeWire, Quartz, etc).
const (
	CaptureBackendAuto CaptureBackendMode = iota
	CaptureBackendNVFBC
	CaptureBackendSharedSurface
	CaptureBackendDXGI
	CaptureBackendDXGI_NV12 // GPU-native NV12 capture (Windows 10+)
	CaptureBackendGDI
	CaptureBackendPipeWire
	CaptureBackendX11
)

var (
	configCaptureBackend atomic.Int32
	activeBackendName    atomic.Value
	fallbackOverride     atomic.Value // []CaptureBackendMode
	sharedSurfaceFlag    atomic.Bool
	captureConfigEpoch   atomic.Uint64
)

func init() {
	configCaptureBackend.Store(int32(CaptureBackendAuto))
	activeBackendName.Store("unknown")
	fallbackOverride.Store([]CaptureBackendMode(nil))
}

func getConfiguredCaptureBackend() CaptureBackendMode {
	return CaptureBackendMode(configCaptureBackend.Load())
}

func setConfiguredCaptureBackend(mode CaptureBackendMode) CaptureBackendMode {
	return CaptureBackendMode(configCaptureBackend.Swap(int32(mode)))
}

func bumpCaptureConfigEpoch() {
	captureConfigEpoch.Add(1)
}

func getCaptureConfigEpoch() uint64 {
	return captureConfigEpoch.Load()
}

func captureBackendFromString(raw string) (CaptureBackendMode, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.ReplaceAll(value, "_", "")
	value = strings.ReplaceAll(value, "-", "")
	switch value {
	case "", "auto":
		return CaptureBackendAuto, nil
	case "nvfbc":
		return CaptureBackendNVFBC, nil
	case "sharedsurface", "shsurf", "predwm":
		return CaptureBackendSharedSurface, nil
	case "dxginv12", "dxgi nv12", "gpunv12":
		return CaptureBackendDXGI_NV12, nil
	case "dxgi":
		return CaptureBackendDXGI, nil
	case "desktopduplication", "duplication", "dup":
		return CaptureBackendDXGI, nil
	case "gdi":
		return CaptureBackendGDI, nil
	case "pipewire":
		return CaptureBackendPipeWire, nil
	case "x11":
		return CaptureBackendX11, nil
	default:
		return CaptureBackendAuto, fmt.Errorf("capture: unsupported backend %q", raw)
	}
}

func captureBackendName(mode CaptureBackendMode) string {
	switch mode {
	case CaptureBackendNVFBC:
		return "nvfbc"
	case CaptureBackendSharedSurface:
		return "shared_surface"
	case CaptureBackendDXGI:
		return "dxgi"
	case CaptureBackendDXGI_NV12:
		return "dxgi_nv12"
	case CaptureBackendGDI:
		return "gdi"
	case CaptureBackendPipeWire:
		return "pipewire"
	case CaptureBackendX11:
		return "x11"
	default:
		return "auto"
	}
}

func setActiveCaptureBackend(name string) {
	if strings.TrimSpace(name) == "" {
		name = "unknown"
	}
	activeBackendName.Store(strings.ToLower(name))
}

func getActiveCaptureBackend() string {
	if v := activeBackendName.Load(); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "unknown"
}

func enableSharedSurfaceCapture(enabled bool) {
	sharedSurfaceFlag.Store(enabled)
}

func isSharedSurfaceEnabled() bool {
	return sharedSurfaceFlag.Load()
}

func setFallbackOrder(order []CaptureBackendMode) {
	clean := make([]CaptureBackendMode, 0, len(order))
	seen := make(map[CaptureBackendMode]struct{}, len(order))
	for _, mode := range order {
		mode = normalizeBackend(mode)
		if mode == CaptureBackendAuto {
			continue
		}
		if !isBackendSelectable(mode) {
			continue
		}
		if _, exists := seen[mode]; exists {
			continue
		}
		seen[mode] = struct{}{}
		clean = append(clean, mode)
	}
	fallbackOverride.Store(clean)
}

func clearFallbackOrder() {
	fallbackOverride.Store([]CaptureBackendMode(nil))
}

func getFallbackOrder() []CaptureBackendMode {
	if raw := fallbackOverride.Load(); raw != nil {
		if order, ok := raw.([]CaptureBackendMode); ok {
			return order
		}
	}
	return nil
}

func normalizeBackend(mode CaptureBackendMode) CaptureBackendMode {
	switch mode {
	case CaptureBackendNVFBC:
		return CaptureBackendNVFBC
	case CaptureBackendSharedSurface:
		return CaptureBackendSharedSurface
	case CaptureBackendDXGI:
		return CaptureBackendDXGI
	case CaptureBackendDXGI_NV12:
		return CaptureBackendDXGI_NV12
	case CaptureBackendGDI:
		return CaptureBackendGDI
	case CaptureBackendPipeWire:
		return CaptureBackendPipeWire
	case CaptureBackendX11:
		return CaptureBackendX11
	default:
		return CaptureBackendAuto
	}
}

func isBackendSelectable(mode CaptureBackendMode) bool {
	if mode == CaptureBackendSharedSurface {
		return isSharedSurfaceEnabled()
	}
	return true
}
