package desktop

import (
	"Rocket/client/config"
	"Rocket/client/telemetry"
)

// ApplyCaptureConfig wires the launcher-provided capture config (mode,
// fallback order, flags) into the desktop worker before any sessions start.
func ApplyCaptureConfig(cfg config.CaptureConfig) {
	desired, err := captureBackendFromString(cfg.Mode)
	if err != nil {
		telemetry.LogStructured("WARN", "capture config: invalid mode, falling back to auto", map[string]interface{}{
			"mode":  cfg.Mode,
			"error": err.Error(),
		})
		desired = CaptureBackendAuto
	}
	prev := setConfiguredCaptureBackend(desired)

	enableSharedSurfaceCapture(cfg.EnablePreDWM)

	if len(cfg.FallbackOrder) > 0 {
		setFallbackOrder(parseFallbackList(cfg.FallbackOrder))
	} else if cfg.EnablePreDWM {
		setFallbackOrder([]CaptureBackendMode{
			CaptureBackendSharedSurface,
			CaptureBackendNVFBC,
			CaptureBackendDXGI,
			CaptureBackendGDI,
		})
	} else {
		setFallbackOrder(nil)
	}

	telemetry.LogStructured("INFO", "capture config applied", map[string]interface{}{
		"requested_mode":    captureBackendName(desired),
		"previous_mode":     captureBackendName(prev),
		"enable_pre_dwm":    cfg.EnablePreDWM,
		"fallback_order":    captureBackendNames(getFallbackOrder()),
		"adapter_luid_hint": cfg.AdapterLUID,
	})
}

func parseFallbackList(raw []string) []CaptureBackendMode {
	out := make([]CaptureBackendMode, 0, len(raw))
	for _, entry := range raw {
		mode, err := captureBackendFromString(entry)
		if err != nil {
			telemetry.LogStructured("WARN", "capture config: invalid fallback entry skipped", map[string]interface{}{
				"value": entry,
				"error": err.Error(),
			})
			continue
		}
		out = append(out, mode)
	}
	return out
}

func captureBackendNames(modes []CaptureBackendMode) []string {
	if len(modes) == 0 {
		return nil
	}
	names := make([]string, 0, len(modes))
	seen := make(map[string]struct{}, len(modes))
	for _, mode := range modes {
		name := captureBackendName(mode)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}
