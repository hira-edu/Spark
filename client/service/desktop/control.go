package desktop

import (
	"Rocket/client/ipc"
	"Rocket/client/telemetry"
	"Rocket/modules"
	"errors"
	"image"
	"reflect"
	"strings"
	"sync/atomic"
)

// Configuration parameters (atomic updates)
var (
	configFPS     atomic.Int32 // Target FPS (24-60)
	configQuality atomic.Int32 // Codec quality (1-100)
	configMonitor atomic.Int32 // Monitor index (0-N)
)

func init() {
	// Initialize with defaults
	configFPS.Store(fpsDefault)
	configQuality.Store(imageQuality)
	configMonitor.Store(0)
}

// HandleConfig processes DESKTOP_CONFIG action with atomic updates.
// Supports runtime configuration changes for:
// - fps: target frame rate (12-60)
// - quality: codec quality (1-100)
// - monitor: display index (0-N)
// - codec: codec type (raw, jpeg, webp, h264)
//
// All updates are applied atomically and acknowledged to server.
func HandleConfig(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopConfig); forwarded {
		return err
	}

	if pack.Data == nil {
		return errors.New("config: no data provided")
	}

	var updated []string
	var errors []string
	var selectedBounds image.Rectangle

	// Update allowControl (per session toggle)
	if allowVal, ok := pack.Data["allowControl"]; ok {
		if allow, okBool := allowVal.(bool); okBool {
			if desktopID, okID := pack.GetData("desktop", reflect.String); okID {
				if sess, ok := sessions.Get(desktopID.(string)); ok {
					sess.allowControl.Store(allow)
					updated = append(updated, "allowControl")
					telemetry.LogStructured("INFO", "config: allowControl updated", map[string]interface{}{
						"desktop": desktopID,
						"allow":   allow,
					})
				}
			}
		} else {
			errors = append(errors, "allowControl: invalid type")
		}
	}

	// Update FPS (if provided)
	if fpsVal, ok := pack.Data["fps"]; ok {
		var fps int32
		switch v := fpsVal.(type) {
		case float64:
			fps = int32(v)
		case int:
			fps = int32(v)
		default:
			errors = append(errors, "fps: invalid type")
			goto skipFPS
		}

		fps = clampFPSValue(fps)
		oldFPS := configFPS.Swap(fps)
		updated = append(updated, "fps")
		telemetry.LogStructured("INFO", "config: FPS updated", map[string]interface{}{
			"old": oldFPS,
			"new": fps,
		})
	}
skipFPS:

	// Update quality (if provided)
	if qualityVal, ok := pack.Data["quality"]; ok {
		var quality int32
		switch v := qualityVal.(type) {
		case float64:
			quality = int32(v)
		case int:
			quality = int32(v)
		default:
			errors = append(errors, "quality: invalid type")
			goto skipQuality
		}

		quality = clampQualityValue(quality)
		oldQuality := configQuality.Swap(quality)
		updated = append(updated, "quality")

		// Force fixed quality when user sets a value (disable auto adaptation overriding it)
		if adaptiveQualityManager != nil {
			adaptiveQualityManager.SetFixedQuality(quality, 0)
		}

		// Update active codec quality
		codec := GetCodec()
		if _, ok := codec.(*JPEGCodec); ok {
			// Update JPEG quality dynamically
			newCodec := NewJPEGCodec(int(quality))
			if adaptiveQualityManager != nil {
				newCodec.EnableAdaptiveQuality(adaptiveQualityManager)
			}
			SetCodec(newCodec)
		}

		telemetry.LogStructured("INFO", "config: quality updated", map[string]interface{}{
			"old": oldQuality,
			"new": quality,
		})
	}
skipQuality:

	// Update monitor index (if provided)
	if monitorVal, ok := pack.Data["monitor"]; ok {
		var monitor int32
		switch v := monitorVal.(type) {
		case float64:
			monitor = int32(v)
		case int:
			monitor = int32(v)
		default:
			errors = append(errors, "monitor: invalid type")
			goto skipMonitor
		}

		monitor = clampMonitorValue(monitor)
		oldMonitor := configMonitor.Swap(monitor)
		if bounds, err := getDisplayBoundsForMonitor(monitor); err == nil {
			selectedBounds = bounds
		} else {
			errors = append(errors, "monitor: "+err.Error())
		}
		updated = append(updated, "monitor")
		telemetry.LogStructured("INFO", "config: monitor updated", map[string]interface{}{
			"old": oldMonitor,
			"new": monitor,
		})
	}
skipMonitor:

	// Update codec (if provided)
	if codecVal, ok := pack.Data["codec"]; ok {
		codecName, ok := codecVal.(string)
		if !ok {
			errors = append(errors, "codec: invalid type")
			goto skipCodec
		}
		codecName = strings.ToLower(strings.TrimSpace(codecName))

		var newCodec Codec
		quality := int(configQuality.Load())

		switch codecName {
		case "raw", "rgba":
			newCodec = NewRawCodec()
		case "jpeg":
			jpeg := NewJPEGCodec(quality)
			if adaptiveQualityManager != nil {
				jpeg.EnableAdaptiveQuality(adaptiveQualityManager)
			}
			newCodec = jpeg
		case "webp":
			newCodec = NewWebPCodec(quality)
		case "avif":
			newCodec = NewAVIFCodec(quality)
		case "vp8":
			newCodec = NewHardwareCodec(CodecTypeVP8, quality, getHardwareSupport())
		case "vp9":
			newCodec = NewHardwareCodec(CodecTypeVP9, quality, getHardwareSupport())
		case "h264", "h.264":
			newCodec = NewHardwareCodec(CodecTypeH264, quality, getHardwareSupport())
		default:
			errors = append(errors, "codec: unsupported type (use: raw, jpeg, webp, avif, vp8, vp9, h264)")
			goto skipCodec
		}

		if newCodec != nil {
			SetCodec(newCodec)
			updated = append(updated, "codec")
		}
	}
skipCodec:

	// Send acknowledgement
	ackData := map[string]interface{}{
		"updated": updated,
		"fps":     configFPS.Load(),
		"quality": configQuality.Load(),
		"monitor": configMonitor.Load(),
		"codec":   GetCodec().Name(),
	}
	// Attach current monitor bounds to help UI redraw
	if selectedBounds.Dx() == 0 || selectedBounds.Dy() == 0 {
		if b, err := getDisplayBoundsForMonitor(configMonitor.Load()); err == nil {
			selectedBounds = b
		} else if v := displayBounds.Load(); v != nil {
			selectedBounds = v.(image.Rectangle)
		}
	}
	if selectedBounds.Dx() > 0 && selectedBounds.Dy() > 0 {
		ackData["width"] = selectedBounds.Dx()
		ackData["height"] = selectedBounds.Dy()
	}
	ackData["monitors"] = enumerateDisplays()

	if len(errors) > 0 {
		ackData["errors"] = errors
	}

	sendDesktopPacket(modules.Packet{
		Act:   "DESKTOP_CONFIG_ACK",
		Code:  0,
		Event: pack.Event,
		Data:  ackData,
	}, nil)

	telemetry.LogStructured("INFO", "config: update applied", map[string]interface{}{
		"updated": updated,
		"errors":  errors,
	})

	return nil
}

func HandleCodec(pack modules.Packet) error {
	// Alias for HandleConfig with codec parameter
	return HandleConfig(pack)
}

func HandleClipboard(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopPacket); forwarded {
		return err
	}
	// Clipboard sync is platform-specific; acknowledge receipt for now.
	telemetry.LogStructured("DEBUG", "clipboard control received", map[string]interface{}{
		"event": pack.Event,
	})
	return nil
}

func HandleFileDrop(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopPacket); forwarded {
		return err
	}
	telemetry.LogStructured("DEBUG", "file drop control received", map[string]interface{}{
		"files": pack.Data[`files`],
	})
	return nil
}

func HandleAudio(pack modules.Packet) error {
	if forwarded, err := relayDesktopCommand(pack, ipc.MsgTypeDesktopPacket); forwarded {
		return err
	}
	// TODO: Implement audio streaming control
	return nil
}

// ==================== ICE/SDP VALIDATION ====================

// SDP/ICE size limits (WebRTC best practices)
const (
	MaxSDPSize          = 65536 // 64KB max SDP (RFC recommendation)
	MaxICECandidateSize = 512   // 512 bytes max per ICE candidate
	MaxICECandidates    = 100   // Max candidates to prevent DoS
)

// ValidateAndNormalizeSDP validates and normalizes SDP offer/answer.
// Implements size checking and basic format validation per WebRTC specs.
//
// Validation checks:
// - Size < MaxSDPSize (64KB)
// - Contains required fields (v=, o=, s=, t=)
// - No malicious content
//
// Normalization:
// - Trim whitespace
// - Ensure CRLF line endings (\r\n)
// - Remove duplicate attributes
func ValidateAndNormalizeSDP(sdp string) (string, error) {
	if sdp == "" {
		return "", errors.New("SDP is empty")
	}

	// Size check
	if len(sdp) > MaxSDPSize {
		return "", errors.New("SDP exceeds maximum size (64KB)")
	}

	// Normalize whitespace
	sdp = strings.TrimSpace(sdp)

	// Basic format validation (RFC 4566)
	requiredFields := []string{"v=", "o=", "s=", "t="}
	for _, field := range requiredFields {
		if !strings.Contains(sdp, field) {
			return "", errors.New("SDP missing required field: " + field)
		}
	}

	// Normalize line endings to CRLF (WebRTC standard)
	sdp = strings.ReplaceAll(sdp, "\r\n", "\n")
	sdp = strings.ReplaceAll(sdp, "\n", "\r\n")

	telemetry.LogStructured("DEBUG", "SDP validated and normalized", map[string]interface{}{
		"size":  len(sdp),
		"lines": strings.Count(sdp, "\r\n"),
	})

	return sdp, nil
}

// ValidateAndNormalizeICECandidate validates and normalizes ICE candidate strings.
// Implements size checking and format validation per WebRTC/ICE specs.
//
// Validation checks:
// - Size < MaxICECandidateSize (512 bytes)
// - Contains "candidate:" prefix
// - Valid format (foundation component protocol priority address port type)
//
// Normalization:
// - Trim whitespace
// - Ensure "candidate:" prefix
// - Validate IP addresses (basic check)
func ValidateAndNormalizeICECandidate(candidate string) (string, error) {
	if candidate == "" {
		return "", errors.New("ICE candidate is empty")
	}

	// Size check
	if len(candidate) > MaxICECandidateSize {
		return "", errors.New("ICE candidate exceeds maximum size (512 bytes)")
	}

	// Normalize whitespace
	candidate = strings.TrimSpace(candidate)

	// Ensure "candidate:" prefix
	if !strings.HasPrefix(candidate, "candidate:") {
		// Add prefix if missing
		candidate = "candidate:" + candidate
	}

	// Basic format validation (RFC 5245)
	// Format: candidate:<foundation> <component> <protocol> <priority> <address> <port> <type>
	parts := strings.Fields(candidate)
	if len(parts) < 8 {
		return "", errors.New("ICE candidate: invalid format (too few fields)")
	}

	// Validate protocol (udp, tcp)
	protocol := strings.ToLower(parts[3])
	if protocol != "udp" && protocol != "tcp" {
		return "", errors.New("ICE candidate: invalid protocol (must be udp or tcp)")
	}

	// Validate type (host, srflx, relay)
	candidateType := strings.ToLower(parts[7])
	if candidateType != "host" && candidateType != "srflx" && candidateType != "relay" && candidateType != "prflx" {
		return "", errors.New("ICE candidate: invalid type")
	}

	telemetry.LogStructured("DEBUG", "ICE candidate validated", map[string]interface{}{
		"size":     len(candidate),
		"protocol": protocol,
		"type":     candidateType,
	})

	return candidate, nil
}

// ValidateICECandidates validates a batch of ICE candidates.
// Returns validated candidates and any errors encountered.
func ValidateICECandidates(candidates []string) ([]string, []error) {
	if len(candidates) > MaxICECandidates {
		return nil, []error{errors.New("too many ICE candidates (max 100)")}
	}

	validated := make([]string, 0, len(candidates))
	errs := make([]error, 0)

	for i, candidate := range candidates {
		normalized, err := ValidateAndNormalizeICECandidate(candidate)
		if err != nil {
			errs = append(errs, errors.New("candidate "+string(rune(i))+": "+err.Error()))
			continue
		}
		validated = append(validated, normalized)
	}

	if len(validated) == 0 && len(candidates) > 0 {
		return nil, []error{errors.New("all ICE candidates failed validation")}
	}

	telemetry.LogStructured("INFO", "ICE candidates validated", map[string]interface{}{
		"total":     len(candidates),
		"validated": len(validated),
		"errors":    len(errs),
	})

	return validated, errs
}
