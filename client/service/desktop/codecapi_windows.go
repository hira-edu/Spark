package desktop

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal ICodecAPI wrapper (Windows) for configuring Media Foundation encoders.

var (
	codecapiOnce    sync.Once
	codecapiGUIDErr error

	iidICodecAPI windows.GUID

	codecapiAVEncCommonLowLatency        windows.GUID
	codecapiAVLowLatencyMode             windows.GUID
	codecapiAVEncCommonRealTime          windows.GUID
	codecapiAVEncCommonRateControlMode   windows.GUID
	codecapiAVEncCommonMeanBitRate       windows.GUID
	codecapiAVEncCommonMaxBitRate        windows.GUID
	codecapiAVEncMPVDefaultBPictureCount windows.GUID
	codecapiAVEncMPVGOPSize              windows.GUID
	codecapiAVEncVideoForceKeyFrame      windows.GUID

	// Additional low-latency settings (from libx264/NVENC low-latency presets)
	codecapiAVEncH264CABACEnable     windows.GUID
	codecapiAVEncVideoMaxNumRefFrame windows.GUID
	codecapiAVEncCommonBufferSize    windows.GUID
	codecapiAVEncVideoEncodeQP       windows.GUID
)

func initCodecapiGuids() error {
	codecapiOnce.Do(func() {
		var err error

		iidICodecAPI, err = parseGUID("901db4c7-31ce-41a2-85dc-8fa0bf41b8da") // IID_ICodecAPI
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse IID_ICodecAPI: %w", err)
			return
		}

		codecapiAVEncCommonLowLatency, err = parseGUID("9d3ecd55-89e8-490a-970a-0c9548d5a56e") // CODECAPI_AVEncCommonLowLatency
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncCommonLowLatency: %w", err)
			return
		}
		codecapiAVLowLatencyMode, err = parseGUID("9c27891a-ed7a-40e1-88e8-b22727a024ee") // CODECAPI_AVLowLatencyMode
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVLowLatencyMode: %w", err)
			return
		}
		codecapiAVEncCommonRealTime, err = parseGUID("143a0ff6-a131-43da-b81e-98fbb8ec378e") // CODECAPI_AVEncCommonRealTime
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncCommonRealTime: %w", err)
			return
		}
		codecapiAVEncCommonRateControlMode, err = parseGUID("1c0608e9-370c-4710-8a58-cb6181c42423") // CODECAPI_AVEncCommonRateControlMode
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncCommonRateControlMode: %w", err)
			return
		}
		codecapiAVEncCommonMeanBitRate, err = parseGUID("f7222374-2144-4815-b550-a37f8e12ee52") // CODECAPI_AVEncCommonMeanBitRate
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncCommonMeanBitRate: %w", err)
			return
		}
		codecapiAVEncCommonMaxBitRate, err = parseGUID("9651eae4-39b9-4ebf-85ef-d7f444ec7465") // CODECAPI_AVEncCommonMaxBitRate
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncCommonMaxBitRate: %w", err)
			return
		}
		codecapiAVEncMPVDefaultBPictureCount, err = parseGUID("8d390aac-dc5c-4200-b57f-814d04babab2") // CODECAPI_AVEncMPVDefaultBPictureCount
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncMPVDefaultBPictureCount: %w", err)
			return
		}
		codecapiAVEncMPVGOPSize, err = parseGUID("95f31b26-95a4-41aa-9303-246a7fc6eef1") // CODECAPI_AVEncMPVGOPSize
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncMPVGOPSize: %w", err)
			return
		}
		codecapiAVEncVideoForceKeyFrame, err = parseGUID("398c1b98-8353-475a-9ef2-8f265d260345") // CODECAPI_AVEncVideoForceKeyFrame
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncVideoForceKeyFrame: %w", err)
			return
		}

		// Additional low-latency settings
		codecapiAVEncH264CABACEnable, err = parseGUID("ee6cad62-d305-4248-a50e-e1b255f7caf8") // CODECAPI_AVEncH264CABACEnable
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncH264CABACEnable: %w", err)
			return
		}
		codecapiAVEncVideoMaxNumRefFrame, err = parseGUID("964829ed-94f9-43b4-b74d-ef40944b69a0") // CODECAPI_AVEncVideoMaxNumRefFrame
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncVideoMaxNumRefFrame: %w", err)
			return
		}
		codecapiAVEncCommonBufferSize, err = parseGUID("0db96574-b6a4-4c8b-8106-3773de0310cd") // CODECAPI_AVEncCommonBufferSize
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncCommonBufferSize: %w", err)
			return
		}
		codecapiAVEncVideoEncodeQP, err = parseGUID("2cb5696b-23fb-4ce1-a0f9-ef5b90fd55ca") // CODECAPI_AVEncVideoEncodeQP
		if err != nil {
			codecapiGUIDErr = fmt.Errorf("parse CODECAPI_AVEncVideoEncodeQP: %w", err)
			return
		}
	})
	return codecapiGUIDErr
}

type iCodecAPI struct {
	vtbl *iCodecAPIVtbl
}

type iCodecAPIVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr

	IsSupported        uintptr
	IsModifiable       uintptr
	GetParameterRange  uintptr
	GetParameterValues uintptr
	GetDefaultValue    uintptr
	GetValue           uintptr
	SetValue           uintptr
	RegisterForEvent   uintptr
	UnregisterForEvent uintptr
	SetAllDefaults     uintptr

	SetValueWithNotify       uintptr
	SetAllDefaultsWithNotify uintptr
}

func (c *iCodecAPI) Release() {
	if c == nil || c.vtbl == nil {
		return
	}
	syscall.SyscallN(c.vtbl.Release, uintptr(unsafe.Pointer(c)))
}

func (c *iCodecAPI) SetValue(api *windows.GUID, v *variant) error {
	if c == nil || c.vtbl == nil {
		return fmt.Errorf("nil ICodecAPI")
	}
	r0, _, _ := syscall.SyscallN(
		c.vtbl.SetValue,
		uintptr(unsafe.Pointer(c)),
		uintptr(unsafe.Pointer(api)),
		uintptr(unsafe.Pointer(v)),
	)
	return hresultError(r0, "ICodecAPI.SetValue")
}

// VARIANT helpers (enough for BOOL/UINT32/UINT64).
// Layout is 24 bytes on amd64, matching Windows VARIANT.

type variant struct {
	vt         uint16
	wReserved1 uint16
	wReserved2 uint16
	wReserved3 uint16
	val        uint64
	val2       uint64
}

const (
	variantVTBool = 11 // VT_BOOL
	variantVTUI4  = 19 // VT_UI4
	variantVTUI8  = 21 // VT_UI8
)

func variantBoolValue(b bool) variant {
	var v variant
	v.vt = variantVTBool
	if b {
		// VARIANT_TRUE is -1 (0xFFFF) in a 16-bit field.
		v.val = 0xFFFF
	}
	return v
}

func variantUI4Value(n uint32) variant {
	var v variant
	v.vt = variantVTUI4
	v.val = uint64(n)
	return v
}

func variantUI8Value(n uint64) variant {
	var v variant
	v.vt = variantVTUI8
	v.val = n
	return v
}

func mfTryInitCodecAPI(transform *imfTransform) (*iCodecAPI, error) {
	if transform == nil {
		return nil, fmt.Errorf("nil transform")
	}
	if err := initCodecapiGuids(); err != nil {
		return nil, err
	}
	unk := (*iUnknown)(unsafe.Pointer(transform))
	p, err := unk.QueryInterface(&iidICodecAPI)
	if err != nil {
		return nil, err
	}
	return (*iCodecAPI)(p), nil
}

func mfConfigureCodecAPIForH264(codec *iCodecAPI, bitRate int, gopSize int) {
	if codec == nil {
		return
	}
	// Ultra-low-latency configuration based on proven patterns from:
	// - libx264 zerolatency preset
	// - NVENC low-latency mode
	// - GStreamer/OBS WebRTC implementations
	//
	// Key principles:
	// 1. Disable B-frames (eliminates reordering delay)
	// 2. Use CAVLC instead of CABAC (faster encoding)
	// 3. Minimize reference frames (reduces lookahead)
	// 4. Use CBR for consistent frame sizes (predictable jitter buffer)
	// 5. Enable low-latency mode flags

	// Primary low-latency flags
	_ = codec.SetValue(&codecapiAVEncCommonLowLatency, ptrVariant(variantBoolValue(true)))
	_ = codec.SetValue(&codecapiAVEncCommonRealTime, ptrVariant(variantBoolValue(true)))
	_ = codec.SetValue(&codecapiAVLowLatencyMode, ptrVariant(variantUI4Value(1)))

	// Disable B-frames completely (critical for low latency)
	_ = codec.SetValue(&codecapiAVEncMPVDefaultBPictureCount, ptrVariant(variantUI4Value(0)))

	// Disable CABAC, use CAVLC (faster decoding, lower latency)
	// Note: This reduces compression efficiency by ~10-15% but significantly reduces latency
	_ = codec.SetValue(&codecapiAVEncH264CABACEnable, ptrVariant(variantBoolValue(false)))

	// Minimize reference frames (1 = only previous frame, no multi-frame lookahead)
	_ = codec.SetValue(&codecapiAVEncVideoMaxNumRefFrame, ptrVariant(variantUI4Value(1)))

	// Use CBR for more consistent frame sizes and predictable jitter buffer behavior.
	// eAVEncCommonRateControlMode_CBR = 2 (codecapi.h)
	// Note: LowDelayVBR (4) can cause larger frame size variations that grow jitter buffer.
	_ = codec.SetValue(&codecapiAVEncCommonRateControlMode, ptrVariant(variantUI4Value(2)))

	if bitRate > 0 {
		_ = codec.SetValue(&codecapiAVEncCommonMeanBitRate, ptrVariant(variantUI4Value(uint32(bitRate))))
		_ = codec.SetValue(&codecapiAVEncCommonMaxBitRate, ptrVariant(variantUI4Value(uint32(bitRate))))

		// Set VBV buffer size to 1 frame worth of data for minimal buffering
		// Formula: buffer_size = bitrate / fps (assume 30fps)
		// This forces the encoder to output each frame immediately
		vbvBufferSize := uint32(bitRate / 30)
		if vbvBufferSize < 10000 {
			vbvBufferSize = 10000 // Minimum 10KB
		}
		_ = codec.SetValue(&codecapiAVEncCommonBufferSize, ptrVariant(variantUI4Value(vbvBufferSize)))
	}

	if gopSize > 0 {
		_ = codec.SetValue(&codecapiAVEncMPVGOPSize, ptrVariant(variantUI4Value(uint32(gopSize))))
	}
}

// ptrVariant returns a pointer to a stack-friendly variant value.
func ptrVariant(v variant) *variant { return &v }
