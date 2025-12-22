//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/pion/webrtc/v4/pkg/media"
	"golang.org/x/sys/windows"
)

// NVENC API version - Video Codec SDK 12.x
const (
	nvencAPIVersion       = 12 | (2 << 24) // NVENCAPI_VERSION = NVENCAPI_MAJOR_VERSION | (NVENCAPI_MINOR_VERSION << 24)
	nvencStructVersion    = 12 | (2 << 24)
	nvencFuncListVersion  = nvencStructVersion | (2 << 16)
	nvencOpenSessionVer   = nvencStructVersion | (1 << 16)
	nvencInitParamsVer    = nvencStructVersion | (6 << 16)
	nvencPicParamsVer     = nvencStructVersion | (6 << 16)
	nvencRegResVer        = nvencStructVersion | (4 << 16)
	nvencMapResVer        = nvencStructVersion | (1 << 16)
	nvencLockBitstreamVer = nvencStructVersion | (2 << 16)
	nvencCreateBufVer     = nvencStructVersion | (1 << 16)
	nvencPresetConfigVer  = nvencStructVersion | (4 << 16)
	nvencConfigVer        = nvencStructVersion | (8 << 16)
	nvencReconfigVer      = nvencStructVersion | (1 << 16)
)

// NVENC GUIDs
var (
	nvencCodecH264GUID = windows.GUID{
		Data1: 0x6bc82762,
		Data2: 0x4e63,
		Data3: 0x4ca4,
		Data4: [8]byte{0xaa, 0x85, 0x1e, 0x50, 0xf3, 0x21, 0xf6, 0xbf},
	}

	// P4 preset - balanced quality/performance for low latency
	nvencPresetP4GUID = windows.GUID{
		Data1: 0xfc0a8d3e,
		Data2: 0x45f8,
		Data3: 0x4cf8,
		Data4: [8]byte{0x80, 0xc7, 0x29, 0x88, 0x71, 0x59, 0x0e, 0xbf},
	}

	// Low latency high quality preset
	nvencPresetLowLatencyHQ = windows.GUID{
		Data1: 0x67082a44,
		Data2: 0x4bad,
		Data3: 0x48fa,
		Data4: [8]byte{0x98, 0xea, 0x93, 0x05, 0x6d, 0x15, 0x0a, 0x58},
	}

	// H.264 profile GUIDs
	nvencH264ProfileBaseline = windows.GUID{
		Data1: 0x0727bcaa,
		Data2: 0x78c4,
		Data3: 0x4c83,
		Data4: [8]byte{0x8c, 0x2f, 0xef, 0x3d, 0xff, 0x26, 0x7c, 0x6a},
	}

	nvencH264ProfileMain = windows.GUID{
		Data1: 0x60b5c1d4,
		Data2: 0x67fe,
		Data3: 0x4790,
		Data4: [8]byte{0x94, 0xd5, 0xc4, 0x72, 0x6d, 0x7b, 0x6e, 0x6d},
	}

	nvencH264ProfileHigh = windows.GUID{
		Data1: 0xe7cbc309,
		Data2: 0x4f7a,
		Data3: 0x4b89,
		Data4: [8]byte{0xaf, 0x13, 0xa0, 0xcd, 0x29, 0x6a, 0x1c, 0xd2},
	}

	nvencH264ProfileConstrainedHigh = windows.GUID{
		Data1: 0x7b39ad49,
		Data2: 0xcb6e,
		Data3: 0x4b6b,
		Data4: [8]byte{0xbc, 0x96, 0x57, 0x1a, 0xfe, 0x44, 0x60, 0x85},
	}
)

// NVENC constants
const (
	nvencDeviceTypeDirectX = 1

	nvencInputResourceTypeDirectX = 0

	nvencBufferFormatNV12      = 1
	nvencBufferFormatARGB      = 0x22
	nvencBufferFormatABGR10    = 0x23
	nvencBufferFormatARGB10    = 0x24
	nvencBufferFormatUndefined = 0xFF

	nvencPicStructFrame = 1

	nvencPicTypeP      = 0
	nvencPicTypeB      = 1
	nvencPicTypeI      = 2
	nvencPicTypeIDR    = 3
	nvencPicTypeBI     = 4
	nvencPicTypeSkip   = 5
	nvencPicTypeIntraR = 6

	nvencTuningInfoUltraLowLatency = 3
	nvencTuningInfoLowLatency      = 2

	nvencRCModeConstQP = 0
	nvencRCModeCBR     = 2
	nvencRCModeVBR     = 1

	nvencH264FMODisable   = 0
	nvencH264EntropyCabac = 1
	nvencH264EntropyCavlc = 2

	nvencMVPrecisionDefault    = 0
	nvencMVPrecisionFullPel    = 1
	nvencMVPrecisionHalfPel    = 2
	nvencMVPrecisionQuarterPel = 3

	nvencLevelAutoselect = 0
	nvencLevel31         = 31
	nvencLevel40         = 40
	nvencLevel41         = 41
	nvencLevel42         = 42
	nvencLevel50         = 50
	nvencLevel51         = 51
	nvencLevel52         = 52

	nvencPicFlagForceIDR   = 0x00000001
	nvencPicFlagForceIntra = 0x00000002
	nvencPicFlagOutputSPS  = 0x00000004

	nvencBufferUsageInputImage = 0

	// Error codes
	nvencSuccess              = 0
	nvencErrNoEncodeDevice    = 1
	nvencErrUnsupportedDevice = 2
	nvencErrInvalidEncoderDev = 3
	nvencErrInvalidDevice     = 4
	nvencErrDeviceNotExist    = 5
	nvencErrInvalidPtr        = 6
	nvencErrInvalidEvent      = 7
	nvencErrInvalidParam      = 8
	nvencErrInvalidCall       = 9
	nvencErrOutOfMemory       = 10
	nvencErrEncoderNotInit    = 11
	nvencErrUnsupportedParam  = 12
	nvencErrLockBusy          = 13
	nvencErrNotEnoughBuffer   = 14
	nvencErrInvalidVersion    = 15
	nvencErrMapFailed         = 16
	nvencErrNeedMoreInput     = 17
	nvencErrEncoderBusy       = 18
	nvencErrEventNotReg       = 19
	nvencErrGeneric           = 20
	nvencErrIncompPatches     = 21
	nvencErrNeedMoreOutput    = 22
)

// NVENC structures

type nvencOpenEncodeSessionExParams struct {
	version    uint32
	deviceType uint32
	device     uintptr
	reserved   uintptr
	apiVersion uint32
	reserved1  [253]uint32
	reserved2  [64]uintptr
}

type nvencInitializeParams struct {
	version               uint32
	encodeGUID            windows.GUID
	presetGUID            windows.GUID
	encodeWidth           uint32
	encodeHeight          uint32
	darWidth              uint32
	darHeight             uint32
	frameRateNum          uint32
	frameRateDen          uint32
	enableEncodeAsync     uint32
	enablePTD             uint32
	reportSliceOffsets    uint32
	enableSubFrameWrite   uint32
	enableExternalMEHints uint32
	enableMEOnlyMode      uint32
	enableWeightedPred    uint32
	enableOutputInVidmem  uint32
	reservedBitFields     uint32
	privDataSize          uint32
	privData              uintptr
	encodeConfig          uintptr
	maxEncodeWidth        uint32
	maxEncodeHeight       uint32
	maxMEHintCountsPerBlk [2]uint32
	tuningInfo            uint32
	bufferFormat          uint32
	reserved              [285]uint32
	reserved2             [64]uintptr
}

type nvencConfig struct {
	version           uint32
	profileGUID       windows.GUID
	gopLength         uint32
	frameIntervalP    int32
	monoChromeEnc     uint32
	frameFieldMode    uint32
	mvPrecision       uint32
	rcParams          nvencRCParams
	encodeCodecConfig nvencCodecConfig
	reserved          [278]uint32
	reserved2         [64]uintptr
}

type nvencRCParams struct {
	version                uint32
	rateControlMode        uint32
	constQP                nvencQP
	averageBitRate         uint32
	maxBitRate             uint32
	vbvBufferSize          uint32
	vbvInitialDelay        uint32
	enableMinQP            uint32
	enableMaxQP            uint32
	enableInitialRCQP      uint32
	enableAQ               uint32
	enableLookahead        uint32
	disableIadapt          uint32
	disableBadapt          uint32
	enableTemporalAQ       uint32
	zeroReorderDelay       uint32
	enableNonRefP          uint32
	strictGOPTarget        uint32
	aqStrength             uint32
	minQP                  nvencQP
	maxQP                  nvencQP
	initialRCQP            nvencQP
	temporalLayerQP        [8]uint32
	targetQuality          uint8
	targetQualityLSB       uint8
	lookaheadDepth         uint16
	lowDelayKeyFrameScale  uint8
	reserved1              [3]uint8
	qpMapMode              uint32
	multiPass              uint32
	alphaLayerBitrateRatio uint32
	cbQPIndexOffset        int32
	crQPIndexOffset        int32
	reserved               [13]uint32
}

type nvencQP struct {
	qpInterP uint32
	qpInterB uint32
	qpIntra  uint32
}

type nvencCodecConfig struct {
	h264Config nvencH264Config
}

type nvencH264Config struct {
	enableStereoMVC             uint32
	hierarchicalPFrames         uint32
	hierarchicalBFrames         uint32
	outputBufferingPeriodSEI    uint32
	outputPictureTimingSEI      uint32
	outputAUD                   uint32
	disableSPSPPS               uint32
	outputFramePackingSEI       uint32
	outputRecoveryPointSEI      uint32
	enableIntraRefresh          uint32
	enableConstrainedEncoding   uint32
	repeatSPSPPS                uint32
	enableVFR                   uint32
	enableLTR                   uint32
	qpPrimeYZeroTransformBypass uint32
	useConstrainedIntraPred     uint32
	enableFillerDataInsertion   uint32
	disableSVCPrefixNalu        uint32
	enableScalabilityInfoSEI    uint32
	singleSliceIntraRefresh     uint32
	maxDecFrameBuffering        uint32
	twoPassRC                   uint32
	strictRCTargetPct           uint32
	reserved                    uint32
	level                       uint32
	idrPeriod                   uint32
	separateColourPlaneFlag     uint32
	chromaFormatIDC             uint32
	maxNumRefFrames             uint32
	useBFramesAsRef             uint32
	numRefL0                    uint32
	numRefL1                    uint32
	sliceMode                   uint32
	sliceModeData               uint32
	h264VUIParameters           nvencH264VUIParams
	ltrNumFrames                uint32
	ltrTrustMode                uint32
	chromaSampleLocationFlag    uint32
	chromaSampleLocationTop     uint32
	chromaSampleLocationBot     uint32
	bitstreamRestrictionFlag    uint32
	entropyCodingMode           uint32
	sliceModeDataUpdate         uint32
	fmoMode                     uint32
	intraRefreshPeriod          uint32
	intraRefreshCnt             uint32
	numTemporalLayers           uint32
	svcTemporalConfig           [8]nvencH264SVCConfig
	reserved2                   [227]uint32
	reserved3                   [64]uintptr
}

type nvencH264VUIParams struct {
	overscanInfoPresentFlag      uint32
	overscanAppropriateFlag      uint32
	videoSignalTypePresentFlag   uint32
	videoFormat                  uint32
	videoFullRangeFlag           uint32
	colourDescriptionPresentFlag uint32
	colourPrimaries              uint32
	transferCharacteristics      uint32
	colourMatrix                 uint32
	chromaSampleLocationFlag     uint32
	chromaSampleLocationTop      uint32
	chromaSampleLocationBot      uint32
	bitstreamRestrictionFlag     uint32
	reserved                     [15]uint32
}

type nvencH264SVCConfig struct {
	numTemporalLayers uint32
	basePriorityID    uint32
	reserved          [254]uint32
}

type nvencPresetConfig struct {
	version   uint32
	presetCfg nvencConfig
	reserved  [255]uint32
	reserved2 [64]uintptr
}

type nvencRegisterResource struct {
	version            uint32
	resourceType       uint32
	width              uint32
	height             uint32
	pitch              uint32
	subResourceIndex   uint32
	resourceToRegister uintptr
	registeredResource uintptr
	bufferFormat       uint32
	bufferUsage        uint32
	pInputFencePoint   uintptr
	pOutputFencePoint  uintptr
	reserved           [247]uint32
	reserved2          [62]uintptr
}

type nvencMapInputResource struct {
	version          uint32
	subResourceIndex uint32
	inputResource    uintptr
	mappedResource   uintptr
	mappedBufferFmt  uint32
	reserved         [251]uint32
	reserved2        [63]uintptr
}

type nvencCreateBitstreamBuffer struct {
	version            uint32
	size               uint32
	memoryHeap         uint32
	reserved           uint32
	bitstreamBuffer    uintptr
	bitstreamBufferPtr uintptr
	reserved2          [58]uint32
	reserved3          [64]uintptr
}

type nvencLockBitstream struct {
	version               uint32
	doNotWait             uint32
	ltrFrame              uint32
	reservedBitFields     uint32
	outputBitstream       uintptr
	sliceOffsets          uintptr
	frameIdx              uint32
	hwEncodeStatus        uint32
	numSlices             uint32
	bitstreamSizeInBytes  uint32
	outputTimeStamp       uint64
	outputDuration        uint64
	bitstreamBufferPtr    uintptr
	pictureType           uint32
	pictureStruct         uint32
	frameAvgQP            uint32
	frameSatd             uint32
	ltrFrameIdx           uint32
	ltrFrameBitmap        uint32
	temporalId            uint32
	intraMBCount          uint32
	interMBCount          uint32
	averageMVX            int32
	averageMVY            int32
	alphaLayerSizeInBytes uint32
	reserved              [218]uint32
	reserved2             [64]uintptr
}

type nvencPicParams struct {
	version              uint32
	inputWidth           uint32
	inputHeight          uint32
	inputPitch           uint32
	encodePicFlags       uint32
	frameIdx             uint32
	inputTimeStamp       uint64
	inputDuration        uint64
	inputBuffer          uintptr
	outputBitstream      uintptr
	completionEvent      uintptr
	bufferFmt            uint32
	pictureStruct        uint32
	pictureType          uint32
	codecPicParams       nvencCodecPicParams
	meHintCountsPerBlock [2]uint32
	meExternalHints      uintptr
	reserved             [286]uint32
	reserved2            [60]uintptr
}

type nvencCodecPicParams struct {
	h264PicParams nvencH264PicParams
}

type nvencH264PicParams struct {
	displayPOCSyntax              uint32
	reserved1                     uint32
	refPicFlag                    uint32
	colourPlaneId                 uint32
	forceIntraRefreshWithFrameCnt uint32
	constrainedFrame              uint32
	sliceModeDataUpdate           uint32
	ltrMarkFrame                  uint32
	ltrUseFrames                  uint32
	ltrUseBitmap                  uint32
	ltrMarkFrameIdx               uint32
	ltrUseFrameBitmap             uint32
	ltrReserved                   uint32
	sliceTypeData                 uintptr
	sliceTypeArrayCnt             uint32
	seiPayloadArrayCnt            uint32
	seiPayloadArray               uintptr
	extPicParams                  uintptr
	reserved2                     [232]uint32
	reserved3                     [62]uintptr
}

// NVENC function list
type nvencFunctions struct {
	version                        uint32
	reserved                       uint32
	nvEncOpenEncodeSession         uintptr
	nvEncGetEncodeGUIDCount        uintptr
	nvEncGetEncodeGUIDs            uintptr
	nvEncGetEncodeProfileGUIDCount uintptr
	nvEncGetEncodeProfileGUIDs     uintptr
	nvEncGetInputFormatCount       uintptr
	nvEncGetInputFormats           uintptr
	nvEncGetEncodeCaps             uintptr
	nvEncGetEncodePresetCount      uintptr
	nvEncGetEncodePresetGUIDs      uintptr
	nvEncGetEncodePresetConfig     uintptr
	nvEncGetEncodePresetConfigEx   uintptr
	nvEncInitializeEncoder         uintptr
	nvEncCreateInputBuffer         uintptr
	nvEncDestroyInputBuffer        uintptr
	nvEncCreateBitstreamBuffer     uintptr
	nvEncDestroyBitstreamBuffer    uintptr
	nvEncEncodePicture             uintptr
	nvEncLockBitstream             uintptr
	nvEncUnlockBitstream           uintptr
	nvEncLockInputBuffer           uintptr
	nvEncUnlockInputBuffer         uintptr
	nvEncGetEncodeStats            uintptr
	nvEncGetSequenceParams         uintptr
	nvEncRegisterAsyncEvent        uintptr
	nvEncUnregisterAsyncEvent      uintptr
	nvEncMapInputResource          uintptr
	nvEncUnmapInputResource        uintptr
	nvEncDestroyEncoder            uintptr
	nvEncInvalidateRefFrames       uintptr
	nvEncOpenEncodeSessionEx       uintptr
	nvEncRegisterResource          uintptr
	nvEncUnregisterResource        uintptr
	nvEncReconfigureEncoder        uintptr
	reserved1                      uintptr
	nvEncCreateMVBuffer            uintptr
	nvEncDestroyMVBuffer           uintptr
	nvEncRunMotionEstimationOnly   uintptr
	nvEncGetLastErrorString        uintptr
	nvEncSetIOCudaStreams          uintptr
	nvEncGetEncodePresetConfigEx2  uintptr
	nvEncGetSequenceParamEx        uintptr
	nvEncLookaheadPicture          uintptr
	reserved2                      [277]uintptr
}

var (
	nvencDLL        *windows.LazyDLL
	nvencCreateInst *windows.LazyProc
	nvencLoadOnce   sync.Once
	nvencLoadErr    error
)

func loadNVENC() error {
	nvencLoadOnce.Do(func() {
		nvencDLL = windows.NewLazySystemDLL("nvEncodeAPI64.dll")
		if err := nvencDLL.Load(); err != nil {
			nvencLoadErr = fmt.Errorf("failed to load nvEncodeAPI64.dll: %w (NVIDIA driver may not be installed)", err)
			return
		}
		nvencCreateInst = nvencDLL.NewProc("NvEncodeAPICreateInstance")
		if err := nvencCreateInst.Find(); err != nil {
			nvencLoadErr = fmt.Errorf("failed to find NvEncodeAPICreateInstance: %w", err)
			return
		}
	})
	return nvencLoadErr
}

// NVENCEncoder implements WebRTCEncoder using NVIDIA NVENC hardware encoder.
type NVENCEncoder struct {
	funcs           *nvencFunctions
	encoder         uintptr
	device          *iD3D11Device
	bitstreamBuffer uintptr
	outputBufSize   uint32

	width              int
	height             int
	bitRate            int
	keyFrameInterval   int
	frameCounter       uint64
	forceKeyFrame      atomic.Bool
	profileGUID        windows.GUID
	h264EntropyMode    uint32
	h264Constrained    uint32
	h264Level          uint32
	expectedProfile    uint8
	expectedConstraint uint8
	expectedLevel      uint8
	profileChecked     bool
	profileMismatch    error

	// Registered input resources (texture -> handle)
	registeredInputs sync.Map // map[uintptr]uintptr

	mu     sync.Mutex
	closed bool
}

// NewNVENCEncoder creates a new NVENC hardware encoder.
func NewNVENCEncoder(cfg WebRTCEncoderConfig) (*NVENCEncoder, error) {
	if err := loadNVENC(); err != nil {
		return nil, err
	}

	bitRate := cfg.BitRate
	if bitRate <= 0 {
		bitRate = 2_000_000 // 2 Mbps default
	}

	keyFrameInterval := cfg.KeyFrameInterval
	if keyFrameInterval <= 0 {
		keyFrameInterval = 60 // Keyframe every 60 frames (2 seconds at 30fps)
	}

	profileGUID, entropyMode, constrained := selectNVENCProfile(cfg)
	level := selectNVENCLevel(cfg.H264LevelID)

	enc := &NVENCEncoder{
		bitRate:            bitRate,
		keyFrameInterval:   keyFrameInterval,
		profileGUID:        profileGUID,
		h264EntropyMode:    entropyMode,
		h264Constrained:    constrained,
		h264Level:          level,
		expectedProfile:    cfg.H264ProfileID,
		expectedConstraint: cfg.H264Constraint,
		expectedLevel:      cfg.H264LevelID,
	}

	return enc, nil
}

// initEncoder initializes the NVENC encoder with the given D3D11 device.
func (e *NVENCEncoder) initEncoder(device *iD3D11Device, width, height int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return errors.New("encoder closed")
	}

	if e.encoder != 0 {
		// Already initialized with same dimensions
		if e.width == width && e.height == height && e.device == device {
			return nil
		}
		// Need to reinitialize with new dimensions/device
		e.resetEncoderLocked()
	}

	if device == nil {
		return errors.New("nil D3D11 device")
	}
	device.AddRef()
	e.device = device
	e.width = width
	e.height = height
	e.frameCounter = 0
	e.profileChecked = false
	e.profileMismatch = nil

	// Get function list
	funcs := &nvencFunctions{
		version: nvencFuncListVersion,
	}

	r0, _, _ := nvencCreateInst.Call(uintptr(unsafe.Pointer(funcs)))
	if r0 != nvencSuccess {
		e.device.Release()
		e.device = nil
		return fmt.Errorf("NvEncodeAPICreateInstance failed: %d", r0)
	}
	e.funcs = funcs

	// Open encode session with D3D11 device
	sessionParams := nvencOpenEncodeSessionExParams{
		version:    nvencOpenSessionVer,
		deviceType: nvencDeviceTypeDirectX,
		device:     uintptr(unsafe.Pointer(device)),
		apiVersion: nvencAPIVersion,
	}

	r0, _, _ = syscall.SyscallN(
		funcs.nvEncOpenEncodeSessionEx,
		uintptr(unsafe.Pointer(&sessionParams)),
		uintptr(unsafe.Pointer(&e.encoder)),
	)
	if r0 != nvencSuccess {
		e.device.Release()
		e.device = nil
		return fmt.Errorf("nvEncOpenEncodeSessionEx failed: %s", nvencErrorString(int(r0)))
	}

	encConfig, presetGUID, tuningInfo, err := e.getPresetConfig()
	if err != nil {
		e.resetEncoderLocked()
		return err
	}

	// Configure encoder
	encConfig.gopLength = uint32(e.keyFrameInterval)
	encConfig.frameIntervalP = 1 // No B-frames for low latency
	encConfig.rcParams.rateControlMode = nvencRCModeCBR
	encConfig.rcParams.averageBitRate = uint32(e.bitRate)
	encConfig.rcParams.maxBitRate = uint32(e.bitRate)
	encConfig.rcParams.vbvBufferSize = uint32(e.bitRate) // 1 second buffer
	encConfig.rcParams.vbvInitialDelay = uint32(e.bitRate) / 2

	// H.264 specific config - Constrained Baseline for WebRTC compatibility
	encConfig.profileGUID = e.profileGUID
	h264Cfg := &encConfig.encodeCodecConfig.h264Config
	h264Cfg.level = e.h264Level
	h264Cfg.chromaFormatIDC = 1 // YUV 4:2:0
	h264Cfg.idrPeriod = uint32(e.keyFrameInterval)
	h264Cfg.repeatSPSPPS = 1 // Include SPS/PPS with each IDR
	h264Cfg.sliceMode = 0    // Single slice
	h264Cfg.sliceModeData = 0
	h264Cfg.entropyCodingMode = e.h264EntropyMode
	h264Cfg.enableConstrainedEncoding = e.h264Constrained
	h264Cfg.maxNumRefFrames = 1 // Low latency

	// Initialize encoder
	initParams := nvencInitializeParams{
		version:         nvencInitParamsVer,
		encodeGUID:      nvencCodecH264GUID,
		presetGUID:      presetGUID,
		encodeWidth:     uint32(width),
		encodeHeight:    uint32(height),
		darWidth:        uint32(width),
		darHeight:       uint32(height),
		frameRateNum:    30,
		frameRateDen:    1,
		enablePTD:       1, // Picture type decision
		tuningInfo:      tuningInfo,
		bufferFormat:    nvencBufferFormatNV12,
		encodeConfig:    uintptr(unsafe.Pointer(&encConfig)),
		maxEncodeWidth:  uint32(width),
		maxEncodeHeight: uint32(height),
	}

	r0, _, _ = syscall.SyscallN(
		funcs.nvEncInitializeEncoder,
		e.encoder,
		uintptr(unsafe.Pointer(&initParams)),
	)
	if r0 != nvencSuccess {
		e.resetEncoderLocked()
		return fmt.Errorf("nvEncInitializeEncoder failed: %s", nvencErrorString(int(r0)))
	}

	// Create output bitstream buffer
	e.outputBufSize = calcNVENCBitstreamBufferSize(width, height)
	createBuf := nvencCreateBitstreamBuffer{
		version: nvencCreateBufVer,
		size:    e.outputBufSize,
	}

	r0, _, _ = syscall.SyscallN(
		funcs.nvEncCreateBitstreamBuffer,
		e.encoder,
		uintptr(unsafe.Pointer(&createBuf)),
	)
	if r0 != nvencSuccess {
		e.resetEncoderLocked()
		return fmt.Errorf("nvEncCreateBitstreamBuffer failed: %s", nvencErrorString(int(r0)))
	}
	e.bitstreamBuffer = createBuf.bitstreamBuffer

	return nil
}

type nvencPresetCandidate struct {
	preset windows.GUID
	tuning uint32
}

func (e *NVENCEncoder) getPresetConfig() (nvencConfig, windows.GUID, uint32, error) {
	if e == nil || e.funcs == nil {
		return nvencConfig{}, windows.GUID{}, 0, errors.New("nvenc functions unavailable")
	}

	candidates := []nvencPresetCandidate{
		{preset: nvencPresetP4GUID, tuning: nvencTuningInfoLowLatency},
		{preset: nvencPresetLowLatencyHQ, tuning: nvencTuningInfoLowLatency},
		{preset: nvencPresetP4GUID, tuning: nvencTuningInfoUltraLowLatency},
		{preset: nvencPresetLowLatencyHQ, tuning: nvencTuningInfoUltraLowLatency},
	}

	var lastErr error
	if e.funcs.nvEncGetEncodePresetConfigEx != 0 {
		for _, candidate := range candidates {
			presetCfg := nvencPresetConfig{version: nvencPresetConfigVer}
			presetCfg.presetCfg.version = nvencConfigVer
			r0, _, _ := syscall.SyscallN(
				e.funcs.nvEncGetEncodePresetConfigEx,
				e.encoder,
				uintptr(unsafe.Pointer(&nvencCodecH264GUID)),
				uintptr(unsafe.Pointer(&candidate.preset)),
				uintptr(candidate.tuning),
				uintptr(unsafe.Pointer(&presetCfg)),
			)
			if r0 == nvencSuccess {
				return presetCfg.presetCfg, candidate.preset, candidate.tuning, nil
			}
			lastErr = fmt.Errorf("nvEncGetEncodePresetConfigEx failed: %s", nvencErrorString(int(r0)))
		}
	}

	if e.funcs.nvEncGetEncodePresetConfig != 0 {
		presets := []windows.GUID{nvencPresetP4GUID, nvencPresetLowLatencyHQ}
		for _, preset := range presets {
			presetCfg := nvencPresetConfig{version: nvencPresetConfigVer}
			presetCfg.presetCfg.version = nvencConfigVer
			r0, _, _ := syscall.SyscallN(
				e.funcs.nvEncGetEncodePresetConfig,
				e.encoder,
				uintptr(unsafe.Pointer(&nvencCodecH264GUID)),
				uintptr(unsafe.Pointer(&preset)),
				uintptr(unsafe.Pointer(&presetCfg)),
			)
			if r0 == nvencSuccess {
				return presetCfg.presetCfg, preset, 0, nil
			}
			lastErr = fmt.Errorf("nvEncGetEncodePresetConfig failed: %s", nvencErrorString(int(r0)))
		}
	}

	if lastErr == nil {
		lastErr = errors.New("nvenc preset config unavailable")
	}
	return nvencConfig{}, windows.GUID{}, 0, lastErr
}

// EncodeGPU encodes a GPU texture (NV12 format) directly without CPU copy.
func (e *NVENCEncoder) EncodeGPU(texture *iD3D11Texture2D, device *iD3D11Device, width, height int, duration time.Duration) (media.Sample, error) {
	if err := e.initEncoder(device, width, height); err != nil {
		return media.Sample{}, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return media.Sample{}, errors.New("encoder closed")
	}
	if e.profileMismatch != nil {
		return media.Sample{}, e.profileMismatch
	}
	if duration <= 0 {
		duration = time.Second / 30
	}

	texPtr := uintptr(unsafe.Pointer(texture))

	// Register texture if not already registered
	var regResource uintptr
	if cached, ok := e.registeredInputs.Load(texPtr); ok {
		regResource = cached.(uintptr)
	} else {
		regRes := nvencRegisterResource{
			version:            nvencRegResVer,
			resourceType:       nvencInputResourceTypeDirectX,
			width:              uint32(width),
			height:             uint32(height),
			pitch:              0, // Auto
			resourceToRegister: texPtr,
			bufferFormat:       nvencBufferFormatNV12,
			bufferUsage:        nvencBufferUsageInputImage,
		}

		r0, _, _ := syscall.SyscallN(
			e.funcs.nvEncRegisterResource,
			e.encoder,
			uintptr(unsafe.Pointer(&regRes)),
		)
		if r0 != nvencSuccess {
			return media.Sample{}, fmt.Errorf("nvEncRegisterResource failed: %s", nvencErrorString(int(r0)))
		}
		regResource = regRes.registeredResource
		e.registeredInputs.Store(texPtr, regResource)
	}

	// Map input resource
	mapRes := nvencMapInputResource{
		version:       nvencMapResVer,
		inputResource: regResource,
	}

	r0, _, _ := syscall.SyscallN(
		e.funcs.nvEncMapInputResource,
		e.encoder,
		uintptr(unsafe.Pointer(&mapRes)),
	)
	if r0 != nvencSuccess {
		return media.Sample{}, fmt.Errorf("nvEncMapInputResource failed: %s", nvencErrorString(int(r0)))
	}

	defer func() {
		syscall.SyscallN(
			e.funcs.nvEncUnmapInputResource,
			e.encoder,
			mapRes.mappedResource,
		)
	}()

	// Encode frame
	e.frameCounter++
	forceIDR := e.forceKeyFrame.Swap(false) || e.frameCounter == 1

	picParams := nvencPicParams{
		version:         nvencPicParamsVer,
		inputWidth:      uint32(width),
		inputHeight:     uint32(height),
		inputPitch:      0,
		inputBuffer:     mapRes.mappedResource,
		outputBitstream: e.bitstreamBuffer,
		bufferFmt:       mapRes.mappedBufferFmt,
		pictureStruct:   nvencPicStructFrame,
		pictureType:     nvencPicTypeP,
		frameIdx:        uint32(e.frameCounter),
		inputTimeStamp:  uint64(time.Now().UnixNano()),
		inputDuration:   uint64(duration.Nanoseconds()),
	}

	if forceIDR || (e.frameCounter%uint64(e.keyFrameInterval)) == 0 {
		picParams.pictureType = nvencPicTypeIDR
		picParams.encodePicFlags = nvencPicFlagForceIDR | nvencPicFlagOutputSPS
	}

	r0, _, _ = syscall.SyscallN(
		e.funcs.nvEncEncodePicture,
		e.encoder,
		uintptr(unsafe.Pointer(&picParams)),
	)
	if r0 == nvencErrNeedMoreInput {
		return media.Sample{Duration: duration}, nil
	}
	if r0 == nvencErrEncoderBusy {
		return media.Sample{}, ErrWebRTCEncoderTimeout
	}
	if r0 == nvencErrNeedMoreOutput {
		return media.Sample{}, ErrWebRTCEncoderTimeout
	}
	if r0 != nvencSuccess {
		return media.Sample{}, fmt.Errorf("nvEncEncodePicture failed: %s", nvencErrorString(int(r0)))
	}

	// Lock and retrieve bitstream
	lockBs := nvencLockBitstream{
		version:         nvencLockBitstreamVer,
		doNotWait:       1,
		outputBitstream: e.bitstreamBuffer,
	}

	r0, _, _ = syscall.SyscallN(
		e.funcs.nvEncLockBitstream,
		e.encoder,
		uintptr(unsafe.Pointer(&lockBs)),
	)
	if r0 == nvencErrLockBusy || r0 == nvencErrNeedMoreOutput {
		return media.Sample{}, ErrWebRTCEncoderTimeout
	}
	if r0 != nvencSuccess {
		return media.Sample{}, fmt.Errorf("nvEncLockBitstream failed: %s", nvencErrorString(int(r0)))
	}

	// Copy bitstream to Go slice
	if lockBs.bitstreamSizeInBytes == 0 {
		syscall.SyscallN(
			e.funcs.nvEncUnlockBitstream,
			e.encoder,
			e.bitstreamBuffer,
		)
		return media.Sample{Duration: duration}, nil
	}
	data := make([]byte, lockBs.bitstreamSizeInBytes)
	copy(data, unsafe.Slice((*byte)(unsafe.Pointer(lockBs.bitstreamBufferPtr)), lockBs.bitstreamSizeInBytes))

	// Unlock bitstream
	syscall.SyscallN(
		e.funcs.nvEncUnlockBitstream,
		e.encoder,
		e.bitstreamBuffer,
	)

	data = ensureAnnexB(data)
	if e.expectedProfile != 0 && !e.profileChecked {
		if prof, constraint, level, ok := extractH264Profile(data); ok {
			e.profileChecked = true
			mismatch := false
			if prof != e.expectedProfile {
				mismatch = true
			}
			if e.expectedConstraint != 0 && constraint != e.expectedConstraint {
				mismatch = true
			}
			if e.expectedLevel != 0 && level != e.expectedLevel {
				mismatch = true
			}
			if mismatch {
				e.profileMismatch = fmt.Errorf("h264 profile mismatch: negotiated %02x%02x (level %02x) got %02x%02x (level %02x)",
					e.expectedProfile, e.expectedConstraint, e.expectedLevel, prof, constraint, level)
				return media.Sample{}, e.profileMismatch
			}
		}
	}

	return media.Sample{
		Data:     data,
		Duration: duration,
	}, nil
}

// Encode implements WebRTCEncoder for CPU RGBA frames.
// This converts RGBA to NV12 and encodes - less efficient than EncodeGPU.
func (e *NVENCEncoder) Encode(img *image.RGBA, duration time.Duration) (media.Sample, error) {
	// For CPU frames, we need to create a staging texture and upload
	// This is a fallback path - prefer EncodeGPU with DXGI capture
	return media.Sample{}, errors.New("NVENC encoder requires GPU frames; use EncodeGPU with DXGI capture")
}

// EncodeFrame implements the frameEncoder interface for GPU frame encoding.
// This is the primary path for DXGI NV12 capture to NVENC encoding.
func (e *NVENCEncoder) EncodeFrame(frame *CaptureFrame, duration time.Duration) (media.Sample, error) {
	if frame == nil {
		return media.Sample{}, errors.New("nil frame")
	}

	gpu := frame.GPU
	if gpu == nil {
		return media.Sample{}, errors.New("NVENC encoder requires GPU frames (dxgi_nv12)")
	}

	if gpu.Backend != "dxgi_nv12" {
		return media.Sample{}, fmt.Errorf("NVENC encoder requires dxgi_nv12 backend, got %s", gpu.Backend)
	}

	// Extract D3D11 texture from GPUFrame
	texture, ok := gpu.Resource.(*iD3D11Texture2D)
	if !ok || texture == nil {
		return media.Sample{}, errors.New("failed to get D3D11 texture from GPU frame")
	}

	// Get shared D3D11 device
	device := getCaptureD3D11Device()
	if device == nil {
		return media.Sample{}, errors.New("no D3D11 device available")
	}
	defer device.Release()

	return e.EncodeGPU(texture, device, gpu.Width, gpu.Height, duration)
}

// ForceKeyFrame requests the next frame be encoded as a keyframe.
func (e *NVENCEncoder) ForceKeyFrame() {
	e.forceKeyFrame.Store(true)
}

// RequestKeyFrame implements the keyFrameRequester interface.
func (e *NVENCEncoder) RequestKeyFrame() {
	e.forceKeyFrame.Store(true)
}

// Close releases all NVENC resources.
func (e *NVENCEncoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closeInternal()
}

func (e *NVENCEncoder) closeInternal() error {
	if e.closed {
		return nil
	}
	e.closed = true
	e.resetEncoderLocked()
	return nil
}

func (e *NVENCEncoder) destroyEncoder() {
	if e.encoder != 0 && e.funcs != nil {
		syscall.SyscallN(e.funcs.nvEncDestroyEncoder, e.encoder)
		e.encoder = 0
	}
}

func (e *NVENCEncoder) resetEncoderLocked() {
	e.unregisterInputsLocked()
	if e.bitstreamBuffer != 0 && e.funcs != nil && e.encoder != 0 {
		syscall.SyscallN(
			e.funcs.nvEncDestroyBitstreamBuffer,
			e.encoder,
			e.bitstreamBuffer,
		)
		e.bitstreamBuffer = 0
	}
	e.destroyEncoder()
	if e.device != nil {
		e.device.Release()
		e.device = nil
	}
	e.funcs = nil
	e.width = 0
	e.height = 0
	e.frameCounter = 0
	e.profileChecked = false
	e.profileMismatch = nil
}

func (e *NVENCEncoder) unregisterInputsLocked() {
	e.registeredInputs.Range(func(key, value interface{}) bool {
		regRes := value.(uintptr)
		if e.funcs != nil && e.encoder != 0 {
			syscall.SyscallN(
				e.funcs.nvEncUnregisterResource,
				e.encoder,
				regRes,
			)
		}
		e.registeredInputs.Delete(key)
		return true
	})
}

func selectNVENCProfile(cfg WebRTCEncoderConfig) (windows.GUID, uint32, uint32) {
	profile := nvencH264ProfileBaseline
	entropy := uint32(nvencH264EntropyCavlc)
	constrained := uint32(0)
	switch cfg.H264ProfileID {
	case 0x4d:
		profile = nvencH264ProfileMain
		entropy = nvencH264EntropyCabac
	case 0x64:
		if cfg.H264Constraint == 0xE0 {
			profile = nvencH264ProfileConstrainedHigh
		} else {
			profile = nvencH264ProfileHigh
		}
		entropy = nvencH264EntropyCabac
	case 0x42:
		if cfg.H264Constraint == 0xE0 {
			constrained = 1
		}
	}
	return profile, entropy, constrained
}

func selectNVENCLevel(levelID uint8) uint32 {
	switch levelID {
	case 0x1f:
		return nvencLevel31
	case 0x28:
		return nvencLevel40
	case 0x29:
		return nvencLevel41
	case 0x2a:
		return nvencLevel42
	case 0x32:
		return nvencLevel50
	case 0x33:
		return nvencLevel51
	case 0x34:
		return nvencLevel52
	case 0:
		return nvencLevelAutoselect
	default:
		return nvencLevelAutoselect
	}
}

func calcNVENCBitstreamBufferSize(width, height int) uint32 {
	if width <= 0 || height <= 0 {
		return 0
	}
	size := uint64(width) * uint64(height) * 4
	if size > uint64(^uint32(0)) {
		return 0
	}
	return uint32(size)
}

func nvencErrorString(code int) string {
	switch code {
	case nvencSuccess:
		return "success"
	case nvencErrNoEncodeDevice:
		return "no encode device"
	case nvencErrUnsupportedDevice:
		return "unsupported device"
	case nvencErrInvalidEncoderDev:
		return "invalid encoder device"
	case nvencErrInvalidDevice:
		return "invalid device"
	case nvencErrDeviceNotExist:
		return "device not exist"
	case nvencErrInvalidPtr:
		return "invalid pointer"
	case nvencErrInvalidEvent:
		return "invalid event"
	case nvencErrInvalidParam:
		return "invalid parameter"
	case nvencErrInvalidCall:
		return "invalid call"
	case nvencErrOutOfMemory:
		return "out of memory"
	case nvencErrEncoderNotInit:
		return "encoder not initialized"
	case nvencErrUnsupportedParam:
		return "unsupported parameter"
	case nvencErrLockBusy:
		return "lock busy"
	case nvencErrNotEnoughBuffer:
		return "not enough buffer"
	case nvencErrInvalidVersion:
		return "invalid version"
	case nvencErrMapFailed:
		return "map failed"
	case nvencErrNeedMoreInput:
		return "need more input"
	case nvencErrEncoderBusy:
		return "encoder busy"
	case nvencErrEventNotReg:
		return "event not registered"
	case nvencErrGeneric:
		return "generic error"
	case nvencErrIncompPatches:
		return "incompatible patches"
	case nvencErrNeedMoreOutput:
		return "need more output"
	default:
		return fmt.Sprintf("unknown error (%d)", code)
	}
}

func ensureAnnexB(buf []byte) []byte {
	if len(buf) < 4 {
		return buf
	}
	for i := 0; i+3 < len(buf); i++ {
		if buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x01 {
			return buf
		}
		if buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x01 {
			return buf
		}
	}
	// Assume length-prefixed (AVCC) and convert to Annex B.
	out := make([]byte, 0, len(buf)+16)
	for i := 0; i+4 <= len(buf); {
		nalLen := int(uint32(buf[i])<<24 | uint32(buf[i+1])<<16 | uint32(buf[i+2])<<8 | uint32(buf[i+3]))
		i += 4
		if nalLen <= 0 || i+nalLen > len(buf) {
			break
		}
		out = append(out, 0x00, 0x00, 0x00, 0x01)
		out = append(out, buf[i:i+nalLen]...)
		i += nalLen
	}
	if len(out) == 0 {
		return buf
	}
	return out
}

func extractH264Profile(buf []byte) (byte, byte, byte, bool) {
	for i := 0; i+4 < len(buf); i++ {
		start := -1
		if buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x01 {
			start = i + 3
		} else if buf[i] == 0x00 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0x01 {
			start = i + 4
		}
		if start < 0 || start+3 >= len(buf) {
			continue
		}
		nalType := buf[start] & 0x1F
		if nalType != 7 {
			continue
		}
		profileIDC := buf[start+1]
		constraintFlags := buf[start+2]
		levelIDC := buf[start+3]
		return profileIDC, constraintFlags, levelIDC, true
	}
	return 0, 0, 0, false
}
