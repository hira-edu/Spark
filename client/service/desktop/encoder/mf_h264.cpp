#include "mf_h264.h"

#include <Mfapi.h>
#include <Mferror.h>
#include <Mfidl.h>
#include <Mfobjects.h>
#include <Mftransform.h>
#include <combaseapi.h>
#include <algorithm>
#include <cstring>
#include <mutex>
#include <new>
#include <vector>
#include <wrl/client.h>
#include <wmcodecdsp.h>
#include <wmcodecdspuuid.h>

using Microsoft::WRL::ComPtr;

namespace {

inline uint8_t ClampToByte(int value) {
	if (value < 0) {
		return 0;
	}
	if (value > 255) {
		return 255;
	}
	return static_cast<uint8_t>(value);
}

void RGBAtoNV12(const uint8_t* src, int stride, int width, int height, std::vector<uint8_t>& dest) {
	const size_t ySize = static_cast<size_t>(width) * height;
	const int uvWidthPairs = (width + 1) / 2;
	const int uvHeight = (height + 1) / 2;
	const size_t uvSize = static_cast<size_t>(uvWidthPairs) * uvHeight * 2;
	dest.resize(ySize + uvSize);
	uint8_t* yPlane = dest.data();
	uint8_t* uvPlane = dest.data() + ySize;
	const int uvStride = uvWidthPairs * 2;

	for (int y = 0; y < height; ++y) {
		const uint8_t* row = src + y * stride;
		uint8_t* yRow = yPlane + y * width;
		for (int x = 0; x < width; ++x) {
			const uint8_t r = row[x * 4 + 0];
			const uint8_t g = row[x * 4 + 1];
			const uint8_t b = row[x * 4 + 2];
			const int yVal = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
			yRow[x] = ClampToByte(yVal);
		}
	}

	for (int y = 0; y < height; y += 2) {
		const uint8_t* row0 = src + y * stride;
		const uint8_t* row1 = (y + 1 < height) ? (src + (y + 1) * stride) : row0;
		uint8_t* uvRow = uvPlane + (y / 2) * uvStride;
		for (int x = 0; x < width; x += 2) {
			const int blockWidth = std::min(2, width - x);
			const int blockHeight = std::min(2, height - y);
			int sumU = 0;
			int sumV = 0;
			for (int dy = 0; dy < blockHeight; ++dy) {
				const uint8_t* row = (dy == 0) ? row0 : row1;
				for (int dx = 0; dx < blockWidth; ++dx) {
					const uint8_t r = row[(x + dx) * 4 + 0];
					const uint8_t g = row[(x + dx) * 4 + 1];
					const uint8_t b = row[(x + dx) * 4 + 2];
					const int uVal = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
					const int vVal = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
					sumU += uVal;
					sumV += vVal;
				}
			}
			const int samples = blockWidth * blockHeight;
			const uint8_t uByte = ClampToByte(sumU / samples);
			const uint8_t vByte = ClampToByte(sumV / samples);
			const int uvIndex = (x / 2) * 2;
			uvRow[uvIndex] = uByte;
			uvRow[uvIndex + 1] = vByte;
		}
	}
}

HRESULT EnsureMFInitialized() {
	static std::once_flag once;
	static HRESULT initResult = S_OK;
	std::call_once(once, []() {
		HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
			initResult = hr;
			return;
		}
		initResult = MFStartup(MF_VERSION, MFSTARTUP_FULL);
	});
	return initResult;
}

class SparkMFEncoderImpl {
   public:
	HRESULT Initialize(int width, int height, int fps, int bitrate) {
		const HRESULT initHr = EnsureMFInitialized();
		if (FAILED(initHr)) {
			return initHr;
		}
		width_ = width;
		height_ = height;
		frameDuration_ = (fps > 0) ? (10'000'000LL / fps) : 0;
		bitrate_ = bitrate;
		nv12Buffer_.resize(static_cast<size_t>(width) * height * 3 / 2);
		ComPtr<IMFTransform> encoder;
		HRESULT hr = CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&encoder));
		if (FAILED(hr)) {
			return hr;
		}
		encoder_ = encoder;

		Microsoft::WRL::ComPtr<IMFAttributes> attrs;
		if (SUCCEEDED(encoder_->GetAttributes(&attrs)) && attrs) {
			attrs->SetUINT32(MF_LOW_LATENCY, TRUE);
			attrs->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
		}

		ComPtr<IMFMediaType> inputType;
		hr = MFCreateMediaType(&inputType);
		if (FAILED(hr)) {
			return hr;
		}
		inputType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
		inputType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
		MFSetAttributeSize(inputType.Get(), MF_MT_FRAME_SIZE, width, height);
		MFSetAttributeRatio(inputType.Get(), MF_MT_FRAME_RATE, fps, 1);
		MFSetAttributeRatio(inputType.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
		inputType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);

		hr = encoder_->SetInputType(0, inputType.Get(), 0);
		if (FAILED(hr)) {
			return hr;
		}

		ComPtr<IMFMediaType> outputType;
		hr = MFCreateMediaType(&outputType);
		if (FAILED(hr)) {
			return hr;
		}
		outputType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
		outputType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
		MFSetAttributeSize(outputType.Get(), MF_MT_FRAME_SIZE, width, height);
		MFSetAttributeRatio(outputType.Get(), MF_MT_FRAME_RATE, fps, 1);
		outputType->SetUINT32(MF_MT_AVG_BITRATE, bitrate);
		outputType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
		outputType->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);

		hr = encoder_->SetOutputType(0, outputType.Get(), 0);
		if (FAILED(hr)) {
			return hr;
		}

		encoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
		encoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
		return S_OK;
	}

	void Shutdown() {
		if (encoder_) {
			encoder_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
			encoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
			encoder_.Reset();
		}
	}

	HRESULT Encode(const uint8_t* rgba,
	               int stride,
	               long long timestampHns,
	               long long durationHns,
	               std::vector<uint8_t>& output,
	               BOOL* keyframe) {
		if (!encoder_) {
			return E_POINTER;
		}
		if (!rgba) {
			return E_POINTER;
		}
		RGBAtoNV12(rgba, stride, width_, height_, nv12Buffer_);

		ComPtr<IMFMediaBuffer> inputBuffer;
		HRESULT hr = MFCreateMemoryBuffer(static_cast<DWORD>(nv12Buffer_.size()), &inputBuffer);
		if (FAILED(hr)) {
			return hr;
		}
		BYTE* dest = nullptr;
		DWORD maxLen = 0;
		inputBuffer->Lock(&dest, &maxLen, nullptr);
		memcpy(dest, nv12Buffer_.data(), nv12Buffer_.size());
		inputBuffer->Unlock();
		inputBuffer->SetCurrentLength(static_cast<DWORD>(nv12Buffer_.size()));

		ComPtr<IMFSample> sample;
		hr = MFCreateSample(&sample);
		if (FAILED(hr)) {
			return hr;
		}
		sample->AddBuffer(inputBuffer.Get());
		sample->SetSampleTime(timestampHns);
		const LONGLONG duration = (durationHns > 0) ? durationHns : frameDuration_;
		if (duration > 0) {
			sample->SetSampleDuration(duration);
		}

		hr = encoder_->ProcessInput(0, sample.Get(), 0);
		if (FAILED(hr)) {
			return hr;
		}

		while (true) {
			MFT_OUTPUT_STREAM_INFO info = {};
			hr = encoder_->GetOutputStreamInfo(0, &info);
			if (FAILED(hr)) {
				return hr;
			}

			ComPtr<IMFMediaBuffer> outBuffer;
			DWORD bufferSize = info.cbSize;
			if (bufferSize == 0) {
				bufferSize = static_cast<DWORD>(nv12Buffer_.size());
			}
			hr = MFCreateMemoryBuffer(bufferSize, &outBuffer);
			if (FAILED(hr)) {
				return hr;
			}

			ComPtr<IMFSample> outSample;
			hr = MFCreateSample(&outSample);
			if (FAILED(hr)) {
				return hr;
			}
			outSample->AddBuffer(outBuffer.Get());

			MFT_OUTPUT_DATA_BUFFER dataBuffer = {};
			dataBuffer.dwStreamID = 0;
			dataBuffer.pSample = outSample.Get();
			DWORD status = 0;
			hr = encoder_->ProcessOutput(0, 1, &dataBuffer, &status);
			if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) {
				output.clear();
				return S_FALSE;
			}
			if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
				continue;
			}
			if (FAILED(hr)) {
				return hr;
			}
			ComPtr<IMFMediaBuffer> contiguous;
			hr = outSample->ConvertToContiguousBuffer(&contiguous);
			if (FAILED(hr)) {
				return hr;
			}
			BYTE* outPtr = nullptr;
			DWORD outLen = 0;
			contiguous->Lock(&outPtr, nullptr, &outLen);
			output.assign(outPtr, outPtr + outLen);
			contiguous->Unlock();
			if (keyframe) {
				UINT32 cleanPoint = FALSE;
				if (SUCCEEDED(outSample->GetUINT32(MFSampleExtension_CleanPoint, &cleanPoint))) {
					*keyframe = cleanPoint;
				} else {
					*keyframe = FALSE;
				}
			}
			return S_OK;
		}
	}

   private:
	ComPtr<IMFTransform> encoder_;
	std::vector<uint8_t> nv12Buffer_;
	int width_ = 0;
	int height_ = 0;
	int bitrate_ = 0;
	LONGLONG frameDuration_ = 0;
};

}  // namespace

extern "C" {

int SparkMFEncoderCreate(int width, int height, int fps, int bitrate, SparkMFEncoderHandle* handle) {
	if (!handle) {
		return E_POINTER;
	}
	if (width <= 0 || height <= 0 || fps <= 0 || bitrate <= 0) {
		return E_INVALIDARG;
	}
	auto* encoder = new (std::nothrow) SparkMFEncoderImpl();
	if (!encoder) {
		return E_OUTOFMEMORY;
	}
	const HRESULT hr = encoder->Initialize(width, height, fps, bitrate);
	if (FAILED(hr)) {
		delete encoder;
		return hr;
	}
	*handle = encoder;
	return S_OK;
}

int SparkMFEncoderEncode(SparkMFEncoderHandle handle,
                         const uint8_t* rgba,
                         int stride,
                         long long timestampHns,
                         long long durationHns,
                         uint8_t** outData,
                         int* outSize,
                         int* isKeyframe) {
	if (!handle || !rgba || !outData || !outSize) {
		return E_POINTER;
	}
	auto* encoder = reinterpret_cast<SparkMFEncoderImpl*>(handle);
	std::vector<uint8_t> buffer;
	BOOL keyframe = FALSE;
	const HRESULT hr = encoder->Encode(rgba, stride, timestampHns, durationHns, buffer, &keyframe);
	if (hr == S_FALSE) {
		return S_FALSE;
	}
	if (FAILED(hr)) {
		return hr;
	}
	const size_t size = buffer.size();
	uint8_t* copy = reinterpret_cast<uint8_t*>(CoTaskMemAlloc(size));
	if (!copy) {
		return E_OUTOFMEMORY;
	}
	memcpy(copy, buffer.data(), size);
	*outData = copy;
	*outSize = static_cast<int>(size);
	if (isKeyframe) {
		*isKeyframe = keyframe ? 1 : 0;
	}
	return S_OK;
}

void SparkMFEncoderFreeBuffer(uint8_t* buffer) {
	if (buffer) {
		CoTaskMemFree(buffer);
	}
}

void SparkMFEncoderDestroy(SparkMFEncoderHandle handle) {
	if (!handle) {
		return;
	}
	auto* encoder = reinterpret_cast<SparkMFEncoderImpl*>(handle);
	encoder->Shutdown();
	delete encoder;
}

}
