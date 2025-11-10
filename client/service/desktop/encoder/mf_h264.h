#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void* SparkMFEncoderHandle;

int SparkMFEncoderCreate(int width, int height, int fps, int bitrate, SparkMFEncoderHandle* handle);
int SparkMFEncoderEncode(SparkMFEncoderHandle handle,
                         const uint8_t* rgba,
                         int stride,
                         long long timestampHns,
                         long long durationHns,
                         uint8_t** outData,
                         int* outSize,
                         int* isKeyframe);
void SparkMFEncoderFreeBuffer(uint8_t* buffer);
void SparkMFEncoderDestroy(SparkMFEncoderHandle handle);

#ifdef __cplusplus
}
#endif
