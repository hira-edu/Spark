#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace glhooks {

// Lifecycle ---------------------------------------------------------------
bool Initialize();
void Shutdown();

// Statistics --------------------------------------------------------------
struct Stats {
    unsigned long long swapBuffers = 0;
    unsigned long long wglSwapBuffers = 0;
    unsigned long long glFinish = 0;
};

Stats GetStats();

struct HookStatus {
    bool swapBuffers = false;
    bool wglSwapBuffers = false;
    bool glFinish = false;
};

HookStatus GetHookStatus();

// Optional telemetry / enforcement hooks ---------------------------------
using TelemetryCallback =
    std::function<void(const char* func, uintptr_t hdc, uintptr_t hwnd, bool blocked)>;
using PolicyCallback =
    std::function<bool(const char* func, uintptr_t hdc, uintptr_t hwnd)>;

void SetTelemetryCallback(TelemetryCallback cb);
void SetPolicyCallback(PolicyCallback cb);

// Returns diagnostic information about the most recent initialization failure.
std::string DescribeLastError();

// Debug helpers for diagnostics.
uintptr_t SwapBuffersOriginalAddress();
uintptr_t SwapBuffersTrampolineAddress();
uintptr_t WglSwapBuffersOriginalAddress();
uintptr_t WglSwapBuffersTrampolineAddress();

} // namespace glhooks
