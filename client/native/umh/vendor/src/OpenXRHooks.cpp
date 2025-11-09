#include "../include/OpenXRHooks.h"

#include <Windows.h>
#include "../include/HookEngine.h"
#include <atomic>
#include <mutex>
#include <string>
#include <sstream>

namespace openxrhooks {
namespace {

#ifndef XRAPI_PTR
#define XRAPI_PTR __stdcall
#endif

#ifndef XRAPI_ATTR
#define XRAPI_ATTR
#endif

typedef int32_t XrResult;
typedef uint64_t XrTime;
typedef uint32_t XrBool32;
#ifndef XR_SUCCESS
#define XR_SUCCESS 0
#endif

typedef struct XrInstance_T* XrInstance;
typedef struct XrSession_T* XrSession;
typedef struct XrSwapchain_T* XrSwapchain;
typedef struct XrSpace_T* XrSpace;

typedef void (XRAPI_PTR* PFN_xrVoidFunction)(void);
typedef XrResult (XRAPI_PTR* PFN_xrGetInstanceProcAddr)(XrInstance instance, const char* name, PFN_xrVoidFunction* function);
typedef XrResult (XRAPI_PTR* PFN_xrWaitFrame)(XrSession session, const void* frameWaitInfo, void* frameState);
typedef XrResult (XRAPI_PTR* PFN_xrBeginFrame)(XrSession session, const void* frameBeginInfo);
typedef XrResult (XRAPI_PTR* PFN_xrEndFrame)(XrSession session, const void* frameEndInfo);
typedef XrResult (XRAPI_PTR* PFN_xrAcquireSwapchainImage)(XrSwapchain swapchain, const void* acquireInfo, uint32_t* index);
typedef XrResult (XRAPI_PTR* PFN_xrReleaseSwapchainImage)(XrSwapchain swapchain, const void* releaseInfo);

std::atomic<bool> g_initialized{false};
std::atomic<PFN_xrGetInstanceProcAddr> g_getInstanceProcAddrOrig{nullptr};
std::atomic<void*> g_hookedGetInstanceProcAddr{nullptr};

std::atomic<PFN_xrWaitFrame> g_waitFrameOrig{nullptr};
std::atomic<PFN_xrBeginFrame> g_beginFrameOrig{nullptr};
std::atomic<PFN_xrEndFrame> g_endFrameOrig{nullptr};
std::atomic<PFN_xrAcquireSwapchainImage> g_acquireSwapchainImageOrig{nullptr};
std::atomic<PFN_xrReleaseSwapchainImage> g_releaseSwapchainImageOrig{nullptr};

std::atomic<unsigned long long> g_waitFrameCount{0};
std::atomic<unsigned long long> g_beginFrameCount{0};
std::atomic<unsigned long long> g_endFrameCount{0};
std::atomic<unsigned long long> g_acquireSwapchainImageCount{0};
std::atomic<unsigned long long> g_releaseSwapchainImageCount{0};

TelemetryCallback g_telemetryCallback;
PolicyCallback g_policyCallback;

std::mutex g_hookMutex;

// Forward declarations of detours
XrResult XRAPI_PTR xrWaitFrame_Detour(XrSession session, const void* frameWaitInfo, void* frameState);
XrResult XRAPI_PTR xrBeginFrame_Detour(XrSession session, const void* frameBeginInfo);
XrResult XRAPI_PTR xrEndFrame_Detour(XrSession session, const void* frameEndInfo);
XrResult XRAPI_PTR xrAcquireSwapchainImage_Detour(XrSwapchain swapchain, const void* acquireInfo, uint32_t* index);
XrResult XRAPI_PTR xrReleaseSwapchainImage_Detour(XrSwapchain swapchain, const void* releaseInfo);

std::string FormatHandle(uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << value;
    return oss.str();
}

void EmitTelemetry(const char* func, const std::string& detail) {
    auto cb = g_telemetryCallback;
    if (!cb) {
        return;
    }
    try {
        cb(func, detail);
    } catch (...) {
    }
}

bool EvaluatePolicy(const char* op, uintptr_t primary, uintptr_t secondary) {
    auto cb = g_policyCallback;
    if (!cb) {
        return false;
    }
    try {
        return cb(op, primary, secondary);
    } catch (...) {
        return false;
    }
}

PFN_xrVoidFunction HookFunction(const char* name, PFN_xrVoidFunction original) {
    if (!name || !original) {
        return original;
    }
    if (std::strcmp(name, "xrWaitFrame") == 0) {
        g_waitFrameOrig.store(reinterpret_cast<PFN_xrWaitFrame>(original), std::memory_order_release);
        return reinterpret_cast<PFN_xrVoidFunction>(&xrWaitFrame_Detour);
    }
    if (std::strcmp(name, "xrBeginFrame") == 0) {
        g_beginFrameOrig.store(reinterpret_cast<PFN_xrBeginFrame>(original), std::memory_order_release);
        return reinterpret_cast<PFN_xrVoidFunction>(&xrBeginFrame_Detour);
    }
    if (std::strcmp(name, "xrEndFrame") == 0) {
        g_endFrameOrig.store(reinterpret_cast<PFN_xrEndFrame>(original), std::memory_order_release);
        return reinterpret_cast<PFN_xrVoidFunction>(&xrEndFrame_Detour);
    }
    if (std::strcmp(name, "xrAcquireSwapchainImage") == 0) {
        g_acquireSwapchainImageOrig.store(reinterpret_cast<PFN_xrAcquireSwapchainImage>(original), std::memory_order_release);
        return reinterpret_cast<PFN_xrVoidFunction>(&xrAcquireSwapchainImage_Detour);
    }
    if (std::strcmp(name, "xrReleaseSwapchainImage") == 0) {
        g_releaseSwapchainImageOrig.store(reinterpret_cast<PFN_xrReleaseSwapchainImage>(original), std::memory_order_release);
        return reinterpret_cast<PFN_xrVoidFunction>(&xrReleaseSwapchainImage_Detour);
    }
    return original;
}

XrResult XRAPI_PTR xrGetInstanceProcAddr_Detour(XrInstance instance, const char* name, PFN_xrVoidFunction* function) {
    auto orig = g_getInstanceProcAddrOrig.load(std::memory_order_acquire);
    if (!orig) {
        return XR_SUCCESS;
    }
    XrResult result = orig(instance, name, function);
    if (result == XR_SUCCESS && function && *function) {
        *function = HookFunction(name, *function);
    }
    return result;
}

XrResult XRAPI_PTR xrWaitFrame_Detour(XrSession session, const void* frameWaitInfo, void* frameState) {
    if (EvaluatePolicy("xr_wait_frame", reinterpret_cast<uintptr_t>(session), 0)) {
        EmitTelemetry("xrWaitFrame_blocked", FormatHandle(reinterpret_cast<uintptr_t>(session)));
        return XR_SUCCESS;
    }
    g_waitFrameCount.fetch_add(1, std::memory_order_relaxed);
    auto orig = g_waitFrameOrig.load(std::memory_order_acquire);
    XrResult res = orig ? orig(session, frameWaitInfo, frameState) : XR_SUCCESS;
    std::ostringstream detail;
    detail << "session=" << FormatHandle(reinterpret_cast<uintptr_t>(session))
           << " result=" << res;
    EmitTelemetry("xrWaitFrame", detail.str());
    return res;
}

XrResult XRAPI_PTR xrBeginFrame_Detour(XrSession session, const void* frameBeginInfo) {
    if (EvaluatePolicy("xr_begin_frame", reinterpret_cast<uintptr_t>(session), 0)) {
        EmitTelemetry("xrBeginFrame_blocked", FormatHandle(reinterpret_cast<uintptr_t>(session)));
        return XR_SUCCESS;
    }
    g_beginFrameCount.fetch_add(1, std::memory_order_relaxed);
    auto orig = g_beginFrameOrig.load(std::memory_order_acquire);
    XrResult res = orig ? orig(session, frameBeginInfo) : XR_SUCCESS;
    std::ostringstream detail;
    detail << "session=" << FormatHandle(reinterpret_cast<uintptr_t>(session))
           << " result=" << res;
    EmitTelemetry("xrBeginFrame", detail.str());
    return res;
}

XrResult XRAPI_PTR xrEndFrame_Detour(XrSession session, const void* frameEndInfo) {
    if (EvaluatePolicy("xr_end_frame", reinterpret_cast<uintptr_t>(session), 0)) {
        EmitTelemetry("xrEndFrame_blocked", FormatHandle(reinterpret_cast<uintptr_t>(session)));
        return XR_SUCCESS;
    }
    g_endFrameCount.fetch_add(1, std::memory_order_relaxed);
    auto orig = g_endFrameOrig.load(std::memory_order_acquire);
    XrResult res = orig ? orig(session, frameEndInfo) : XR_SUCCESS;
    std::ostringstream detail;
    detail << "session=" << FormatHandle(reinterpret_cast<uintptr_t>(session))
           << " result=" << res;
    EmitTelemetry("xrEndFrame", detail.str());
    return res;
}

XrResult XRAPI_PTR xrAcquireSwapchainImage_Detour(XrSwapchain swapchain, const void* acquireInfo, uint32_t* index) {
    g_acquireSwapchainImageCount.fetch_add(1, std::memory_order_relaxed);
    auto orig = g_acquireSwapchainImageOrig.load(std::memory_order_acquire);
    XrResult res = orig ? orig(swapchain, acquireInfo, index) : XR_SUCCESS;
    std::ostringstream detail;
    detail << "swapchain=" << FormatHandle(reinterpret_cast<uintptr_t>(swapchain))
           << " result=" << res;
    if (index) {
        detail << " index=" << *index;
    }
    EmitTelemetry("xrAcquireSwapchainImage", detail.str());
    return res;
}

XrResult XRAPI_PTR xrReleaseSwapchainImage_Detour(XrSwapchain swapchain, const void* releaseInfo) {
    g_releaseSwapchainImageCount.fetch_add(1, std::memory_order_relaxed);
    auto orig = g_releaseSwapchainImageOrig.load(std::memory_order_acquire);
    XrResult res = orig ? orig(swapchain, releaseInfo) : XR_SUCCESS;
    std::ostringstream detail;
    detail << "swapchain=" << FormatHandle(reinterpret_cast<uintptr_t>(swapchain))
           << " result=" << res;
    EmitTelemetry("xrReleaseSwapchainImage", detail.str());
    return res;
}

bool EnvDisabled(const wchar_t* name) {
    wchar_t buf[32] = {};
    DWORD len = GetEnvironmentVariableW(name, buf, 32);
    if (!len || len >= 32) {
        return false;
    }
    std::wstring value(buf, buf + len);
    for (auto& c : value) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return (value == L"1" || value == L"true" || value == L"yes" || value == L"on");
}

void InstallHook(void* target, std::atomic<void*>& storage, LPVOID detour, LPVOID* originalSlot) {
    if (!target || storage.load(std::memory_order_acquire)) {
        return;
    }
    HookEngine& engine = HookEngine::getInstance();
    if (engine.installInlineHook(target, detour, originalSlot)) {
        storage.store(target, std::memory_order_release);
    }
}

} // namespace

void Initialize() {
    if (g_initialized.exchange(true)) {
        return;
    }

    if (EnvDisabled(L"MLHOOK_DISABLE_OPENXR")) {
        g_initialized.store(false);
        return;
    }

    HMODULE xrLoader = GetModuleHandleW(L"openxr_loader.dll");
    if (!xrLoader) {
        xrLoader = LoadLibraryW(L"openxr_loader.dll");
    }
    if (!xrLoader) {
        g_initialized.store(false);
        return;
    }

    void* proc = reinterpret_cast<void*>(GetProcAddress(xrLoader, "xrGetInstanceProcAddr"));
    if (!proc) {
        g_initialized.store(false);
        return;
    }

    HookEngine& engine = HookEngine::getInstance();
    std::lock_guard<std::mutex> lock(g_hookMutex);
    if (g_hookedGetInstanceProcAddr.load(std::memory_order_acquire)) {
        return;
    }
    if (engine.installInlineHook(proc,
                                 reinterpret_cast<LPVOID>(&xrGetInstanceProcAddr_Detour),
                                 reinterpret_cast<LPVOID*>(&g_getInstanceProcAddrOrig))) {
        g_hookedGetInstanceProcAddr.store(proc, std::memory_order_release);
    } else {
        g_initialized.store(false);
    }
}

void Shutdown() {
    HookEngine& engine = HookEngine::getInstance();
    if (void* hook = g_hookedGetInstanceProcAddr.exchange(nullptr)) {
        engine.removeHook(hook);
    }
    g_getInstanceProcAddrOrig.store(nullptr, std::memory_order_release);
    g_waitFrameOrig.store(nullptr, std::memory_order_release);
    g_beginFrameOrig.store(nullptr, std::memory_order_release);
    g_endFrameOrig.store(nullptr, std::memory_order_release);
    g_acquireSwapchainImageOrig.store(nullptr, std::memory_order_release);
    g_releaseSwapchainImageOrig.store(nullptr, std::memory_order_release);
    g_waitFrameCount.store(0, std::memory_order_release);
    g_beginFrameCount.store(0, std::memory_order_release);
    g_endFrameCount.store(0, std::memory_order_release);
    g_acquireSwapchainImageCount.store(0, std::memory_order_release);
    g_releaseSwapchainImageCount.store(0, std::memory_order_release);
    g_telemetryCallback = nullptr;
    g_policyCallback = nullptr;
    g_initialized.store(false);
}

Stats GetStats() {
    Stats stats{};
    stats.waitFrame = g_waitFrameCount.load(std::memory_order_relaxed);
    stats.beginFrame = g_beginFrameCount.load(std::memory_order_relaxed);
    stats.endFrame = g_endFrameCount.load(std::memory_order_relaxed);
    stats.acquireSwapchainImage = g_acquireSwapchainImageCount.load(std::memory_order_relaxed);
    stats.releaseSwapchainImage = g_releaseSwapchainImageCount.load(std::memory_order_relaxed);
    return stats;
}

void SetTelemetryCallback(TelemetryCallback cb) {
    g_telemetryCallback = std::move(cb);
}

void SetPolicyCallback(PolicyCallback cb) {
    g_policyCallback = std::move(cb);
}

} // namespace openxrhooks
