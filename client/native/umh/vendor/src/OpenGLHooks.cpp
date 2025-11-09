#include "../include/OpenGLHooks.h"

#include <Windows.h>

#include "../include/MultiLayerHook.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace glhooks {
namespace {

using SwapBuffers_t = BOOL(WINAPI*)(HDC);
using WglSwapBuffers_t = BOOL(WINAPI*)(HDC);
using GlFinish_t = void(APIENTRY*)();

std::atomic<bool> g_initialized{false};
std::atomic<bool> g_ready{false};

SwapBuffers_t g_swapTrampoline = nullptr;
WglSwapBuffers_t g_wglTrampoline = nullptr;
GlFinish_t g_glFinishTrampoline = nullptr;

std::atomic<SwapBuffers_t> g_swapOriginal{nullptr};
std::atomic<WglSwapBuffers_t> g_wglOriginal{nullptr};
std::atomic<GlFinish_t> g_glFinishOriginal{nullptr};

std::atomic<bool> g_swapHooked{false};
std::atomic<bool> g_wglHooked{false};
std::atomic<bool> g_glFinishHooked{false};

std::atomic<unsigned long long> g_swapCount{0};
std::atomic<unsigned long long> g_wglCount{0};
std::atomic<unsigned long long> g_finishCount{0};

std::mutex g_callbackMutex;
TelemetryCallback g_telemetryCallback;
PolicyCallback g_policyCallback;

std::mutex g_stateMutex;
std::string g_lastErrorMessage;
DWORD g_lastExceptionCode = 0;

void RecordFailure(const char* stage, DWORD exceptionCode = 0) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    std::ostringstream oss;
    oss << (stage ? stage : "unknown");
    if (exceptionCode != 0) {
        oss << " exception=0x" << std::hex << exceptionCode;
    }
    g_lastErrorMessage = oss.str();
    g_lastExceptionCode = exceptionCode;
}

void ClearFailure() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_lastErrorMessage.clear();
    g_lastExceptionCode = 0;
}

struct TelemetryScope {
    TelemetryScope(const char* funcName,
                   uintptr_t hdcValue,
                   uintptr_t hwndValue,
                   bool blockedValue)
        : func(funcName),
          hdc(hdcValue),
          hwnd(hwndValue),
          blocked(blockedValue) {}

    const char* func = nullptr;
    uintptr_t hdc = 0;
    uintptr_t hwnd = 0;
    bool blocked = false;
};

void DispatchTelemetry(const TelemetryScope& scope) {
    TelemetryCallback callback;
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        callback = g_telemetryCallback;
    }
    if (!callback) {
        return;
    }

    try {
        callback(scope.func, scope.hdc, scope.hwnd, scope.blocked);
    } catch (...) {
        // Swallow exceptions from user telemetry callbacks to keep detours stable.
    }
}

bool ShouldBlockCall(const char* func, uintptr_t hdc, uintptr_t hwnd) {
    PolicyCallback policy;
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        policy = g_policyCallback;
    }
    if (!policy) {
        return false;
    }

    bool blocked = false;
    try {
        blocked = policy(func, hdc, hwnd);
    } catch (...) {
        blocked = false;
    }
    return blocked;
}

SwapBuffers_t ResolveSwapBuffersFallback() {
    static SwapBuffers_t fallback = reinterpret_cast<SwapBuffers_t>(
        GetProcAddress(GetModuleHandleW(L"gdi32.dll"), "SwapBuffers"));
    return fallback;
}

WglSwapBuffers_t ResolveWglSwapBuffersFallback() {
    static WglSwapBuffers_t fallback = reinterpret_cast<WglSwapBuffers_t>(
        GetProcAddress(GetModuleHandleW(L"opengl32.dll"), "wglSwapBuffers"));
    return fallback;
}

GlFinish_t ResolveGlFinishFallback() {
    static GlFinish_t fallback = reinterpret_cast<GlFinish_t>(
        GetProcAddress(GetModuleHandleW(L"opengl32.dll"), "glFinish"));
    return fallback;
}

BOOL WINAPI SwapBuffers_Detour(HDC hdc) {
    HWND hwnd = hdc ? WindowFromDC(hdc) : nullptr;
    const uintptr_t hdcValue = reinterpret_cast<uintptr_t>(hdc);
    const uintptr_t hwndValue = reinterpret_cast<uintptr_t>(hwnd);

    g_swapCount.fetch_add(1, std::memory_order_relaxed);
    const bool blocked = ShouldBlockCall("SwapBuffers", hdcValue, hwndValue);
    DispatchTelemetry(TelemetryScope{"SwapBuffers", hdcValue, hwndValue, blocked});

    if (blocked) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    SwapBuffers_t original = g_swapOriginal.load(std::memory_order_acquire);
    if (!original) {
        SwapBuffers_t trampoline = g_swapTrampoline;
        if (!trampoline) {
            trampoline = ResolveSwapBuffersFallback();
        }
        if (!trampoline) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }
        g_swapOriginal.store(trampoline, std::memory_order_release);
        original = trampoline;
    }
    return original(hdc);
}

BOOL WINAPI WglSwapBuffers_Detour(HDC hdc) {
    HWND hwnd = hdc ? WindowFromDC(hdc) : nullptr;
    const uintptr_t hdcValue = reinterpret_cast<uintptr_t>(hdc);
    const uintptr_t hwndValue = reinterpret_cast<uintptr_t>(hwnd);

    g_wglCount.fetch_add(1, std::memory_order_relaxed);
    const bool blocked = ShouldBlockCall("wglSwapBuffers", hdcValue, hwndValue);
    DispatchTelemetry(TelemetryScope{"wglSwapBuffers", hdcValue, hwndValue, blocked});

    if (blocked) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    WglSwapBuffers_t original = g_wglOriginal.load(std::memory_order_acquire);
    if (!original) {
        WglSwapBuffers_t trampoline = g_wglTrampoline;
        if (!trampoline) {
            trampoline = ResolveWglSwapBuffersFallback();
        }
        if (!trampoline) {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return FALSE;
        }
        g_wglOriginal.store(trampoline, std::memory_order_release);
        original = trampoline;
    }
    return original(hdc);
}

void APIENTRY GlFinish_Detour() {
    g_finishCount.fetch_add(1, std::memory_order_relaxed);
    const bool blocked = ShouldBlockCall("glFinish", 0, 0);
    DispatchTelemetry(TelemetryScope{"glFinish", 0, 0, blocked});

    if (blocked) {
        return;
    }

    GlFinish_t original = g_glFinishOriginal.load(std::memory_order_acquire);
    if (!original) {
        GlFinish_t trampoline = g_glFinishTrampoline;
        if (!trampoline) {
            trampoline = ResolveGlFinishFallback();
        }
        if (!trampoline) {
            return;
        }
        g_glFinishOriginal.store(trampoline, std::memory_order_release);
        original = trampoline;
    }
    original();
}

void ResetState() {
    g_swapCount.store(0, std::memory_order_release);
    g_wglCount.store(0, std::memory_order_release);
    g_finishCount.store(0, std::memory_order_release);
    g_swapOriginal.store(nullptr, std::memory_order_release);
    g_wglOriginal.store(nullptr, std::memory_order_release);
    g_glFinishOriginal.store(nullptr, std::memory_order_release);
    g_swapHooked.store(false, std::memory_order_release);
    g_wglHooked.store(false, std::memory_order_release);
    g_glFinishHooked.store(false, std::memory_order_release);
    g_swapTrampoline = nullptr;
    g_wglTrampoline = nullptr;
    g_glFinishTrampoline = nullptr;
}

void EnsureModulesLoaded() {
    if (!GetModuleHandleW(L"gdi32.dll")) {
        LoadLibraryW(L"gdi32.dll");
    }
    if (!GetModuleHandleW(L"opengl32.dll")) {
        LoadLibraryW(L"opengl32.dll");
    }
}

bool InstallHookSafe(const wchar_t* moduleName,
                     const char* functionName,
                     LPVOID detour,
                     LPVOID* original,
                     std::atomic<bool>& hookFlag,
                     const std::vector<HookLayer>& preferredLayers) {
    HookTargetDescriptor descriptor;
    descriptor.moduleName = moduleName;
    descriptor.functionName = functionName;

    std::vector<HookLayer> layers = preferredLayers;
    if (layers.empty()) {
        if (std::strcmp(functionName, "glFinish") == 0) {
            layers = {HookLayer::Inline, HookLayer::IAT};
        } else {
            layers = {HookLayer::Inline, HookLayer::IAT};
        }
    }

    auto InstallWithSEH = [](const HookTargetDescriptor& desc,
                             LPVOID detourPtr,
                             LPVOID* originalPtr,
                             const std::vector<HookLayer>& layerOrder,
                             DWORD* exceptionCodeOut) -> bool {
        DWORD code = 0;
        bool installed = false;
        __try {
            installed = InstallMultiLayerHook(desc, detourPtr, originalPtr, layerOrder);
        } __except (code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
            installed = false;
        }
        if (exceptionCodeOut) {
            *exceptionCodeOut = code;
        }
        return installed;
    };

    DWORD exceptionCode = 0;
    bool installed = InstallWithSEH(descriptor, detour, original, layers, &exceptionCode);

    if (installed) {
        hookFlag.store(true, std::memory_order_release);
        return true;
    }

    hookFlag.store(false, std::memory_order_release);
    if (exceptionCode != 0) {
        std::ostringstream oss;
        oss << "[OpenGLHooks] InstallMultiLayerHook raised exception for "
            << (functionName ? functionName : "(null)") << " code=0x"
            << std::hex << exceptionCode;
        OutputDebugStringA(oss.str().c_str());
        RecordFailure(functionName ? functionName : "Install", exceptionCode);
    }
    return false;
}

} // namespace

bool Initialize() {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return g_ready.load(std::memory_order_acquire);
    }

    ResetState();
    EnsureModulesLoaded();
    ClearFailure();

    bool anyInstalled = false;

    std::vector<HookLayer> swapLayers = {HookLayer::Inline, HookLayer::IAT};
    if (InstallHookSafe(L"gdi32.dll",
                        "SwapBuffers",
                        reinterpret_cast<LPVOID>(&SwapBuffers_Detour),
                        reinterpret_cast<LPVOID*>(&g_swapTrampoline),
                        g_swapHooked,
                        swapLayers)) {
        anyInstalled = true;
        g_swapOriginal.store(g_swapTrampoline, std::memory_order_release);
    }

    if (InstallHookSafe(L"opengl32.dll",
                        "wglSwapBuffers",
                        reinterpret_cast<LPVOID>(&WglSwapBuffers_Detour),
                        reinterpret_cast<LPVOID*>(&g_wglTrampoline),
                        g_wglHooked,
                        swapLayers)) {
        anyInstalled = true;
        g_wglOriginal.store(g_wglTrampoline, std::memory_order_release);
    }

    std::vector<HookLayer> finishLayers = {HookLayer::Inline, HookLayer::IAT};
    if (InstallHookSafe(L"opengl32.dll",
                        "glFinish",
                        reinterpret_cast<LPVOID>(&GlFinish_Detour),
                        reinterpret_cast<LPVOID*>(&g_glFinishTrampoline),
                        g_glFinishHooked,
                        finishLayers)) {
        anyInstalled = true;
        g_glFinishOriginal.store(g_glFinishTrampoline, std::memory_order_release);
    }

    if (!g_swapHooked.load(std::memory_order_acquire) &&
        !g_wglHooked.load(std::memory_order_acquire) &&
        !g_glFinishHooked.load(std::memory_order_acquire)) {
        // No hooks succeeded; leave module marked uninitialised for retry.
        if (g_lastErrorMessage.empty()) {
            RecordFailure("No hooks installed");
        }
        Shutdown();
        return false;
    }

    g_ready.store(anyInstalled, std::memory_order_release);
    return anyInstalled;
}

void Shutdown() {
    bool expected = true;
    if (!g_initialized.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return;
    }

    UninstallMultiLayerHook("SwapBuffers");
    UninstallMultiLayerHook("wglSwapBuffers");
    UninstallMultiLayerHook("glFinish");

    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        g_policyCallback = {};
        g_telemetryCallback = {};
    }

    ResetState();
    g_ready.store(false, std::memory_order_release);
    g_initialized.store(false, std::memory_order_release);
}

Stats GetStats() {
    Stats stats{};
    stats.swapBuffers = g_swapCount.load(std::memory_order_relaxed);
    stats.wglSwapBuffers = g_wglCount.load(std::memory_order_relaxed);
    stats.glFinish = g_finishCount.load(std::memory_order_relaxed);
    return stats;
}

HookStatus GetHookStatus() {
    HookStatus status{};
    status.swapBuffers = g_swapHooked.load(std::memory_order_acquire);
    status.wglSwapBuffers = g_wglHooked.load(std::memory_order_acquire);
    status.glFinish = g_glFinishHooked.load(std::memory_order_acquire);
    return status;
}

void SetTelemetryCallback(TelemetryCallback cb) {
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    g_telemetryCallback = std::move(cb);
}

void SetPolicyCallback(PolicyCallback cb) {
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    g_policyCallback = std::move(cb);
}

std::string DescribeLastError() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_lastErrorMessage;
}

uintptr_t SwapBuffersOriginalAddress() {
    return reinterpret_cast<uintptr_t>(g_swapOriginal.load(std::memory_order_acquire));
}

uintptr_t SwapBuffersTrampolineAddress() {
    return reinterpret_cast<uintptr_t>(g_swapTrampoline);
}

uintptr_t WglSwapBuffersOriginalAddress() {
    return reinterpret_cast<uintptr_t>(g_wglOriginal.load(std::memory_order_acquire));
}

uintptr_t WglSwapBuffersTrampolineAddress() {
    return reinterpret_cast<uintptr_t>(g_wglTrampoline);
}

} // namespace glhooks
