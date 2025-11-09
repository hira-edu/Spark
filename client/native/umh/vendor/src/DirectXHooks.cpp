#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN10
#endif

#include <sdkddkver.h>

#include "../include/DirectXHooks.h"
#include <Windows.h>
#include "../include/HookEngine.h"
#include <algorithm>
#include <atomic>
#include <objbase.h>
#include <d3d9.h>
#include <d3d11.h>
#include <d3d12.h>
#include <dxgi.h>
#include <dxgi1_2.h>
#include <dxgi1_3.h>
#include <dxgi1_4.h>
#include <dxgi1_6.h>
#include <dcomp.h>
#include <inspectable.h>
#include <wrl/client.h>
#include <activation.h>
#include <roapi.h>
#include <winstring.h>
#include <windows.graphics.capture.interop.h>
#include <string>
#ifndef DXGI_OUTDUPLICATION_FRAME_INFO
typedef DXGI_OUTDUPL_FRAME_INFO DXGI_OUTDUPLICATION_FRAME_INFO;
#endif
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <limits>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <cwchar>
#include <dxgi1_2.h>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d12.lib")
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

namespace dxhooks {

namespace {

struct DirtyRectSummary {
    bool valid = false;
    bool truncated = false;
    UINT count = 0;
    LONG left = 0;
    LONG top = 0;
    LONG right = 0;
    LONG bottom = 0;
    ULONGLONG boundingArea = 0;
    ULONGLONG totalArea = 0;
};

bool IsReadableRange(const void* address, size_t length) {
    if (!address || length == 0) {
        return false;
    }

    const std::uintptr_t start = reinterpret_cast<std::uintptr_t>(address);
    if (length > std::numeric_limits<std::uintptr_t>::max() - start) {
        return false;
    }

    const BYTE* current = reinterpret_cast<const BYTE*>(address);
    const BYTE* end = reinterpret_cast<const BYTE*>(start + length);
    while (current < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(current, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            return false;
        }

        if (mbi.State != MEM_COMMIT) {
            return false;
        }

        DWORD protect = mbi.Protect;
        if ((protect & PAGE_NOACCESS) != 0 || (protect & PAGE_GUARD) != 0) {
            return false;
        }

        const BYTE* regionEnd = static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= current) {
            return false;
        }

        current = regionEnd;
    }

    return true;
}

bool IsReadableRectArray(const RECT* rects, UINT count) {
    if (!rects || count == 0) {
        return false;
    }

    const size_t maxCount = std::numeric_limits<size_t>::max() / sizeof(RECT);
    if (static_cast<size_t>(count) > maxCount) {
        return false;
    }

    const size_t byteCount = static_cast<size_t>(count) * sizeof(RECT);
    return IsReadableRange(rects, byteCount);
}

DirtyRectSummary SummarizeDirtyRects(const RECT* rects, UINT count) {
    DirtyRectSummary summary;
    if (!rects || count == 0) {
        return summary;
    }

    constexpr UINT kMaxRects = 128;
    UINT capped = (count > kMaxRects) ? kMaxRects : count;

    if (!IsReadableRectArray(rects, capped)) {
        return summary;
    }

    LONG left = rects[0].left;
    LONG top = rects[0].top;
    LONG right = rects[0].right;
    LONG bottom = rects[0].bottom;
    ULONGLONG totalArea = 0;
    for (UINT i = 0; i < capped; ++i) {
        const RECT& r = rects[i];
        left = std::min(left, r.left);
        top = std::min(top, r.top);
        right = std::max(right, r.right);
        bottom = std::max(bottom, r.bottom);
        LONG width = std::max<LONG>(0, r.right - r.left);
        LONG height = std::max<LONG>(0, r.bottom - r.top);
        totalArea += static_cast<ULONGLONG>(width) * static_cast<ULONGLONG>(height);
    }

    summary.valid = true;
    summary.truncated = (count > capped);
    summary.count = count;
    summary.left = left;
    summary.top = top;
    summary.right = right;
    summary.bottom = bottom;
    LONG bboxWidth = std::max<LONG>(0, right - left);
    LONG bboxHeight = std::max<LONG>(0, bottom - top);
    summary.boundingArea = static_cast<ULONGLONG>(bboxWidth) * static_cast<ULONGLONG>(bboxHeight);
    summary.totalArea = totalArea;

    return summary;
}

struct OverlayModuleInfo {
    const wchar_t* module;
    const char* tag;
};

const OverlayModuleInfo kOverlayModules[] = {
    { L"gameoverlayrenderer64.dll", "steam" },
    { L"gameoverlayrenderer.dll", "steam" },
    { L"discordhook64.dll", "discord" },
    { L"discordhook.dll", "discord" },
    { L"nvspcap64.dll", "geforce" },
    { L"nvspcap.dll", "geforce" }
};

const char* DetectOverlayTag() {
    for (const auto& entry : kOverlayModules) {
        if (GetModuleHandleW(entry.module)) {
            return entry.tag;
        }
    }
    return nullptr;
}

} // namespace

// Forward declarations for detours and originals used during initialization
HRESULT APIENTRY PresentDetour(IDirect3DDevice9*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*);
HRESULT APIENTRY EndSceneDetour(IDirect3DDevice9*);
HRESULT STDMETHODCALLTYPE DXGIPresentDetour(IDXGISwapChain*, UINT, UINT);
HRESULT STDMETHODCALLTYPE ResizeBuffersDetour(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
HRESULT STDMETHODCALLTYPE DXGIPresent1Detour(IDXGISwapChain4*, UINT, UINT, const DXGI_PRESENT_PARAMETERS*);
HRESULT STDMETHODCALLTYPE CreateSwapChainDetour(IDXGIFactory*, IUnknown*, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**);
HRESULT STDMETHODCALLTYPE CreateSwapChainForHwndDetour(IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1**);
HRESULT STDMETHODCALLTYPE CreateSwapChainForCoreWindowDetour(IDXGIFactory2*, IUnknown*, IInspectable*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**);
HRESULT STDMETHODCALLTYPE CreateSwapChainForCompositionDetour(IDXGIFactory2*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**);
HRESULT STDMETHODCALLTYPE CreateSwapChainForCompositionMediaDetour(IDXGIFactoryMedia*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**);
HRESULT WINAPI CreateDXGIFactoryDetour(REFIID riid, void** ppFactory);
HRESULT WINAPI CreateDXGIFactory1Detour(REFIID riid, void** ppFactory);
HRESULT WINAPI CreateDXGIFactory2Detour(UINT Flags, REFIID riid, void** ppFactory);
void STDMETHODCALLTYPE D3D12ExecuteCommandListsDetour(ID3D12CommandQueue*, UINT, ID3D12CommandList* const*);
HRESULT WINAPI DCompositionCreateDevice_Detour(IDXGIDevice*, REFIID, void**);
HRESULT STDMETHODCALLTYPE DuplicateOutputDetour(IDXGIOutput1*, IUnknown*, IDXGIOutputDuplication**);
HRESULT STDMETHODCALLTYPE AcquireNextFrameDetour(IDXGIOutputDuplication*, UINT, DXGI_OUTDUPLICATION_FRAME_INFO*, IDXGIResource**);
HRESULT WINAPI CaptureForWindowDetour(HWND, REFIID, void**);
HRESULT WINAPI CaptureForMonitorDetour(HMONITOR, REFIID, void**);

extern HRESULT (APIENTRY* PresentOriginal)(IDirect3DDevice9*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*);
extern HRESULT (APIENTRY* EndSceneOriginal)(IDirect3DDevice9*);
extern HRESULT (STDMETHODCALLTYPE* DXGIPresentOriginal)(IDXGISwapChain*, UINT, UINT);
extern HRESULT (STDMETHODCALLTYPE* ResizeBuffersOriginal)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT);
extern HRESULT (STDMETHODCALLTYPE* CreateSwapChainOriginal)(IDXGIFactory*, IUnknown*, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**);
extern HRESULT (STDMETHODCALLTYPE* CreateSwapChainForHwndOriginal)(IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1**);
extern HRESULT (STDMETHODCALLTYPE* CreateSwapChainForCoreWindowOriginal)(IDXGIFactory2*, IUnknown*, IInspectable*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**);
extern HRESULT (STDMETHODCALLTYPE* CreateSwapChainForCompositionOriginal)(IDXGIFactory2*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**);
extern HRESULT (WINAPI* CreateDXGIFactory_Orig)(REFIID, void**);
extern HRESULT (WINAPI* CreateDXGIFactory1_Orig)(REFIID, void**);
extern HRESULT (WINAPI* CreateDXGIFactory2_Orig)(UINT, REFIID, void**);
extern HRESULT (STDMETHODCALLTYPE* DXGIPresent1Original)(IDXGISwapChain4*, UINT, UINT, const DXGI_PRESENT_PARAMETERS*);
extern void (STDMETHODCALLTYPE* D3D12ExecuteCommandListsOriginal)(ID3D12CommandQueue*, UINT, ID3D12CommandList* const*);
extern HRESULT (STDMETHODCALLTYPE* CreateSwapChainForCompositionMedia_Orig)(IDXGIFactoryMedia*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**);
extern HRESULT (WINAPI* DCompositionCreateDevice_Orig)(IDXGIDevice*, REFIID, void**);
extern HRESULT (STDMETHODCALLTYPE* DuplicateOutputOriginal)(IDXGIOutput1*, IUnknown*, IDXGIOutputDuplication**);
extern HRESULT (STDMETHODCALLTYPE* AcquireNextFrameOriginal)(IDXGIOutputDuplication*, UINT, DXGI_OUTDUPLICATION_FRAME_INFO*, IDXGIResource**);
extern HRESULT (WINAPI* CaptureForWindow_Orig)(HWND, REFIID, void**);
extern HRESULT (WINAPI* CaptureForMonitor_Orig)(HMONITOR, REFIID, void**);

// D3D11 creation hook (to cover future swap chains)
typedef HRESULT (WINAPI* D3D11CreateDeviceAndSwapChain_t)(
    IDXGIAdapter*,
    D3D_DRIVER_TYPE,
    HMODULE,
    UINT,
    const D3D_FEATURE_LEVEL*,
    UINT,
    UINT,
    const DXGI_SWAP_CHAIN_DESC*,
    IDXGISwapChain**, ID3D11Device**, D3D_FEATURE_LEVEL*, ID3D11DeviceContext**);

static D3D11CreateDeviceAndSwapChain_t g_D3D11CreateDeviceAndSwapChain_Orig = nullptr;
static HRESULT WINAPI D3D11CreateDeviceAndSwapChain_Detour(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    HMODULE Software,
    UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
    IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext);
static void HookSwapChainIfNeeded(IDXGISwapChain* swap);
static void HookCommandQueueIfNeeded(IUnknown* device);

namespace {
constexpr size_t kOutputDuplicateIndex = 24;
constexpr size_t kDuplicationAcquireIndex = 4;
constexpr size_t kFactoryMediaCreateSwapchainIndex = 3;
constexpr size_t kCaptureForWindowIndex = 3;
constexpr size_t kCaptureForMonitorIndex = 4;

// Track addresses we hook so we can cleanly unhook on shutdown
std::atomic<void*> g_d3d9PresentAddr{nullptr};
std::atomic<void*> g_d3d9EndSceneAddr{nullptr};
std::atomic<void*> g_dxgiPresentAddr{nullptr};
std::atomic<void*> g_dxgiResizeAddr{nullptr};
std::atomic<void*> g_dxgiCreateSwapChainAddr{nullptr};
std::atomic<void*> g_dxgiCreateSwapChainHwndAddr{nullptr};
std::atomic<void*> g_dxgiCreateSwapChainCoreWindowAddr{nullptr};
std::atomic<void*> g_dxgiCreateSwapChainCompositionAddr{nullptr};
std::atomic<void*> g_createFactoryAddr{nullptr};
std::atomic<void*> g_createFactory1Addr{nullptr};
std::atomic<void*> g_createFactory2Addr{nullptr};
std::atomic<void*> g_dxgiPresent1Addr{nullptr};
std::atomic<void*> g_d3d12QueueExecuteAddr{nullptr};
std::atomic<void*> g_dcompCreateDeviceAddr{nullptr};
std::atomic<void*> g_factoryMediaCreateSwapchainAddr{nullptr};
std::atomic<void*> g_duplicateOutputAddr{nullptr};
std::atomic<void*> g_duplicationAcquireAddr{nullptr};
std::atomic<void*> g_captureForWindowAddr{nullptr};
std::atomic<void*> g_captureForMonitorAddr{nullptr};
std::atomic<bool> g_graphicsCaptureHookFailed{false};
std::atomic<bool> g_graphicsCaptureHookActive{false};

// Optional Present callback
static std::function<void(const char* api)> g_presentCallback;
static TelemetryCallback g_telemetryCallback;
static PolicyCallback g_policyCallback;
static std::mutex g_swapKindMutex;
static std::unordered_map<IDXGISwapChain*, bool> g_swapIsD3D12;

bool EnvEnabled(const wchar_t* name) {
    if (!name) return false;
    wchar_t buf[32] = {}; DWORD len = GetEnvironmentVariableW(name, buf, 32);
    if (!len || len >= 32) return false; std::wstring v(buf, buf + len);
    for (auto& c : v) c = (wchar_t)towlower(c);
    return (v == L"1" || v == L"true" || v == L"yes" || v == L"on");
}

void Debug(const char* s) {
    OutputDebugStringA(s);
}

std::string HexPtr(const void* ptr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(ptr);
    return oss.str();
}

std::string GuidToString(REFIID iid) {
    wchar_t buffer[64];
    int written = StringFromGUID2(iid, buffer, static_cast<int>(_countof(buffer)));
    if (written <= 0) {
        return std::string();
    }
    int required = WideCharToMultiByte(CP_UTF8, 0, buffer, written, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return std::string();
    }
    std::string narrow(static_cast<size_t>(required), '\0');
    int converted = WideCharToMultiByte(CP_UTF8, 0, buffer, written, narrow.data(), required, nullptr, nullptr);
    if (converted <= 0) {
        return std::string();
    }
    if (!narrow.empty() && narrow.back() == '\0') {
        narrow.pop_back();
    }
    return narrow;
}

void EmitTelemetry(const char* event, const char* func, const std::string& detail) {
    if (!g_telemetryCallback || !func) {
        return;
    }
    try {
        g_telemetryCallback(event ? event : "graphics", func, detail);
    } catch (...) {
        // Swallow exceptions from external callbacks to avoid destabilising the hook.
    }
}

std::wstring RandomWindowClassName() {
    GUID guid{};
    if (UuidCreate(&guid) != RPC_S_OK) {
        return L"W" + std::to_wstring(GetTickCount64());
    }
    RPC_WSTR rpcStr = nullptr;
    if (UuidToStringW(&guid, &rpcStr) != RPC_S_OK) {
        return L"W" + std::to_wstring(GetTickCount64());
    }
    std::wstring token(reinterpret_cast<const wchar_t*>(rpcStr));
    RpcStringFreeW(&rpcStr);
    token.erase(std::remove(token.begin(), token.end(), L'-'), token.end());
    if (token.empty()) {
        token.assign(L"WCLS");
    }
    if (!iswalpha(token.front())) {
        token.insert(token.begin(), L'W');
    }
    return token;
}

struct RoUninitializeScope {
    using Fn = HRESULT (WINAPI*)(RO_INIT_TYPE);
    using UninitFn = void (WINAPI*)();

    UninitFn fn{};
    bool active{false};

    ~RoUninitializeScope() {
        if (active && fn) {
            fn();
        }
    }
};

struct HStringScope {
    using DeleteFn = HRESULT (WINAPI*)(HSTRING);

    DeleteFn fn{};
    HSTRING value{nullptr};

    ~HStringScope() {
        if (value && fn) {
            fn(value);
        }
    }
};

void TryHookFactoryMethod(void** vtbl,
                          size_t index,
                          std::atomic<void*>& storage,
                          LPVOID detour,
                          LPVOID* originalSlot) {
    if (!vtbl || storage.load(std::memory_order_acquire)) {
        return;
    }
    void* target = vtbl[index];
    if (!target) {
        return;
    }
    HookEngine& eng = HookEngine::getInstance();
    if (eng.installInlineHook(target, detour, originalSlot)) {
        storage.store(target, std::memory_order_release);
    }
}

bool InstallCaptureHookEntry(void** vtbl,
                             size_t index,
                             std::atomic<void*>& storage,
                             LPVOID detour,
                             LPVOID* originalSlot,
                             HookEngine& eng) {
    if (storage.load(std::memory_order_acquire)) {
        return true;
    }

    if (!IsReadableRange(&vtbl[index], sizeof(void*))) {
        return false;
    }

    void* target = vtbl[index];
    if (!target) {
        return true;
    }

    if (!eng.installInlineHook(target, detour, originalSlot)) {
        return false;
    }

    storage.store(target, std::memory_order_release);
    return true;
}

void InstallGraphicsCaptureHooks(void** vtbl) {
    if (!vtbl) {
        return;
    }
    HookEngine& eng = HookEngine::getInstance();

    const size_t maxIndex = std::max(kCaptureForWindowIndex, kCaptureForMonitorIndex);
    if (!IsReadableRange(vtbl, (maxIndex + 1) * sizeof(void*))) {
        g_graphicsCaptureHookFailed.store(true, std::memory_order_release);
        return;
    }

    if (!InstallCaptureHookEntry(vtbl,
                                 kCaptureForWindowIndex,
                                 g_captureForWindowAddr,
                                 reinterpret_cast<LPVOID>(&CaptureForWindowDetour),
                                 reinterpret_cast<LPVOID*>(&CaptureForWindow_Orig),
                                 eng)) {
        g_graphicsCaptureHookFailed.store(true, std::memory_order_release);
        return;
    }

    if (!InstallCaptureHookEntry(vtbl,
                                 kCaptureForMonitorIndex,
                                 g_captureForMonitorAddr,
                                 reinterpret_cast<LPVOID>(&CaptureForMonitorDetour),
                                 reinterpret_cast<LPVOID*>(&CaptureForMonitor_Orig),
                                 eng)) {
        g_graphicsCaptureHookFailed.store(true, std::memory_order_release);
        return;
    }

    if (g_captureForWindowAddr.load(std::memory_order_acquire) &&
        g_captureForMonitorAddr.load(std::memory_order_acquire)) {
        g_graphicsCaptureHookActive.store(true, std::memory_order_release);
    }
}

void HookFactoryIfNeeded(IDXGIFactory* factory) {
    if (!factory) {
        return;
    }

    void** vtbl = *(void***)factory;
    TryHookFactoryMethod(vtbl,
                         10, // IDXGIFactory::CreateSwapChain
                         g_dxgiCreateSwapChainAddr,
                         reinterpret_cast<LPVOID>(&CreateSwapChainDetour),
                         reinterpret_cast<LPVOID*>(&CreateSwapChainOriginal));

    Microsoft::WRL::ComPtr<IDXGIFactory2> factory2;
    if (SUCCEEDED(factory->QueryInterface(IID_PPV_ARGS(&factory2))) && factory2) {
        void** vtbl2 = *(void***)factory2.Get();
        TryHookFactoryMethod(vtbl2,
                             15, // CreateSwapChainForHwnd
                             g_dxgiCreateSwapChainHwndAddr,
                             reinterpret_cast<LPVOID>(&CreateSwapChainForHwndDetour),
                             reinterpret_cast<LPVOID*>(&CreateSwapChainForHwndOriginal));
        TryHookFactoryMethod(vtbl2,
                             16, // CreateSwapChainForCoreWindow
                             g_dxgiCreateSwapChainCoreWindowAddr,
                             reinterpret_cast<LPVOID>(&CreateSwapChainForCoreWindowDetour),
                             reinterpret_cast<LPVOID*>(&CreateSwapChainForCoreWindowOriginal));
        TryHookFactoryMethod(vtbl2,
                             24, // CreateSwapChainForComposition (IDXGIFactory2 + offset)
                             g_dxgiCreateSwapChainCompositionAddr,
                             reinterpret_cast<LPVOID>(&CreateSwapChainForCompositionDetour),
                             reinterpret_cast<LPVOID*>(&CreateSwapChainForCompositionOriginal));
    }

    Microsoft::WRL::ComPtr<IDXGIFactoryMedia> factoryMedia;
    if (SUCCEEDED(factory->QueryInterface(IID_PPV_ARGS(&factoryMedia))) && factoryMedia) {
        void** vtblMedia = *(void***)factoryMedia.Get();
        void* mediaAddr = vtblMedia[kFactoryMediaCreateSwapchainIndex];
        if (mediaAddr && !g_factoryMediaCreateSwapchainAddr.load(std::memory_order_acquire)) {
            HookEngine& eng = HookEngine::getInstance();
            if (eng.installInlineHook(mediaAddr,
                                      reinterpret_cast<LPVOID>(&CreateSwapChainForCompositionMediaDetour),
                                      reinterpret_cast<LPVOID*>(&CreateSwapChainForCompositionMedia_Orig))) {
                g_factoryMediaCreateSwapchainAddr.store(mediaAddr, std::memory_order_release);
            }
        }
    }
}

void HookDuplicationIfNeeded(IDXGIOutputDuplication* duplication) {
    if (!duplication) {
        return;
    }
    void** vtbl = *(void***)duplication;
    if (!vtbl) {
        return;
    }
    void* acquireAddr = vtbl[kDuplicationAcquireIndex];
    if (acquireAddr && !g_duplicationAcquireAddr.load(std::memory_order_acquire)) {
        HookEngine& eng = HookEngine::getInstance();
        if (eng.installInlineHook(acquireAddr,
                                      reinterpret_cast<LPVOID>(&AcquireNextFrameDetour),
                                      reinterpret_cast<LPVOID*>(&AcquireNextFrameOriginal))) {
            g_duplicationAcquireAddr.store(acquireAddr, std::memory_order_release);
        }
    }
}

void HookOutputIfNeeded(IDXGIOutput* output) {
    if (!output) {
        return;
    }
    Microsoft::WRL::ComPtr<IDXGIOutput1> output1;
    if (FAILED(output->QueryInterface(IID_PPV_ARGS(&output1))) || !output1) {
        return;
    }
    void** vtbl = *(void***)output1.Get();
    if (!vtbl) {
        return;
    }
    void* duplicateAddr = vtbl[kOutputDuplicateIndex];
    if (duplicateAddr && !g_duplicateOutputAddr.load(std::memory_order_acquire)) {
        HookEngine& eng = HookEngine::getInstance();
        if (eng.installInlineHook(duplicateAddr,
                                      reinterpret_cast<LPVOID>(&DuplicateOutputDetour),
                                      reinterpret_cast<LPVOID*>(&DuplicateOutputOriginal))) {
            g_duplicateOutputAddr.store(duplicateAddr, std::memory_order_release);
        }
    }
}
void HookGraphicsCaptureInterop() {
    if (g_graphicsCaptureHookFailed.load(std::memory_order_acquire)) {
        return;
    }
    if (g_captureForWindowAddr.load(std::memory_order_acquire) &&
        g_captureForMonitorAddr.load(std::memory_order_acquire)) {
        return;
    }

    HMODULE combase = GetModuleHandleW(L"combase.dll");
    if (!combase) {
        combase = LoadLibraryW(L"combase.dll");
        if (!combase) {
            return;
        }
    }

    using RoInitialize_t = HRESULT (WINAPI*)(RO_INIT_TYPE);
    using RoUninitialize_t = void (WINAPI*)();
    using RoGetActivationFactory_t = HRESULT (WINAPI*)(HSTRING, REFIID, void**);
    using WindowsCreateString_t = HRESULT (WINAPI*)(PCNZWCH, UINT32, HSTRING*);
    using WindowsDeleteString_t = HRESULT (WINAPI*)(HSTRING);

    auto roInitialize = reinterpret_cast<RoInitialize_t>(GetProcAddress(combase, "RoInitialize"));
    auto roUninitialize = reinterpret_cast<RoUninitialize_t>(GetProcAddress(combase, "RoUninitialize"));
    auto roGetActivationFactory = reinterpret_cast<RoGetActivationFactory_t>(GetProcAddress(combase, "RoGetActivationFactory"));
    auto windowsCreateString = reinterpret_cast<WindowsCreateString_t>(GetProcAddress(combase, "WindowsCreateString"));
    auto windowsDeleteString = reinterpret_cast<WindowsDeleteString_t>(GetProcAddress(combase, "WindowsDeleteString"));

    if (!roGetActivationFactory || !windowsCreateString || !windowsDeleteString) {
        return;
    }

    HRESULT initHr = roInitialize ? roInitialize(RO_INIT_MULTITHREADED) : S_OK;
    RoUninitializeScope roScope{roUninitialize, roUninitialize && SUCCEEDED(initHr)};

    static constexpr wchar_t kGraphicsCaptureItemClass[] = L"Windows.Graphics.Capture.GraphicsCaptureItem";
    HSTRING classId = nullptr;
    HRESULT hr = windowsCreateString(kGraphicsCaptureItemClass,
                                     static_cast<UINT32>(wcslen(kGraphicsCaptureItemClass)),
                                     &classId);
    if (FAILED(hr)) {
        return;
    }
    HStringScope hstrScope{windowsDeleteString, classId};

    Microsoft::WRL::ComPtr<IActivationFactory> factory;
    hr = roGetActivationFactory(classId,
                                __uuidof(IActivationFactory),
                                reinterpret_cast<void**>(factory.GetAddressOf()));
    if (FAILED(hr) || !factory) {
        return;
    }

    Microsoft::WRL::ComPtr<IGraphicsCaptureItemInterop> interop;
    hr = factory.As(&interop);
    if (FAILED(hr) || !interop) {
        return;
    }

    void** vtbl = *(void***)interop.Get();
    if (!vtbl) {
        return;
    }

    InstallGraphicsCaptureHooks(vtbl);
}
}

void Initialize() {
    static std::atomic<bool> g_initialized{false};
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) {
        Debug("[DirectXHooks] Already initialized.\n");
        return;
    }
    if (EnvEnabled(L"MLHOOK_DISABLE_D3D9") && EnvEnabled(L"MLHOOK_DISABLE_DXGI")) {
        Debug("[DirectXHooks] Disabled via environment.\n");
        return;
    }

    Debug("[DirectXHooks] Initialize.\n");

    // D3D9 hook setup
    if (!EnvEnabled(L"MLHOOK_DISABLE_D3D9")) {
        std::wstring className = RandomWindowClassName();
        WNDCLASSW wc{}; wc.lpfnWndProc = DefWindowProcW; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = className.c_str();
        if (RegisterClassW(&wc)) {
            HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);

            IDirect3D9* d3d = Direct3DCreate9(D3D_SDK_VERSION);
            if (d3d && hwnd) {
                D3DPRESENT_PARAMETERS pp{};
                pp.Windowed = TRUE; pp.SwapEffect = D3DSWAPEFFECT_DISCARD; pp.hDeviceWindow = hwnd;
                IDirect3DDevice9* device = nullptr;
                if (SUCCEEDED(d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
                                                D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &device))) {
                    void** vtbl = *(void***)device;
                    void* presentAddr = vtbl[17];
                    void* endSceneAddr = vtbl[42];

                    HookEngine& eng = HookEngine::getInstance();

                    if (presentAddr) {
                        eng.installInlineHook(presentAddr, reinterpret_cast<LPVOID>(&PresentDetour), reinterpret_cast<LPVOID*>(&PresentOriginal));
                        g_d3d9PresentAddr.store(presentAddr, std::memory_order_release);
                    }
                    if (endSceneAddr) {
                        eng.installInlineHook(endSceneAddr, reinterpret_cast<LPVOID>(&EndSceneDetour), reinterpret_cast<LPVOID*>(&EndSceneOriginal));
                        g_d3d9EndSceneAddr.store(endSceneAddr, std::memory_order_release);
                    }

                    device->Release();
                }
            }
            if (d3d) d3d->Release();
            if (hwnd) { DestroyWindow(hwnd); }
            UnregisterClassW(className.c_str(), wc.hInstance);
        }
    }
    HMODULE dxgi = GetModuleHandleW(L"dxgi.dll");
    if (!dxgi) {
        dxgi = LoadLibraryW(L"dxgi.dll");
    }
    if (dxgi) {
        HookEngine& eng = HookEngine::getInstance();
        if (!g_createFactoryAddr.load(std::memory_order_acquire)) {
            if (void* fn = reinterpret_cast<void*>(GetProcAddress(dxgi, "CreateDXGIFactory"))) {
                if (eng.installInlineHook(fn,
                                          reinterpret_cast<LPVOID>(&CreateDXGIFactoryDetour),
                                          reinterpret_cast<LPVOID*>(&CreateDXGIFactory_Orig))) {
                    g_createFactoryAddr.store(fn, std::memory_order_release);
                }
            }
        }
        if (!g_createFactory1Addr.load(std::memory_order_acquire)) {
            if (void* fn = reinterpret_cast<void*>(GetProcAddress(dxgi, "CreateDXGIFactory1"))) {
                if (eng.installInlineHook(fn,
                                          reinterpret_cast<LPVOID>(&CreateDXGIFactory1Detour),
                                          reinterpret_cast<LPVOID*>(&CreateDXGIFactory1_Orig))) {
                    g_createFactory1Addr.store(fn, std::memory_order_release);
                }
            }
        }
        if (!g_createFactory2Addr.load(std::memory_order_acquire)) {
            if (void* fn = reinterpret_cast<void*>(GetProcAddress(dxgi, "CreateDXGIFactory2"))) {
                if (eng.installInlineHook(fn,
                                          reinterpret_cast<LPVOID>(&CreateDXGIFactory2Detour),
                                          reinterpret_cast<LPVOID*>(&CreateDXGIFactory2_Orig))) {
                    g_createFactory2Addr.store(fn, std::memory_order_release);
                }
            }
        }
    }

    HMODULE dcomp = GetModuleHandleW(L"dcomp.dll");
    if (!dcomp) {
        dcomp = LoadLibraryW(L"dcomp.dll");
    }
    if (dcomp && !g_dcompCreateDeviceAddr.load(std::memory_order_acquire)) {
        if (void* fn = reinterpret_cast<void*>(GetProcAddress(dcomp, "DCompositionCreateDevice"))) {
            HookEngine& eng = HookEngine::getInstance();
            if (eng.installInlineHook(fn,
                                      reinterpret_cast<LPVOID>(&DCompositionCreateDevice_Detour),
                                      reinterpret_cast<LPVOID*>(&DCompositionCreateDevice_Orig))) {
                g_dcompCreateDeviceAddr.store(fn, std::memory_order_release);
            }
        }
    }

    // DXGI/D3D11 hook setup
    if (!EnvEnabled(L"MLHOOK_DISABLE_DXGI")) {
        std::wstring classNameDx11 = RandomWindowClassName();
        WNDCLASSW wc{}; wc.lpfnWndProc = DefWindowProcW; wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = classNameDx11.c_str();
        if (RegisterClassW(&wc)) {
            HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);

            DXGI_SWAP_CHAIN_DESC sd{};
            sd.BufferCount = 1;
            sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            sd.OutputWindow = hwnd;
            sd.SampleDesc.Count = 1;
            sd.Windowed = TRUE;

            D3D_FEATURE_LEVEL fl = D3D_FEATURE_LEVEL_11_0, got = {};
            IDXGISwapChain* swap = nullptr; ID3D11Device* dev = nullptr; ID3D11DeviceContext* ctx = nullptr;
            HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                                       &fl, 1, D3D11_SDK_VERSION, &sd, &swap, &dev, &got, &ctx);
            if (SUCCEEDED(hr) && swap) {
                void** vtbl = *(void***)swap;
                void* presentAddr = vtbl[8];
                void* resizeAddr = vtbl[13];

                HookEngine& eng = HookEngine::getInstance();
                if (presentAddr) {
                    eng.installInlineHook(presentAddr, reinterpret_cast<LPVOID>(&DXGIPresentDetour), reinterpret_cast<LPVOID*>(&DXGIPresentOriginal));
                    g_dxgiPresentAddr.store(presentAddr, std::memory_order_release);
                }
                if (resizeAddr) {
                    eng.installInlineHook(resizeAddr, reinterpret_cast<LPVOID>(&ResizeBuffersDetour), reinterpret_cast<LPVOID*>(&ResizeBuffersOriginal));
                    g_dxgiResizeAddr.store(resizeAddr, std::memory_order_release);
                }
                swap->Release();
            }
            if (ctx) ctx->Release();
            if (dev) dev->Release();
            if (hwnd) { DestroyWindow(hwnd); }
            UnregisterClassW(classNameDx11.c_str(), wc.hInstance);
        }

        // Also hook D3D11CreateDeviceAndSwapChain globally so future swap chains get covered
        HMODULE d3d11 = GetModuleHandleW(L"d3d11.dll");
        if (!d3d11) d3d11 = LoadLibraryW(L"d3d11.dll");
        if (d3d11) {
            void* pfn = reinterpret_cast<void*>(GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain"));
            if (pfn) {
                HookEngine& eng = HookEngine::getInstance();
                eng.installInlineHook(pfn, reinterpret_cast<LPVOID>(&D3D11CreateDeviceAndSwapChain_Detour), reinterpret_cast<LPVOID*>(&g_D3D11CreateDeviceAndSwapChain_Orig));
            }
        }
    }

    HookGraphicsCaptureInterop();
}

void Shutdown() {
    Debug("[DirectXHooks] Shutdown. Unhooking DirectX entries.\n");
    HookEngine& eng = HookEngine::getInstance();
    if (void* p = g_d3d9PresentAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_d3d9EndSceneAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiPresentAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiResizeAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiPresent1Addr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_d3d12QueueExecuteAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_factoryMediaCreateSwapchainAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dcompCreateDeviceAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_duplicateOutputAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_duplicationAcquireAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_captureForWindowAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_captureForMonitorAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiCreateSwapChainAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiCreateSwapChainHwndAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiCreateSwapChainCoreWindowAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_dxgiCreateSwapChainCompositionAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_createFactoryAddr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_createFactory1Addr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_createFactory2Addr.exchange(nullptr)) {
        eng.removeHook(p);
    }
    {
        std::lock_guard<std::mutex> lock(g_swapKindMutex);
        g_swapIsD3D12.clear();
    }
    // Remove D3D11CreateDeviceAndSwapChain hook if installed
    if (g_D3D11CreateDeviceAndSwapChain_Orig) {
        // We don't need the address to remove because our engine removes by target address
        HMODULE d3d11 = GetModuleHandleW(L"d3d11.dll");
        if (d3d11) {
            if (void* pfn = reinterpret_cast<void*>(GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain"))) {
                eng.removeHook(pfn);
            }
        }
        g_D3D11CreateDeviceAndSwapChain_Orig = nullptr;
    }
    CreateSwapChainOriginal = nullptr;
    CreateSwapChainForHwndOriginal = nullptr;
    CreateSwapChainForCoreWindowOriginal = nullptr;
    CreateSwapChainForCompositionOriginal = nullptr;
    CreateDXGIFactory_Orig = nullptr;
    CreateDXGIFactory1_Orig = nullptr;
    CreateDXGIFactory2_Orig = nullptr;
    DXGIPresent1Original = nullptr;
    D3D12ExecuteCommandListsOriginal = nullptr;
    CreateSwapChainForCompositionMedia_Orig = nullptr;
    DCompositionCreateDevice_Orig = nullptr;
    DuplicateOutputOriginal = nullptr;
    AcquireNextFrameOriginal = nullptr;
    CaptureForWindow_Orig = nullptr;
    CaptureForMonitor_Orig = nullptr;
}

} // namespace dxhooks

// =======================
// D3D9 detours & counters
// =======================
namespace dxhooks {
namespace {
HRESULT CallCaptureForWindowSafe(HWND hwnd, REFIID iid, void** item, HRESULT (WINAPI* orig)(HWND, REFIID, void**), bool& exceptionHit) {
    exceptionHit = false;
    HRESULT hr = E_FAIL;
    __try {
        hr = orig(hwnd, iid, item);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionHit = true;
    }
    return hr;
}

HRESULT CallCaptureForMonitorSafe(HMONITOR monitor, REFIID iid, void** item, HRESULT (WINAPI* orig)(HMONITOR, REFIID, void**), bool& exceptionHit) {
    exceptionHit = false;
    HRESULT hr = E_FAIL;
    __try {
        hr = orig(monitor, iid, item);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        exceptionHit = true;
    }
    return hr;
}

std::atomic<unsigned long long> g_d3d9EndScene{0};
std::atomic<unsigned long long> g_d3d9Present{0};
std::atomic<unsigned long long> g_dxgiPresent{0};
std::atomic<unsigned long long> g_d3d12Present{0};
std::atomic<unsigned long long> g_d3d12CommandSubmit{0};
std::atomic<unsigned long long> g_dcompCreateDevice{0};
std::atomic<unsigned long long> g_factoryMediaSwapchain{0};
std::atomic<unsigned long long> g_dxgiDupAcquire{0};
std::atomic<unsigned long long> g_graphicsCaptureWindow{0};
std::atomic<unsigned long long> g_graphicsCaptureMonitor{0};

    typedef HRESULT (APIENTRY* Present_t)(IDirect3DDevice9*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*);
    typedef HRESULT (APIENTRY* EndScene_t)(IDirect3DDevice9*);
}

HRESULT (APIENTRY* PresentOriginal)(IDirect3DDevice9*, CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*) = nullptr;
HRESULT (APIENTRY* EndSceneOriginal)(IDirect3DDevice9*) = nullptr;
HRESULT (STDMETHODCALLTYPE* DXGIPresentOriginal)(IDXGISwapChain*, UINT, UINT) = nullptr;
HRESULT (STDMETHODCALLTYPE* ResizeBuffersOriginal)(IDXGISwapChain*, UINT, UINT, UINT, DXGI_FORMAT, UINT) = nullptr;
HRESULT (STDMETHODCALLTYPE* CreateSwapChainOriginal)(IDXGIFactory*, IUnknown*, DXGI_SWAP_CHAIN_DESC*, IDXGISwapChain**) = nullptr;
HRESULT (STDMETHODCALLTYPE* CreateSwapChainForHwndOriginal)(IDXGIFactory2*, IUnknown*, HWND, const DXGI_SWAP_CHAIN_DESC1*, const DXGI_SWAP_CHAIN_FULLSCREEN_DESC*, IDXGIOutput*, IDXGISwapChain1**) = nullptr;
HRESULT (STDMETHODCALLTYPE* CreateSwapChainForCoreWindowOriginal)(IDXGIFactory2*, IUnknown*, IInspectable*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**) = nullptr;
HRESULT (STDMETHODCALLTYPE* CreateSwapChainForCompositionOriginal)(IDXGIFactory2*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**) = nullptr;
HRESULT (WINAPI* CreateDXGIFactory_Orig)(REFIID, void**) = nullptr;
HRESULT (WINAPI* CreateDXGIFactory1_Orig)(REFIID, void**) = nullptr;
HRESULT (WINAPI* CreateDXGIFactory2_Orig)(UINT, REFIID, void**) = nullptr;
HRESULT (STDMETHODCALLTYPE* DXGIPresent1Original)(IDXGISwapChain4*, UINT, UINT, const DXGI_PRESENT_PARAMETERS*) = nullptr;
void (STDMETHODCALLTYPE* D3D12ExecuteCommandListsOriginal)(ID3D12CommandQueue*, UINT, ID3D12CommandList* const*) = nullptr;
HRESULT (STDMETHODCALLTYPE* DuplicateOutputOriginal)(IDXGIOutput1*, IUnknown*, IDXGIOutputDuplication**) = nullptr;
HRESULT (STDMETHODCALLTYPE* AcquireNextFrameOriginal)(IDXGIOutputDuplication*, UINT, DXGI_OUTDUPLICATION_FRAME_INFO*, IDXGIResource**) = nullptr;
HRESULT (WINAPI* CaptureForWindow_Orig)(HWND, REFIID, void**) = nullptr;
HRESULT (WINAPI* CaptureForMonitor_Orig)(HMONITOR, REFIID, void**) = nullptr;
HRESULT (WINAPI* DCompositionCreateDevice_Orig)(IDXGIDevice*, REFIID, void**) = nullptr;
HRESULT (STDMETHODCALLTYPE* CreateSwapChainForCompositionMedia_Orig)(IDXGIFactoryMedia*, IUnknown*, const DXGI_SWAP_CHAIN_DESC1*, IDXGIOutput*, IDXGISwapChain1**) = nullptr;

HRESULT APIENTRY PresentDetour(IDirect3DDevice9* device, CONST RECT* src, CONST RECT* dst, HWND wnd, CONST RGNDATA* dirty) {
    (void)src; (void)dst; (void)wnd; (void)dirty;
    g_d3d9Present.fetch_add(1, std::memory_order_relaxed);
    if (g_presentCallback) g_presentCallback("d3d9");
    if (g_telemetryCallback) {
        std::ostringstream detail;
        detail << "device=" << HexPtr(device);
        if (const char* overlay = DetectOverlayTag()) {
            detail << " overlay=" << overlay;
        }
        EmitTelemetry("display", "D3D9::Present", detail.str());
    }
    return PresentOriginal ? PresentOriginal(device, src, dst, wnd, dirty) : D3D_OK;
}

HRESULT APIENTRY EndSceneDetour(IDirect3DDevice9* device) {
    (void)device;
    g_d3d9EndScene.fetch_add(1, std::memory_order_relaxed);
    return EndSceneOriginal ? EndSceneOriginal(device) : D3D_OK;
}

Stats GetStats() {
    Stats s{};
    s.d3d9EndScene = g_d3d9EndScene.load(std::memory_order_relaxed);
    s.d3d9Present = g_d3d9Present.load(std::memory_order_relaxed);
    s.dxgiPresent = g_dxgiPresent.load(std::memory_order_relaxed);
    s.d3d12Present = g_d3d12Present.load(std::memory_order_relaxed);
    s.d3d12CommandSubmit = g_d3d12CommandSubmit.load(std::memory_order_relaxed);
    s.dcompCreateDevice = g_dcompCreateDevice.load(std::memory_order_relaxed);
    s.dxgiFactoryMediaSwapchain = g_factoryMediaSwapchain.load(std::memory_order_relaxed);
    s.dxgiDupAcquire = g_dxgiDupAcquire.load(std::memory_order_relaxed);
    s.graphicsCaptureForWindow = g_graphicsCaptureWindow.load(std::memory_order_relaxed);
    s.graphicsCaptureForMonitor = g_graphicsCaptureMonitor.load(std::memory_order_relaxed);
    return s;
}

} // namespace dxhooks

// =======================
// DXGI detours
// =======================
namespace dxhooks {
HRESULT STDMETHODCALLTYPE DXGIPresentDetour(IDXGISwapChain* swap, UINT SyncInterval, UINT Flags) {
    g_dxgiPresent.fetch_add(1, std::memory_order_relaxed);
    bool blocked = false;
    if (g_policyCallback && swap) {
        blocked = g_policyCallback("swap_chain_present",
                                   reinterpret_cast<uintptr_t>(swap),
                                   static_cast<uintptr_t>(Flags));
    }
    bool isD3D12 = false;
    {
        std::lock_guard<std::mutex> lock(g_swapKindMutex);
        auto it = g_swapIsD3D12.find(swap);
        if (it == g_swapIsD3D12.end()) {
            Microsoft::WRL::ComPtr<ID3D12Device> device12;
            if (SUCCEEDED(swap->GetDevice(IID_PPV_ARGS(&device12)))) {
                isD3D12 = true;
            }
            g_swapIsD3D12.emplace(swap, isD3D12);
        } else {
            isD3D12 = it->second;
        }
    }
    HRESULT hr = S_OK;
    if (!blocked) {
        if (isD3D12) {
            g_d3d12Present.fetch_add(1, std::memory_order_relaxed);
            if (g_presentCallback) g_presentCallback("d3d12");
        } else {
            if (g_presentCallback) g_presentCallback("dxgi");
        }
        hr = DXGIPresentOriginal ? DXGIPresentOriginal(swap, SyncInterval, Flags) : S_OK;
    } else {
        hr = DXGI_ERROR_ACCESS_DENIED;
    }
    if (g_telemetryCallback) {
        std::ostringstream detail;
        detail << "swap=" << HexPtr(swap)
               << " interval=" << SyncInterval
               << " flags=0x" << std::hex << std::uppercase << Flags
               << " blocked=" << (blocked ? 1 : 0)
               << " hr=0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr);
        if (isD3D12) {
            detail << " d3d12=1";
        }
        if (const char* overlay = DetectOverlayTag()) {
            detail << " overlay=" << overlay;
        }
        detail << std::dec;
        EmitTelemetry("display", "DXGI::Present", detail.str());
    }
    return hr;
}

HRESULT STDMETHODCALLTYPE ResizeBuffersDetour(IDXGISwapChain* swap, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags) {
    {
        std::lock_guard<std::mutex> lock(g_swapKindMutex);
        g_swapIsD3D12.erase(swap);
    }
    return ResizeBuffersOriginal ? ResizeBuffersOriginal(swap, BufferCount, Width, Height, NewFormat, SwapChainFlags) : S_OK;
}

HRESULT STDMETHODCALLTYPE DXGIPresent1Detour(IDXGISwapChain4* swap, UINT SyncInterval, UINT Flags, const DXGI_PRESENT_PARAMETERS* params) {
    g_dxgiPresent.fetch_add(1, std::memory_order_relaxed);
    IDXGISwapChain* base = swap;
    bool blocked = false;
    if (g_policyCallback && swap) {
        blocked = g_policyCallback("swap_chain_present",
                                   reinterpret_cast<uintptr_t>(base),
                                   static_cast<uintptr_t>(Flags));
    }
    bool isD3D12 = false;
    {
        std::lock_guard<std::mutex> lock(g_swapKindMutex);
        auto it = g_swapIsD3D12.find(base);
        if (it == g_swapIsD3D12.end()) {
            Microsoft::WRL::ComPtr<ID3D12Device> device12;
            if (SUCCEEDED(base->GetDevice(IID_PPV_ARGS(&device12)))) {
                isD3D12 = true;
            }
            g_swapIsD3D12.emplace(base, isD3D12);
        } else {
            isD3D12 = it->second;
        }
    }
    HRESULT hr = S_OK;
    if (!blocked) {
        if (isD3D12) {
            g_d3d12Present.fetch_add(1, std::memory_order_relaxed);
            if (g_presentCallback) g_presentCallback("d3d12");
        } else {
            if (g_presentCallback) g_presentCallback("dxgi");
        }
        hr = DXGIPresent1Original ? DXGIPresent1Original(swap, SyncInterval, Flags, params) : S_OK;
    } else {
        hr = DXGI_ERROR_ACCESS_DENIED;
    }
    if (g_telemetryCallback) {
        DirtyRectSummary dirtySummary;
        RECT scrollRect{};
        bool hasScrollRect = false;
        POINT scrollOffset{};
        bool hasScrollOffset = false;

        if (params) {
            if (params->DirtyRectsCount && params->pDirtyRects) {
                dirtySummary = SummarizeDirtyRects(params->pDirtyRects, params->DirtyRectsCount);
            }
            if (params->pScrollRect) {
                if (IsReadableRange(params->pScrollRect, sizeof(RECT))) {
                    scrollRect = *params->pScrollRect;
                    hasScrollRect = true;
                } else {
                    hasScrollRect = false;
                }
            }
            if (params->pScrollOffset) {
                if (IsReadableRange(params->pScrollOffset, sizeof(POINT))) {
                    scrollOffset = *params->pScrollOffset;
                    hasScrollOffset = true;
                } else {
                    hasScrollOffset = false;
                }
            }
        }

        std::ostringstream detail;
        detail << "swap=" << HexPtr(base)
               << " interval=" << SyncInterval
               << " flags=0x" << std::hex << std::uppercase << Flags
               << " blocked=" << (blocked ? 1 : 0)
               << " hr=0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr)
               << " present1=1";
        if (const char* overlay = DetectOverlayTag()) {
            detail << " overlay=" << overlay;
        }
        if (params) {
            detail << " dirty=" << params->DirtyRectsCount;
            if (dirtySummary.valid) {
                LONG bboxWidth = std::max<LONG>(0, dirtySummary.right - dirtySummary.left);
                LONG bboxHeight = std::max<LONG>(0, dirtySummary.bottom - dirtySummary.top);
                detail << std::dec
                       << " dirty_bbox_w=" << bboxWidth
                       << " dirty_bbox_h=" << bboxHeight
                       << " dirty_bbox_area=" << dirtySummary.boundingArea
                       << " dirty_total_area=" << dirtySummary.totalArea;
                if (dirtySummary.truncated) {
                    detail << " dirty_trunc=1";
                }
                detail << std::hex << std::uppercase;
            }
            if (hasScrollRect) {
                detail << std::dec
                       << " scroll_rect=" << scrollRect.left << "," << scrollRect.top << ","
                       << scrollRect.right << "," << scrollRect.bottom
                       << std::hex << std::uppercase;
            }
            if (hasScrollOffset) {
                detail << std::dec
                       << " scroll_dx=" << scrollOffset.x
                       << " scroll_dy=" << scrollOffset.y
                       << std::hex << std::uppercase;
            }
        }
        if (isD3D12) {
            detail << " d3d12=1";
        }
        detail << std::dec;
        EmitTelemetry("display", "DXGI::Present1", detail.str());
    }
    return hr;
}

void STDMETHODCALLTYPE D3D12ExecuteCommandListsDetour(ID3D12CommandQueue* queue,
                                                      UINT numLists,
                                                      ID3D12CommandList* const* ppCommandLists) {
    g_d3d12CommandSubmit.fetch_add(1, std::memory_order_relaxed);
    auto orig = D3D12ExecuteCommandListsOriginal;
    if (orig) {
        orig(queue, numLists, ppCommandLists);
    }
}

HRESULT WINAPI DCompositionCreateDevice_Detour(IDXGIDevice* dxgiDevice,
                                               REFIID iid,
                                               void** surface) {
    g_dcompCreateDevice.fetch_add(1, std::memory_order_relaxed);
    HookGraphicsCaptureInterop();
    auto orig = DCompositionCreateDevice_Orig;
    if (!orig) {
        HMODULE dcomp = GetModuleHandleW(L"dcomp.dll");
        if (dcomp) {
            orig = reinterpret_cast<decltype(orig)>(GetProcAddress(dcomp, "DCompositionCreateDevice"));
            DCompositionCreateDevice_Orig = orig;
        }
    }
    if (!orig) {
        return E_FAIL;
    }
    return orig(dxgiDevice, iid, surface);
}

HRESULT STDMETHODCALLTYPE CreateSwapChainForCompositionMediaDetour(IDXGIFactoryMedia* factory,
                                                                   IUnknown* device,
                                                                   const DXGI_SWAP_CHAIN_DESC1* desc,
                                                                   IDXGIOutput* restrictToOutput,
                                                                   IDXGISwapChain1** swap) {
    HookGraphicsCaptureInterop();
    HookOutputIfNeeded(restrictToOutput);
    HookCommandQueueIfNeeded(device);
    g_factoryMediaSwapchain.fetch_add(1, std::memory_order_relaxed);
    auto orig = CreateSwapChainForCompositionMedia_Orig;
    if (!orig) {
        return DXGI_ERROR_INVALID_CALL;
    }
    return orig(factory, device, desc, restrictToOutput, swap);
}

HRESULT STDMETHODCALLTYPE DuplicateOutputDetour(IDXGIOutput1* output,
                                                IUnknown* device,
                                                IDXGIOutputDuplication** duplication) {
    HookCommandQueueIfNeeded(device);
    auto orig = DuplicateOutputOriginal;
    if (!orig && output) {
        void** vtbl = *(void***)output;
        if (vtbl) {
            orig = reinterpret_cast<decltype(orig)>(vtbl[kOutputDuplicateIndex]);
        }
    }
    if (!orig) {
        return DXGI_ERROR_INVALID_CALL;
    }
    HRESULT hr = orig(output, device, duplication);
    if (SUCCEEDED(hr) && duplication && *duplication) {
        HookDuplicationIfNeeded(*duplication);
    }
    IDXGIOutputDuplication* dupInstance = (duplication && *duplication) ? *duplication : nullptr;
    if (g_telemetryCallback) {
        std::ostringstream detail;
        detail << "hr=0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr);
        if (output) {
            detail << " output=" << HexPtr(output);
        }
        if (device) {
            detail << " device=" << HexPtr(device);
        }
        if (dupInstance) {
            detail << " dup=" << HexPtr(dupInstance);
        }
        EmitTelemetry("graphics", "DuplicateOutput", detail.str());
    }
    return hr;
}

HRESULT STDMETHODCALLTYPE AcquireNextFrameDetour(IDXGIOutputDuplication* duplication,
                                                 UINT timeout,
                                                 DXGI_OUTDUPLICATION_FRAME_INFO* info,
                                                 IDXGIResource** resource) {
    g_dxgiDupAcquire.fetch_add(1, std::memory_order_relaxed);
    if (g_policyCallback && duplication) {
        if (g_policyCallback("duplication_acquire",
                             reinterpret_cast<uintptr_t>(duplication),
                             static_cast<uintptr_t>(timeout))) {
            return DXGI_ERROR_ACCESS_DENIED;
        }
    }
    auto orig = AcquireNextFrameOriginal;
    if (!orig && duplication) {
        void** vtbl = *(void***)duplication;
        if (vtbl) {
            orig = reinterpret_cast<decltype(orig)>(vtbl[kDuplicationAcquireIndex]);
        }
    }
    HRESULT hr = orig ? orig(duplication, timeout, info, resource) : DXGI_ERROR_ACCESS_LOST;
    if (g_telemetryCallback) {
        std::ostringstream detail;
        detail << "hr=0x" << std::hex << std::uppercase << static_cast<unsigned long>(hr)
               << " dup=" << HexPtr(duplication)
               << " timeout=" << std::dec << timeout;
        if (info) {
            detail << " frames=" << info->AccumulatedFrames
                   << " last_present=" << static_cast<unsigned long long>(info->LastPresentTime.QuadPart)
                   << " pointer_visible=" << (info->PointerPosition.Visible ? 1 : 0);
            if (info->PointerPosition.Visible) {
                detail << " pointer_x=" << info->PointerPosition.Position.x
                       << " pointer_y=" << info->PointerPosition.Position.y;
            }
            detail << " pointer_shape=" << info->PointerShapeBufferSize;
        }
        if (resource && *resource) {
            detail << " resource=" << HexPtr(*resource);
        }
        EmitTelemetry("graphics", "AcquireNextFrame", detail.str());
    }
    return hr;
}

HRESULT STDMETHODCALLTYPE CreateSwapChainDetour(IDXGIFactory* factory,
                                                IUnknown* device,
                                                DXGI_SWAP_CHAIN_DESC* desc,
                                                IDXGISwapChain** swap) {
    HookCommandQueueIfNeeded(device);
    auto orig = CreateSwapChainOriginal;
    if (!orig && factory) {
        void** vtbl = *(void***)factory;
        orig = reinterpret_cast<decltype(orig)>(vtbl[10]);
    }
    HRESULT hr = orig ? orig(factory, device, desc, swap) : E_FAIL;
    if (SUCCEEDED(hr) && swap && *swap) {
        HookSwapChainIfNeeded(*swap);
    }
    return hr;
}

HRESULT STDMETHODCALLTYPE CreateSwapChainForHwndDetour(IDXGIFactory2* factory,
                                                       IUnknown* device,
                                                       HWND hwnd,
                                                       const DXGI_SWAP_CHAIN_DESC1* desc,
                                                       const DXGI_SWAP_CHAIN_FULLSCREEN_DESC* fs,
                                                       IDXGIOutput* restrictToOutput,
                                                       IDXGISwapChain1** swap) {
    HookOutputIfNeeded(restrictToOutput);
    HookCommandQueueIfNeeded(device);
    auto orig = CreateSwapChainForHwndOriginal;
    if (!orig && factory) {
        void** vtbl = *(void***)factory;
        orig = reinterpret_cast<decltype(orig)>(vtbl[15]);
    }
    HRESULT hr = orig ? orig(factory, device, hwnd, desc, fs, restrictToOutput, swap) : E_FAIL;
    if (SUCCEEDED(hr) && swap && *swap) {
        HookSwapChainIfNeeded(*swap);
    }
    return hr;
}

HRESULT STDMETHODCALLTYPE CreateSwapChainForCoreWindowDetour(IDXGIFactory2* factory,
                                                             IUnknown* device,
                                                             IInspectable* window,
                                                             const DXGI_SWAP_CHAIN_DESC1* desc,
                                                             IDXGIOutput* restrictToOutput,
                                                             IDXGISwapChain1** swap) {
    HookOutputIfNeeded(restrictToOutput);
    HookCommandQueueIfNeeded(device);
    auto orig = CreateSwapChainForCoreWindowOriginal;
    if (!orig && factory) {
        void** vtbl = *(void***)factory;
        orig = reinterpret_cast<decltype(orig)>(vtbl[16]);
    }
    HRESULT hr = orig ? orig(factory, device, window, desc, restrictToOutput, swap) : E_FAIL;
    if (SUCCEEDED(hr) && swap && *swap) {
        HookSwapChainIfNeeded(*swap);
    }
    return hr;
}

HRESULT STDMETHODCALLTYPE CreateSwapChainForCompositionDetour(IDXGIFactory2* factory,
                                                               IUnknown* device,
                                                               const DXGI_SWAP_CHAIN_DESC1* desc,
                                                               IDXGIOutput* restrictToOutput,
                                                               IDXGISwapChain1** swap) {
    HookOutputIfNeeded(restrictToOutput);
    HookCommandQueueIfNeeded(device);
    auto orig = CreateSwapChainForCompositionOriginal;
    if (!orig && factory) {
        void** vtbl = *(void***)factory;
        orig = reinterpret_cast<decltype(orig)>(vtbl[24]);
    }
    HRESULT hr = orig ? orig(factory, device, desc, restrictToOutput, swap) : E_FAIL;
    if (SUCCEEDED(hr) && swap && *swap) {
        HookSwapChainIfNeeded(*swap);
    }
    return hr;
}

HRESULT WINAPI CaptureForWindowDetour(HWND hwnd, REFIID iid, void** item) {
    g_graphicsCaptureWindow.fetch_add(1, std::memory_order_relaxed);
    if (g_policyCallback && hwnd) {
        if (g_policyCallback("capture_window", reinterpret_cast<uintptr_t>(hwnd), 0)) {
            return E_ACCESSDENIED;
        }
    }
    auto orig = CaptureForWindow_Orig;
    if (!orig) {
        HookGraphicsCaptureInterop();
        orig = CaptureForWindow_Orig;
    }
    if (!orig) {
        return E_NOINTERFACE;
    }
    bool exceptionHit = false;
    HRESULT result = CallCaptureForWindowSafe(hwnd, iid, item, orig, exceptionHit);
    if (exceptionHit) {
        g_graphicsCaptureHookFailed.store(true, std::memory_order_release);
        HookEngine& eng = HookEngine::getInstance();
        if (void* addr = g_captureForWindowAddr.exchange(nullptr)) {
            eng.removeHook(addr);
        }
        g_graphicsCaptureHookActive.store(false, std::memory_order_release);
        return E_FAIL;
    }
    if (g_telemetryCallback) {
        std::ostringstream detail;
        detail << "hr=0x" << std::hex << std::uppercase << static_cast<unsigned long>(result)
               << " hwnd=" << HexPtr(reinterpret_cast<const void*>(hwnd))
               << " iid=" << GuidToString(iid);
        if (item && *item) {
            detail << " item=" << HexPtr(*item);
        }
        EmitTelemetry("graphics", "GraphicsCaptureForWindow", detail.str());
    }
    return result;
}

HRESULT WINAPI CaptureForMonitorDetour(HMONITOR monitor, REFIID iid, void** item) {
    g_graphicsCaptureMonitor.fetch_add(1, std::memory_order_relaxed);
    if (g_policyCallback && monitor) {
        if (g_policyCallback("capture_monitor", reinterpret_cast<uintptr_t>(monitor), 0)) {
            return E_ACCESSDENIED;
        }
    }
    auto orig = CaptureForMonitor_Orig;
    if (!orig) {
        HookGraphicsCaptureInterop();
        orig = CaptureForMonitor_Orig;
    }
    if (!orig) {
        return E_NOINTERFACE;
    }
    bool exceptionHit = false;
    HRESULT result = CallCaptureForMonitorSafe(monitor, iid, item, orig, exceptionHit);
    if (exceptionHit) {
        g_graphicsCaptureHookFailed.store(true, std::memory_order_release);
        HookEngine& eng = HookEngine::getInstance();
        if (void* addr = g_captureForMonitorAddr.exchange(nullptr)) {
            eng.removeHook(addr);
        }
        g_graphicsCaptureHookActive.store(false, std::memory_order_release);
        return E_FAIL;
    }
    if (g_telemetryCallback) {
        std::ostringstream detail;
        detail << "hr=0x" << std::hex << std::uppercase << static_cast<unsigned long>(result)
               << " monitor=" << HexPtr(reinterpret_cast<const void*>(monitor))
               << " iid=" << GuidToString(iid);
        if (item && *item) {
            detail << " item=" << HexPtr(*item);
        }
        EmitTelemetry("graphics", "GraphicsCaptureForMonitor", detail.str());
    }
    return result;
}

bool GraphicsCaptureHooksActiveInternal() {
    return g_graphicsCaptureHookActive.load(std::memory_order_acquire) &&
           !g_graphicsCaptureHookFailed.load(std::memory_order_acquire);
}

HRESULT WINAPI CreateDXGIFactoryDetour(REFIID riid, void** ppFactory) {
    auto orig = CreateDXGIFactory_Orig;
    if (!orig) {
        HMODULE dxgi = GetModuleHandleW(L"dxgi.dll");
        if (dxgi) {
            orig = reinterpret_cast<decltype(orig)>(GetProcAddress(dxgi, "CreateDXGIFactory"));
        }
    }
    HRESULT hr = orig ? orig(riid, ppFactory) : E_FAIL;
    if (SUCCEEDED(hr) && ppFactory && *ppFactory) {
        Microsoft::WRL::ComPtr<IDXGIFactory> factory;
        if (SUCCEEDED(reinterpret_cast<IUnknown*>(*ppFactory)->QueryInterface(IID_PPV_ARGS(&factory))) && factory) {
            HookFactoryIfNeeded(factory.Get());
            HookGraphicsCaptureInterop();
        }
    }
    return hr;
}

HRESULT WINAPI CreateDXGIFactory1Detour(REFIID riid, void** ppFactory) {
    auto orig = CreateDXGIFactory1_Orig;
    if (!orig) {
        HMODULE dxgi = GetModuleHandleW(L"dxgi.dll");
        if (dxgi) {
            orig = reinterpret_cast<decltype(orig)>(GetProcAddress(dxgi, "CreateDXGIFactory1"));
        }
    }
    HRESULT hr = orig ? orig(riid, ppFactory) : E_FAIL;
    if (SUCCEEDED(hr) && ppFactory && *ppFactory) {
        Microsoft::WRL::ComPtr<IDXGIFactory> factory;
        if (SUCCEEDED(reinterpret_cast<IUnknown*>(*ppFactory)->QueryInterface(IID_PPV_ARGS(&factory))) && factory) {
            HookFactoryIfNeeded(factory.Get());
            HookGraphicsCaptureInterop();
        }
    }
    return hr;
}

HRESULT WINAPI CreateDXGIFactory2Detour(UINT Flags, REFIID riid, void** ppFactory) {
    auto orig = CreateDXGIFactory2_Orig;
    if (!orig) {
        HMODULE dxgi = GetModuleHandleW(L"dxgi.dll");
        if (dxgi) {
            orig = reinterpret_cast<decltype(orig)>(GetProcAddress(dxgi, "CreateDXGIFactory2"));
        }
    }
    HRESULT hr = orig ? orig(Flags, riid, ppFactory) : E_FAIL;
    if (SUCCEEDED(hr) && ppFactory && *ppFactory) {
        Microsoft::WRL::ComPtr<IDXGIFactory> factory;
        if (SUCCEEDED(reinterpret_cast<IUnknown*>(*ppFactory)->QueryInterface(IID_PPV_ARGS(&factory))) && factory) {
            HookFactoryIfNeeded(factory.Get());
            HookGraphicsCaptureInterop();
        }
    }
    return hr;
}
} // namespace dxhooks

// ===== D3D11 CreateDeviceAndSwapChain detour implementation =====
namespace dxhooks {
static void HookCommandQueueIfNeeded(IUnknown* device) {
    if (!device || g_d3d12QueueExecuteAddr.load(std::memory_order_acquire)) {
        return;
    }

    Microsoft::WRL::ComPtr<ID3D12CommandQueue> queue;
    if (SUCCEEDED(device->QueryInterface(IID_PPV_ARGS(&queue))) && queue) {
        void** vtbl = *(void***)queue.Get();
        const size_t kExecuteIndex = 10; // ID3D12CommandQueue::ExecuteCommandLists
        void* executeAddr = vtbl[kExecuteIndex];
        if (!executeAddr) {
            return;
        }
        HookEngine& eng = HookEngine::getInstance();
        if (eng.installInlineHook(executeAddr,
                                  reinterpret_cast<LPVOID>(&D3D12ExecuteCommandListsDetour),
                                  reinterpret_cast<LPVOID*>(&D3D12ExecuteCommandListsOriginal))) {
            g_d3d12QueueExecuteAddr.store(executeAddr, std::memory_order_release);
        }
    }
}

static void HookSwapChainIfNeeded(IDXGISwapChain* swap) {
    if (!swap) return;
    void** vtbl = *(void***)swap;
    void* presentAddr = vtbl[8];
    void* resizeAddr = vtbl[13];
    HookEngine& eng = HookEngine::getInstance();

    {
        bool isD3D12 = false;
        Microsoft::WRL::ComPtr<ID3D12Device> dev12;
        if (SUCCEEDED(swap->GetDevice(IID_PPV_ARGS(&dev12))) && dev12) {
            isD3D12 = true;
        }
        std::lock_guard<std::mutex> lock(g_swapKindMutex);
        g_swapIsD3D12[swap] = isD3D12;
    }

    if (presentAddr && !g_dxgiPresentAddr.load(std::memory_order_acquire)) {
        eng.installInlineHook(presentAddr, reinterpret_cast<LPVOID>(&DXGIPresentDetour), reinterpret_cast<LPVOID*>(&DXGIPresentOriginal));
        g_dxgiPresentAddr.store(presentAddr, std::memory_order_release);
    }
    if (resizeAddr && !g_dxgiResizeAddr.load(std::memory_order_acquire)) {
        eng.installInlineHook(resizeAddr, reinterpret_cast<LPVOID>(&ResizeBuffersDetour), reinterpret_cast<LPVOID*>(&ResizeBuffersOriginal));
        g_dxgiResizeAddr.store(resizeAddr, std::memory_order_release);
    }

    Microsoft::WRL::ComPtr<IDXGISwapChain4> swap4;
    if (SUCCEEDED(swap->QueryInterface(IID_PPV_ARGS(&swap4))) && swap4) {
        void** vtbl4 = *(void***)swap4.Get();
        const size_t kPresent1Index = 22;
        void* present1Addr = vtbl4[kPresent1Index];
        if (present1Addr && !g_dxgiPresent1Addr.load(std::memory_order_acquire)) {
            if (eng.installInlineHook(present1Addr,
                                      reinterpret_cast<LPVOID>(&DXGIPresent1Detour),
                                      reinterpret_cast<LPVOID*>(&DXGIPresent1Original))) {
                g_dxgiPresent1Addr.store(present1Addr, std::memory_order_release);
            }
        }
    }
}

static HRESULT WINAPI D3D11CreateDeviceAndSwapChain_Detour(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    HMODULE Software,
    UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
    IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext) {

    auto orig = g_D3D11CreateDeviceAndSwapChain_Orig;
    if (!orig) {
        // If the hook was installed but original not set, fallback to lookup
        HMODULE d3d11 = GetModuleHandleW(L"d3d11.dll");
        if (d3d11) orig = (D3D11CreateDeviceAndSwapChain_t)GetProcAddress(d3d11, "D3D11CreateDeviceAndSwapChain");
    }
    HRESULT hr = orig ? orig(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                              pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext)
                      : E_FAIL;
    if (SUCCEEDED(hr) && ppSwapChain && *ppSwapChain) {
        HookSwapChainIfNeeded(*ppSwapChain);
    }
    return hr;
}
} // namespace dxhooks

// ===== Public callback registration =====
namespace dxhooks {
void SetPresentCallback(std::function<void(const char* api)> cb) {
    g_presentCallback = std::move(cb);
}

void SetTelemetryCallback(TelemetryCallback cb) {
    g_telemetryCallback = std::move(cb);
}

void SetPolicyCallback(PolicyCallback cb) {
    g_policyCallback = std::move(cb);
}

bool GraphicsCaptureHooksActive() {
    return GraphicsCaptureHooksActiveInternal();
}

bool GraphicsCaptureHooksFailed() {
    return g_graphicsCaptureHookFailed.load(std::memory_order_acquire);
}
}
