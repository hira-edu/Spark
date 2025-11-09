#include "../include/VulkanHooks.h"

#include <Windows.h>
#include "../include/HookEngine.h"
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <string>
#include <cstdint>

#if __has_include(<vulkan/vulkan.h>)
#include <vulkan/vulkan.h>
#else
#ifndef VKAPI_PTR
#define VKAPI_PTR __stdcall
#endif
typedef uint32_t VkResult;
#ifndef VK_SUCCESS
#define VK_SUCCESS 0
#endif
typedef struct VkInstance_T* VkInstance;
typedef struct VkDevice_T* VkDevice;
typedef struct VkQueue_T* VkQueue;
typedef struct VkSwapchainKHR_T* VkSwapchainKHR;
typedef struct VkSemaphore_T* VkSemaphore;
typedef struct VkFence_T* VkFence;
typedef struct VkCommandList_T* VkCommandList;
typedef void (VKAPI_PTR* PFN_vkVoidFunction)(void);
struct VkPresentInfoKHR;
struct VkCommandBuffer_T;
#endif


namespace vkhooks {
namespace {

using PFN_vkGetInstanceProcAddr = PFN_vkVoidFunction (VKAPI_PTR *)(VkInstance instance, const char* pName);
using PFN_vkGetDeviceProcAddr = PFN_vkVoidFunction (VKAPI_PTR *)(VkDevice device, const char* pName);
using PFN_vkQueuePresentKHR = VkResult (VKAPI_PTR *)(VkQueue queue, const VkPresentInfoKHR* pPresentInfo);
using PFN_vkAcquireNextImageKHR = VkResult (VKAPI_PTR *)(VkDevice device, VkSwapchainKHR swapchain, uint64_t timeout, VkSemaphore semaphore, VkFence fence, uint32_t* pImageIndex);

std::atomic<bool> g_initialized{false};
std::atomic<void*> g_hookedInstanceProc{nullptr};
std::atomic<void*> g_hookedDeviceProc{nullptr};
std::atomic<PFN_vkGetInstanceProcAddr> g_instanceProcOrig{nullptr};
std::atomic<PFN_vkGetDeviceProcAddr> g_deviceProcOrig{nullptr};
std::atomic<PFN_vkQueuePresentKHR> g_queuePresentOrig{nullptr};
std::atomic<PFN_vkAcquireNextImageKHR> g_acquireOrig{nullptr};
std::atomic<unsigned long long> g_queuePresentCount{0};
std::atomic<unsigned long long> g_acquireCount{0};
std::mutex g_trampolineMutex;
std::function<void()> g_presentCallback;

PFN_vkVoidFunction VKAPI_PTR vkGetInstanceProcAddr_Detour(VkInstance instance, const char* pName);
PFN_vkVoidFunction VKAPI_PTR vkGetDeviceProcAddr_Detour(VkDevice device, const char* pName);
VkResult VKAPI_PTR vkQueuePresentKHR_Detour(VkQueue queue, const VkPresentInfoKHR* pPresentInfo);
VkResult VKAPI_PTR vkAcquireNextImageKHR_Detour(VkDevice device, VkSwapchainKHR swapchain, uint64_t timeout, VkSemaphore semaphore, VkFence fence, uint32_t* pImageIndex);

bool EnvDisabled(const wchar_t* name) {
    wchar_t buf[32] = {};
    DWORD len = GetEnvironmentVariableW(name, buf, 32);
    if (!len || len >= 32) {
        return false;
    }
    std::wstring value(buf, buf + len);
    for (auto& c : value) {
        c = (wchar_t)towlower(c);
    }
    return (value == L"1" || value == L"true" || value == L"yes" || value == L"on");
}

PFN_vkVoidFunction HookFunction(const char* name, PFN_vkVoidFunction original) {
    if (!name || !original) {
        return original;
    }
    if (std::strcmp(name, "vkQueuePresentKHR") == 0) {
        g_queuePresentOrig.store(reinterpret_cast<PFN_vkQueuePresentKHR>(original), std::memory_order_release);
        return reinterpret_cast<PFN_vkVoidFunction>(&vkQueuePresentKHR_Detour);
    }
    if (std::strcmp(name, "vkAcquireNextImageKHR") == 0) {
        g_acquireOrig.store(reinterpret_cast<PFN_vkAcquireNextImageKHR>(original), std::memory_order_release);
        return reinterpret_cast<PFN_vkVoidFunction>(&vkAcquireNextImageKHR_Detour);
    }
    if (std::strcmp(name, "vkGetDeviceProcAddr") == 0) {
        g_deviceProcOrig.store(reinterpret_cast<PFN_vkGetDeviceProcAddr>(original), std::memory_order_release);
        return reinterpret_cast<PFN_vkVoidFunction>(&vkGetDeviceProcAddr_Detour);
    }
    return original;
}

PFN_vkVoidFunction VKAPI_PTR vkGetInstanceProcAddr_Detour(VkInstance instance, const char* pName) {
    auto orig = g_instanceProcOrig.load(std::memory_order_acquire);
    PFN_vkVoidFunction fn = orig ? orig(instance, pName) : nullptr;
    return HookFunction(pName, fn);
}

PFN_vkVoidFunction VKAPI_PTR vkGetDeviceProcAddr_Detour(VkDevice device, const char* pName) {
    auto orig = g_deviceProcOrig.load(std::memory_order_acquire);
    PFN_vkVoidFunction fn = orig ? orig(device, pName) : nullptr;
    return HookFunction(pName, fn);
}

VkResult VKAPI_PTR vkQueuePresentKHR_Detour(VkQueue queue, const VkPresentInfoKHR* pPresentInfo) {
    g_queuePresentCount.fetch_add(1, std::memory_order_relaxed);
    if (g_presentCallback) {
        try {
            g_presentCallback();
        } catch (...) {
        }
    }
    auto orig = g_queuePresentOrig.load(std::memory_order_acquire);
    return orig ? orig(queue, pPresentInfo) : VK_SUCCESS;
}

VkResult VKAPI_PTR vkAcquireNextImageKHR_Detour(VkDevice device, VkSwapchainKHR swapchain, uint64_t timeout, VkSemaphore semaphore, VkFence fence, uint32_t* pImageIndex) {
    g_acquireCount.fetch_add(1, std::memory_order_relaxed);
    auto orig = g_acquireOrig.load(std::memory_order_acquire);
    return orig ? orig(device, swapchain, timeout, semaphore, fence, pImageIndex) : VK_SUCCESS;
}

void InstallHook(void* target, std::atomic<void*>& storage, LPVOID detour, LPVOID* originalSlot) {
    if (!target || storage.load(std::memory_order_acquire)) {
        return;
    }
    HookEngine& eng = HookEngine::getInstance();
    if (eng.installInlineHook(target, detour, originalSlot)) {
        storage.store(target, std::memory_order_release);
    }
}

} // namespace

void Initialize() {
    if (g_initialized.exchange(true)) {
        return;
    }
    if (EnvDisabled(L"MLHOOK_DISABLE_VULKAN")) {
        return;
    }

    HMODULE vulkan = GetModuleHandleW(L"vulkan-1.dll");
    if (!vulkan) {
        vulkan = LoadLibraryW(L"vulkan-1.dll");
    }
    if (!vulkan) {
        g_initialized.store(false);
        return;
    }

    HookEngine& eng = HookEngine::getInstance();

    if (void* pfn = reinterpret_cast<void*>(GetProcAddress(vulkan, "vkGetInstanceProcAddr"))) {
        InstallHook(pfn,
                    g_hookedInstanceProc,
                    reinterpret_cast<LPVOID>(&vkGetInstanceProcAddr_Detour),
                    reinterpret_cast<LPVOID*>(&g_instanceProcOrig));
    }

    if (void* pfn = reinterpret_cast<void*>(GetProcAddress(vulkan, "vkGetDeviceProcAddr"))) {
        InstallHook(pfn,
                    g_hookedDeviceProc,
                    reinterpret_cast<LPVOID>(&vkGetDeviceProcAddr_Detour),
                    reinterpret_cast<LPVOID*>(&g_deviceProcOrig));
    }
}

void Shutdown() {
    HookEngine& eng = HookEngine::getInstance();
    if (void* p = g_hookedInstanceProc.exchange(nullptr)) {
        eng.removeHook(p);
    }
    if (void* p = g_hookedDeviceProc.exchange(nullptr)) {
        eng.removeHook(p);
    }
    g_instanceProcOrig.store(nullptr, std::memory_order_release);
    g_deviceProcOrig.store(nullptr, std::memory_order_release);
    g_queuePresentOrig.store(nullptr, std::memory_order_release);
    g_acquireOrig.store(nullptr, std::memory_order_release);
    g_queuePresentCount.store(0, std::memory_order_release);
    g_acquireCount.store(0, std::memory_order_release);
    g_presentCallback = nullptr;
    g_initialized.store(false);
}

Stats GetStats() {
    Stats stats{};
    stats.queuePresent = g_queuePresentCount.load(std::memory_order_relaxed);
    stats.acquireNextImage = g_acquireCount.load(std::memory_order_relaxed);
    return stats;
}

HookStatus GetHookStatus() {
    HookStatus status{};
    status.instanceProc = (g_hookedInstanceProc.load(std::memory_order_acquire) != nullptr);
    status.deviceProc = (g_hookedDeviceProc.load(std::memory_order_acquire) != nullptr);
    status.queuePresent = (g_queuePresentOrig.load(std::memory_order_acquire) != nullptr);
    status.acquireNextImage = (g_acquireOrig.load(std::memory_order_acquire) != nullptr);
    return status;
}

void SetPresentCallback(std::function<void()> cb) {
    g_presentCallback = std::move(cb);
}

} // namespace vkhooks
