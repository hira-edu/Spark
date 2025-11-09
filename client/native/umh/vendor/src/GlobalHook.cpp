// GlobalHook.cpp - System-wide global hook using SetWindowsHookEx
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <mutex>
#include <Psapi.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <atomic>
#include <algorithm>
#include "../include/MultiLayerHook.h"

// Shared data section for all processes
#pragma data_seg("SHARED")
HHOOK g_hHook = nullptr;
BOOL g_hookActive = FALSE;
#pragma data_seg()
#pragma comment(linker, "/SECTION:SHARED,RWS")

namespace {
std::once_flag g_processInitFlag;
HANDLE g_logFileMutex = nullptr;
std::mutex g_processedWindowsMutex;
std::set<HWND> g_processedWindows;
std::mutex g_hookInstallMutex;
std::atomic<bool> g_hookInstalled{false};

void PruneProcessedWindows_NoLock() {
    for (auto it = g_processedWindows.begin(); it != g_processedWindows.end(); ) {
        if (!IsWindow(*it)) {
            it = g_processedWindows.erase(it);
        } else {
            ++it;
        }
    }
}

using SetWindowDisplayAffinity_t = BOOL (WINAPI*)(HWND, DWORD);
SetWindowDisplayAffinity_t g_originalSetWindowDisplayAffinity = nullptr;
LPVOID g_setWindowDisplayAffinityTarget = nullptr;

std::string HookLayerToString(HookLayer layer) {
    switch (layer) {
    case HookLayer::Inline:
        return "inline";
    case HookLayer::IAT:
        return "iat";
    case HookLayer::EAT:
        return "eat";
    case HookLayer::VEH:
        return "veh";
    case HookLayer::Instrumentation:
        return "instrumentation";
    case HookLayer::Syscall:
        return "syscall";
    default:
        return "unknown";
    }
}

std::string DescribeInstalledLayers(const std::string& functionName) {
    auto contexts = QueryInstalledHooks();
    auto it = std::find_if(contexts.begin(), contexts.end(), [&](const HookContext& ctx) {
        return _stricmp(ctx.target.functionName.c_str(), functionName.c_str()) == 0;
    });
    if (it == contexts.end()) {
        return "none";
    }

    std::ostringstream oss;
    bool first = true;
    for (const auto& state : it->layers) {
        if (!state.installed) {
            continue;
        }
        if (!first) {
            oss << ", ";
        }
        oss << HookLayerToString(state.layer);
        if (!state.verified) {
            oss << "(!)";
        }
        first = false;
    }

    if (first) {
        return "none";
    }

    if (it->vehMetadata.has_value()) {
        oss << " [veh hits=" << it->vehMetadata->hitCount
            << " rearm=" << it->vehMetadata->rearmCount
            << (it->vehMetadata->autoDisabled ? " disabled" : "") << "]";
    }

    return oss.str();
}
}

// Export for SetWindowsHookEx
extern "C" __declspec(dllexport) LRESULT CALLBACK GlobalHookProc(int nCode, WPARAM wParam, LPARAM lParam);

void InitializeProcessResources() {
    CreateDirectoryW(L"C:\\Temp", nullptr);
    g_logFileMutex = CreateMutexW(nullptr, FALSE, L"GlobalHookLogMutex");
}

// Log to file
void LogHookEvent(const std::string& message) {
    std::call_once(g_processInitFlag, InitializeProcessResources);

    SYSTEMTIME st;
    GetLocalTime(&st);

    std::ostringstream builder;
    builder << "[" << std::setfill('0')
            << std::setw(2) << st.wHour << ":"
            << std::setw(2) << st.wMinute << ":"
            << std::setw(2) << st.wSecond << "] "
            << std::setfill(' ')
            << "[PID:" << GetCurrentProcessId() << "] "
            << message << '\n';

    HANDLE mutexHandle = g_logFileMutex;
    DWORD waitResult = WAIT_FAILED;
    if (mutexHandle) {
        waitResult = WaitForSingleObject(mutexHandle, 5000);
    }

    if (!mutexHandle || waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED) {
        std::ofstream logFile("C:\\Temp\\global_hook.log", std::ios::app);
        if (logFile.is_open()) {
            logFile << builder.str();
            logFile.flush();
        }
        if (mutexHandle) {
            ReleaseMutex(mutexHandle);
        }
    }
}

BOOL WINAPI HookedSetWindowDisplayAffinity(HWND hWnd, DWORD affinity) {
    LogHookEvent("Intercepted SetWindowDisplayAffinity request");

    if (g_originalSetWindowDisplayAffinity) {
        return g_originalSetWindowDisplayAffinity(hWnd, WDA_NONE);
    }

    auto fallback = reinterpret_cast<SetWindowDisplayAffinity_t>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowDisplayAffinity"));
    if (fallback) {
        return fallback(hWnd, WDA_NONE);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

bool InstallSetWindowDisplayAffinityHook() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (!user32) {
        user32 = LoadLibraryW(L"user32.dll");
    }

    FARPROC target = user32 ? GetProcAddress(user32, "SetWindowDisplayAffinity") : nullptr;
    if (!target) {
        LogHookEvent("Failed to resolve SetWindowDisplayAffinity");
        return false;
    }

    if (g_hookInstalled.load(std::memory_order_acquire)) {
        return true;
    }

    LPVOID original = nullptr;
    HookTargetDescriptor descriptor;
    descriptor.moduleName = L"user32.dll";
    descriptor.functionName = "SetWindowDisplayAffinity";

    if (!InstallMultiLayerHook(descriptor,
                               reinterpret_cast<LPVOID>(&HookedSetWindowDisplayAffinity),
                               &original,
                               {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation})) {
        LogHookEvent("Failed to install SetWindowDisplayAffinity hook");
        return false;
    }

    g_originalSetWindowDisplayAffinity =
        reinterpret_cast<SetWindowDisplayAffinity_t>(original);
    g_setWindowDisplayAffinityTarget = reinterpret_cast<LPVOID>(target);
    g_hookInstalled.store(true, std::memory_order_release);

    LogHookEvent("SetWindowDisplayAffinity hook installed");
    std::string layerSummary = DescribeInstalledLayers("SetWindowDisplayAffinity");
    if (!layerSummary.empty()) {
        LogHookEvent(std::string("    Layers: ") + layerSummary);
    }
    return true;
}

void RestoreSetWindowDisplayAffinityHook() {
    if (!g_hookInstalled.load(std::memory_order_acquire)) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_hookInstallMutex);

    if (g_setWindowDisplayAffinityTarget) {
        LogHookEvent("Skipping removal of SetWindowDisplayAffinity hook per configuration");
    }

    g_setWindowDisplayAffinityTarget = nullptr;
    g_originalSetWindowDisplayAffinity = nullptr;
    g_hookInstalled.store(false, std::memory_order_release);
}

// Hook SetWindowDisplayAffinity for current process
void HookCurrentProcess() {
    if (g_hookInstalled.load(std::memory_order_acquire)) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_hookInstallMutex);
    if (g_hookInstalled.load(std::memory_order_acquire)) {
        return;
    }

    if (!InstallSetWindowDisplayAffinityHook()) {
        LogHookEvent("Failed to install SetWindowDisplayAffinity hook for process");
    }
}

// Check if window uses display affinity
void CheckWindowDisplayAffinity(HWND hWnd) {
    if (!hWnd || !IsWindow(hWnd)) return;

    // Skip if already processed
    {
        std::lock_guard<std::mutex> lock(g_processedWindowsMutex);
        if (g_processedWindows.size() > 1024) {
            PruneProcessedWindows_NoLock();
        }

        auto insertResult = g_processedWindows.insert(hWnd);
        if (!insertResult.second) {
            return;
        }
    }

    // Get window process
    DWORD processId;
    DWORD threadId = GetWindowThreadProcessId(hWnd, &processId);

    // Get window title
    char windowTitle[256] = { 0 };
    GetWindowTextA(hWnd, windowTitle, sizeof(windowTitle));

    // Get process name
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        char processName[MAX_PATH] = { 0 };
        GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH);

        // Check if this is a process that typically uses display affinity
        std::string procName = processName;
        if (procName.find("discord") != std::string::npos ||
            procName.find("teams") != std::string::npos ||
            procName.find("zoom") != std::string::npos ||
            procName.find("obs") != std::string::npos ||
            procName.find("slack") != std::string::npos) {

            std::string msg = "Found potential display affinity user: " + procName;
            if (strlen(windowTitle) > 0) {
                msg += " - Window: " + std::string(windowTitle);
            }
            LogHookEvent(msg);

            // Attempt to reset display affinity
            SetWindowDisplayAffinity(hWnd, WDA_NONE);
        }

        CloseHandle(hProcess);
    }
}

// Global hook procedure
LRESULT CALLBACK GlobalHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        // Hook into current process if not already done
        HookCurrentProcess();

        // For WH_CALLWNDPROC hook
        if (nCode == HC_ACTION) {
            CWPSTRUCT* pCwp = (CWPSTRUCT*)lParam;
            if (pCwp) {
                // Check for window creation/activation
                if (pCwp->message == WM_CREATE ||
                    pCwp->message == WM_ACTIVATE ||
                    pCwp->message == WM_SHOWWINDOW) {

                    CheckWindowDisplayAffinity(pCwp->hwnd);
                }

                // Detect SetWindowDisplayAffinity calls indirectly
                if (pCwp->message == WM_DWMCOMPOSITIONCHANGED ||
                    pCwp->message == WM_DISPLAYCHANGE) {

                    // Force reset display affinity
                    SetWindowDisplayAffinity(pCwp->hwnd, WDA_NONE);
                }
            }
        }
    }

    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;

        case DLL_PROCESS_DETACH:
            RestoreSetWindowDisplayAffinityHook();
            if (g_logFileMutex) {
                CloseHandle(g_logFileMutex);
                g_logFileMutex = nullptr;
            }
            break;
    }
    return TRUE;
}

// Export function to install global hook
extern "C" __declspec(dllexport) BOOL InstallGlobalHook() {
    if (g_hHook != nullptr) {
        return FALSE;  // Already installed
    }

    HINSTANCE hInstance = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&InstallGlobalHook),
                            &hInstance)) {
        LogHookEvent("InstallGlobalHook: failed to resolve module handle");
        return FALSE;
    }

    // Install global hook (WH_CALLWNDPROC)
    g_hHook = SetWindowsHookEx(WH_CALLWNDPROC, GlobalHookProc, hInstance, 0);

    if (g_hHook != nullptr) {
        g_hookActive = TRUE;
        LogHookEvent("Global hook installed successfully");
        return TRUE;
    }

    LogHookEvent("SetWindowsHookEx failed to install global hook");
    return FALSE;
}

// Export function to uninstall global hook
extern "C" __declspec(dllexport) BOOL UninstallGlobalHook() {
    if (g_hHook == nullptr) {
        return FALSE;
    }

    BOOL result = UnhookWindowsHookEx(g_hHook);
    if (result) {
        g_hHook = nullptr;
        g_hookActive = FALSE;
        LogHookEvent("Global hook uninstalled");
        RestoreSetWindowDisplayAffinityHook();
    } else {
        LogHookEvent("UnhookWindowsHookEx failed to remove global hook");
    }

    return result;
}

// Export function to check hook status
extern "C" __declspec(dllexport) BOOL IsHookActive() {
    return g_hookActive;
}
