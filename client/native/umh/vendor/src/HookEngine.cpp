#include "../include/HookEngine.h"
#include "../third_party/minhook/include/MinHook.h"
#include "../include/MultiLayerHook.h"
#include "../include/DirectXHooks.h"

#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <functional>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Psapi.lib")

namespace {

void LogMessage(const std::string& message) {
    OutputDebugStringA(message.c_str());
    std::cerr << message << std::endl;
}

void LogMinHookError(const char* context, MH_STATUS status) {
    std::ostringstream oss;
    oss << "[HookEngine] " << context << " failed: "
        << MH_StatusToString(status) << " (" << static_cast<int>(status) << ")";
    LogMessage(oss.str());
}

void LogWin32Error(const char* context) {
    DWORD error = GetLastError();
    std::ostringstream oss;
    oss << "[HookEngine] " << context << " failed. GetLastError=" << error;
    LogMessage(oss.str());
}

bool WithWritablePage(LPVOID address, const std::function<bool()>& fn) {
    SYSTEM_INFO sys{};
    GetNativeSystemInfo(&sys);
    SIZE_T pageSize = sys.dwPageSize ? sys.dwPageSize : 0x1000;
    uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    uintptr_t page = addr & ~(pageSize - 1);

    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(page), pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return fn();
    }

    bool result = fn();

    DWORD ignored = 0;
    VirtualProtect(reinterpret_cast<LPVOID>(page), pageSize, oldProtect, &ignored);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(page), pageSize);
    return result;
}

bool DisableHookWithUnprotect(LPVOID target, const char* context) {
    MH_STATUS status = MH_DisableHook(target);
    if (status == MH_OK || status == MH_ERROR_DISABLED) {
        return true;
    }
    if (status == MH_ERROR_MEMORY_PROTECT) {
        WithWritablePage(target, [&]() {
            MH_DisableHook(target);
            return true;
        });
        return true;
    }
    LogMinHookError(context, status);
    return false;
}

bool RemoveHookWithUnprotect(LPVOID target, const char* context) {
    MH_STATUS status = MH_RemoveHook(target);
    if (status == MH_OK || status == MH_ERROR_NOT_CREATED) {
        return true;
    }
    if (status == MH_ERROR_MEMORY_PROTECT) {
        WithWritablePage(target, [&]() {
            MH_RemoveHook(target);
            return true;
        });
        return true;
    }
    LogMinHookError(context, status);
    return false;
}

bool g_suppressUnknownHookLogs = false;

} // namespace

HookEngine& HookEngine::getInstance() {
    static HookEngine instance;
    return instance;
}

HookEngine::HookEngine() : initialized(false) {
    MH_STATUS status = MH_Initialize();
    if (status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED) {
        initialized = true;
    } else {
        LogMinHookError("MH_Initialize", status);
    }
}

HookEngine::~HookEngine() {
    removeAllHooks();
    if (initialized) {
        MH_Uninitialize();
        initialized = false;
    }
}

bool HookEngine::createInlineHookInternal(LPVOID targetFunc, LPVOID hookFunc, LPVOID* origFunc) {
    if (!initialized) {
        LogMessage("[HookEngine] createInlineHookInternal called before initialization.");
        return false;
    }
    if (!targetFunc || !hookFunc || !origFunc) {
        LogMessage("[HookEngine] Invalid parameters passed to createInlineHookInternal.");
        return false;
    }

    MH_STATUS status = MH_CreateHook(targetFunc, hookFunc, origFunc);
    if (status != MH_OK) {
        LogMinHookError("MH_CreateHook", status);
        return false;
    }

    status = MH_EnableHook(targetFunc);
    if (status != MH_OK) {
        LogMinHookError("MH_EnableHook", status);
        MH_STATUS cleanupStatus = MH_RemoveHook(targetFunc);
        if (cleanupStatus != MH_OK && cleanupStatus != MH_ERROR_NOT_CREATED) {
            LogMinHookError("MH_RemoveHook (cleanup)", cleanupStatus);
        }
        return false;
    }

    return true;
}

bool HookEngine::installHook(LPVOID targetFunc, LPVOID hookFunc, LPVOID* origFunc, const std::string& funcName) {
    if (!origFunc) {
        LogMessage("[HookEngine] installHook requires a valid origFunc pointer.");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex);

    if (!initialized) {
        LogMessage("[HookEngine] installHook called before initialization.");
        return false;
    }

    auto existing = std::find_if(hooks.begin(), hooks.end(),
        [targetFunc](const HookInfo& info) { return info.targetFunction == targetFunc; });
    if (existing != hooks.end()) {
        LogMessage("[HookEngine] installHook called for an already hooked function.");
        return false;
    }

    if (!createInlineHookInternal(targetFunc, hookFunc, origFunc)) {
        std::ostringstream oss;
        oss << "[HookEngine] Failed to install inline hook for " << funcName;
        LogMessage(oss.str());
        return false;
    }

    HookInfo info;
    info.targetFunction = targetFunc;
    info.hookFunction = hookFunc;
    info.originalFunction = *origFunc;
    info.functionName = funcName;
    info.isActive = true;
    hooks.push_back(info);

    return true;
}

bool HookEngine::installInlineHook(LPVOID targetFunc, LPVOID hookFunc, LPVOID* origFunc) {
    std::lock_guard<std::mutex> lock(mutex);

    if (!initialized) {
        LogMessage("[HookEngine] installInlineHook called before initialization.");
        return false;
    }

    auto existing = std::find_if(hooks.begin(), hooks.end(),
        [targetFunc](const HookInfo& info) { return info.targetFunction == targetFunc; });
    if (existing != hooks.end()) {
        LogMessage("[HookEngine] installInlineHook called for an already hooked function.");
        return false;
    }

    if (!createInlineHookInternal(targetFunc, hookFunc, origFunc)) {
        LogMessage("[HookEngine] installInlineHook failed.");
        return false;
    }

    HookInfo info;
    info.targetFunction = targetFunc;
    info.hookFunction = hookFunc;
    info.originalFunction = *origFunc;
    info.functionName.clear();
    info.isActive = true;
    hooks.push_back(info);

    return true;
}

bool HookEngine::installIATHook(const char* targetModule, const char* targetFunc, LPVOID hookFunc, LPVOID* origFunc) {
    if (!targetModule || !targetFunc || !hookFunc || !origFunc) {
        LogMessage("[HookEngine] installIATHook received invalid parameters.");
        return false;
    }

    HMODULE selfModule = GetModuleHandleW(nullptr);
    if (!selfModule) {
        LogWin32Error("GetModuleHandleW(nullptr)");
        return false;
    }

    ULONG importSize = 0;
    auto importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        ImageDirectoryEntryToData(selfModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &importSize));
    if (!importDesc) {
        LogMessage("[HookEngine] installIATHook failed to locate import descriptors.");
        return false;
    }

    for (; importDesc->Name != 0; ++importDesc) {
        const char* moduleName = reinterpret_cast<const char*>(
            reinterpret_cast<const BYTE*>(selfModule) + importDesc->Name);
        if (!moduleName || _stricmp(moduleName, targetModule) != 0) {
            continue;
        }

        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(selfModule) + importDesc->FirstThunk);
        auto originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(selfModule) + importDesc->OriginalFirstThunk);

        if (!thunk || !originalThunk) {
            LogMessage("[HookEngine] installIATHook encountered a module with missing thunk data.");
            return false;
        }

        for (; originalThunk->u1.AddressOfData != 0; ++thunk, ++originalThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                continue;
            }

            auto import = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                reinterpret_cast<BYTE*>(selfModule) + originalThunk->u1.AddressOfData);
            if (!import || !import->Name) {
                continue;
            }

            if (std::strcmp(reinterpret_cast<const char*>(import->Name), targetFunc) != 0) {
                continue;
            }

            DWORD oldProtect = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                LogWin32Error("VirtualProtect (IAT patch)");
                return false;
            }

            *origFunc = reinterpret_cast<LPVOID>(thunk->u1.Function);
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(hookFunc);

            FlushInstructionCache(GetCurrentProcess(), &thunk->u1.Function, sizeof(LPVOID));
            DWORD ignored = 0;
            VirtualProtect(&thunk->u1.Function, sizeof(LPVOID), oldProtect, &ignored);
            return true;
        }
    }

    std::ostringstream oss;
    oss << "[HookEngine] installIATHook could not find "
        << targetFunc << " in module " << targetModule;
    LogMessage(oss.str());
    return false;
}

bool HookEngine::removeHook(LPVOID targetFunc) {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = std::find_if(hooks.begin(), hooks.end(),
        [targetFunc](const HookInfo& info) { return info.targetFunction == targetFunc; });
    if (it == hooks.end()) {
        if (!g_suppressUnknownHookLogs) {
            LogMessage("[HookEngine] removeHook called with unknown target.");
        }
        return false;
    }

    if (initialized) {
        if (!DisableHookWithUnprotect(targetFunc, "MH_DisableHook")) {
            return false;
        }
        if (!RemoveHookWithUnprotect(targetFunc, "MH_RemoveHook")) {
            return false;
        }
    }

    hooks.erase(it);
    return true;
}

void HookEngine::removeAllHooks() {
    std::lock_guard<std::mutex> lock(mutex);
    g_suppressUnknownHookLogs = true;

    if (initialized) {
        for (const auto& hook : hooks) {
            DisableHookWithUnprotect(hook.targetFunction, "MH_DisableHook (removeAllHooks)");
            RemoveHookWithUnprotect(hook.targetFunction, "MH_RemoveHook (removeAllHooks)");
        }
    }

    hooks.clear();
}

bool HookEngine::enableHook(LPVOID targetFunc, bool enable) {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = std::find_if(hooks.begin(), hooks.end(),
        [targetFunc](const HookInfo& info) { return info.targetFunction == targetFunc; });
    if (it == hooks.end()) {
        LogMessage("[HookEngine] enableHook called with unknown target.");
        return false;
    }

    if (!initialized) {
        LogMessage("[HookEngine] enableHook called before initialization.");
        return false;
    }

    MH_STATUS status = enable ? MH_EnableHook(targetFunc) : MH_DisableHook(targetFunc);
    if (status != MH_OK) {
        if (!(enable && status == MH_ERROR_ENABLED) && !( !enable && status == MH_ERROR_DISABLED)) {
            LogMinHookError(enable ? "MH_EnableHook" : "MH_DisableHook", status);
            return false;
        }
    }

    it->isActive = enable;
    return true;
}

std::vector<HookInfo> HookEngine::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex);
    return hooks;
}

bool HookEngine::queryHookByTarget(LPVOID targetFunc, HookInfo& outInfo) const {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = std::find_if(hooks.begin(), hooks.end(),
        [targetFunc](const HookInfo& info) { return info.targetFunction == targetFunc; });
    if (it == hooks.end()) {
        return false;
    }

    outInfo = *it;
    return true;
}

bool HookEngine::queryHookByName(const std::string& funcName, HookInfo& outInfo) const {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = std::find_if(hooks.begin(), hooks.end(), [&](const HookInfo& info) {
        return _stricmp(info.functionName.c_str(), funcName.c_str()) == 0;
    });
    if (it == hooks.end()) {
        return false;
    }

    outInfo = *it;
    return true;
}

namespace {
    std::string LayerToString(HookLayer layer) {
        switch (layer) {
        case HookLayer::Inline:          return "inline";
        case HookLayer::IAT:             return "iat";
        case HookLayer::EAT:             return "eat";
        case HookLayer::VEH:             return "veh";
        case HookLayer::Instrumentation: return "instrumentation";
        case HookLayer::Syscall:         return "syscall";
        default:                         return "unknown";
        }
    }

    // Escape a string minimally for JSON (quotes and backslashes)
    std::string JsonEscape(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
            }
        }
        return out;
    }
}

std::vector<HookEngine::HookTelemetry> HookEngine::telemetrySnapshot() const {
    // Pull live contexts from the multi-layer registry
    std::vector<HookContext> contexts = QueryInstalledHooks();
    std::vector<HookTelemetry> out;
    out.reserve(contexts.size());

    for (const auto& ctx : contexts) {
        HookTelemetry t;
        t.functionName = ctx.target.functionName;
        t.isActive = ctx.isActive;
        t.layers.reserve(ctx.layers.size());
        for (const auto& st : ctx.layers) {
            HookLayerStatus s;
            s.layer = LayerToString(st.layer);
            s.installed = st.installed;
            s.verified = st.verified;
            s.bypassDetected = st.bypassDetected;
            s.failureCount = st.failureCount;
            t.layers.push_back(std::move(s));
        }
        if (ctx.vehMetadata.has_value()) {
            t.vehHitCount = ctx.vehMetadata->hitCount;
            t.vehRearmCount = ctx.vehMetadata->rearmCount;
            t.vehAutoDisabled = ctx.vehMetadata->autoDisabled;
        }
        out.push_back(std::move(t));
    }

    // Also expose any legacy inline/IAT-only hooks that may not be registered
    // in the multi-layer registry (defensive). These will show only an "inline"
    // layer entry if not already represented above.
    {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& h : hooks) {
            bool already = false;
            for (const auto& existing : out) {
                if (_stricmp(existing.functionName.c_str(), h.functionName.c_str()) == 0) {
                    already = true; break;
                }
            }
            if (already) continue;

            HookTelemetry t;
            t.functionName = h.functionName.empty() ? "(anonymous)" : h.functionName;
            t.isActive = h.isActive;
            HookLayerStatus s;
            s.layer = "inline";
            s.installed = true;
            s.verified = h.isActive; // best-effort signal
            s.bypassDetected = false;
            s.failureCount = 0;
            t.layers.push_back(std::move(s));
            out.push_back(std::move(t));
        }
    }

    return out;
}

bool HookEngine::getHookTelemetry(const std::string& functionName, HookTelemetry& out) const {
    auto all = telemetrySnapshot();
    auto it = std::find_if(all.begin(), all.end(), [&](const HookTelemetry& t) {
        return _stricmp(t.functionName.c_str(), functionName.c_str()) == 0;
    });
    if (it == all.end()) return false;
    out = *it;
    return true;
}

std::string HookEngine::exportTelemetryJson() const {
    auto all = telemetrySnapshot();
    std::ostringstream oss;
    oss << "[";
    bool firstHook = true;
    for (const auto& t : all) {
        if (!firstHook) oss << ",";
        firstHook = false;
        oss << "{\"function\":\"" << JsonEscape(t.functionName) << "\",";
        oss << "\"active\":" << (t.isActive ? "true" : "false") << ",";
        oss << "\"veh\":{\"hits\":" << t.vehHitCount
            << ",\"rearm\":" << t.vehRearmCount
            << ",\"disabled\":" << (t.vehAutoDisabled ? "true" : "false")
            << "},";
        oss << "\"layers\":[";
        bool firstLayer = true;
        for (const auto& s : t.layers) {
            if (!firstLayer) oss << ",";
            firstLayer = false;
            oss << "{\"name\":\"" << JsonEscape(s.layer) << "\",";
            oss << "\"installed\":" << (s.installed ? "true" : "false") << ",";
            oss << "\"verified\":" << (s.verified ? "true" : "false") << ",";
            oss << "\"bypass\":" << (s.bypassDetected ? "true" : "false") << ",";
            oss << "\"failures\":" << s.failureCount << "}";
        }
        oss << "]}";
    }
    // Append DX telemetry as synthetic entry
    {
        auto dx = dxhooks::GetStats();
        if (!firstHook) oss << ",";
        oss << "{\"function\":\"dx\",\"dx\":{"
               "\"d3d9_end_scene\":" << dx.d3d9EndScene << ","
               "\"d3d9_present\":" << dx.d3d9Present << ","
               "\"dxgi_present\":" << dx.dxgiPresent << "}}";
    }
    oss << "]";
    return oss.str();
}
