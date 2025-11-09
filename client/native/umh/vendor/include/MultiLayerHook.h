#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Enumerates the hook strategies we can apply. The order reflects preference.
enum class HookLayer : uint8_t {
    Inline = 0,
    IAT,
    EAT,
    VEH,
    Instrumentation,
    Syscall
};

// Tracks per-layer lifecycle so we can reason about health/repairs.
struct HookLayerState {
    HookLayer layer = HookLayer::Inline;
    bool installed = false;
    bool verified = false;
    bool bypassDetected = false;
    uint32_t failureCount = 0;
    ULONGLONG lastAttemptTick = 0;
    ULONGLONG lastSuccessTick = 0;
};

// Captures static metadata about a target function.
struct HookTargetDescriptor {
    std::wstring moduleName;     // L"user32.dll"
    std::string functionName;    // "SetWindowDisplayAffinity"
    uintptr_t resolvedRva = 0;   // Optional if moduleName supplied but address resolved at runtime
};

// Records runtime state for a single hooked function.
struct HookContext {
    HookTargetDescriptor target;
    LPVOID targetAddress = nullptr;
    LPVOID detour = nullptr;
    LPVOID original = nullptr;
    std::array<uint8_t, 32> originalBytes{};
    SIZE_T originalSize = 0;
    std::vector<HookLayerState> layers;
    bool isActive = false;
    bool isPinned = false;

    struct IATMetadata {
        LPVOID* slot = nullptr;          // Address inside IAT that we patched.
        LPVOID originalTarget = nullptr; // Value before we patched.
        HMODULE owningModule = nullptr;  // Module containing the IAT.
    };
    std::optional<IATMetadata> iatMetadata;

    struct EATMetadata {
        PDWORD exportEntry = nullptr;     // Pointer to the entry modified inside the export table.
        DWORD originalRva = 0;            // Original RVA recorded before patching.
        HMODULE owningModule = nullptr;   // Module whose export table we altered.
        bool shadowActive = false;
        LPBYTE shadowCopy = nullptr;
        SIZE_T shadowSize = 0;
        DWORD shadowRva = 0;
        DWORD originalDirectoryRva = 0;
        DWORD originalDirectorySize = 0;
#if defined(_WIN64)
        bool unwindRegistered = false;
        PRUNTIME_FUNCTION runtimeFunction = nullptr;
        LPVOID runtimeAllocation = nullptr;
        DWORD64 runtimeBase = 0;
#endif
    };
    std::optional<EATMetadata> eatMetadata;

    struct VEHMetadata {
        LPBYTE patchedAddress = nullptr;  // Address of the INT3 patch.
        BYTE originalByte = 0;
        bool armed = false;
        bool pendingRearm = false;
        uint64_t hitCount = 0;
        uint64_t rearmCount = 0;
        DWORD lastThreadId = 0;
        ULONGLONG pendingSinceTick = 0;
        uint32_t consecutiveFaults = 0;
        bool autoDisabled = false;
    };
    std::optional<VEHMetadata> vehMetadata;

    struct InstrumentationMetadata {
        bool installed = false;
    } instrumentation;

    struct SyscallMetadata {
        DWORD syscallNumber = 0;
        LPBYTE stubAddress = nullptr;
        SIZE_T patchLength = 0;
        BYTE returnOpcode = 0xC3;
        WORD returnOperand = 0;
        std::array<uint8_t, 32> originalBytes{};
        LPBYTE trampoline = nullptr;
        SIZE_T trampolineSize = 0;
    };
    std::optional<SyscallMetadata> syscallMetadata;
};

struct HookCapabilities {
    bool cfgEnabled = false;
    bool wow64Process = false;
    bool supportsInstrumentation = false;
    bool supportsVEH = true;
    bool supportsSyscall = true;
    bool supportsEATPatch = true;
};

// Registry responsible for storing hook contexts and coordinating repairs.
class HookRegistry {
public:
    static HookRegistry& instance();

    HookCapabilities capabilities() const;

    HookContext* find(const std::string& functionName);
    HookContext* findByAddress(LPVOID address);

    HookContext& add(const HookTargetDescriptor& descriptor, LPVOID detour);
    void remove(const std::string& functionName);
    void bindAddress(const std::string& functionName, LPVOID address);
    LPVOID getOriginal(const std::string& functionName) const;

    std::vector<HookContext> snapshot() const;

    void clear();
    void disableInstrumentationSupport();
    void disableSyscallSupport();

private:
    HookRegistry();
    HookRegistry(const HookRegistry&) = delete;
    HookRegistry& operator=(const HookRegistry&) = delete;

    void detectCapabilities();

    mutable std::mutex mutex_;
    std::map<std::string, HookContext> hooksByName_;
    std::map<LPVOID, std::string> hooksByAddress_;
    HookCapabilities capabilities_{};
    bool capabilitiesDetected_ = false;
};

// Utility to run a callback for each thread in the process. Used for instrumentation cleanup.
using ThreadEnumerationCallback = std::function<void(DWORD threadId, HANDLE threadHandle)>;
void ForEachThread(const ThreadEnumerationCallback& callback);

// Helper that temporarily changes page protection and restores it automatically.
class ScopedProtect {
public:
    ScopedProtect(LPVOID address, SIZE_T size, DWORD newProtect);
    ~ScopedProtect();

    bool succeeded() const { return success_; }

private:
    LPVOID address_ = nullptr;
    SIZE_T size_ = 0;
    DWORD oldProtect_ = 0;
    bool success_ = false;
};

class MultiLayerHookEngine;
MultiLayerHookEngine& GetMultiLayerHookEngine();

bool InstallMultiLayerHook(const HookTargetDescriptor& descriptor,
                           LPVOID detour,
                           LPVOID* original = nullptr,
                           const std::vector<HookLayer>& preferredLayers = {});

bool UninstallMultiLayerHook(const std::string& functionName);

std::vector<HookContext> QueryInstalledHooks();

void MonitorAndRepairHooks();
