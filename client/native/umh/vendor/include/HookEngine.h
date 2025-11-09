#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <optional>

// Hook structure for managing individual hooks
struct HookInfo {
    LPVOID targetFunction = nullptr;
    LPVOID hookFunction = nullptr;
    LPVOID originalFunction = nullptr;
    std::string functionName;
    bool isActive = false;
};

class HookEngine {
public:
    static HookEngine& getInstance();

    // Install a hook on a target function
    bool installHook(LPVOID targetFunc, LPVOID hookFunc, LPVOID* origFunc, const std::string& funcName);

    // Remove a specific hook
    bool removeHook(LPVOID targetFunc);

    // Remove all hooks
    void removeAllHooks();

    // Inline hooking implementation
    bool installInlineHook(LPVOID targetFunc, LPVOID hookFunc, LPVOID* origFunc);

    // IAT (Import Address Table) hooking
    bool installIATHook(const char* targetModule, const char* targetFunc, LPVOID hookFunc, LPVOID* origFunc);

    // Enable or disable a specific hook if it is installed.
    bool enableHook(LPVOID targetFunc, bool enable);

    // Snapshot current hook metadata for diagnostics.
    std::vector<HookInfo> snapshot() const;
    bool queryHookByTarget(LPVOID targetFunc, HookInfo& outInfo) const;
    bool queryHookByName(const std::string& funcName, HookInfo& outInfo) const;

    // Rich introspection/telemetry (multi-layer aware)
    struct HookLayerStatus {
        std::string layer;       // inline, iat, eat, veh, instrumentation, syscall
        bool installed = false;
        bool verified = false;
        bool bypassDetected = false;
        uint32_t failureCount = 0;
    };

    struct HookTelemetry {
        std::string functionName;
        bool isActive = false;
        std::vector<HookLayerStatus> layers;
        // VEH counters (if applicable)
        uint64_t vehHitCount = 0;
        uint64_t vehRearmCount = 0;
        bool vehAutoDisabled = false;
    };

    // Produce a snapshot of telemetry for all registered hooks.
    std::vector<HookTelemetry> telemetrySnapshot() const;

    // Lookup telemetry for a single function by name (case-insensitive).
    bool getHookTelemetry(const std::string& functionName, HookTelemetry& out) const;

    // Convenience: export the telemetry snapshot as a compact JSON string.
    // This avoids external JSON dependencies while remaining easy to parse.
    std::string exportTelemetryJson() const;

private:
    HookEngine();
    ~HookEngine();

    std::vector<HookInfo> hooks;
    mutable std::mutex mutex;
    bool initialized;

    bool createInlineHookInternal(LPVOID targetFunc, LPVOID hookFunc, LPVOID* origFunc);

    // Prevent copying
    HookEngine(const HookEngine&) = delete;
    HookEngine& operator=(const HookEngine&) = delete;
};

// Macro for easier hook declaration
#define DECLARE_HOOK(returnType, callingConvention, functionName, ...) \
    typedef returnType (callingConvention* functionName##_t)(__VA_ARGS__); \
    functionName##_t Original##functionName = nullptr; \
    returnType callingConvention Hook##functionName(__VA_ARGS__)
