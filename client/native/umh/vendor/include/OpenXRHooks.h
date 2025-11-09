#pragma once

#include <functional>
#include <string>
#include <cstdint>

namespace openxrhooks {

struct Stats {
    unsigned long long waitFrame = 0;
    unsigned long long beginFrame = 0;
    unsigned long long endFrame = 0;
    unsigned long long acquireSwapchainImage = 0;
    unsigned long long releaseSwapchainImage = 0;
};

using TelemetryCallback = std::function<void(const char* function, const std::string& detail)>;
using PolicyCallback = std::function<bool(const char* operation, uintptr_t primary, uintptr_t secondary)>;

// Install OpenXR detours if the loader is present.
void Initialize();

// Remove any OpenXR detours that were installed.
void Shutdown();

// Retrieve cumulative counters for instrumented OpenXR APIs.
Stats GetStats();

// Structured telemetry callback invoked whenever an OpenXR detour executes.
void SetTelemetryCallback(TelemetryCallback cb);

// Policy callback invoked before sensitive OpenXR APIs execute.
// Returning true indicates the call should be blocked.
void SetPolicyCallback(PolicyCallback cb);

} // namespace openxrhooks

