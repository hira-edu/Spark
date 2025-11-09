#pragma once

#include <functional>
#include <string>
#include <cstdint>

namespace dxhooks {

// Initializes DirectX hooks (D3D9, DXGI/D3D11) if available and not disabled.
// Current implementation is a stub; real hooks will be added incrementally.
void Initialize();

// Tears down any DirectX hooks.
void Shutdown();

struct Stats {
    unsigned long long d3d9EndScene = 0;
    unsigned long long d3d9Present = 0;
    unsigned long long dxgiPresent = 0;
    unsigned long long d3d12Present = 0;
    unsigned long long d3d12CommandSubmit = 0;
    unsigned long long dcompCreateDevice = 0;
    unsigned long long dxgiFactoryMediaSwapchain = 0;
    unsigned long long dxgiDupAcquire = 0;
    unsigned long long graphicsCaptureForWindow = 0;
    unsigned long long graphicsCaptureForMonitor = 0;
};

Stats GetStats();

// Optional: callback invoked on each Present (D3D9, DXGI, D3D12)
// The callback receives the API name: "d3d9", "dxgi", or "d3d12".
void SetPresentCallback(std::function<void(const char* api)> cb);

using TelemetryCallback = std::function<void(const char* event, const char* func, const std::string& detail)>;

// Register a telemetry callback invoked when DirectX capture/copy detours emit structured events.
void SetTelemetryCallback(TelemetryCallback cb);

using PolicyCallback = std::function<bool(const char* operation, uintptr_t primary, uintptr_t secondary)>;

// Register a policy callback invoked before sensitive graphics APIs execute.
// Returning true blocks the original API and signals that enforcement was applied.
void SetPolicyCallback(PolicyCallback cb);

// Returns true if Win32 graphics capture detours were successfully installed.
bool GraphicsCaptureHooksActive();

// Returns true if Win32 graphics capture hooking was attempted but permanently disabled.
bool GraphicsCaptureHooksFailed();

}
