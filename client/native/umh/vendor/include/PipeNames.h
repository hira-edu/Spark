#pragma once

#include <Windows.h>
#include <cstddef>

namespace pipes {

constexpr const wchar_t kControlPipeName[] = L"\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-control";
constexpr const wchar_t kServicePipeName[] = L"\\\\.\\pipe\\{95c1a2e0-f84e-4c8a-9c32}-service";
constexpr const wchar_t kTelemetryPipePattern[] = L"\\\\.\\pipe\\{3a8c7f2b-7f4d-4c5e-b120}-tlm-%08X";

inline void FormatTelemetryPipe(wchar_t* buffer, size_t count, DWORD pid) {
    if (!buffer || count == 0) {
        return;
    }
    _snwprintf_s(buffer, count, _TRUNCATE, kTelemetryPipePattern, pid);
}

} // namespace pipes
