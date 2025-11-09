// HookDLL.cpp - Advanced Hook DLL instrumentation without bypass behaviour
#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include "../include/HookEngine.h"
#include "../include/MultiLayerHook.h"
#include "../include/DirectSyscall.h"
#include <iomanip>
#include <algorithm>
#include <mutex>
#include <cwctype>
#include <atomic>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <deque>
#include <cstdio>
#include <dinput.h>
#include <set>
#include <limits>
#include <unordered_set>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <array>
#include <bcrypt.h>
#include <wrl/client.h>
#include <dxgi1_6.h>
#include "../include/DirectXHooks.h"
#include "../include/VulkanHooks.h"
#include "../include/OpenXRHooks.h"
#include "../include/PipeNames.h"
#include "../include/JsonUtil.h"
#include "../include/Config.h"

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

HHOOK WINAPI HookSetWindowsHookExW(int idHook,
                                   HOOKPROC lpfn,
                                   HINSTANCE hmod,
                                   DWORD dwThreadId);
HHOOK WINAPI HookSetWindowsHookExA(int idHook,
                                   HOOKPROC lpfn,
                                   HINSTANCE hmod,
                                   DWORD dwThreadId);

#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// Forward declaration for uninstallation routine defined later
void UninstallHooks();

// Anti-detection API (linked from static lib)
extern "C" {
    bool DetectAnalysis();
    void ApplyAntiAnalysis();
    void* CreateTimingEvasion();
    bool DetectTiming(void* instance);
void DestroyTimingEvasion(void* instance);
}

// Log file for monitoring
namespace {
void RotateLogFileIfNeeded();
int ExtractTriState(const std::string& src,
                    const char* key,
                    bool& found);
void ApplyPolicyOverride(std::atomic<int>& storage,
                         int state,
                         const char* name);
void ParseHandleList(const std::string& src,
                     const char* key,
                     std::vector<uintptr_t>& outHandles);
void ApplyHandlePolicy(std::unordered_set<uintptr_t>& storage,
                       const std::vector<uintptr_t>& handles,
                       bool add,
                       const char* event,
                       const char* label);

HANDLE g_logMutex = nullptr;
CRITICAL_SECTION g_logCs;
std::ofstream g_logFile;
std::once_flag g_logInitOnce;
bool g_logAvailable = false;
bool g_memoryLogEnabled = false;
bool g_telemetryEnabled = true;
bool g_telemetryEncrypt = true;
bool g_pipeOnlyMode = false;
bool g_diskSinkDisabled = false;
bool g_debugFallbackEnabled = true;
std::vector<uint8_t> g_logKey;
std::string g_logPathUtf8;
size_t g_maxLogBytes = 1024 * 1024; // 1 MB default
constexpr size_t kMemoryLogLimitDefault = 512;
size_t g_memoryLogLimit = kMemoryLogLimitDefault;
struct MemoryLogEntry {
    SYSTEMTIME timestamp{};
    std::string payload;
    bool encrypted = false;
};
std::mutex g_memoryLogMutex;
std::deque<MemoryLogEntry> g_memoryLog;
HMODULE g_selfModule = nullptr;
std::mutex g_hookManagementMutex;
bool g_installAttempted = false;
bool g_installSucceeded = false;
HANDLE g_pipeStopEvent = nullptr;
HANDLE g_pipeThread = nullptr;
HANDLE g_graphicsScanThread = nullptr;
HANDLE g_graphicsScanStopEvent = nullptr;
std::atomic<void*> g_directInput8CreateAddr{nullptr};
std::atomic<void*> g_dinputCreateDeviceAddr{nullptr};
std::atomic<void*> g_dinputAcquireAddr{nullptr};
std::atomic<void*> g_dinputSetCoopAddr{nullptr};
std::mutex g_graphicsModuleMutex;
std::set<std::wstring> g_reportedGraphicsModules;
std::atomic<int> g_forceInputPolicy{0};
std::atomic<int> g_forceWdaPolicy{0};
std::mutex g_graphicsPolicyMutex;
std::unordered_set<uintptr_t> g_blockedDuplicationHandles;
std::unordered_set<uintptr_t> g_blockedWindowTargets;
std::unordered_set<uintptr_t> g_blockedMonitorTargets;
std::unordered_set<uintptr_t> g_blockedSwapChains;
constexpr DWORD kSessionUnknown = 0xFFFFFFFF;
std::atomic<DWORD> g_cachedSessionId{kSessionUnknown};

DWORD CurrentSessionId() {
    DWORD cached = g_cachedSessionId.load(std::memory_order_acquire);
    if (cached != kSessionUnknown) {
        return cached;
    }
    DWORD session = kSessionUnknown;
    DWORD value = 0;
    if (ProcessIdToSessionId(GetCurrentProcessId(), &value)) {
        session = value;
    }
    DWORD expected = kSessionUnknown;
    g_cachedSessionId.compare_exchange_strong(expected, session, std::memory_order_release, std::memory_order_relaxed);
    return session;
}

std::string AppendSessionDetail(const std::string& detail) {
    DWORD session = CurrentSessionId();
    if (session == kSessionUnknown) {
        return detail;
    }
    if (detail.empty()) {
        return std::string("session=") + std::to_string(session);
    }
    std::string augmented = detail;
    augmented.append(" session=").append(std::to_string(session));
    return augmented;
}

// Legacy/unused; actual server is defined later in file
DWORD WINAPI TelemetryPipeServer_UNUSED(LPVOID) {
    DWORD pid = GetCurrentProcessId();
    wchar_t pipeName[128] = {};
    pipes::FormatTelemetryPipe(pipeName, _countof(pipeName), pid);

    for (;;) {
        HANDLE hPipe = CreateNamedPipeW(pipeName,
                                        PIPE_ACCESS_DUPLEX,
                                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                        1,
                                        64 * 1024,
                                        64 * 1024,
                                        0,
                                        nullptr);
        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }

        HANDLE waitObjs[2] = { g_pipeStopEvent, hPipe };
        BOOL connected = ConnectNamedPipe(hPipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(hPipe);
            if (WaitForSingleObject(g_pipeStopEvent, 0) == WAIT_OBJECT_0) break;
            continue;
        }

        // Simple protocol: any read triggers emit of JSON telemetry
        char req[8] = {};
        DWORD rd = 0; ReadFile(hPipe, req, sizeof(req), &rd, nullptr);

        // Build telemetry JSON
        std::ostringstream oss;
        oss << "{";
        // HookEngine telemetry summary
        try {
            HookEngine& eng = HookEngine::getInstance();
            auto infos = eng.snapshot();
            oss << "\"hooks\":[";
            for (size_t i = 0; i < infos.size(); ++i) {
                const auto& hi = infos[i];
                if (i) oss << ",";
                // Minimal ASCII escape for JSON
                std::string esc; esc.reserve(hi.functionName.size()+8);
                for (char c : hi.functionName) { if (c=='\\\\') esc+="\\\\"; else if (c=='\"') esc+="\\\""; else if (c=='\n') esc+="\\n"; else if (c=='\r') esc+="\\r"; else if (c=='\t') esc+="\\t"; else esc+=c; }
                oss << "{\"name\":\"" << esc << "\",\"active\":" << (hi.isActive ? 1 : 0) << "}";
            }
            oss << "],";
        } catch (...) {
            // ignore
        }
        // DX stats
        auto s = dxhooks::GetStats();
        oss << "\"dx\":{\"d3d9_end\":" << s.d3d9EndScene << ",\"d3d9_present\":" << s.d3d9Present
            << ",\"dxgi_present\":" << s.dxgiPresent << "}}";

        std::string body = oss.str();
        DWORD wr = 0; WriteFile(hPipe, body.data(), (DWORD)body.size(), &wr, nullptr);
        FlushFileBuffers(hPipe);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        if (WaitForSingleObject(g_pipeStopEvent, 0) == WAIT_OBJECT_0) break;
    }
    return 0;
}

// Ensure we can disable all active hooks when requested via pipe
static void InternalUninstallAllHooks() {
    try {
        // Remove multi-layer hooks first (if any)
        auto contexts = QueryInstalledHooks();
        for (const auto& ctx : contexts) {
            if (!ctx.target.functionName.empty()) {
                UninstallMultiLayerHook(ctx.target.functionName);
            }
        }
    } catch (...) {
        // ignore
    }
    try { HookEngine::getInstance().removeAllHooks(); } catch (...) {}
}

bool EnvOrRegEnabled(const wchar_t* name) {
    if (!name) return false;
    wchar_t buf[32] = {}; DWORD len = GetEnvironmentVariableW(name, buf, 32);
    if (len && len < 32) {
        std::wstring v(buf, buf+len); for (auto& c : v) c=(wchar_t)towlower(c);
        if (v==L"1"||v==L"true"||v==L"yes"||v==L"on") return true;
        if (v==L"0"||v==L"false"||v==L"no"||v==L"off") return false;
    }
    HKEY hKey=nullptr; if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\UserModeHook\\Flags", 0, KEY_QUERY_VALUE, &hKey)==ERROR_SUCCESS) {
        wchar_t val[32] = {}; DWORD type=0, size=sizeof(val);
        if (RegQueryValueExW(hKey, name, nullptr, &type, reinterpret_cast<LPBYTE>(val), &size)==ERROR_SUCCESS) {
            RegCloseKey(hKey); std::wstring s(val); for(auto& c:s) c=(wchar_t)towlower(c);
            return s==L"1"||s==L"true"||s==L"yes"||s==L"on";
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool EnvOrRegString(const wchar_t* name, std::wstring& valueOut) {
    valueOut.clear();
    if (!name) {
        return false;
    }

    DWORD required = GetEnvironmentVariableW(name, nullptr, 0);
    if (required != 0) {
        std::wstring temp(required, L'\0');
        DWORD written = GetEnvironmentVariableW(name, temp.data(), required);
        if (written != 0 && written < required) {
            temp.resize(written);
            valueOut = std::move(temp);
            return true;
        }
    }

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\UserModeHook\\Flags", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[260] = {};
        DWORD type = 0;
        DWORD size = sizeof(buffer);
        if (RegQueryValueExW(hKey, name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            valueOut.assign(buffer);
            return true;
        }
        RegCloseKey(hKey);
    }

    return false;
}

std::string Narrow(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }

    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return std::string();
    }

    std::string result(static_cast<size_t>(required - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), required, nullptr, nullptr);
    return result;
}

bool ParseHexKey(const std::wstring& input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.empty()) {
        return false;
    }
    std::wstring trimmed;
    trimmed.reserve(input.size());
    for (wchar_t c : input) {
        if (!iswspace(c)) {
            trimmed.push_back(c);
        }
    }
    if (trimmed.empty() || trimmed.size() % 2 != 0) {
        return false;
    }
    output.reserve(trimmed.size() / 2);
    for (size_t i = 0; i < trimmed.size(); i += 2) {
        wchar_t hi = trimmed[i];
        wchar_t lo = trimmed[i + 1];
        auto hexToNibble = [](wchar_t ch) -> int {
            if (ch >= L'0' && ch <= L'9') return ch - L'0';
            if (ch >= L'a' && ch <= L'f') return ch - L'a' + 10;
            if (ch >= L'A' && ch <= L'F') return ch - L'A' + 10;
            return -1;
        };
        int hiNibble = hexToNibble(hi);
        int loNibble = hexToNibble(lo);
        if (hiNibble < 0 || loNibble < 0) {
            output.clear();
            return false;
        }
        output.push_back(static_cast<uint8_t>((hiNibble << 4) | loNibble));
    }
    return !output.empty();
}

bool GenerateRandomKey(std::vector<uint8_t>& key, size_t size) {
    key.resize(size);
    if (size == 0) {
        return false;
    }
    NTSTATUS status = BCryptGenRandom(nullptr,
                                      key.data(),
                                      static_cast<ULONG>(size),
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0) {
        key.clear();
        return false;
    }
    return true;
}

std::string Base64Encode(const unsigned char* data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t triple = 0;
        size_t chunk = std::min(static_cast<size_t>(3), len - i);
        for (size_t j = 0; j < chunk; ++j) {
            triple |= data[i + j] << ((2 - j) * 8);
        }
        for (size_t j = 0; j < 4; ++j) {
            if (j <= (chunk + 0)) {
                uint32_t index = (triple >> ((3 - j) * 6)) & 0x3F;
                out.push_back(table[index]);
            } else {
                out.push_back('=');
            }
        }
        if (chunk < 3) {
            out.back() = '=';
            if (chunk == 1) {
                out[out.size() - 2] = '=';
            }
        }
    }
    return out;
}

std::string Base64Encode(const std::string& data) {
    return Base64Encode(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

bool EncryptTelemetryBuffer(const std::string& plain, std::string& encoded) {
    if (!g_telemetryEncrypt || g_logKey.empty()) {
        encoded = plain;
        return false;
    }
    std::string cipher(plain.size(), '\0');
    for (size_t i = 0; i < plain.size(); ++i) {
        cipher[i] = static_cast<char>(plain[i] ^ g_logKey[i % g_logKey.size()]);
    }
    encoded = Base64Encode(cipher);
    return true;
}

std::string Narrow(const wchar_t* value) {
    return value ? Narrow(std::wstring(value)) : std::string();
}

void InitializeLogging() {
    g_telemetryEnabled = !EnvOrRegEnabled(L"HOOKDLL_DISABLE_TELEMETRY");

    const bool pipeOnly = EnvOrRegEnabled(L"HOOKDLL_LOG_PIPE_ONLY");
    const bool disableDiskLog = EnvOrRegEnabled(L"HOOKDLL_DISABLE_DISKLOG") ||
                                EnvOrRegEnabled(L"HOOKDLL_LOG_MEMORY_ONLY") ||
                                pipeOnly;
    const bool fileOnly = EnvOrRegEnabled(L"HOOKDLL_LOG_FILE_ONLY");
    const bool disableMemoryLog = EnvOrRegEnabled(L"HOOKDLL_LOG_DISABLE_MEMORY");
    const bool requestMemoryLog = EnvOrRegEnabled(L"HOOKDLL_ENABLE_MEMORY_LOG") || pipeOnly;
    const bool suppressDebugFallback = EnvOrRegEnabled(L"HOOKDLL_LOG_SUPPRESS_DEBUG");

    g_pipeOnlyMode = pipeOnly;
    g_diskSinkDisabled = disableDiskLog;
    g_debugFallbackEnabled = !suppressDebugFallback && !pipeOnly;

    const bool memoryAllowed = !(disableMemoryLog || (fileOnly && !pipeOnly));
    g_memoryLogEnabled = memoryAllowed && (!g_telemetryEnabled || disableDiskLog || requestMemoryLog);

    g_logAvailable = false;
    g_logPathUtf8.clear();
    g_logMutex = nullptr;

    g_memoryLogLimit = kMemoryLogLimitDefault;
    std::wstring memoryLimitStr;
    if (EnvOrRegString(L"HOOKDLL_LOG_MEMORY_LIMIT", memoryLimitStr)) {
        try {
            size_t limit = std::stoul(memoryLimitStr);
            limit = std::max<size_t>(limit, 16);
            limit = std::min<size_t>(limit, 8192);
            g_memoryLogLimit = limit;
        } catch (...) {
            g_memoryLogLimit = kMemoryLogLimitDefault;
        }
    }

    bool needCrypto = g_telemetryEnabled || g_memoryLogEnabled;
    g_logKey.clear();
    if (needCrypto) {
        std::wstring keyHex;
        if (EnvOrRegString(L"HOOKDLL_LOG_KEY", keyHex)) {
            if (!ParseHexKey(keyHex, g_logKey)) {
                OutputDebugStringW(L"[HookDLL] HOOKDLL_LOG_KEY invalid; generating random key.\n");
                g_logKey.clear();
            }
        }
        if (g_logKey.empty() && !GenerateRandomKey(g_logKey, 32)) {
            OutputDebugStringW(L"[HookDLL] Failed to generate telemetry key; encryption disabled.\n");
        }
    }

    g_telemetryEncrypt = needCrypto && !EnvOrRegEnabled(L"HOOKDLL_LOG_DISABLE_ENCRYPTION") && !g_logKey.empty();

    std::wstring maxKbStr;
    if (EnvOrRegString(L"HOOKDLL_LOG_MAX_KB", maxKbStr)) {
        try {
            size_t maxKb = std::stoul(maxKbStr);
            if (maxKb > 0) {
                g_maxLogBytes = maxKb * 1024;
            }
        } catch (...) {
        }
    }

    if (!g_telemetryEnabled || disableDiskLog) {
        return;
    }

    g_logMutex = CreateMutexW(nullptr, FALSE, nullptr);

    std::wstring logPathOverride;
    if (EnvOrRegString(L"HOOKDLL_LOG_PATH", logPathOverride) && !logPathOverride.empty()) {
        g_logPathUtf8 = Narrow(logPathOverride);
    } else {
        wchar_t buf[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
        std::wstring base = (n && n < MAX_PATH) ? std::wstring(buf, buf + n) : L"C:\\ProgramData";
        std::wstring dir = base + L"\\UserModeHook";
        if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            OutputDebugStringW(L"[HookDLL] Failed to ensure ProgramData directory, falling back to C:\\Temp\\\n");
            CreateDirectoryW(L"C:\\Temp", nullptr);
            g_logPathUtf8 = "C:\\Temp\\api_hooks.log";
        } else {
            std::wstring path = dir + L"\\api_hooks.log";
            g_logPathUtf8 = Narrow(path);
        }
    }

    g_logFile.open(g_logPathUtf8.c_str(), std::ios::binary | std::ios::app);
    if (!g_logFile.is_open()) {
        OutputDebugStringW(L"[HookDLL] Failed to open log file; disabling disk telemetry.\n");
        g_logAvailable = false;
        g_diskSinkDisabled = true;
        return;
    }

    g_logAvailable = true;
}

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

void LogMessage(const std::string& message) {
    std::call_once(g_logInitOnce, InitializeLogging);

    SYSTEMTIME ts{};
    GetLocalTime(&ts);

    std::ostringstream formatted;
    formatted << "[" << std::setfill('0')
              << std::setw(2) << ts.wHour << ":"
              << std::setw(2) << ts.wMinute << ":"
              << std::setw(2) << ts.wSecond << "."
              << std::setw(3) << ts.wMilliseconds << "] "
              << std::setfill(' ')
              << "[PID:" << GetCurrentProcessId() << "] "
              << message;

    std::string plainLine = formatted.str();
    std::string encodedLine;
    bool encrypted = EncryptTelemetryBuffer(plainLine, encodedLine);

    if (g_memoryLogEnabled && g_memoryLogLimit > 0) {
        MemoryLogEntry entry;
        entry.timestamp = ts;
        entry.payload = encrypted ? encodedLine : plainLine;
        entry.encrypted = encrypted;
        std::lock_guard<std::mutex> lock(g_memoryLogMutex);
        while (g_memoryLog.size() >= g_memoryLogLimit) {
            g_memoryLog.pop_front();
        }
        g_memoryLog.push_back(entry);
    }

    if (!g_telemetryEnabled || !g_logAvailable) {
        if (g_debugFallbackEnabled) {
            std::string dbg = "[HookDLL] " + plainLine;
            OutputDebugStringA(dbg.c_str());
        }
        return;
    }

    EnterCriticalSection(&g_logCs);

    HANDLE mutexHandle = g_logMutex;
    DWORD waitResult = WAIT_FAILED;
    if (mutexHandle) {
        waitResult = WaitForSingleObject(mutexHandle, 5000);
    }

    if (!mutexHandle || waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED) {
        if (encrypted) {
            g_logFile << "ENC:" << encodedLine << std::endl;
        } else {
            g_logFile << plainLine << std::endl;
        }
        g_logFile.flush();
        if (mutexHandle) {
            ReleaseMutex(mutexHandle);
        }
        RotateLogFileIfNeeded();
    }

    LeaveCriticalSection(&g_logCs);
}

void RotateLogFileIfNeeded() {
    if (!g_logAvailable || g_logPathUtf8.empty()) {
        return;
    }
    std::streampos pos = g_logFile.tellp();
    if (pos == std::streampos(-1)) {
        return;
    }
    if (static_cast<size_t>(pos) <= g_maxLogBytes) {
        return;
    }

    g_logFile.close();

    std::string backupPath = g_logPathUtf8 + ".1";
    MoveFileExA(g_logPathUtf8.c_str(), backupPath.c_str(), MOVEFILE_REPLACE_EXISTING);

    g_logFile.open(g_logPathUtf8.c_str(), std::ios::binary | std::ios::trunc | std::ios::out);
    g_logFile.close();
    g_logFile.open(g_logPathUtf8.c_str(), std::ios::binary | std::ios::app);
}

std::wstring EscapeJson(const std::wstring& s) {
    std::wstring o; o.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
        case L'\\': o += L"\\\\"; break;
        case L'\"': o += L"\\\""; break;
        case L'\n': o += L"\\n"; break;
        case L'\r': o += L"\\r"; break;
        case L'\t': o += L"\\t"; break;
        default: o += c; break;
        }
    }
    return o;
}

std::string EscapeJsonAscii(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[7] = {};
                std::snprintf(buf, sizeof(buf), "\\u%04X", c);
                out += buf;
            } else {
                out += static_cast<char>(c);
            }
            break;
        }
    }
    return out;
}

std::string WrapEncryptedPayload(const std::string& plain) {
    if (!g_telemetryEncrypt) {
        return plain;
    }
    std::string encoded;
    if (EncryptTelemetryBuffer(plain, encoded)) {
        std::ostringstream oss;
        oss << "{\"encrypted\":1,\"data\":\"" << EscapeJsonAscii(encoded) << "\"}\n";
        return oss.str();
    }
    return plain;
}

std::string FormatTimestamp(const SYSTEMTIME& st) {
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << st.wHour << ":"
        << std::setw(2) << st.wMinute << ":"
        << std::setw(2) << st.wSecond << "."
        << std::setw(3) << st.wMilliseconds;
    return oss.str();
}

std::string BuildLogSnapshotJson() {
    auto dxStats = dxhooks::GetStats();
    auto vkStats = vkhooks::GetStats();
    auto xrStats = openxrhooks::GetStats();
    std::ostringstream oss;
    oss << "{\"mode\":\"";
    if (g_logAvailable) {
        oss << "file";
    } else if (g_memoryLogEnabled) {
        oss << (g_diskSinkDisabled ? "pipe" : "memory");
    } else {
        oss << "none";
    }
    oss << "\",\"encrypted\":" << (g_telemetryEncrypt ? 1 : 0)
        << ",\"stats\":{\"dx\":{\"d3d9_end\":" << dxStats.d3d9EndScene
         << ",\"d3d9_present\":" << dxStats.d3d9Present
         << ",\"dxgi_present\":" << dxStats.dxgiPresent
         << ",\"d3d12_present\":" << dxStats.d3d12Present
         << ",\"d3d12_submit\":" << dxStats.d3d12CommandSubmit
        << ",\"dcomp_create\":" << dxStats.dcompCreateDevice
        << ",\"dxgi_factory_media\":" << dxStats.dxgiFactoryMediaSwapchain
        << "},\"vk\":{\"queue_present\":" << vkStats.queuePresent
        << ",\"acquire\":" << vkStats.acquireNextImage
        << "},\"xr\":{\"wait_frame\":" << xrStats.waitFrame
        << ",\"begin_frame\":" << xrStats.beginFrame
        << ",\"end_frame\":" << xrStats.endFrame
        << ",\"acquire_image\":" << xrStats.acquireSwapchainImage
        << ",\"release_image\":" << xrStats.releaseSwapchainImage
        << "}},\"logs\":[";

    bool first = true;
    {
        std::lock_guard<std::mutex> lock(g_memoryLogMutex);
        for (const auto& entry : g_memoryLog) {
            if (!first) {
                oss << ",";
            }
            first = false;
            oss << "{\"ts\":\"" << FormatTimestamp(entry.timestamp) << "\"";
            if (entry.encrypted) {
                oss << ",\"encrypted\":1,\"data\":\"" << EscapeJsonAscii(entry.payload) << "\"}";
            } else {
                oss << ",\"encrypted\":0,\"msg\":\"" << EscapeJsonAscii(entry.payload) << "\"}";
            }
        }
    }

    oss << "]}\n";
    return oss.str();
}

DWORD WINAPI TelemetryPipeServer(LPVOID) {
    DWORD pid = GetCurrentProcessId();
        wchar_t pipeName[128] = {};
        pipes::FormatTelemetryPipe(pipeName, _countof(pipeName), pid);

    while (WaitForSingleObject(g_pipeStopEvent, 0) == WAIT_TIMEOUT) {
        OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE pipe = CreateNamedPipeW(pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 64 * 1024, 64 * 1024, 5000, nullptr);

        if (pipe == INVALID_HANDLE_VALUE) {
            if (ov.hEvent) CloseHandle(ov.hEvent);
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        BOOL ok = ConnectNamedPipe(pipe, &ov);
        DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && gle == ERROR_IO_PENDING) {
            HANDLE waitObjs[2] = { g_pipeStopEvent, ov.hEvent };
            DWORD wr = WaitForMultipleObjects(2, waitObjs, FALSE, 5000);
            if (wr == WAIT_OBJECT_0) {
                CancelIoEx(pipe, &ov);
                CloseHandle(pipe);
                CloseHandle(ov.hEvent);
                break;
            }
            // Connected or timed out
        } else if (!ok && gle == ERROR_PIPE_CONNECTED) {
            // Client connected between CreateNamedPipe and ConnectNamedPipe
        } else if (!ok) {
            CloseHandle(pipe);
            CloseHandle(ov.hEvent);
            continue;
        }

        // Optional request read
        std::string req; req.resize(4096);
        DWORD readBytes = 0;
        ReadFile(pipe, req.data(), (DWORD)req.size()-1, &readBytes, nullptr);
        req[readBytes] = '\0';

        auto hasOp = [&](const char* op) -> bool {
            return req.find(std::string("\"op\":\"") + op + "\"") != std::string::npos;
        };

        bool handled = false;
        if (!req.empty() && req[0] == '{') {
            if (hasOp("repair")) {
                try { MonitorAndRepairHooks(); } catch (...) {}
                const char* ok = "{\"ok\":true}\n"; DWORD wr=0; WriteFile(pipe, ok, (DWORD)strlen(ok), &wr, nullptr);
                handled = true;
            } else if (hasOp("setFlags")) {
                size_t p = req.find("\"flags\"");
                if (p != std::string::npos) {
                    p = req.find('{', p);
                    size_t end = req.find('}', p);
                    if (p != std::string::npos && end != std::string::npos && end > p) {
                        std::string body = req.substr(p+1, end-p-1);
                        size_t cur=0; while (cur < body.size()) {
                            size_t k1 = body.find('"', cur); if (k1==std::string::npos) break; size_t k2 = body.find('"', k1+1); if (k2==std::string::npos) break;
                            std::string key = body.substr(k1+1, k2-k1-1);
                            size_t colon = body.find(':', k2); if (colon==std::string::npos) break;
                            size_t vstart = body.find_first_not_of(" \t\r\n", colon+1);
                            std::string val;
                            if (vstart != std::string::npos && body[vstart] == '"') {
                                size_t v2 = body.find('"', vstart+1);
                                val = body.substr(vstart+1, v2-(vstart+1));
                                cur = v2+1;
                            } else {
                                size_t v2 = body.find(',', vstart);
                                if (v2 == std::string::npos) v2 = body.size();
                                val = body.substr(vstart, v2-vstart);
                                cur = v2+1;
                            }
                            std::wstring wkey(key.begin(), key.end());
                            std::wstring wval(val.begin(), val.end());
                            SetEnvironmentVariableW(wkey.c_str(), wval.c_str());
                        }
                    }
                }
                const char* ok = "{\"ok\":true}\n"; DWORD wr=0; WriteFile(pipe, ok, (DWORD)strlen(ok), &wr, nullptr);
                handled = true;
            } else if (hasOp("policy")) {
                bool hasInput = false;
                bool hasWda = false;
                int inputState = ExtractTriState(req, "\"force_input\"", hasInput);
                int wdaState = ExtractTriState(req, "\"force_wda\"", hasWda);
                if (hasInput) {
                    ApplyPolicyOverride(g_forceInputPolicy, inputState, "force_input");
                }
                if (hasWda) {
                    ApplyPolicyOverride(g_forceWdaPolicy, wdaState, "force_wda");
                }
                std::vector<uintptr_t> blockDup;
                std::vector<uintptr_t> clearDup;
                std::vector<uintptr_t> blockWindows;
                std::vector<uintptr_t> clearWindows;
                std::vector<uintptr_t> blockMonitors;
                std::vector<uintptr_t> clearMonitors;
                std::vector<uintptr_t> blockSwapChains;
                std::vector<uintptr_t> clearSwapChains;
                ParseHandleList(req, "\"block_duplications\"", blockDup);
                ParseHandleList(req, "\"clear_duplications\"", clearDup);
                ParseHandleList(req, "\"block_capture_windows\"", blockWindows);
                ParseHandleList(req, "\"clear_capture_windows\"", clearWindows);
                ParseHandleList(req, "\"block_capture_monitors\"", blockMonitors);
                ParseHandleList(req, "\"clear_capture_monitors\"", clearMonitors);
                ParseHandleList(req, "\"block_swapchains\"", blockSwapChains);
                ParseHandleList(req, "\"clear_swapchains\"", clearSwapChains);
                if (!blockDup.empty()) {
                    ApplyHandlePolicy(g_blockedDuplicationHandles, blockDup, true, "duplication_policy", "dup");
                }
                if (!clearDup.empty()) {
                    ApplyHandlePolicy(g_blockedDuplicationHandles, clearDup, false, "duplication_policy", "dup");
                }
                if (!blockWindows.empty()) {
                    ApplyHandlePolicy(g_blockedWindowTargets, blockWindows, true, "capture_window_policy", "hwnd");
                }
                if (!clearWindows.empty()) {
                    ApplyHandlePolicy(g_blockedWindowTargets, clearWindows, false, "capture_window_policy", "hwnd");
                }
                if (!blockMonitors.empty()) {
                    ApplyHandlePolicy(g_blockedMonitorTargets, blockMonitors, true, "capture_monitor_policy", "monitor");
                }
                if (!clearMonitors.empty()) {
                    ApplyHandlePolicy(g_blockedMonitorTargets, clearMonitors, false, "capture_monitor_policy", "monitor");
                }
                if (!blockSwapChains.empty()) {
                    ApplyHandlePolicy(g_blockedSwapChains, blockSwapChains, true, "swapchain_policy", "swap");
                }
                if (!clearSwapChains.empty()) {
                    ApplyHandlePolicy(g_blockedSwapChains, clearSwapChains, false, "swapchain_policy", "swap");
                }
                const char* ok = "{\"ok\":true}\n"; DWORD wr=0; WriteFile(pipe, ok, (DWORD)strlen(ok), &wr, nullptr);
                handled = true;
            } else if (hasOp("disable")) {
                try { UninstallHooks(); } catch (...) {}
                const char* ok = "{\"ok\":true}\n"; DWORD wr=0; WriteFile(pipe, ok, (DWORD)strlen(ok), &wr, nullptr);
                handled = true;
            } else if (hasOp("logs")) {
                std::string payload = BuildLogSnapshotJson();
                std::string response = WrapEncryptedPayload(payload);
                DWORD wr = 0;
                WriteFile(pipe, response.c_str(), (DWORD)response.size(), &wr, nullptr);
                handled = true;
            }
        }

        if (!handled) {
            // Produce telemetry JSON
            try {
                std::string json = HookEngine::getInstance().exportTelemetryJson();
                std::string response = WrapEncryptedPayload(json);
                DWORD toWrite = static_cast<DWORD>(response.size());
                DWORD written = 0;
                WriteFile(pipe, response.data(), toWrite, &written, nullptr);
            } catch (...) {
            }
        }

        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        if (ov.hEvent) CloseHandle(ov.hEvent);
    }
    return 0;
}

void LogStructured(const std::string& event,
                   const std::string& func,
                   const std::string& details = std::string()) {
    std::ostringstream line;
    line << "umh event=" << event
         << " func=" << func
         << " pid=" << GetCurrentProcessId()
         << " tid=" << GetCurrentThreadId();
    if (!details.empty()) {
        line << " " << details;
    }
    LogMessage(line.str());
}

void ApplyPolicyOverride(std::atomic<int>& storage,
                         int state,
                         const char* name) {
    state = (state > 0) ? 1 : (state < 0 ? -1 : 0);
    int previous = storage.exchange(state, std::memory_order_relaxed);
    if (previous != state) {
        std::ostringstream detail;
        detail << "state=" << state;
        LogStructured("policy", name, detail.str());
    }
}

bool ForceInputEnabled() {
    int overrideState = g_forceInputPolicy.load(std::memory_order_relaxed);
    if (overrideState > 0) {
        return true;
    }
    if (overrideState < 0) {
        return false;
    }
    return EnvOrRegEnabled(L"HOOKDLL_FORCE_INPUT");
}

bool ForceWdaNoneEnabled() {
    int overrideState = g_forceWdaPolicy.load(std::memory_order_relaxed);
    if (overrideState > 0) {
        return true;
    }
    if (overrideState < 0) {
        return false;
    }
    return EnvOrRegEnabled(L"HOOKDLL_FORCE_WDA_NONE");
}

int ExtractTriState(const std::string& src,
                    const char* key,
                    bool& found) {
    found = false;
    if (!key) {
        return 0;
    }
    size_t pos = src.find(key);
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::strlen(key);
    size_t start = src.find_first_not_of(" \t\r\n\":", pos);
    if (start == std::string::npos) {
        return 0;
    }

    auto parseNumeric = [&](size_t s) -> int {
        size_t end = s;
        if (src[s] == '-' || src[s] == '+') {
            ++end;
        }
        while (end < src.size() && std::isdigit(static_cast<unsigned char>(src[end]))) {
            ++end;
        }
        int value = std::atoi(src.substr(s, end - s).c_str());
        return (value > 0) ? 1 : (value < 0 ? -1 : 0);
    };

    int result = 0;
    if (src[start] == '"') {
        size_t end = src.find('"', start + 1);
        if (end != std::string::npos) {
            std::string token = src.substr(start + 1, end - start - 1);
            for (auto& ch : token) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            if (token == "true" || token == "on" || token == "enable" || token == "enabled") {
                result = 1;
            } else if (token == "false" || token == "off" || token == "disable" || token == "disabled") {
                result = -1;
            } else {
                result = 0;
            }
        }
    } else if (std::isdigit(static_cast<unsigned char>(src[start])) || src[start] == '-' || src[start] == '+') {
        result = parseNumeric(start);
    } else if (src.compare(start, 4, "true") == 0) {
        result = 1;
    } else if (src.compare(start, 5, "false") == 0) {
        result = -1;
    } else {
        result = 0;
    }

    found = true;
    if (result > 0) return 1;
    if (result < 0) return -1;
    return 0;
}

std::string HexFromValue(uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << value;
    return oss.str();
}

uintptr_t ParseHandleToken(const std::string& token) {
    std::string trimmed = token;
    trimmed.erase(trimmed.begin(), std::find_if(trimmed.begin(), trimmed.end(), [](unsigned char c) { return !std::isspace(c); }));
    trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](unsigned char c) { return !std::isspace(c); }).base(), trimmed.end());
    if (trimmed.empty()) {
        return 0;
    }
    unsigned long long value = 0;
    try {
        if (trimmed.size() > 2 && (trimmed[0] == '0') && (trimmed[1] == 'x' || trimmed[1] == 'X')) {
            value = std::stoull(trimmed.substr(2), nullptr, 16);
        } else {
            value = std::stoull(trimmed, nullptr, 0);
        }
    } catch (...) {
        return 0;
    }
    return static_cast<uintptr_t>(value);
}

void ParseHandleList(const std::string& src,
                     const char* key,
                     std::vector<uintptr_t>& out) {
    if (!key) {
        return;
    }
    size_t pos = src.find(key);
    if (pos == std::string::npos) {
        return;
    }
    pos = src.find('[', pos);
    if (pos == std::string::npos) {
        return;
    }
    size_t end = src.find(']', pos);
    if (end == std::string::npos) {
        return;
    }
    size_t cur = pos + 1;
    while (cur < end) {
        while (cur < end && std::isspace(static_cast<unsigned char>(src[cur]))) {
            ++cur;
        }
        if (cur >= end) {
            break;
        }
        bool quoted = src[cur] == '"';
        size_t valueStart = quoted ? cur + 1 : cur;
        size_t valueEnd = quoted ? src.find('"', valueStart) : src.find_first_of(", ]", valueStart);
        if (valueEnd == std::string::npos || valueEnd > end) {
            break;
        }
        std::string token = src.substr(valueStart, valueEnd - valueStart);
        uintptr_t value = ParseHandleToken(token);
        if (value) {
            out.push_back(value);
        }
        cur = quoted ? valueEnd + 1 : valueEnd;
        size_t comma = src.find(',', cur);
        if (comma == std::string::npos || comma > end) {
            break;
        }
        cur = comma + 1;
    }
}

void ApplyHandlePolicy(std::unordered_set<uintptr_t>& storage,
                       const std::vector<uintptr_t>& handles,
                       bool block,
                       const char* funcName,
                       const char* keyName) {
    if (handles.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_graphicsPolicyMutex);
    for (uintptr_t handle : handles) {
        if (!handle) {
            continue;
        }
        bool changed = false;
        if (block) {
            if (storage.insert(handle).second) {
                changed = true;
            }
        } else {
            auto it = storage.find(handle);
            if (it != storage.end()) {
                storage.erase(it);
                changed = true;
            }
        }
        if (changed) {
            std::ostringstream detail;
            detail << keyName << "=" << HexFromValue(handle)
                   << " state=" << (block ? 1 : 0);
            LogStructured("policy", funcName, detail.str());
        }
    }
}

bool IsHandleBlocked(const std::unordered_set<uintptr_t>& storage, uintptr_t handle) {
    std::lock_guard<std::mutex> lock(g_graphicsPolicyMutex);
    return storage.find(handle) != storage.end();
}

bool IsDuplicationBlocked(uintptr_t handle) {
    if (!handle) {
        return false;
    }
    return IsHandleBlocked(g_blockedDuplicationHandles, handle);
}

bool IsWindowTargetBlocked(uintptr_t handle) {
    if (!handle) {
        return false;
    }
    return IsHandleBlocked(g_blockedWindowTargets, handle);
}

bool IsMonitorTargetBlocked(uintptr_t handle) {
    if (!handle) {
        return false;
    }
    return IsHandleBlocked(g_blockedMonitorTargets, handle);
}

bool IsSwapChainBlocked(uintptr_t handle) {
    if (!handle) {
        return false;
    }
    return IsHandleBlocked(g_blockedSwapChains, handle);
}

void LogHardwareSchedulingStatus() {
    DWORD hwschValue = 0;
    DWORD valueSize = sizeof(hwschValue);
    LONG status = RegGetValueW(HKEY_LOCAL_MACHINE,
                               L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
                               L"HwSchMode",
                               RRF_RT_DWORD,
                               nullptr,
                               &hwschValue,
                               &valueSize);
    std::ostringstream detail;
    detail << "available=" << (status == ERROR_SUCCESS ? 1 : 0);
    if (status == ERROR_SUCCESS) {
        detail << " mode=" << hwschValue;
        if (hwschValue == 1) {
            detail << " enabled=1";
        } else if (hwschValue == 2) {
            detail << " enabled=0 forced=1";
        }
    } else {
        detail << " error=" << status;
    }
    LogStructured("graphics", "HardwareScheduling", AppendSessionDetail(detail.str()));
}

void LogAdapterTopology() {
    HMODULE dxgi = LoadLibraryW(L"dxgi.dll");
    if (!dxgi) {
        LogStructured("graphics", "AdapterSummary", AppendSessionDetail("status=no_dxgi"));
        return;
    }

    using CreateFactoryFn = HRESULT (WINAPI*)(REFIID, void**);
    auto createFactory = reinterpret_cast<CreateFactoryFn>(GetProcAddress(dxgi, "CreateDXGIFactory1"));
    if (!createFactory) {
        LogStructured("graphics", "AdapterSummary", AppendSessionDetail("status=no_factory"));
        return;
    }

    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
    HRESULT hr = createFactory(IID_PPV_ARGS(&factory));
    if (FAILED(hr) || !factory) {
        std::ostringstream detail;
        detail << "status=factory_fail hr=0x" << std::hex << std::uppercase << hr;
        LogStructured("graphics", "AdapterSummary", AppendSessionDetail(detail.str()));
        return;
    }

    UINT totalAdapters = 0;
    UINT hardwareAdapters = 0;
    for (UINT index = 0;; ++index) {
        Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
        if (factory->EnumAdapters1(index, &adapter) == DXGI_ERROR_NOT_FOUND) {
            break;
        }
        ++totalAdapters;

        DXGI_ADAPTER_DESC1 desc{};
        if (SUCCEEDED(adapter->GetDesc1(&desc))) {
            bool software = (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0;
            bool remote = (desc.Flags & DXGI_ADAPTER_FLAG_REMOTE) != 0;
            if (!software && !remote) {
                ++hardwareAdapters;
            }

            std::ostringstream detail;
            detail << "index=" << index
                   << " name=" << Narrow(desc.Description)
                   << " vendor=0x" << std::hex << std::uppercase << desc.VendorId
                   << " device=0x" << desc.DeviceId
                   << std::dec
                   << " dedicated_mb=" << static_cast<unsigned long long>(desc.DedicatedVideoMemory / (1024ull * 1024ull))
                   << " shared_mb=" << static_cast<unsigned long long>(desc.SharedSystemMemory / (1024ull * 1024ull));
            if (software) detail << " software=1";
            if (remote) detail << " remote=1";
            LogStructured("graphics", "Adapter", AppendSessionDetail(detail.str()));
        }
    }

    std::string highPerfName;
    Microsoft::WRL::ComPtr<IDXGIFactory6> factory6;
    if (SUCCEEDED(factory.As(&factory6)) && factory6) {
        Microsoft::WRL::ComPtr<IDXGIAdapter1> highPerf;
        if (SUCCEEDED(factory6->EnumAdapterByGpuPreference(0,
                                                           DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
                                                           IID_PPV_ARGS(&highPerf))) && highPerf) {
            DXGI_ADAPTER_DESC1 desc{};
            if (SUCCEEDED(highPerf->GetDesc1(&desc))) {
                highPerfName = Narrow(desc.Description);
            }
        }
    }

    std::ostringstream summary;
    summary << "adapters=" << totalAdapters
            << " hardware=" << hardwareAdapters;
    if (!highPerfName.empty()) {
        summary << " high=" << highPerfName;
    }
    LogStructured("graphics", "AdapterSummary", AppendSessionDetail(summary.str()));
}

void LogGraphicsModuleIfNew(const wchar_t* moduleName, HMODULE module) {
    if (!moduleName || !module) {
        return;
    }

    std::wstring lowered(moduleName);
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::towlower);

    {
        std::lock_guard<std::mutex> lock(g_graphicsModuleMutex);
        if (!g_reportedGraphicsModules.insert(lowered).second) {
            return;
        }
    }

    std::string narrow = Narrow(lowered);
    std::ostringstream detail;
    detail << "module=" << narrow
           << " base=0x" << std::hex << reinterpret_cast<UINT_PTR>(module);
    detail << std::dec;
    LogStructured("module", "GraphicsModule", AppendSessionDetail(detail.str()));
}

void ScanGraphicsModulesOnce() {
    static const wchar_t* kGraphicsModules[] = {
        L"d3d12.dll",
        L"d3d11.dll",
        L"d3d10.dll",
        L"vulkan-1.dll",
        L"dcomp.dll",
        L"openxr_loader.dll",
        L"xrclient.dll",
        L"oculusclient.dll",
        L"gameoverlayrenderer64.dll",
        L"gameoverlayrenderer.dll",
        L"discordhook64.dll",
        L"discordhook.dll",
        L"nvspcap64.dll",
        L"nvspcap.dll"
    };

    for (const auto* name : kGraphicsModules) {
        HMODULE handle = GetModuleHandleW(name);
        if (handle) {
            LogGraphicsModuleIfNew(name, handle);
        }
    }
}

DWORD WINAPI GraphicsModuleScannerThread(LPVOID) {
    ScanGraphicsModulesOnce();
    while (true) {
        DWORD wait = WAIT_TIMEOUT;
        if (g_graphicsScanStopEvent) {
            wait = WaitForSingleObject(g_graphicsScanStopEvent, 3000);
        } else {
            Sleep(3000);
            continue;
        }
        if (wait == WAIT_OBJECT_0) {
            break;
        }
        ScanGraphicsModulesOnce();
    }
    return 0;
}

void StartGraphicsModuleScanner() {
    if (!g_graphicsScanStopEvent) {
        g_graphicsScanStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    } else {
        ResetEvent(g_graphicsScanStopEvent);
    }

    if (!g_graphicsScanThread) {
        g_graphicsScanThread = CreateThread(nullptr,
                                            0,
                                            GraphicsModuleScannerThread,
                                            nullptr,
                                            0,
                                            nullptr);
        if (!g_graphicsScanThread && g_graphicsScanStopEvent) {
            CloseHandle(g_graphicsScanStopEvent);
            g_graphicsScanStopEvent = nullptr;
        }
    }
}

void StopGraphicsModuleScanner() {
    if (g_graphicsScanStopEvent) {
        SetEvent(g_graphicsScanStopEvent);
    }
    if (g_graphicsScanThread) {
        WaitForSingleObject(g_graphicsScanThread, 2000);
        CloseHandle(g_graphicsScanThread);
        g_graphicsScanThread = nullptr;
    }
    if (g_graphicsScanStopEvent) {
        CloseHandle(g_graphicsScanStopEvent);
        g_graphicsScanStopEvent = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(g_graphicsModuleMutex);
        g_reportedGraphicsModules.clear();
    }
}
} // anonymous namespace

// =========================
// SetWindowDisplayAffinity Hook - THE MAIN BYPASS
// =========================
typedef BOOL (WINAPI* SetWindowDisplayAffinity_t)(HWND, DWORD);
SetWindowDisplayAffinity_t OriginalSetWindowDisplayAffinity = nullptr;

BOOL WINAPI HookSetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity) {
    DWORD applied = dwAffinity;
    bool forced = false;
    if (ForceWdaNoneEnabled() && dwAffinity != WDA_NONE) {
        applied = WDA_NONE;
        forced = true;
    }

    std::stringstream ss;
    ss << "SetWindowDisplayAffinity called: HWND=0x" << std::hex << reinterpret_cast<UINT_PTR>(hWnd)
       << " requested=0x" << dwAffinity
       << " applied=0x" << applied
       << " forced=" << (forced ? "TRUE" : "FALSE");
    LogMessage(ss.str());

    std::ostringstream detail;
    detail << "hwnd=0x" << std::hex << reinterpret_cast<UINT_PTR>(hWnd)
           << " requested=0x" << dwAffinity
           << " applied=0x" << applied
           << " forced=" << (forced ? 1 : 0);
    LogStructured("call", "SetWindowDisplayAffinity", detail.str());

    if (OriginalSetWindowDisplayAffinity) {
        return OriginalSetWindowDisplayAffinity(hWnd, applied);
    }

    static SetWindowDisplayAffinity_t real = reinterpret_cast<SetWindowDisplayAffinity_t>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetWindowDisplayAffinity"));
    if (real) {
        return real(hWnd, applied);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

// =========================
// BlockInput Hooks (user-mode + native)
// =========================
typedef BOOL (WINAPI* BlockInput_t)(BOOL);
BlockInput_t OriginalBlockInput = nullptr;

BOOL WINAPI HookBlockInput(BOOL fBlockIt) {
    BOOL requested = fBlockIt;
    const bool forceDisable = ForceInputEnabled();
    if (forceDisable) {
        fBlockIt = FALSE;
    }

    std::stringstream ss;
    ss << "BlockInput: requested=" << (requested ? "TRUE" : "FALSE")
       << " applied=" << (fBlockIt ? "TRUE" : "FALSE");
    LogMessage(ss.str());
    std::ostringstream detail;
    detail << "requested=" << (requested ? 1 : 0)
           << " applied=" << (fBlockIt ? 1 : 0);
    LogStructured("call", "BlockInput", detail.str());

    if (OriginalBlockInput) {
        return OriginalBlockInput(fBlockIt);
    }

    static BlockInput_t real = reinterpret_cast<BlockInput_t>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "BlockInput"));
    if (real) {
        return real(fBlockIt);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

typedef NTSTATUS (NTAPI* NtUserBlockInput_t)(BOOL);
NtUserBlockInput_t OriginalNtUserBlockInput = nullptr;

NTSTATUS NTAPI HookNtUserBlockInput(BOOL fBlockIt) {
    BOOL requested = fBlockIt;
    const bool forceDisable = ForceInputEnabled();
    if (forceDisable) {
        fBlockIt = FALSE;
    }

    std::stringstream ss;
    ss << "NtUserBlockInput: requested=" << (requested ? "TRUE" : "FALSE")
       << " applied=" << (fBlockIt ? "TRUE" : "FALSE");
    LogMessage(ss.str());
    std::ostringstream detail;
    detail << "requested=" << (requested ? 1 : 0)
           << " applied=" << (fBlockIt ? 1 : 0);
    LogStructured("call", "NtUserBlockInput", detail.str());

    if (OriginalNtUserBlockInput) {
        return OriginalNtUserBlockInput(fBlockIt);
    }

    return STATUS_NOT_IMPLEMENTED;
}

typedef BOOL (WINAPI* EnableWindow_t)(HWND, BOOL);
EnableWindow_t OriginalEnableWindow = nullptr;

BOOL WINAPI HookEnableWindow(HWND hwnd, BOOL bEnable) {
    BOOL requested = bEnable;
    BOOL applied = bEnable;
    BOOL forced = FALSE;
    if (!bEnable && ForceInputEnabled()) {
        applied = TRUE;
        forced = TRUE;
    }

    std::ostringstream detail;
    detail << "hwnd=0x" << std::hex << reinterpret_cast<UINT_PTR>(hwnd)
           << std::dec
           << " requested=" << (requested ? 1 : 0)
           << " applied=" << (applied ? 1 : 0)
           << " forced=" << (forced ? 1 : 0);

    LogMessage((std::stringstream()
                   << "EnableWindow: hwnd=0x" << std::hex << reinterpret_cast<UINT_PTR>(hwnd)
                   << std::dec
                   << " requested=" << (requested ? "TRUE" : "FALSE")
                   << " applied=" << (applied ? "TRUE" : "FALSE")
                   << " forced=" << (forced ? "TRUE" : "FALSE")).str());
    LogStructured("call", "EnableWindow", detail.str());

    if (OriginalEnableWindow) {
        return OriginalEnableWindow(hwnd, applied);
    }

    static EnableWindow_t real = reinterpret_cast<EnableWindow_t>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "EnableWindow"));
    if (real) {
        return real(hwnd, applied);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return applied;
}

// =========================
// AttachThreadInput and SystemParametersInfoW Hooks
// =========================
typedef BOOL (WINAPI* AttachThreadInput_t)(DWORD, DWORD, BOOL);
AttachThreadInput_t OriginalAttachThreadInput = nullptr;

BOOL WINAPI HookAttachThreadInput(DWORD idAttach, DWORD idAttachTo, BOOL fAttach) {
    BOOL requested = fAttach;
    BOOL applied = fAttach;
    if (ForceInputEnabled() && fAttach) {
        applied = FALSE;
    }

    std::ostringstream detail;
    detail << "from=" << idAttach
           << " to=" << idAttachTo
           << " attach=" << (requested ? 1 : 0)
           << " applied=" << (applied ? 1 : 0);

    LogMessage((std::stringstream()
                   << "AttachThreadInput: from=" << idAttach
                   << " to=" << idAttachTo
                   << " attach=" << (requested ? "TRUE" : "FALSE")
                   << " applied=" << (applied ? "TRUE" : "FALSE")).str());
    LogStructured("call", "AttachThreadInput", detail.str());

    if (OriginalAttachThreadInput) {
        return OriginalAttachThreadInput(idAttach, idAttachTo, applied);
    }

    static AttachThreadInput_t real = reinterpret_cast<AttachThreadInput_t>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "AttachThreadInput"));
    if (real) {
        return real(idAttach, idAttachTo, applied);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

typedef BOOL (WINAPI* SystemParametersInfoW_t)(UINT, UINT, PVOID, UINT);
SystemParametersInfoW_t OriginalSystemParametersInfoW = nullptr;
constexpr UINT kSpiSetBlockSendInputResets = 0x1025;

BOOL WINAPI HookSystemParametersInfoW(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni) {
    BOOL desired = FALSE;
    BOOL forced = FALSE;

    if (uiAction == kSpiSetBlockSendInputResets && pvParam) {
        desired = (*reinterpret_cast<PBOOL>(pvParam)) ? TRUE : FALSE;
        if (ForceInputEnabled() && desired) {
            *reinterpret_cast<PBOOL>(pvParam) = FALSE;
            forced = TRUE;
        }

        std::ostringstream detail;
        detail << "action=SPI_SETBLOCKSENDINPUTRESETS"
               << " requested=" << (desired ? 1 : 0)
               << " applied=" << ((*reinterpret_cast<PBOOL>(pvParam)) ? 1 : 0)
               << " forced=" << (forced ? 1 : 0);
        LogStructured("call", "SystemParametersInfoW", detail.str());
    }

    BOOL result = FALSE;
    if (OriginalSystemParametersInfoW) {
        result = OriginalSystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
    } else {
        static SystemParametersInfoW_t real = reinterpret_cast<SystemParametersInfoW_t>(
            GetProcAddress(GetModuleHandleW(L"user32.dll"), "SystemParametersInfoW"));
        if (real) {
            result = real(uiAction, uiParam, pvParam, fWinIni);
        } else {
            SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
            return FALSE;
        }
    }

    if (uiAction == kSpiSetBlockSendInputResets) {
    LogMessage((std::stringstream()
                   << "SystemParametersInfoW: action=SPI_SETBLOCKSENDINPUTRESETS requested="
                   << (desired ? "TRUE" : "FALSE")
                   << " forced=" << (forced ? "TRUE" : "FALSE")
                   << " result=" << (result ? "TRUE" : "FALSE")).str());
    }

    return result;
}

// =========================
// NtUser-level Keyboard Hooks
// =========================
typedef NTSTATUS (NTAPI* NtUserAttachThreadInput_t)(DWORD, DWORD, BOOL);
NtUserAttachThreadInput_t OriginalNtUserAttachThreadInput = nullptr;

NTSTATUS NTAPI HookNtUserAttachThreadInput(DWORD idAttach, DWORD idAttachTo, BOOL fAttach) {
    BOOL requested = fAttach;
    BOOL applied = fAttach;
    if (ForceInputEnabled() && fAttach) {
        applied = FALSE;
    }

    std::ostringstream detail;
    detail << "from=" << idAttach
           << " to=" << idAttachTo
           << " attach=" << (requested ? 1 : 0)
           << " applied=" << (applied ? 1 : 0)
           << " forced=" << ((requested && !applied) ? 1 : 0);

    LogMessage((std::stringstream()
                   << "NtUserAttachThreadInput: from=" << idAttach
                   << " to=" << idAttachTo
                   << " attach=" << (requested ? "TRUE" : "FALSE")
                   << " applied=" << (applied ? "TRUE" : "FALSE")).str());
    LogStructured("call", "NtUserAttachThreadInput", detail.str());

    if (OriginalNtUserAttachThreadInput) {
        return OriginalNtUserAttachThreadInput(idAttach, idAttachTo, applied);
    }
    return STATUS_NOT_IMPLEMENTED;
}

typedef NTSTATUS (NTAPI* NtUserSetInformationThread_t)(HANDLE, ULONG, PVOID, ULONG);
NtUserSetInformationThread_t OriginalNtUserSetInformationThread = nullptr;

NTSTATUS NTAPI HookNtUserSetInformationThread(HANDLE hThread,
                                              ULONG infoClass,
                                              PVOID info,
                                              ULONG infoLength) {
    ULONG_PTR preview = 0;
    bool captured = false;
    if (info && infoLength >= sizeof(ULONG_PTR) &&
        !IsBadReadPtr(info, sizeof(ULONG_PTR))) {
        preview = *reinterpret_cast<ULONG_PTR*>(info);
        captured = true;
    }

    bool forced = false;
    if (ForceInputEnabled()) {
        forced = true;
    }

    std::ostringstream detail;
    detail << "class=" << infoClass
           << " length=" << infoLength
           << " preview=0x" << std::hex << (captured ? preview : 0)
           << std::dec << " forced=" << (forced ? 1 : 0);

    LogStructured("call", "NtUserSetInformationThread", detail.str());

    if (forced) {
        return STATUS_ACCESS_DENIED;
    }

    if (OriginalNtUserSetInformationThread) {
        return OriginalNtUserSetInformationThread(hThread, infoClass, info, infoLength);
    }
    return STATUS_NOT_IMPLEMENTED;
}

// =========================
// Low-Level Keyboard Hook Instrumentation
// =========================
typedef HHOOK (WINAPI* SetWindowsHookExW_t)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HHOOK (WINAPI* SetWindowsHookExA_t)(int, HOOKPROC, HINSTANCE, DWORD);

SetWindowsHookExW_t OriginalSetWindowsHookExW = nullptr;
SetWindowsHookExA_t OriginalSetWindowsHookExA = nullptr;

static bool IsKeyboardHookId(int idHook) {
    return idHook == WH_KEYBOARD || idHook == WH_KEYBOARD_LL;
}

static HHOOK CallOriginalSetWindowsHookExW(int idHook,
                                           HOOKPROC lpfn,
                                           HINSTANCE hmod,
                                           DWORD threadId) {
    if (OriginalSetWindowsHookExW) {
        return OriginalSetWindowsHookExW(idHook, lpfn, hmod, threadId);
    }
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (!user32) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return nullptr;
    }
    auto real = reinterpret_cast<SetWindowsHookExW_t>(
        GetProcAddress(user32, "SetWindowsHookExW"));
    if (real && real != &HookSetWindowsHookExW) {
        return real(idHook, lpfn, hmod, threadId);
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return nullptr;
}

static HHOOK CallOriginalSetWindowsHookExA(int idHook,
                                           HOOKPROC lpfn,
                                           HINSTANCE hmod,
                                           DWORD threadId) {
    if (OriginalSetWindowsHookExA) {
        return OriginalSetWindowsHookExA(idHook, lpfn, hmod, threadId);
    }
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (!user32) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return nullptr;
    }
    auto real = reinterpret_cast<SetWindowsHookExA_t>(
        GetProcAddress(user32, "SetWindowsHookExA"));
    if (real && real != &HookSetWindowsHookExA) {
        return real(idHook, lpfn, hmod, threadId);
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return nullptr;
}

HHOOK WINAPI HookSetWindowsHookExW(int idHook,
                                   HOOKPROC lpfn,
                                   HINSTANCE hmod,
                                   DWORD threadId) {
    const bool keyboard = IsKeyboardHookId(idHook);
    bool forced = false;
    bool allowed = true;
    if (keyboard && ForceInputEnabled()) {
        forced = true;
        allowed = false;
    }

    if (keyboard) {
        std::ostringstream detail;
        detail << "type=keyboard"
               << " id=" << idHook
               << " thread=" << threadId
               << " allowed=" << (allowed ? 1 : 0)
               << " forced=" << (forced ? 1 : 0)
               << " cb=0x" << std::hex << reinterpret_cast<UINT_PTR>(lpfn);
        detail << std::dec;

        LogMessage((std::stringstream()
                        << "SetWindowsHookExW: id=" << idHook
                        << " thread=" << threadId
                        << " allowed=" << (allowed ? "TRUE" : "FALSE"))
                       .str());
        LogStructured("call", "SetWindowsHookExW", detail.str());

        if (!allowed) {
            SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }
    }

    return CallOriginalSetWindowsHookExW(idHook, lpfn, hmod, threadId);
}

HHOOK WINAPI HookSetWindowsHookExA(int idHook,
                                   HOOKPROC lpfn,
                                   HINSTANCE hmod,
                                   DWORD threadId) {
    const bool keyboard = IsKeyboardHookId(idHook);
    bool forced = false;
    bool allowed = true;
    if (keyboard && ForceInputEnabled()) {
        forced = true;
        allowed = false;
    }

    if (keyboard) {
        std::ostringstream detail;
        detail << "type=keyboard"
               << " id=" << idHook
               << " thread=" << threadId
               << " allowed=" << (allowed ? 1 : 0)
               << " forced=" << (forced ? 1 : 0)
               << " cb=0x" << std::hex << reinterpret_cast<UINT_PTR>(lpfn);
        detail << std::dec;

        LogMessage((std::stringstream()
                        << "SetWindowsHookExA: id=" << idHook
                        << " thread=" << threadId
                        << " allowed=" << (allowed ? "TRUE" : "FALSE"))
                       .str());
        LogStructured("call", "SetWindowsHookExA", detail.str());

        if (!allowed) {
            SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }
    }

    return CallOriginalSetWindowsHookExA(idHook, lpfn, hmod, threadId);
}

// =========================
// DirectInput Hooks
// =========================
typedef HRESULT (WINAPI* DirectInput8Create_t)(HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
typedef HRESULT (STDMETHODCALLTYPE* DI8_CreateDevice_t)(IDirectInput8*, REFGUID, LPDIRECTINPUTDEVICE8*, LPUNKNOWN);
typedef HRESULT (STDMETHODCALLTYPE* DIDevice_Acquire_t)(IDirectInputDevice8*);
typedef HRESULT (STDMETHODCALLTYPE* DIDevice_SetCooperativeLevel_t)(IDirectInputDevice8*, HWND, DWORD);

DirectInput8Create_t OriginalDirectInput8Create = nullptr;
DI8_CreateDevice_t OriginalDICreateDevice = nullptr;
DIDevice_Acquire_t OriginalDIDeviceAcquire = nullptr;
DIDevice_SetCooperativeLevel_t OriginalDIDeviceSetCooperativeLevel = nullptr;

void HookDirectInputDevice(IDirectInputDevice8* device);

HRESULT STDMETHODCALLTYPE DIDeviceAcquireDetour(IDirectInputDevice8* self) {
    if (!self) {
        return DIERR_INVALIDPARAM;
    }
    std::ostringstream detail;
    detail << "device=0x" << std::hex << reinterpret_cast<UINT_PTR>(self);
    LogStructured("call", "DirectInput::Acquire", detail.str());
    if (!OriginalDIDeviceAcquire) {
        HookDirectInputDevice(self);
    }
    return OriginalDIDeviceAcquire ? OriginalDIDeviceAcquire(self) : DIERR_NOTINITIALIZED;
}

HRESULT STDMETHODCALLTYPE DIDeviceSetCooperativeLevelDetour(IDirectInputDevice8* self, HWND hwnd, DWORD flags) {
    if (!self) {
        return DIERR_INVALIDPARAM;
    }
    DWORD applied = flags;
    bool forced = false;
    if (ForceInputEnabled() && (applied & DISCL_EXCLUSIVE)) {
        applied &= ~DISCL_EXCLUSIVE;
        applied |= DISCL_NONEXCLUSIVE;
        forced = true;
    }

    std::ostringstream detail;
    detail << "device=0x" << std::hex << reinterpret_cast<UINT_PTR>(self)
           << std::dec << " flags=0x" << std::hex << flags
           << std::dec << " applied=0x" << std::hex << applied
           << std::dec << " forced=" << (forced ? 1 : 0);
    LogStructured("call", "DirectInput::SetCooperativeLevel", detail.str());

    if (!OriginalDIDeviceSetCooperativeLevel) {
        HookDirectInputDevice(self);
    }
    return OriginalDIDeviceSetCooperativeLevel ? OriginalDIDeviceSetCooperativeLevel(self, hwnd, applied)
                                               : DIERR_NOTINITIALIZED;
}

void HookDirectInputDevice(IDirectInputDevice8* device) {
    if (!device) {
        return;
    }
    void** vtbl = *(void***)device;
    if (!vtbl) {
        return;
    }

    HookEngine& eng = HookEngine::getInstance();

    void* acquireAddr = vtbl[7];
    if (acquireAddr && !g_dinputAcquireAddr.load(std::memory_order_acquire)) {
        if (eng.installInlineHook(acquireAddr,
                                  reinterpret_cast<LPVOID>(&DIDeviceAcquireDetour),
                                  reinterpret_cast<LPVOID*>(&OriginalDIDeviceAcquire))) {
            g_dinputAcquireAddr.store(acquireAddr, std::memory_order_release);
        }
    }

    void* coopAddr = vtbl[13];
    if (coopAddr && !g_dinputSetCoopAddr.load(std::memory_order_acquire)) {
        if (eng.installInlineHook(coopAddr,
                                  reinterpret_cast<LPVOID>(&DIDeviceSetCooperativeLevelDetour),
                                  reinterpret_cast<LPVOID*>(&OriginalDIDeviceSetCooperativeLevel))) {
            g_dinputSetCoopAddr.store(coopAddr, std::memory_order_release);
        }
    }
}

HRESULT STDMETHODCALLTYPE DICreateDeviceDetour(IDirectInput8* self,
                                               REFGUID rguid,
                                               LPDIRECTINPUTDEVICE8* device,
                                               LPUNKNOWN outer) {
    if (!OriginalDICreateDevice) {
        return DIERR_NOTINITIALIZED;
    }
    HRESULT hr = OriginalDICreateDevice(self, rguid, device, outer);
    if (SUCCEEDED(hr) && device && *device) {
        HookDirectInputDevice(*device);
    }
    return hr;
}

void HookDirectInputInterface(IDirectInput8* di) {
    if (!di) {
        return;
    }
    void** vtbl = *(void***)di;
    if (!vtbl) {
        return;
    }
    void* createDeviceAddr = vtbl[3];
    if (!createDeviceAddr) {
        return;
    }
    if (g_dinputCreateDeviceAddr.load(std::memory_order_acquire)) {
        return;
    }
    HookEngine& eng = HookEngine::getInstance();
    if (eng.installInlineHook(createDeviceAddr,
                              reinterpret_cast<LPVOID>(&DICreateDeviceDetour),
                              reinterpret_cast<LPVOID*>(&OriginalDICreateDevice))) {
        g_dinputCreateDeviceAddr.store(createDeviceAddr, std::memory_order_release);
    }
}

HRESULT WINAPI HookDirectInput8Create(HINSTANCE hinst,
                                      DWORD version,
                                      REFIID riid,
                                      LPVOID* out,
                                      LPUNKNOWN outer) {
    auto orig = OriginalDirectInput8Create;
    if (!orig) {
        HMODULE mod = GetModuleHandleW(L"dinput8.dll");
        if (mod) {
            orig = reinterpret_cast<DirectInput8Create_t>(GetProcAddress(mod, "DirectInput8Create"));
            OriginalDirectInput8Create = orig;
        }
    }
    if (orig && !g_directInput8CreateAddr.load(std::memory_order_acquire)) {
        g_directInput8CreateAddr.store(reinterpret_cast<void*>(orig), std::memory_order_release);
    }
    HRESULT hr = orig ? orig(hinst, version, riid, out, outer) : DIERR_NOTINITIALIZED;
    if (SUCCEEDED(hr) && out && *out) {
        auto* di = reinterpret_cast<IDirectInput8*>(*out);
        HookDirectInputInterface(di);
    }
    return hr;
}

// =========================
// BitBlt Hook (Screenshot detection)
// =========================
typedef BOOL (WINAPI* BitBlt_t)(HDC, int, int, int, int, HDC, int, int, DWORD);
BitBlt_t OriginalBitBlt = nullptr;

typedef BOOL (WINAPI* SwapBuffers_t)(HDC);
SwapBuffers_t OriginalSwapBuffers = nullptr;

typedef BOOL (WINAPI* WglSwapBuffers_t)(HDC);
WglSwapBuffers_t OriginalWglSwapBuffers = nullptr;

typedef void (APIENTRY* GlFinish_t)();
GlFinish_t OriginalGlFinish = nullptr;

BOOL WINAPI HookBitBlt(
    HDC hdcDest, int nXDest, int nYDest, int nWidth, int nHeight,
    HDC hdcSrc, int nXSrc, int nYSrc, DWORD dwRop) {

    std::stringstream ss;
    ss << "BitBlt: Screenshot operation detected - "
       << "Size(" << nWidth << "x" << nHeight << ")";
    LogMessage(ss.str());
    LogStructured("call", "BitBlt",
                  (std::stringstream() << "width=" << nWidth << " height=" << nHeight).str());

    if (OriginalBitBlt) {
        return OriginalBitBlt(hdcDest, nXDest, nYDest, nWidth, nHeight,
                              hdcSrc, nXSrc, nYSrc, dwRop);
    }

    static BitBlt_t realBitBlt = reinterpret_cast<BitBlt_t>(
        GetProcAddress(GetModuleHandleW(L"gdi32.dll"), "BitBlt"));
    if (realBitBlt) {
        return realBitBlt(hdcDest, nXDest, nYDest, nWidth, nHeight,
                          hdcSrc, nXSrc, nYSrc, dwRop);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI HookSwapBuffers(HDC hdc) {
    HWND hwnd = hdc ? WindowFromDC(hdc) : nullptr;
    const bool blocked = (hwnd != nullptr) &&
        IsWindowTargetBlocked(reinterpret_cast<uintptr_t>(hwnd));

    std::ostringstream detail;
    detail << "hdc=" << HexFromValue(reinterpret_cast<uintptr_t>(hdc));
    if (hwnd) {
        detail << " hwnd=" << HexFromValue(reinterpret_cast<uintptr_t>(hwnd));
    }
    detail << " blocked=" << (blocked ? 1 : 0);
    const std::string detailStr = detail.str();
    LogStructured("graphics", "SwapBuffers", AppendSessionDetail(detailStr));

    if (blocked) {
        LogStructured("policy",
                      "swapbuffers_enforced",
                      AppendSessionDetail(detailStr + " forced=1 reason=policy_window"));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    SwapBuffers_t target = OriginalSwapBuffers;
    if (!target) {
        static SwapBuffers_t real = reinterpret_cast<SwapBuffers_t>(
            GetProcAddress(GetModuleHandleW(L"gdi32.dll"), "SwapBuffers"));
        target = real;
    }
    if (target) {
        return target(hdc);
    }
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

BOOL WINAPI HookWglSwapBuffers(HDC hdc) {
    HWND hwnd = hdc ? WindowFromDC(hdc) : nullptr;
    const bool blocked = (hwnd != nullptr) &&
        IsWindowTargetBlocked(reinterpret_cast<uintptr_t>(hwnd));

    std::ostringstream detail;
    detail << "hdc=" << HexFromValue(reinterpret_cast<uintptr_t>(hdc));
    if (hwnd) {
        detail << " hwnd=" << HexFromValue(reinterpret_cast<uintptr_t>(hwnd));
    }
    detail << " blocked=" << (blocked ? 1 : 0);
    const std::string detailStr = detail.str();
    LogStructured("graphics", "wglSwapBuffers", AppendSessionDetail(detailStr));

    if (blocked) {
        LogStructured("policy",
                      "wglswapbuffers_enforced",
                      AppendSessionDetail(detailStr + " forced=1 reason=policy_window"));
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    WglSwapBuffers_t target = OriginalWglSwapBuffers;
    if (!target) {
        static WglSwapBuffers_t real = reinterpret_cast<WglSwapBuffers_t>(
            GetProcAddress(GetModuleHandleW(L"opengl32.dll"), "wglSwapBuffers"));
        target = real;
    }
    if (target) {
        return target(hdc);
    }
    SetLastError(ERROR_PROC_NOT_FOUND);
    return FALSE;
}

void APIENTRY HookGlFinish() {
    std::ostringstream detail;
    detail << "tid=" << GetCurrentThreadId();
    LogStructured("graphics", "glFinish", AppendSessionDetail(detail.str()));

    GlFinish_t target = OriginalGlFinish;
    if (!target) {
        static GlFinish_t real = reinterpret_cast<GlFinish_t>(
            GetProcAddress(GetModuleHandleW(L"opengl32.dll"), "glFinish"));
        target = real;
    }
    if (target) {
        target();
    }
}

// =========================
// MessageBoxA Hook (for testing)
// =========================
typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = nullptr;

int WINAPI HookMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::stringstream ss;
    ss << "MessageBoxA: \"" << (lpText ? lpText : "null") << "\"";
    LogMessage(ss.str());
    LogStructured("call", "MessageBoxA");

    std::string modifiedText = std::string("[HOOKED] ") + (lpText ? lpText : "");
    if (OriginalMessageBoxA) {
        return OriginalMessageBoxA(hWnd, modifiedText.c_str(), lpCaption, uType);
    }

    static MessageBoxA_t realMessageBoxA = reinterpret_cast<MessageBoxA_t>(
        GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxA"));
    if (realMessageBoxA) {
        return realMessageBoxA(hWnd, modifiedText.c_str(), lpCaption, uType);
    }

    return IDOK;
}

// =========================
// CreateFileW Hook (File monitoring)
// =========================
typedef HANDLE (WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileW_t OriginalCreateFileW = nullptr;

HANDLE WINAPI HookCreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {

    if (lpFileName) {
        std::wstring wfileName(lpFileName);
        std::string fileName = Narrow(wfileName);

        std::stringstream ss;
        ss << "CreateFileW: \"" << fileName << "\"";
        LogMessage(ss.str());
        LogStructured("call", "CreateFileW",
                      (std::stringstream() << "path=\"" << fileName << "\"").str());
    }

    if (OriginalCreateFileW) {
        return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                                   lpSecurityAttributes, dwCreationDisposition,
                                   dwFlagsAndAttributes, hTemplateFile);
    }

    static CreateFileW_t realCreateFileW = reinterpret_cast<CreateFileW_t>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateFileW"));
    if (realCreateFileW) {
        return realCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                               lpSecurityAttributes, dwCreationDisposition,
                               dwFlagsAndAttributes, hTemplateFile);
    }

    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return INVALID_HANDLE_VALUE;
}

// =========================
// NtUserSetWindowDisplayAffinity Hook (Native API level)
// =========================
typedef LONG (NTAPI* NtUserSetWindowDisplayAffinity_t)(HWND, DWORD);
NtUserSetWindowDisplayAffinity_t OriginalNtUserSetWindowDisplayAffinity = nullptr;

LONG NTAPI HookNtUserSetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity) {
    DWORD applied = dwAffinity;
    bool forced = false;
    if (ForceWdaNoneEnabled() && dwAffinity != WDA_NONE) {
        applied = WDA_NONE;
        forced = true;
    }

    std::stringstream ss;
    ss << "NtUserSetWindowDisplayAffinity: HWND=0x" << std::hex << reinterpret_cast<UINT_PTR>(hWnd)
       << " requested=0x" << dwAffinity
       << " applied=0x" << applied
       << " forced=" << (forced ? "TRUE" : "FALSE");
    LogMessage(ss.str());

    std::ostringstream detail;
    detail << "hwnd=0x" << std::hex << reinterpret_cast<UINT_PTR>(hWnd)
           << " requested=0x" << dwAffinity
           << " applied=0x" << applied
           << " forced=" << (forced ? 1 : 0);
    LogStructured("call", "NtUserSetWindowDisplayAffinity", detail.str());

    if (OriginalNtUserSetWindowDisplayAffinity) {
        return OriginalNtUserSetWindowDisplayAffinity(hWnd, applied);
    }

    return STATUS_NOT_IMPLEMENTED;
}

// =========================
// Hook Installation
// =========================
bool InstallHooks() {
    std::lock_guard<std::mutex> lock(g_hookManagementMutex);
    if (g_installAttempted) {
        return g_installSucceeded;
    }

    g_installAttempted = true;

    LogMessage("=== Installing HookDLL instrumentation ===");
    LogMessage("Process: " + std::to_string(GetCurrentProcessId()));

    WCHAR processPath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, processPath, MAX_PATH)) {
        LogMessage("Target Process: " + Narrow(processPath));
    }

    auto installSingleHook = [&](const wchar_t* moduleName,
                                 const char* functionName,
                                 LPVOID detour,
                                 LPVOID* original,
                                 const char* label,
                                 const std::vector<HookLayer>& layers) {
        if (!moduleName) {
            std::stringstream ss;
            ss << "[!] Skipping " << label << " hook - module not loaded";
            LogMessage(ss.str());
            return false;
        }

        HookTargetDescriptor descriptor;
        descriptor.moduleName = moduleName;
        descriptor.functionName = functionName;

        if (InstallMultiLayerHook(descriptor, detour, original, layers)) {
            std::stringstream ss;
            ss << "[+] Hook installed: " << label;
            LogMessage(ss.str());

            std::string layerSummary = DescribeInstalledLayers(functionName ? functionName : "");
            if (!layerSummary.empty()) {
                std::stringstream layerStream;
                layerStream << "    Layers: " << layerSummary;
                LogMessage(layerStream.str());
            }
            return true;
        }

        std::stringstream ss;
        ss << "[!] Failed to install hook: " << label;
        LogMessage(ss.str());
        return false;
    };

    bool anySuccess = false;

    anySuccess |= installSingleHook(
        L"user32.dll",
        "SetWindowDisplayAffinity",
        (LPVOID)HookSetWindowDisplayAffinity,
        (LPVOID*)&OriginalSetWindowDisplayAffinity,
        "SetWindowDisplayAffinity",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"win32u.dll",
        "NtUserSetWindowDisplayAffinity",
        (LPVOID)HookNtUserSetWindowDisplayAffinity,
        (LPVOID*)&OriginalNtUserSetWindowDisplayAffinity,
        "NtUserSetWindowDisplayAffinity",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Syscall});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "BlockInput",
        (LPVOID)HookBlockInput,
        (LPVOID*)&OriginalBlockInput,
        "BlockInput",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"win32u.dll",
        "NtUserBlockInput",
        (LPVOID)HookNtUserBlockInput,
        (LPVOID*)&OriginalNtUserBlockInput,
        "NtUserBlockInput",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::Syscall, HookLayer::VEH});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "EnableWindow",
        (LPVOID)HookEnableWindow,
        (LPVOID*)&OriginalEnableWindow,
        "EnableWindow",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "AttachThreadInput",
        (LPVOID)HookAttachThreadInput,
        (LPVOID*)&OriginalAttachThreadInput,
        "AttachThreadInput",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"win32u.dll",
        "NtUserAttachThreadInput",
        (LPVOID)HookNtUserAttachThreadInput,
        (LPVOID*)&OriginalNtUserAttachThreadInput,
        "NtUserAttachThreadInput",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::Syscall, HookLayer::VEH});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "SystemParametersInfoW",
        (LPVOID)HookSystemParametersInfoW,
        (LPVOID*)&OriginalSystemParametersInfoW,
        "SystemParametersInfoW",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"win32u.dll",
        "NtUserSetInformationThread",
        (LPVOID)HookNtUserSetInformationThread,
        (LPVOID*)&OriginalNtUserSetInformationThread,
        "NtUserSetInformationThread",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::Syscall, HookLayer::VEH});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "SetWindowsHookExW",
        (LPVOID)HookSetWindowsHookExW,
        (LPVOID*)&OriginalSetWindowsHookExW,
        "SetWindowsHookExW",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "SetWindowsHookExA",
        (LPVOID)HookSetWindowsHookExA,
        (LPVOID*)&OriginalSetWindowsHookExA,
        "SetWindowsHookExA",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH, HookLayer::Instrumentation});

    anySuccess |= installSingleHook(
        L"gdi32.dll",
        "BitBlt",
        (LPVOID)HookBitBlt,
        (LPVOID*)&OriginalBitBlt,
        "BitBlt",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::EAT, HookLayer::VEH});

    anySuccess |= installSingleHook(
        L"gdi32.dll",
        "SwapBuffers",
        (LPVOID)HookSwapBuffers,
        (LPVOID*)&OriginalSwapBuffers,
        "SwapBuffers",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::EAT, HookLayer::VEH});

    anySuccess |= installSingleHook(
        L"opengl32.dll",
        "wglSwapBuffers",
        (LPVOID)HookWglSwapBuffers,
        (LPVOID*)&OriginalWglSwapBuffers,
        "wglSwapBuffers",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::EAT, HookLayer::VEH});

    anySuccess |= installSingleHook(
        L"opengl32.dll",
        "glFinish",
        (LPVOID)HookGlFinish,
        (LPVOID*)&OriginalGlFinish,
        "glFinish",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::EAT});

    anySuccess |= installSingleHook(
        L"user32.dll",
        "MessageBoxA",
        (LPVOID)HookMessageBoxA,
        (LPVOID*)&OriginalMessageBoxA,
        "MessageBoxA",
        {HookLayer::Inline, HookLayer::IAT});

    anySuccess |= installSingleHook(
        L"kernel32.dll",
        "CreateFileW",
        (LPVOID)HookCreateFileW,
        (LPVOID*)&OriginalCreateFileW,
        "CreateFileW",
        {HookLayer::Inline, HookLayer::IAT});

    anySuccess |= installSingleHook(
        L"dinput8.dll",
        "DirectInput8Create",
        (LPVOID)HookDirectInput8Create,
        (LPVOID*)&OriginalDirectInput8Create,
        "DirectInput8Create",
        {HookLayer::Inline, HookLayer::IAT, HookLayer::VEH});

    if (anySuccess) {
        LogMessage("=== Hook installation complete ===");
    } else {
        LogMessage("[!] No hooks were installed; see previous messages for details");
    }

    g_installSucceeded = anySuccess;
    return g_installSucceeded;
}

void UninstallHooks() {
    std::lock_guard<std::mutex> lock(g_hookManagementMutex);
    if (!g_installAttempted) {
        return;
    }

    LogMessage("=== Uninstalling hooks ===");

    // Remove all installed hooks (multi-layer + inline)
    InternalUninstallAllHooks();
    StopGraphicsModuleScanner();

    g_installAttempted = false;
    g_installSucceeded = false;
    OriginalSetWindowDisplayAffinity = nullptr;
    OriginalNtUserSetWindowDisplayAffinity = nullptr;
    OriginalBlockInput = nullptr;
    OriginalNtUserBlockInput = nullptr;
    OriginalEnableWindow = nullptr;
    OriginalAttachThreadInput = nullptr;
    OriginalNtUserAttachThreadInput = nullptr;
    OriginalSystemParametersInfoW = nullptr;
    OriginalNtUserSetInformationThread = nullptr;
    OriginalSetWindowsHookExW = nullptr;
    OriginalSetWindowsHookExA = nullptr;
    OriginalBitBlt = nullptr;
    OriginalSwapBuffers = nullptr;
    OriginalWglSwapBuffers = nullptr;
    OriginalGlFinish = nullptr;
    OriginalMessageBoxA = nullptr;
    OriginalCreateFileW = nullptr;
    OriginalDirectInput8Create = nullptr;
    OriginalDICreateDevice = nullptr;
    OriginalDIDeviceAcquire = nullptr;
    OriginalDIDeviceSetCooperativeLevel = nullptr;
    g_directInput8CreateAddr.store(nullptr, std::memory_order_relaxed);
    g_dinputCreateDeviceAddr.store(nullptr, std::memory_order_relaxed);
    g_dinputAcquireAddr.store(nullptr, std::memory_order_relaxed);
    g_dinputSetCoopAddr.store(nullptr, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> policyLock(g_graphicsPolicyMutex);
        g_blockedDuplicationHandles.clear();
        g_blockedWindowTargets.clear();
        g_blockedMonitorTargets.clear();
        g_blockedSwapChains.clear();
    }
}

// =========================
// Self-Protection
// =========================
void EnableSelfProtection() {
    HMODULE module = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_PIN,
                           reinterpret_cast<LPCWSTR>(&EnableSelfProtection),
                           &module)) {
        g_selfModule = module;
        LogMessage("Self-protection enabled - DLL pinned in memory");
    } else {
        LogMessage("[!] Failed to pin DLL in memory; continuing without self-protection");
    }
}

// =========================
// DLL Entry Point
// =========================
DWORD WINAPI HookDllWorkerThread(LPVOID) {
    LogMessage("==============================================");
    LogMessage("HookDLL loaded into process");
    LogMessage("Initializing instrumentation");
    LogMessage("==============================================");

    // Load configuration (sets process env vars for flags)
    try {
        std::wstring used = umh::LoadAndApplyConfig();
        if (!used.empty()) {
            LogMessage(std::string("Loaded config: ") + Narrow(used));
        }
    } catch (...) {
        LogMessage("[!] Config load failed; proceeding with defaults");
    }

    EnableSelfProtection();
    injection::SetDirectSyscallStructuredLogger(LogStructured);

    dxhooks::SetTelemetryCallback([](const char* event, const char* func, const std::string& detail) {
        const std::string evt = event ? event : "graphics";
        const std::string fn = func ? func : "unknown";
        LogStructured(evt, fn, AppendSessionDetail(detail));
    });
    dxhooks::SetPolicyCallback([](const char* operation, uintptr_t primary, uintptr_t secondary) -> bool {
        if (!operation) {
            return false;
        }
        if (std::strcmp(operation, "duplication_acquire") == 0) {
            if (IsDuplicationBlocked(primary)) {
                std::ostringstream detail;
                detail << "dup=" << HexFromValue(primary)
                       << " state=1";
                if (secondary) {
                    detail << " timeout=" << secondary;
                }
                LogStructured("policy", "duplication_enforced", AppendSessionDetail(detail.str()));
                return true;
            }
            return false;
        }
        if (std::strcmp(operation, "capture_window") == 0) {
            if (IsWindowTargetBlocked(primary)) {
                std::ostringstream detail;
                detail << "hwnd=" << HexFromValue(primary)
                       << " state=1";
                LogStructured("policy", "capture_window_enforced", AppendSessionDetail(detail.str()));
                return true;
            }
            return false;
        }
        if (std::strcmp(operation, "capture_monitor") == 0) {
            if (IsMonitorTargetBlocked(primary)) {
                std::ostringstream detail;
                detail << "monitor=" << HexFromValue(primary)
                       << " state=1";
                LogStructured("policy", "capture_monitor_enforced", AppendSessionDetail(detail.str()));
                return true;
            }
            return false;
        }
        if (std::strcmp(operation, "swap_chain_present") == 0) {
            if (IsSwapChainBlocked(primary)) {
                std::ostringstream detail;
                detail << "swap=" << HexFromValue(primary)
                       << " state=1";
                if (secondary) {
                    detail << " flags=" << HexFromValue(secondary);
                }
                LogStructured("policy", "swap_chain_enforced", AppendSessionDetail(detail.str()));
                return true;
            }
            return false;
        }
        return false;
    });

    openxrhooks::SetTelemetryCallback([](const char* func, const std::string& detail) {
        const char* name = func ? func : "unknown";
        LogStructured("openxr", name, AppendSessionDetail(detail));
    });
    openxrhooks::SetPolicyCallback([](const char* operation, uintptr_t primary, uintptr_t secondary) -> bool {
        UNREFERENCED_PARAMETER(operation);
        UNREFERENCED_PARAMETER(primary);
        UNREFERENCED_PARAMETER(secondary);
        return false;
    });

    LogHardwareSchedulingStatus();
    LogAdapterTopology();

    if (EnvOrRegEnabled(L"HOOKDLL_ENABLE_ANTIANALYSIS")) {
        const bool detected = DetectAnalysis();
        LogStructured("anti_detect", "analysis", std::string("detected=") + (detected?"1":"0"));
        if (detected && EnvOrRegEnabled(L"HOOKDLL_APPLY_COUNTERMEASURES")) {
            ApplyAntiAnalysis();
        }
    }

    if (EnvOrRegEnabled(L"HOOKDLL_ENABLE_TIMING_EVASION")) {
        void* tev = CreateTimingEvasion();
        bool tdet = false;
        if (tev) {
            tdet = DetectTiming(tev);
            LogStructured("anti_detect", "timing", std::string("detected=") + (tdet?"1":"0"));
            DestroyTimingEvasion(tev);
        }
    }

    vkhooks::Initialize();
    dxhooks::Initialize();
    openxrhooks::Initialize();
    InstallHooks();
    StartGraphicsModuleScanner();

    // Start telemetry pipe server for UnifiedAgent/status queries
    if (!g_pipeStopEvent) {
        g_pipeStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    if (!g_pipeThread) {
        g_pipeThread = CreateThread(nullptr, 0, TelemetryPipeServer, nullptr, 0, nullptr);
    }

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        InitializeCriticalSection(&g_logCs);
        DisableThreadLibraryCalls(hModule);
        g_selfModule = hModule;

        if (!QueueUserWorkItem(HookDllWorkerThread, nullptr, WT_EXECUTEDEFAULT)) {
            LogMessage("[!] Failed to queue initialization work item; running inline");
            HookDllWorkerThread(nullptr);
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        UninstallHooks();
        if (g_pipeStopEvent) { SetEvent(g_pipeStopEvent); }
        if (g_pipeThread) { WaitForSingleObject(g_pipeThread, 2000); CloseHandle(g_pipeThread); g_pipeThread = nullptr; }
        if (g_pipeStopEvent) { CloseHandle(g_pipeStopEvent); g_pipeStopEvent = nullptr; }
        dxhooks::SetPolicyCallback({});
        dxhooks::SetTelemetryCallback({});
        dxhooks::Shutdown();
        openxrhooks::SetPolicyCallback({});
        openxrhooks::SetTelemetryCallback({});
        openxrhooks::Shutdown();
        vkhooks::Shutdown();
        LogMessage("Hook DLL unloading");
        LogMessage("==============================================");

        if (g_logFile.is_open()) {
            g_logFile.close();
        }
        if (g_logMutex) {
            CloseHandle(g_logMutex);
            g_logMutex = nullptr;
        }
        DeleteCriticalSection(&g_logCs);
        break;
    }

    return TRUE;
}



