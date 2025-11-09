#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <set>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <map>
#include <atomic>
#include <cctype>
#include <limits>
#include <cwctype>
#include <sddl.h>
#include <dxgi1_6.h>
#include <deque>
#include <wbemidl.h>
#include "../include/JsonUtil.h"
#include "../include/UnifiedAgentState.h"
#include "../include/ProcessTargets.h"

#ifndef ERROR_NOT_FOUND
#define ERROR_NOT_FOUND 1168L
#endif

#include "../include/InjectionEngine.h"
#include "../include/DirectXHooks.h"
#include "../include/PipeNames.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace {

constexpr DWORD kInvalidSessionId = 0xFFFFFFFFu;
constexpr int kPolicyNoChange = std::numeric_limits<int>::max();
constexpr ULONGLONG kPolicyAttemptCooldownMs = 2000; // 2 seconds
constexpr ULONGLONG kKeyboardRelaxMs = 60000;        // 60 seconds
constexpr ULONGLONG kDisplayRelaxMs = 60000;         // 60 seconds
constexpr ULONGLONG kPolicyCleanupMs = 300000;       // 5 minutes

struct KeyboardTelemetryEntry {
    ULONGLONG blockRequests = 0;
    ULONGLONG blockForced = 0;
    ULONGLONG ntRequests = 0;
    ULONGLONG ntForced = 0;
    ULONGLONG attachRequests = 0;
    ULONGLONG attachPrevented = 0;
    ULONGLONG ntAttachRequests = 0;
    ULONGLONG ntAttachPrevented = 0;
    ULONGLONG spiRequests = 0;
    ULONGLONG spiForced = 0;
    ULONGLONG enableRequests = 0;
    ULONGLONG enableForced = 0;
    ULONGLONG ntSetInfoRequests = 0;
    ULONGLONG ntSetInfoBlocked = 0;
    ULONGLONG hookAttempts = 0;
    ULONGLONG hookBlocked = 0;
    ULONGLONG diAcquire = 0;
    ULONGLONG diSetCoop = 0;
    ULONGLONG diSetCoopForced = 0;
    ULONGLONG lastTick = 0;
    std::wstring lastKnownName;
    DWORD sessionId = kInvalidSessionId;
    std::wstring userSid;
    std::wstring userName;
};

struct DuplicationTelemetryEntry {
    ULONGLONG createCount = 0;
    ULONGLONG acquireCount = 0;
    ULONGLONG lastHr = 0;
    ULONGLONG lastPresentTime = 0;
    ULONGLONG pointerVisible = 0;
    LONG pointerX = 0;
    LONG pointerY = 0;
    ULONGLONG pointerShapeBytes = 0;
    ULONGLONG outputHandle = 0;
    ULONGLONG deviceHandle = 0;
    ULONGLONG resourceHandle = 0;
    ULONGLONG lastTimeout = 0;
    ULONGLONG lastFrames = 0;
    ULONGLONG lastTick = 0;
};

struct CaptureTelemetryEntry {
    ULONGLONG createCount = 0;
    ULONGLONG lastHr = 0;
    ULONGLONG targetHandle = 0;
    bool isMonitor = false;
    std::wstring iid;
    ULONGLONG itemHandle = 0;
    ULONGLONG lastTick = 0;
};

struct SwapChainTelemetryEntry {
    ULONGLONG presentCount = 0;
    ULONGLONG blockedCount = 0;
    ULONGLONG lastHr = 0;
    ULONGLONG lastFlags = 0;
    ULONGLONG lastInterval = 0;
    bool lastWasPresent1 = false;
    bool lastWasD3D12 = false;
    ULONGLONG lastTick = 0;
};

struct GraphicsTelemetryEntry {
    std::map<std::string, unsigned long long> modules;
    std::map<unsigned long long, DuplicationTelemetryEntry> duplications;
    std::map<unsigned long long, CaptureTelemetryEntry> captures;
    std::map<unsigned long long, SwapChainTelemetryEntry> swapChains;
    ULONGLONG lastTick = 0;
    DWORD sessionId = kInvalidSessionId;
    std::wstring userSid;
    std::wstring userName;
};

struct DisplayTelemetryEntry {
    ULONGLONG userModeRequests = 0;
    ULONGLONG userModeForced = 0;
    ULONGLONG nativeRequests = 0;
    ULONGLONG nativeForced = 0;
    ULONGLONG swapRequests = 0;
    ULONGLONG swapBlocked = 0;
    ULONGLONG glFinishCalls = 0;
    ULONGLONG lastTick = 0;
    std::wstring lastKnownName;
    DWORD sessionId = kInvalidSessionId;
    std::wstring userSid;
    std::wstring userName;
};

struct ProcessIdentityInfo {
    DWORD sessionId = kInvalidSessionId;
    std::wstring userSid;
    std::wstring userName;
    ULONGLONG lastSeen = 0;
};

struct PolicyState {
    int forceInput = 0;
    unsigned long long keyboardForcedCount = 0;
    ULONGLONG keyboardLastEventTick = 0;
    ULONGLONG lastForceInputApplied = 0;
    ULONGLONG lastForceInputAttempt = 0;
    int forceWda = 0;
    unsigned long long wdaForcedCount = 0;
    ULONGLONG wdaLastEventTick = 0;
    ULONGLONG lastForceWdaApplied = 0;
    ULONGLONG lastForceWdaAttempt = 0;
};

static std::map<DWORD, KeyboardTelemetryEntry> g_keyboardTelemetry;
static ULONGLONG g_keyboardLastOffset = 0;
constexpr size_t kMaxKeyboardTelemetryEntries = 512;
static std::map<DWORD, GraphicsTelemetryEntry> g_graphicsTelemetry;
constexpr size_t kMaxGraphicsTelemetryEntries = 512;
constexpr size_t kMaxGraphicsConnectionsPerType = 128;
static std::set<DWORD> g_graphicsEscalated;
static std::map<DWORD, ProcessIdentityInfo> g_processIdentity;
static std::map<DWORD, PolicyState> g_policyState;
static std::map<DWORD, std::set<unsigned long long>> g_policyBlockedDuplications;
static std::map<DWORD, std::set<unsigned long long>> g_policyBlockedCaptureWindows;
static std::map<DWORD, std::set<unsigned long long>> g_policyBlockedCaptureMonitors;
static std::map<DWORD, std::set<unsigned long long>> g_policyBlockedSwapChains;
static std::map<DWORD, DisplayTelemetryEntry> g_displayTelemetry;
constexpr size_t kMaxDisplayTelemetryEntries = 512;
struct InjectionBackoffState {
    ULONGLONG nextAttemptTick = 0;
    unsigned int attempts = 0;
    std::wstring lastError;
};
static std::map<DWORD, InjectionBackoffState> g_injectionBackoff;
constexpr ULONGLONG kInitialBackoffMs = 4000;  // 4 seconds
constexpr ULONGLONG kMaxBackoffMs = 60000;     // 60 seconds
constexpr unsigned int kMaxBackoffSteps = 6;
constexpr ULONGLONG kFallbackSweepMs = 15000;  // run full snapshot every 15 seconds as safety net
static std::set<std::wstring> g_forceFingerprints;
static std::set<std::wstring> g_skipFingerprints;
static FILETIME g_fingerprintLastWrite = {};
static std::set<DWORD> g_fingerprintSkipLogged;
static std::set<DWORD> g_fingerprintForceLogged;
static bool g_wmiInitAttempted = false;
static bool g_wmiCoInitialized = false;
static IWbemLocator* g_wmiLocator = nullptr;
static IWbemServices* g_wmiServices = nullptr;
static IEnumWbemClassObject* g_wmiProcessEvents = nullptr;
static std::deque<DWORD> g_processEventQueue;
static bool g_processEventOverflowed = false;
constexpr size_t kMaxProcessEventQueue = 1024;

bool EnvEnabled(const wchar_t* name) {
    if (!name) return false; wchar_t b[32] = {}; DWORD n = GetEnvironmentVariableW(name, b, 32);
    if (!n || n >= 32) return false; std::wstring v(b, b+n); for (auto& c : v) c = (wchar_t)towlower(c);
    return (v == L"1" || v == L"true" || v == L"yes" || v == L"on");
}

std::wstring GetExeDir() {
    wchar_t path[MAX_PATH]{}; GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring p(path); auto pos = p.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
}

std::wstring DataDir() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring base = (n && n < MAX_PATH) ? std::wstring(buf, buf + n) : L"C:\\ProgramData";
    std::wstring dir = base + L"\\UserModeHook";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

void Log(const std::wstring& msg) {
    std::wstring path = DataDir() + L"\\agent.log";
    std::wofstream f(path, std::ios::app);
    if (!f.is_open()) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    f << L"[" << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L"] " << msg << L"\n";
}

ULONGLONG ComputeBackoffDelayMs(unsigned int attempts) {
    if (attempts == 0) {
        return kInitialBackoffMs;
    }
    unsigned int clamped = std::min(attempts - 1, kMaxBackoffSteps - 1);
    ULONGLONG delay = static_cast<ULONGLONG>(kInitialBackoffMs) << clamped;
    return std::min(delay, kMaxBackoffMs);
}

std::wstring TrimLower(const std::wstring& input) {
    size_t start = 0;
    while (start < input.size() && iswspace(input[start])) {
        ++start;
    }
    size_t end = input.size();
    while (end > start && iswspace(input[end - 1])) {
        --end;
    }
    std::wstring result = input.substr(start, end - start);
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

void LoadFingerprintConfig(bool log) {
    g_forceFingerprints.clear();
    g_skipFingerprints.clear();
    g_fingerprintSkipLogged.clear();
    g_fingerprintForceLogged.clear();

    std::wstring path = DataDir() + L"\\agent_fingerprints.txt";
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        g_fingerprintLastWrite = fad.ftLastWriteTime;
    } else {
        g_fingerprintLastWrite = {};
    }

    std::wifstream in(path);
    if (!in.is_open()) {
        if (log) {
            Log(L"[fingerprint] No fingerprint configuration found at " + path);
        }
        return;
    }

    std::wstring line;
    while (std::getline(in, line)) {
        if (line.empty()) {
            continue;
        }
        if (line[0] == L'#' || line[0] == L';') {
            continue;
        }
        auto pos = line.find(L'=');
        if (pos == std::wstring::npos) {
            continue;
        }
        std::wstring key = TrimLower(line.substr(0, pos));
        std::wstring value = line.substr(pos + 1);
        if (value.empty()) {
            continue;
        }
        std::vector<std::wstring> tokens;
        size_t start = 0;
        while (start < value.size()) {
            size_t sep = value.find_first_of(L",;", start);
            std::wstring token = TrimLower(value.substr(start, sep == std::wstring::npos ? std::wstring::npos : sep - start));
            if (!token.empty()) {
                tokens.push_back(token);
            }
            if (sep == std::wstring::npos) {
                break;
            }
            start = sep + 1;
        }
        if (key == L"force") {
            g_forceFingerprints.insert(tokens.begin(), tokens.end());
        } else if (key == L"skip") {
            g_skipFingerprints.insert(tokens.begin(), tokens.end());
        }
    }

    if (log) {
        std::wstringstream msg;
        msg << L"[fingerprint] Loaded " << g_forceFingerprints.size()
            << L" force and " << g_skipFingerprints.size()
            << L" skip fingerprints";
        Log(msg.str());
    }
}

std::wstring ComputeModuleFingerprint(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        return std::wstring();
    }

    DWORD required = 0;
    std::vector<HMODULE> modules(256);
    if (!EnumProcessModulesEx(process, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                              &required, LIST_MODULES_ALL)) {
        if (!EnumProcessModules(process, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                &required)) {
            CloseHandle(process);
            return std::wstring();
        }
    }

    size_t count = required / sizeof(HMODULE);
    if (count > modules.size()) {
        modules.resize(count);
        if (!EnumProcessModulesEx(process, modules.data(),
                                  static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                  &required, LIST_MODULES_ALL)) {
            if (!EnumProcessModules(process, modules.data(),
                                    static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                    &required)) {
                CloseHandle(process);
                return std::wstring();
            }
        }
        count = required / sizeof(HMODULE);
    }

    std::vector<std::wstring> names;
    names.reserve(count);
    wchar_t modulePath[MAX_PATH] = {};
    for (size_t i = 0; i < count; ++i) {
        HMODULE mod = modules[i];
        if (!mod) {
            continue;
        }
        if (GetModuleFileNameExW(process, mod, modulePath, MAX_PATH)) {
            std::wstring path(modulePath);
            size_t pos = path.find_last_of(L"\\/");
            std::wstring base = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
            base = TrimLower(base);
            if (!base.empty()) {
                names.push_back(base);
            }
        }
    }
    CloseHandle(process);

    if (names.empty()) {
        return std::wstring();
    }

    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    if (names.size() > 32) {
        names.resize(32);
    }

    std::wstring fingerprint;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) {
            fingerprint.push_back(L';');
        }
        fingerprint.append(names[i]);
    }
    return fingerprint;
}

void ShutdownProcessWatcher();

bool InitializeProcessWatcher() {
    if (g_wmiProcessEvents) {
        return true;
    }
    if (g_wmiInitAttempted && !g_wmiProcessEvents) {
        return false;
    }
    g_wmiInitAttempted = true;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        g_wmiCoInitialized = true;
    } else if (hr == RPC_E_CHANGED_MODE) {
        g_wmiCoInitialized = false;
        Log(L"[wmi] CoInitializeEx reported mode change; continuing with existing COM apartment");
    } else {
        std::wstringstream msg;
        msg << L"[wmi] CoInitializeEx failed: 0x" << std::hex << hr;
        Log(msg.str());
        return false;
    }

    hr = CoInitializeSecurity(nullptr,
                              -1,
                              nullptr,
                              nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr,
                              EOAC_NONE,
                              nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        std::wstringstream msg;
        msg << L"[wmi] CoInitializeSecurity failed: 0x" << std::hex << hr;
        Log(msg.str());
    }

    hr = CoCreateInstance(CLSID_WbemLocator,
                          nullptr,
                          CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator,
                          reinterpret_cast<void**>(&g_wmiLocator));
    if (FAILED(hr) || !g_wmiLocator) {
        std::wstringstream msg;
        msg << L"[wmi] CoCreateInstance(CLSID_WbemLocator) failed: 0x" << std::hex << hr;
        Log(msg.str());
        ShutdownProcessWatcher();
        return false;
    }

    BSTR ns = SysAllocString(L"ROOT\\CIMV2");
    hr = g_wmiLocator->ConnectServer(ns,
                                     nullptr,
                                     nullptr,
                                     nullptr,
                                     0,
                                     nullptr,
                                     nullptr,
                                     &g_wmiServices);
    SysFreeString(ns);
    if (FAILED(hr) || !g_wmiServices) {
        std::wstringstream msg;
        msg << L"[wmi] ConnectServer failed: 0x" << std::hex << hr;
        Log(msg.str());
        ShutdownProcessWatcher();
        return false;
    }

    hr = CoSetProxyBlanket(g_wmiServices,
                           RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE,
                           nullptr,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr,
                           EOAC_NONE);
    if (FAILED(hr)) {
        std::wstringstream msg;
        msg << L"[wmi] CoSetProxyBlanket(service) failed: 0x" << std::hex << hr;
        Log(msg.str());
    }

    BSTR lang = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
    hr = g_wmiServices->ExecNotificationQuery(lang,
                                              query,
                                              WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
                                              nullptr,
                                              &g_wmiProcessEvents);
    SysFreeString(lang);
    SysFreeString(query);
    if (FAILED(hr) || !g_wmiProcessEvents) {
        std::wstringstream msg;
        msg << L"[wmi] ExecNotificationQuery failed: 0x" << std::hex << hr;
        Log(msg.str());
        ShutdownProcessWatcher();
        return false;
    }

    hr = CoSetProxyBlanket(g_wmiProcessEvents,
                           RPC_C_AUTHN_WINNT,
                           RPC_C_AUTHZ_NONE,
                           nullptr,
                           RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE,
                           nullptr,
                           EOAC_NONE);
    if (FAILED(hr)) {
        std::wstringstream msg;
        msg << L"[wmi] CoSetProxyBlanket(enumerator) failed: 0x" << std::hex << hr;
        Log(msg.str());
    }

    Log(L"[wmi] Process start watcher initialised");
    return true;
}

void PollProcessWatcher() {
    if (!g_wmiProcessEvents) {
        InitializeProcessWatcher();
        if (!g_wmiProcessEvents) {
            return;
        }
    }

    for (;;) {
        IWbemClassObject* eventObj = nullptr;
        ULONG returned = 0;
        HRESULT hr = g_wmiProcessEvents->Next(0, 1, &eventObj, &returned);
        if (FAILED(hr)) {
            std::wstringstream msg;
            msg << L"[wmi] Enumerator Next failed: 0x" << std::hex << hr;
            Log(msg.str());
            if (eventObj) {
                eventObj->Release();
            }
            ShutdownProcessWatcher();
            break;
        }
        if (returned == 0 || !eventObj) {
            if (eventObj) {
                eventObj->Release();
            }
            break;
        }

        VARIANT varInstance;
        VariantInit(&varInstance);
        hr = eventObj->Get(L"TargetInstance", 0, &varInstance, nullptr, nullptr);
        if (SUCCEEDED(hr) && varInstance.vt == VT_UNKNOWN && varInstance.punkVal) {
            IWbemClassObject* instance = nullptr;
            if (SUCCEEDED(varInstance.punkVal->QueryInterface(IID_IWbemClassObject,
                                                              reinterpret_cast<void**>(&instance)))) {
                VARIANT varHandle;
                VariantInit(&varHandle);
                if (SUCCEEDED(instance->Get(L"Handle", 0, &varHandle, nullptr, nullptr)) &&
                    varHandle.vt == VT_BSTR) {
                    DWORD pid = wcstoul(varHandle.bstrVal, nullptr, 10);
                    if (pid > 4) {
                        if (g_processEventQueue.size() >= kMaxProcessEventQueue) {
                            g_processEventOverflowed = true;
                            g_processEventQueue.pop_front();
                        }
                        g_processEventQueue.push_back(pid);
                    }
                }
                VariantClear(&varHandle);
                instance->Release();
            }
        }
        VariantClear(&varInstance);
        eventObj->Release();
    }
}

void ShutdownProcessWatcher() {
    if (g_wmiProcessEvents) {
        g_wmiProcessEvents->Release();
        g_wmiProcessEvents = nullptr;
    }
    if (g_wmiServices) {
        g_wmiServices->Release();
        g_wmiServices = nullptr;
    }
    if (g_wmiLocator) {
        g_wmiLocator->Release();
        g_wmiLocator = nullptr;
    }
    g_processEventQueue.clear();
    g_processEventOverflowed = false;
    g_wmiInitAttempted = false;
    if (g_wmiCoInitialized) {
        CoUninitialize();
        g_wmiCoInitialized = false;
    }
}

bool IsProcessAlive(DWORD pid) {
    if (pid <= 4) {
        return true;
    }
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        DWORD err = GetLastError();
        if (err == ERROR_INVALID_PARAMETER ||
            err == ERROR_INVALID_HANDLE ||
            err == ERROR_PROC_NOT_FOUND ||
            err == ERROR_NOT_FOUND) {
            return false;
        }
        return true;
    }
    DWORD code = STILL_ACTIVE;
    bool alive = true;
    if (GetExitCodeProcess(process, &code)) {
        alive = (code == STILL_ACTIVE);
    }
    CloseHandle(process);
    return alive;
}

int ExtractIntField(const std::string& line, const char* key) {
    size_t pos = line.find(key);
    if (pos == std::string::npos) return -1;
    pos += std::strlen(key);
    const char* start = line.c_str() + pos;
    char* end = nullptr;
    long value = std::strtol(start, &end, 10);
    if (start == end) return -1;
    return static_cast<int>(value);
}

std::string ExtractStringField(const std::string& line, const char* key) {
    size_t pos = line.find(key);
    if (pos == std::string::npos) {
        return {};
    }
    pos += std::strlen(key);
    size_t end = line.find_first_of(" \t\r\n", pos);
    if (end == std::string::npos) {
        end = line.size();
    }
    return line.substr(pos, end - pos);
}

unsigned long long ExtractHexField(const std::string& line, const char* key) {
    size_t pos = line.find(key);
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::strlen(key);
    const char* start = line.c_str() + pos;
    char* end = nullptr;
    unsigned long long value = std::strtoull(start, &end, 16);
    if (start == end) {
        return 0;
    }
    return value;
}

unsigned long long ExtractUnsignedField(const std::string& line, const char* key) {
    if (!key) {
        return 0;
    }
    size_t pos = line.find(key);
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::strlen(key);
    const char* start = line.c_str() + pos;
    char* end = nullptr;
    unsigned long long value = std::strtoull(start, &end, 10);
    if (start == end) {
        return 0;
    }
    return value;
}

std::wstring Widen(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }
    return std::wstring(value.begin(), value.end());
}

unsigned long long ComposeCaptureKey(unsigned long long itemHandle,
                                     unsigned long long targetHandle,
                                     bool isMonitor) {
    if (itemHandle) {
        return itemHandle;
    }
    unsigned long long key = targetHandle;
    if (key == 0) {
        key = isMonitor ? (1ull << 62) : (1ull << 61);
    }
    if (isMonitor) {
        key |= (1ull << 63);
    }
    return key;
}

ProcessIdentityInfo QueryProcessIdentity(DWORD pid) {
    ProcessIdentityInfo info{};
    info.sessionId = kInvalidSessionId;
    DWORD session = 0;
    if (ProcessIdToSessionId(pid, &session)) {
        info.sessionId = session;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (!process) {
        return info;
    }

    HANDLE token = nullptr;
    if (OpenProcessToken(process, TOKEN_QUERY, &token)) {
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        if (size && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            std::vector<BYTE> buffer(size);
            if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
                auto user = reinterpret_cast<TOKEN_USER*>(buffer.data());
                LPWSTR sidString = nullptr;
                if (ConvertSidToStringSidW(user->User.Sid, &sidString)) {
                    info.userSid.assign(sidString);
                    LocalFree(sidString);
                }

                WCHAR name[256];
                WCHAR domain[256];
                DWORD nameLen = static_cast<DWORD>(_countof(name));
                DWORD domainLen = static_cast<DWORD>(_countof(domain));
                SID_NAME_USE use = SidTypeUnknown;
                if (LookupAccountSidW(nullptr,
                                      user->User.Sid,
                                      name,
                                      &nameLen,
                                      domain,
                                      &domainLen,
                                      &use)) {
                    if (domainLen > 0) {
                        info.userName.assign(domain);
                        info.userName.append(L"\\");
                        info.userName.append(name);
                    } else {
                        info.userName.assign(name);
                    }
                }
            }
        }
        CloseHandle(token);
    }

    CloseHandle(process);
    return info;
}

void ApplyIdentityToTelemetry(DWORD pid, const ProcessIdentityInfo& identity) {
    if (!identity.userSid.empty() || !identity.userName.empty() || identity.sessionId != kInvalidSessionId) {
        auto kt = g_keyboardTelemetry.find(pid);
        if (kt != g_keyboardTelemetry.end()) {
            kt->second.sessionId = identity.sessionId;
            if (!identity.userSid.empty()) {
                kt->second.userSid = identity.userSid;
            }
            if (!identity.userName.empty()) {
                kt->second.userName = identity.userName;
            }
        }

        auto gt = g_graphicsTelemetry.find(pid);
        if (gt != g_graphicsTelemetry.end()) {
            gt->second.sessionId = identity.sessionId;
            if (!identity.userSid.empty()) {
                gt->second.userSid = identity.userSid;
            }
            if (!identity.userName.empty()) {
                gt->second.userName = identity.userName;
            }
        }

        auto dt = g_displayTelemetry.find(pid);
        if (dt != g_displayTelemetry.end()) {
            dt->second.sessionId = identity.sessionId;
            if (!identity.userSid.empty()) {
                dt->second.userSid = identity.userSid;
            }
            if (!identity.userName.empty()) {
                dt->second.userName = identity.userName;
            }
        }
    }
}

bool SendPolicyCommand(DWORD pid,
                       int forceInput,
                       int forceWda,
                       const std::vector<unsigned long long>& blockDup = {},
                       const std::vector<unsigned long long>& clearDup = {},
                       const std::vector<unsigned long long>& blockCaptureWindows = {},
                       const std::vector<unsigned long long>& clearCaptureWindows = {},
                       const std::vector<unsigned long long>& blockCaptureMonitors = {},
                       const std::vector<unsigned long long>& clearCaptureMonitors = {},
                       const std::vector<unsigned long long>& blockSwapChains = {},
                       const std::vector<unsigned long long>& clearSwapChains = {}) {
    wchar_t pipeName[128] = {};
    _snwprintf_s(pipeName, _TRUNCATE, L"\\\\.\\pipe\\umh_telemetry_%lu", pid);
    if (!WaitNamedPipeW(pipeName, 50)) {
        return false;
    }

    HANDLE pipe = CreateFileW(pipeName,
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::ostringstream req;
    req << "{\"op\":\"policy\"";
    if (forceInput != kPolicyNoChange) {
        req << ",\"force_input\":" << forceInput;
    }
    if (forceWda != kPolicyNoChange) {
        req << ",\"force_wda\":" << forceWda;
    }
    auto appendHandleArray = [&](const char* key, const std::vector<unsigned long long>& handles) {
        if (handles.empty()) {
            return;
        }
        req << ",\"" << key << "\":[";
        for (size_t i = 0; i < handles.size(); ++i) {
            if (i) {
                req << ",";
            }
            std::ostringstream value;
            value << "0x" << std::hex << std::uppercase << handles[i];
            req << "\"" << value.str() << "\"";
        }
        req << "]";
    };
    appendHandleArray("block_duplications", blockDup);
    appendHandleArray("clear_duplications", clearDup);
    appendHandleArray("block_capture_windows", blockCaptureWindows);
    appendHandleArray("clear_capture_windows", clearCaptureWindows);
    appendHandleArray("block_capture_monitors", blockCaptureMonitors);
    appendHandleArray("clear_capture_monitors", clearCaptureMonitors);
    appendHandleArray("block_swapchains", blockSwapChains);
    appendHandleArray("clear_swapchains", clearSwapChains);
    req << "}";

    std::string payload = req.str();
    DWORD written = 0;
    BOOL ok = WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
    if (ok) {
        char buffer[64] = {};
        DWORD read = 0;
        ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr);
    }
    FlushFileBuffers(pipe);
    CloseHandle(pipe);
    return ok == TRUE;
}

void UpdateKeyboardTelemetry() {
    const std::wstring logPath = DataDir() + L"\\api_hooks.log";
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(logPath.c_str(), GetFileExInfoStandard, &fad)) {
        g_keyboardLastOffset = 0;
        return;
    }
    ULONGLONG size = (static_cast<ULONGLONG>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
    if (size < g_keyboardLastOffset) {
        g_keyboardLastOffset = 0;
    }

    std::ifstream in(logPath, std::ios::binary);
    if (!in.is_open()) {
        return;
    }
    in.seekg(static_cast<std::streamoff>(g_keyboardLastOffset));

    ULONGLONG now = GetTickCount64();
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.find("func=") == std::string::npos && line.find("event=policy") == std::string::npos) {
            continue;
        }

        int pidField = ExtractIntField(line, "pid=");
        if (pidField <= 0) {
            continue;
        }
        DWORD pid = static_cast<DWORD>(pidField);

        if (line.find("event=policy") != std::string::npos) {
            int state = ExtractIntField(line, "state=");
            auto& policy = g_policyState[pid];
            if (line.find("func=force_input") != std::string::npos) {
                policy.forceInput = state;
                policy.lastForceInputApplied = now;
                policy.lastForceInputAttempt = now;
            } else if (line.find("func=force_wda") != std::string::npos) {
                policy.forceWda = state;
                policy.lastForceWdaApplied = now;
                policy.lastForceWdaAttempt = now;
            }
            continue;
        }
        if (line.find("func=GraphicsModule") != std::string::npos) {
            std::string moduleName = ExtractStringField(line, "module=");
            if (!moduleName.empty()) {
                std::transform(moduleName.begin(),
                               moduleName.end(),
                               moduleName.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                unsigned long long base = ExtractHexField(line, "base=0x");
                auto& graphicsEntry = g_graphicsTelemetry[pid];
                graphicsEntry.modules[moduleName] = base;
                graphicsEntry.lastTick = now;
            }
            continue;
        }

        if (line.find("func=DuplicateOutput") != std::string::npos) {
            auto& graphicsEntry = g_graphicsTelemetry[pid];
            graphicsEntry.lastTick = now;
            unsigned long long dupHandle = ExtractHexField(line, "dup=0x");
            auto& dup = graphicsEntry.duplications[dupHandle];
            dup.createCount++;
            dup.lastHr = ExtractHexField(line, "hr=0x");
            unsigned long long outputHandle = ExtractHexField(line, "output=0x");
            if (outputHandle) dup.outputHandle = outputHandle;
            unsigned long long deviceHandle = ExtractHexField(line, "device=0x");
            if (deviceHandle) dup.deviceHandle = deviceHandle;
            dup.lastTick = now;
            continue;
        }

        if (line.find("func=AcquireNextFrame") != std::string::npos) {
            auto& graphicsEntry = g_graphicsTelemetry[pid];
            graphicsEntry.lastTick = now;
            unsigned long long dupHandle = ExtractHexField(line, "dup=0x");
            auto& dup = graphicsEntry.duplications[dupHandle];
            dup.acquireCount++;
            dup.lastHr = ExtractHexField(line, "hr=0x");
            dup.lastPresentTime = ExtractUnsignedField(line, "last_present=");
            dup.lastFrames = ExtractUnsignedField(line, "frames=");
            dup.pointerVisible = ExtractUnsignedField(line, "pointer_visible=");
            if (dup.pointerVisible > 0) {
                dup.pointerX = ExtractIntField(line, "pointer_x=");
                dup.pointerY = ExtractIntField(line, "pointer_y=");
            }
            dup.pointerShapeBytes = ExtractUnsignedField(line, "pointer_shape=");
            dup.lastTimeout = ExtractUnsignedField(line, "timeout=");
            unsigned long long resourceHandle = ExtractHexField(line, "resource=0x");
            if (resourceHandle) dup.resourceHandle = resourceHandle;
            dup.lastTick = now;
            continue;
        }

        if (line.find("func=GraphicsCaptureForWindow") != std::string::npos) {
            auto& graphicsEntry = g_graphicsTelemetry[pid];
            graphicsEntry.lastTick = now;
            unsigned long long itemHandle = ExtractHexField(line, "item=0x");
            unsigned long long hwndHandle = ExtractHexField(line, "hwnd=0x");
            unsigned long long key = ComposeCaptureKey(itemHandle, hwndHandle, false);
            auto& cap = graphicsEntry.captures[key];
            cap.createCount++;
            cap.lastHr = ExtractHexField(line, "hr=0x");
            cap.targetHandle = hwndHandle;
            cap.isMonitor = false;
            if (itemHandle) cap.itemHandle = itemHandle;
            std::string iid = ExtractStringField(line, "iid=");
            if (!iid.empty()) {
                cap.iid = Widen(iid);
            }
            cap.lastTick = now;
            continue;
        }

        if (line.find("func=GraphicsCaptureForMonitor") != std::string::npos) {
            auto& graphicsEntry = g_graphicsTelemetry[pid];
            graphicsEntry.lastTick = now;
            unsigned long long itemHandle = ExtractHexField(line, "item=0x");
            unsigned long long monitorHandle = ExtractHexField(line, "monitor=0x");
            unsigned long long key = ComposeCaptureKey(itemHandle, monitorHandle, true);
            auto& cap = graphicsEntry.captures[key];
            cap.createCount++;
            cap.lastHr = ExtractHexField(line, "hr=0x");
            cap.targetHandle = monitorHandle;
            cap.isMonitor = true;
            if (itemHandle) cap.itemHandle = itemHandle;
            std::string iid = ExtractStringField(line, "iid=");
            if (!iid.empty()) {
                cap.iid = Widen(iid);
            }
            cap.lastTick = now;
            continue;
        }

        auto& entry = g_keyboardTelemetry[pid];
        bool recognized = false;

        if (line.find("func=BlockInput") != std::string::npos) {
            recognized = true;
            entry.blockRequests++;
            int requested = ExtractIntField(line, "requested=");
            int applied = ExtractIntField(line, "applied=");
            if (requested == 1 && applied == 0) {
                entry.blockForced++;
            }
        } else if (line.find("func=NtUserBlockInput") != std::string::npos) {
            recognized = true;
            entry.ntRequests++;
            int requested = ExtractIntField(line, "requested=");
            int applied = ExtractIntField(line, "applied=");
            if (requested == 1 && applied == 0) {
                entry.ntForced++;
            }
        } else if (line.find("func=AttachThreadInput") != std::string::npos) {
            int attach = ExtractIntField(line, "attach=");
            int applied = ExtractIntField(line, "applied=");
            if (attach == 1) {
                recognized = true;
                entry.attachRequests++;
                if (applied == 0) {
                    entry.attachPrevented++;
                }
            }
        } else if (line.find("func=NtUserAttachThreadInput") != std::string::npos) {
            int attach = ExtractIntField(line, "attach=");
            int applied = ExtractIntField(line, "applied=");
            if (attach == 1) {
                recognized = true;
                entry.ntAttachRequests++;
                if (applied == 0) {
                    entry.ntAttachPrevented++;
                }
            }
        } else if (line.find("func=SystemParametersInfoW") != std::string::npos) {
            recognized = true;
            entry.spiRequests++;
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1) {
                entry.spiForced++;
            }
        } else if (line.find("func=EnableWindow") != std::string::npos) {
            recognized = true;
            entry.enableRequests++;
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1) {
                entry.enableForced++;
            }
        } else if (line.find("func=NtUserSetInformationThread") != std::string::npos) {
            recognized = true;
            entry.ntSetInfoRequests++;
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1) {
                entry.ntSetInfoBlocked++;
            }
        } else if (line.find("func=SetWindowsHookEx") != std::string::npos &&
                   line.find("type=keyboard") != std::string::npos) {
            recognized = true;
            entry.hookAttempts++;
            int allowed = ExtractIntField(line, "allowed=");
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1 || allowed == 0) {
                entry.hookBlocked++;
            }
        } else if (line.find("func=DirectInput::SetCooperativeLevel") != std::string::npos) {
            recognized = true;
            entry.diSetCoop++;
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1) {
                entry.diSetCoopForced++;
            }
        } else if (line.find("func=DirectInput::Acquire") != std::string::npos) {
            recognized = true;
            entry.diAcquire++;
        } else if (line.find("func=SetWindowDisplayAffinity") != std::string::npos) {
            auto& display = g_displayTelemetry[pid];
            display.userModeRequests++;
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1) {
                display.userModeForced++;
            }
            display.lastTick = now;
            continue;
        } else if (line.find("func=NtUserSetWindowDisplayAffinity") != std::string::npos) {
            auto& display = g_displayTelemetry[pid];
            display.nativeRequests++;
            int forced = ExtractIntField(line, "forced=");
            if (forced == 1) {
                display.nativeForced++;
            }
            display.lastTick = now;
            continue;
        } else if (line.find("func=DXGI::Present") != std::string::npos) {
            auto& display = g_displayTelemetry[pid];
            display.swapRequests++;
            int blocked = ExtractIntField(line, "blocked=");
            if (blocked == 1) {
                display.swapBlocked++;
            }
            display.lastTick = now;
            auto& graphicsEntry = g_graphicsTelemetry[pid];
            graphicsEntry.lastTick = now;
            unsigned long long swapHandle = ExtractHexField(line, "swap=0x");
            if (swapHandle) {
                auto& swapEntry = graphicsEntry.swapChains[swapHandle];
                swapEntry.presentCount++;
                if (blocked == 1) {
                    swapEntry.blockedCount++;
                }
                swapEntry.lastHr = ExtractHexField(line, "hr=0x");
                if (line.find("flags=") != std::string::npos) {
                    swapEntry.lastFlags = ExtractHexField(line, "flags=0x");
                }
                if (line.find("interval=") != std::string::npos) {
                    swapEntry.lastInterval = ExtractUnsignedField(line, "interval=");
                }
                unsigned long long isD3D12 = ExtractUnsignedField(line, "d3d12=");
                swapEntry.lastWasD3D12 = (isD3D12 == 1);
                swapEntry.lastWasPresent1 = (line.find("func=DXGI::Present1") != std::string::npos);
                swapEntry.lastTick = now;
            }
            continue;
        } else if (line.find("func=SwapBuffers") != std::string::npos ||
                   line.find("func=wglSwapBuffers") != std::string::npos) {
            auto& display = g_displayTelemetry[pid];
            display.swapRequests++;
            int blocked = ExtractIntField(line, "blocked=");
            if (blocked == 1) {
                display.swapBlocked++;
            }
            display.lastTick = now;
            continue;
        } else if (line.find("func=glFinish") != std::string::npos) {
            auto& display = g_displayTelemetry[pid];
            display.glFinishCalls++;
            display.lastTick = now;
            continue;
        }

        if (recognized) {
            entry.lastTick = now;
        }
    }

    std::streampos pos = in.tellg();
    if (pos != std::streampos(-1)) {
        g_keyboardLastOffset = static_cast<ULONGLONG>(pos);
    } else {
        g_keyboardLastOffset = size;
    }
    in.close();

    while (g_keyboardTelemetry.size() > kMaxKeyboardTelemetryEntries) {
        auto victim = std::min_element(
            g_keyboardTelemetry.begin(),
            g_keyboardTelemetry.end(),
            [](const std::pair<const DWORD, KeyboardTelemetryEntry>& a,
               const std::pair<const DWORD, KeyboardTelemetryEntry>& b) {
                return a.second.lastTick < b.second.lastTick;
            });
        if (victim == g_keyboardTelemetry.end()) {
            break;
        }
        g_keyboardTelemetry.erase(victim);
    }
    while (g_displayTelemetry.size() > kMaxDisplayTelemetryEntries) {
        auto victim = std::min_element(
            g_displayTelemetry.begin(),
            g_displayTelemetry.end(),
            [](const std::pair<const DWORD, DisplayTelemetryEntry>& a,
               const std::pair<const DWORD, DisplayTelemetryEntry>& b) {
                return a.second.lastTick < b.second.lastTick;
            });
        if (victim == g_displayTelemetry.end()) {
            break;
        }
        g_displayTelemetry.erase(victim);
    }
    while (g_graphicsTelemetry.size() > kMaxGraphicsTelemetryEntries) {
        auto victim = std::min_element(
            g_graphicsTelemetry.begin(),
            g_graphicsTelemetry.end(),
            [](const std::pair<const DWORD, GraphicsTelemetryEntry>& a,
               const std::pair<const DWORD, GraphicsTelemetryEntry>& b) {
                return a.second.lastTick < b.second.lastTick;
            });
        if (victim == g_graphicsTelemetry.end()) {
            break;
        }
        g_graphicsTelemetry.erase(victim);
    }

    const ULONGLONG expireMs = 5ull * 60ull * 1000ull;
    for (auto it = g_keyboardTelemetry.begin(); it != g_keyboardTelemetry.end(); ) {
        if (now - it->second.lastTick > expireMs) {
            it = g_keyboardTelemetry.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = g_displayTelemetry.begin(); it != g_displayTelemetry.end(); ) {
        if (now - it->second.lastTick > expireMs) {
            it = g_displayTelemetry.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = g_graphicsTelemetry.begin(); it != g_graphicsTelemetry.end(); ) {
        if (now - it->second.lastTick > expireMs) {
            it = g_graphicsTelemetry.erase(it);
        } else {
            ++it;
        }
    }

    auto pruneDuplications = [&](std::map<unsigned long long, DuplicationTelemetryEntry>& container) {
        for (auto it = container.begin(); it != container.end(); ) {
            if (now - it->second.lastTick > expireMs) {
                it = container.erase(it);
            } else {
                ++it;
            }
        }
        while (container.size() > kMaxGraphicsConnectionsPerType) {
            auto victim = std::min_element(
                container.begin(),
                container.end(),
                [](const std::pair<const unsigned long long, DuplicationTelemetryEntry>& a,
                   const std::pair<const unsigned long long, DuplicationTelemetryEntry>& b) {
                    return a.second.lastTick < b.second.lastTick;
                });
            if (victim == container.end()) {
                break;
            }
            container.erase(victim);
        }
    };

    auto pruneCaptures = [&](std::map<unsigned long long, CaptureTelemetryEntry>& container) {
        for (auto it = container.begin(); it != container.end(); ) {
            if (now - it->second.lastTick > expireMs) {
                it = container.erase(it);
            } else {
                ++it;
            }
        }
        while (container.size() > kMaxGraphicsConnectionsPerType) {
            auto victim = std::min_element(
                container.begin(),
                container.end(),
                [](const std::pair<const unsigned long long, CaptureTelemetryEntry>& a,
                   const std::pair<const unsigned long long, CaptureTelemetryEntry>& b) {
                    return a.second.lastTick < b.second.lastTick;
                });
            if (victim == container.end()) {
                break;
            }
            container.erase(victim);
        }
    };

    auto pruneSwapChains = [&](std::map<unsigned long long, SwapChainTelemetryEntry>& container) {
        for (auto it = container.begin(); it != container.end(); ) {
            if (now - it->second.lastTick > expireMs) {
                it = container.erase(it);
            } else {
                ++it;
            }
        }
        while (container.size() > kMaxGraphicsConnectionsPerType) {
            auto victim = std::min_element(
                container.begin(),
                container.end(),
                [](const std::pair<const unsigned long long, SwapChainTelemetryEntry>& a,
                   const std::pair<const unsigned long long, SwapChainTelemetryEntry>& b) {
                    return a.second.lastTick < b.second.lastTick;
                });
            if (victim == container.end()) {
                break;
            }
            container.erase(victim);
        }
    };

    for (auto& kv : g_graphicsTelemetry) {
        pruneDuplications(kv.second.duplications);
        pruneCaptures(kv.second.captures);
        pruneSwapChains(kv.second.swapChains);
    }
}

bool ProcessHasModule(DWORD pid, const wchar_t* moduleName) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) {
        return false;
    }

    DWORD required = 0;
    std::vector<HMODULE> modules;
    HMODULE stack[256] = {};
    BOOL success = EnumProcessModulesEx(process, stack, sizeof(stack), &required, LIST_MODULES_ALL);
    if (!success) {
        if (!EnumProcessModules(process, stack, sizeof(stack), &required)) {
            CloseHandle(process);
            return false;
        }
    }

    size_t count = required / sizeof(HMODULE);
    modules.assign(stack, stack + std::min(count, static_cast<size_t>(_countof(stack))));
    if (count > _countof(stack)) {
        modules.resize(count);
        if (EnumProcessModulesEx(process,
                                 modules.data(),
                                 static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                 &required,
                                 LIST_MODULES_ALL)) {
            modules.resize(required / sizeof(HMODULE));
        } else if (EnumProcessModules(process,
                                      modules.data(),
                                      static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                      &required)) {
            modules.resize(required / sizeof(HMODULE));
        }
    }

    bool found = false;
    std::wstring needle(moduleName);
    std::transform(needle.begin(), needle.end(), needle.begin(), ::towlower);
    wchar_t modulePath[MAX_PATH] = {};
    for (HMODULE mod : modules) {
        if (!mod) {
            continue;
        }
        if (GetModuleFileNameExW(process, mod, modulePath, MAX_PATH)) {
            std::wstring path(modulePath);
            std::transform(path.begin(), path.end(), path.begin(), ::towlower);
            if (path.rfind(needle) != std::wstring::npos) {
                found = true;
                break;
            }
        }
    }

    CloseHandle(process);
    return found;
}

std::vector<std::wstring> CollectGraphicsModulesForPid(DWORD pid) {
    static const wchar_t* kGraphicsModules[] = {
        L"d3d12.dll",
        L"d3d11.dll",
        L"d3d10.dll",
        L"vulkan-1.dll",
        L"dcomp.dll",
        L"libcef.dll",
        L"webview2.dll",
        L"chrome_elf.dll",
        L"electron.dll",
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
    std::vector<std::wstring> modules;
    for (const auto* name : kGraphicsModules) {
        if (ProcessHasModule(pid, name)) {
            modules.emplace_back(name);
        }
    }
    return modules;
}

std::vector<unsigned long long> CollectDuplicationHandlesForPid(DWORD pid) {
    std::vector<unsigned long long> handles;
    auto it = g_graphicsTelemetry.find(pid);
    if (it == g_graphicsTelemetry.end()) {
        return handles;
    }
    for (const auto& kv : it->second.duplications) {
        if (kv.first) {
            handles.push_back(kv.first);
        }
    }
    return handles;
}

std::vector<std::wstring> SplitFingerprintComponents(const std::wstring& fingerprint) {
    std::vector<std::wstring> components;
    size_t start = 0;
    while (start < fingerprint.size()) {
        size_t sep = fingerprint.find(L';', start);
        std::wstring token = fingerprint.substr(start, sep == std::wstring::npos ? fingerprint.size() - start : sep - start);
        if (!token.empty()) {
            components.push_back(token);
        }
        if (sep == std::wstring::npos) {
            break;
        }
        start = sep + 1;
    }
    return components;
}

bool ShouldAutoForceFingerprint(const std::wstring& fingerprint, std::wstring& matchedToken) {
    static const wchar_t* kAutoForceTokens[] = {
        L"libcef.dll",
        L"webview2.dll",
        L"chrome_elf.dll",
        L"electron.dll",
        L"openxr_loader.dll",
        L"xrclient.dll",
        L"oculusclient.dll",
        L"gameoverlayrenderer64.dll",
        L"gameoverlayrenderer.dll",
        L"discordhook64.dll",
        L"discordhook.dll"
    };
    if (fingerprint.empty()) {
        return false;
    }
    auto tokens = SplitFingerprintComponents(fingerprint);
    for (const auto& token : tokens) {
        for (const auto* forceToken : kAutoForceTokens) {
            if (token == forceToken) {
                matchedToken = forceToken;
                return true;
            }
        }
    }
    return false;
}

std::vector<unsigned long long> CollectCaptureWindowTargetsForPid(DWORD pid) {
    std::vector<unsigned long long> handles;
    auto it = g_graphicsTelemetry.find(pid);
    if (it == g_graphicsTelemetry.end()) {
        return handles;
    }
    for (const auto& kv : it->second.captures) {
        const auto& entry = kv.second;
        if (!entry.isMonitor && entry.targetHandle) {
            handles.push_back(entry.targetHandle);
        }
    }
    return handles;
}

std::vector<unsigned long long> CollectCaptureMonitorTargetsForPid(DWORD pid) {
    std::vector<unsigned long long> handles;
    auto it = g_graphicsTelemetry.find(pid);
    if (it == g_graphicsTelemetry.end()) {
        return handles;
    }
    for (const auto& kv : it->second.captures) {
        const auto& entry = kv.second;
        if (entry.isMonitor && entry.targetHandle) {
            handles.push_back(entry.targetHandle);
        }
    }
    return handles;
}

std::vector<unsigned long long> CollectSwapChainHandlesForPid(DWORD pid) {
    std::vector<unsigned long long> handles;
    auto it = g_graphicsTelemetry.find(pid);
    if (it == g_graphicsTelemetry.end()) {
        return handles;
    }
    for (const auto& kv : it->second.swapChains) {
        if (kv.first) {
            handles.push_back(kv.first);
        }
    }
    return handles;
}

bool UsesGraphicsModules(DWORD pid) {
    auto modules = CollectGraphicsModulesForPid(pid);
    return !modules.empty();
}

bool IsKeyboardFlagged(DWORD pid, ULONGLONG nowTicks) {
    auto it = g_keyboardTelemetry.find(pid);
    if (it == g_keyboardTelemetry.end()) {
        return false;
    }
    const ULONGLONG windowMs = 120000;
    if (nowTicks - it->second.lastTick > windowMs) {
        return false;
    }
    const auto& entry = it->second;
    ULONGLONG forced = entry.blockForced + entry.ntForced + entry.attachPrevented + entry.ntAttachPrevented +
                       entry.spiForced + entry.enableForced + entry.ntSetInfoBlocked +
                       entry.hookBlocked + entry.diSetCoopForced;
    ULONGLONG total = entry.blockRequests + entry.ntRequests + entry.attachRequests + entry.ntAttachRequests +
                      entry.spiRequests + entry.enableRequests + entry.ntSetInfoRequests +
                      entry.hookAttempts + entry.diSetCoop + entry.diAcquire;
    return forced > 0 || total >= 3;
}

bool IsElevated(HANDLE hProcess) {
    HANDLE hToken{}; if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) return false;
    TOKEN_ELEVATION e{}; DWORD sz{}; BOOL ok = GetTokenInformation(hToken, TokenElevation, &e, sizeof(e), &sz);
    CloseHandle(hToken); return ok && e.TokenIsElevated;
}

bool Is64BitProcess(HANDLE process) {
#ifdef _WIN64
    BOOL wow64 = FALSE; IsWow64Process(process, &wow64); return !wow64;
#else
    BOOL wow64 = FALSE; IsWow64Process(process, &wow64); return !wow64 ? true : false; // 32-bit sees wow64 TRUE for 64-bit
#endif
}

} // namespace

// Windows subsystem entry (silent)
int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    using namespace injection;

    bool aggressive = EnvEnabled(L"AGENT_AGGRESSIVE");
    int intervalSec = [](){ wchar_t buf[16]{}; DWORD n = GetEnvironmentVariableW(L"AGENT_INTERVAL", buf, 16); if (!n) return 5; return _wtoi(buf) > 0 ? _wtoi(buf) : 5; }();

    std::wstring dllPath;
    {
        wchar_t buf[MAX_PATH]{}; DWORD n = GetEnvironmentVariableW(L"AGENT_DLL", buf, MAX_PATH);
        if (n && n < MAX_PATH) dllPath.assign(buf, buf + n);
        if (dllPath.empty()) dllPath = GetExeDir() + L"\\AdvancedHookDLL.dll";
    }

    Log(L"UnifiedAgent starting. dll=" + dllPath + L" aggressive=" + std::to_wstring(aggressive));

    // Initialize DirectX hooks (optional) and wire present telemetry
    static std::atomic<unsigned long long> dx_d3d9{0};
    static std::atomic<unsigned long long> dx_dxgi{0};
    if (!EnvEnabled(L"MLHOOK_DISABLE_D3D9") || !EnvEnabled(L"MLHOOK_DISABLE_DXGI")) {
        dxhooks::SetPresentCallback([&](const char* api){ if (api && api[0]=='d' && api[3]=='9') dx_d3d9.fetch_add(1, std::memory_order_relaxed); else dx_dxgi.fetch_add(1, std::memory_order_relaxed); });
        if (!EnvEnabled(L"MLHOOK_DX_LAZY_INIT")) {
            dxhooks::Initialize();
        }
    }

    // Load config file (agent.config) if present
    auto LoadConfig = [&](bool log) {
        std::wstring cfgPath = GetExeDir() + L"\\agent.config";
        std::wifstream cfg(cfgPath);
        if (!cfg.is_open()) return;
        std::wstring line;
        while (std::getline(cfg, line)) {
            if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
            auto pos = line.find(L'=');
            if (pos == std::wstring::npos) continue;
            std::wstring key = line.substr(0, pos);
            std::wstring val = line.substr(pos + 1);
            auto trim = [](std::wstring& s){ while(!s.empty() && iswspace(s.front())) s.erase(0,1); while(!s.empty() && iswspace(s.back())) s.pop_back(); };
            trim(key); trim(val);
            std::wstring keyL = key; std::transform(keyL.begin(), keyL.end(), keyL.begin(), ::towlower);
            if (keyL == L"aggressive") aggressive = (val == L"1" || val == L"true" || val == L"yes" || val == L"on");
            else if (keyL == L"interval") { int v = _wtoi(val.c_str()); if (v > 0) intervalSec = v; }
            else if (keyL == L"dll") { dllPath = val; }
            else if (keyL == L"section_rwx") SetEnvironmentVariableW(L"MLHOOK_SECTION_RWX", val.c_str());
            else if (keyL == L"section_notls") SetEnvironmentVariableW(L"MLHOOK_SECTION_NOTLS", val.c_str());
            else if (keyL == L"disable_section_map") SetEnvironmentVariableW(L"MLHOOK_DISABLE_SECTION_MAP", val.c_str());
            else if (keyL == L"disable_d3d9") SetEnvironmentVariableW(L"MLHOOK_DISABLE_D3D9", val.c_str());
            else if (keyL == L"disable_dxgi") SetEnvironmentVariableW(L"MLHOOK_DISABLE_DXGI", val.c_str());
            else if (keyL == L"dx_lazy_init") SetEnvironmentVariableW(L"MLHOOK_DX_LAZY_INIT", val.c_str());
            else if (keyL == L"force_input") SetEnvironmentVariableW(L"HOOKDLL_FORCE_INPUT", val.c_str());
        }
        cfg.close(); if (log) Log(L"Loaded agent.config");
    };
    LoadConfig(true);
    LoadFingerprintConfig(true);

    InitializeProcessWatcher();

    std::set<std::wstring> systemNames = {
        L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"services.exe", L"lsass.exe",
        L"winlogon.exe", L"svchost.exe", L"conhost.exe", L"audiodg.exe", L"searchindexer.exe", L"spoolsv.exe", L"dwm.exe"
    };
    std::set<std::wstring> targetNames = {
        L"discord.exe", L"slack.exe", L"teams.exe", L"zoom.exe", L"obs64.exe", L"obs32.exe", L"streamlabs.exe",
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"opera.exe", L"brave.exe", L"vlc.exe", L"spotify.exe",
        L"steam.exe", L"gameoverlayui.exe", L"epicgameslauncher.exe"
    };
    if (umh::HasProcessTargetFilter()) {
        targetNames.clear();
        const auto& targets = umh::GetProcessTargets();
        targetNames.insert(targets.begin(), targets.end());
        std::wstringstream msg;
        msg << L"[targets] Process allowlist active (" << targetNames.size() << L" entries)";
        Log(msg.str());
    }
    std::set<std::wstring> userTargets;
    std::set<std::wstring> userBlacklist;

    auto EscapeJson = [](const std::wstring& s){ return EscapeJsonW(s); };
    std::set<DWORD> injected;
    std::map<DWORD, std::wstring> injectedNames;
    UnifiedAgentCacheState cacheState;
    bool pendingConfigSweep = false;
    bool pendingFingerprintSweep = false;
    bool initialSweepDone = false;
    ULONGLONG totalScans = 0, seenPids = 0, attempts = 0, success = 0, suppressedByBackoff = 0;
    struct Event { std::wstring ts; DWORD pid; std::wstring name; std::wstring method; bool ok; std::wstring detail; };
    std::vector<Event> events;
    auto NowStr = [](){ SYSTEMTIME st{}; GetLocalTime(&st); std::wstringstream ss; ss<<st.wHour<<L":"<<st.wMinute<<L":"<<st.wSecond; return ss.str(); };
    auto MethodToString = [](injection::InjectionMethod m){
        switch(m){case injection::InjectionMethod::Standard: return L"Standard"; case injection::InjectionMethod::ManualMap: return L"ManualMap"; case injection::InjectionMethod::SectionMap: return L"SectionMap"; case injection::InjectionMethod::Reflective: return L"Reflective"; case injection::InjectionMethod::DirectSyscall: return L"DirectSyscall";} return L"Unknown"; };
    InjectionEngine engine;

    ULONGLONG lastSweepTick = GetTickCount64();
    std::wstring lastSafetySweepReason;
    ULONGLONG lastSafetySweepTick = 0;
    unsigned long safetySweepCount = 0;

    while (true) {
        // Auto-reload config if changed
        {
            std::wstring cfgPath = GetExeDir() + L"\\agent.config";
            WIN32_FILE_ATTRIBUTE_DATA fad{}; if (GetFileAttributesExW(cfgPath.c_str(), GetFileExInfoStandard, &fad)) {
                static FILETIME last{}; if (CompareFileTime(&fad.ftLastWriteTime, &last) == 1) {
                    LoadConfig(false); last = fad.ftLastWriteTime; Log(L"Reloaded agent.config");
                    // Parse targets/blacklist lists
                    userTargets.clear(); userBlacklist.clear();
                    std::wifstream cfg(cfgPath);
                    if (cfg.is_open()) {
                        std::wstring line;
                        while (std::getline(cfg, line)) {
                            if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
                            auto pos = line.find(L'='); if (pos == std::wstring::npos) continue;
                            std::wstring key = line.substr(0, pos);
                            std::wstring val = line.substr(pos + 1);
                            auto trim = [](std::wstring& s){ while(!s.empty() && iswspace(s.front())) s.erase(0,1); while(!s.empty() && iswspace(s.back())) s.pop_back(); };
                            trim(key); trim(val);
                            std::transform(key.begin(), key.end(), key.begin(), ::towlower);
                            auto parseList = [&](const std::wstring& v, std::set<std::wstring>& out){ size_t start=0; while (start<v.size()) { size_t comma=v.find(L',', start); std::wstring item=v.substr(start, comma==std::wstring::npos? v.size()-start : comma-start); std::wstring t=item; trim(t); std::transform(t.begin(), t.end(), t.begin(), ::towlower); if(!t.empty()) out.insert(t); if (comma==std::wstring::npos) break; start=comma+1; } };
                            if (key == L"targets") parseList(val, userTargets);
                            else if (key == L"blacklist") parseList(val, userBlacklist);
                            else if (key == L"force_input") SetEnvironmentVariableW(L"HOOKDLL_FORCE_INPUT", val.c_str());
                        }
                        cfg.close();
                    }
                    pendingConfigSweep = true;
                }
            }
        }

        {
            std::wstring fpPath = DataDir() + L"\\agent_fingerprints.txt";
            WIN32_FILE_ATTRIBUTE_DATA fpFad{};
            if (GetFileAttributesExW(fpPath.c_str(), GetFileExInfoStandard, &fpFad)) {
                if (CompareFileTime(&fpFad.ftLastWriteTime, &g_fingerprintLastWrite) == 1) {
                    LoadFingerprintConfig(false);
                    pendingFingerprintSweep = true;
                }
            } else if (g_fingerprintLastWrite.dwLowDateTime || g_fingerprintLastWrite.dwHighDateTime) {
                g_fingerprintLastWrite = {};
                LoadFingerprintConfig(false);
                pendingFingerprintSweep = true;
            }
        }

        UpdateKeyboardTelemetry();
        ULONGLONG nowTicks = GetTickCount64();
        PollProcessWatcher();

        std::set<DWORD> activePids;
        std::vector<FlaggedProcessContext> graphicsFlaggedSnapshot;
        std::set<DWORD> graphicsFlaggedSeen;
        std::map<DWORD, std::vector<std::wstring>> graphicsModulesSnapshot;
        std::map<DWORD, std::wstring> fingerprintSnapshot;
        bool hasFingerprintRules = !g_forceFingerprints.empty() || !g_skipFingerprints.empty();

        std::set<DWORD> eventCandidates;
        while (!g_processEventQueue.empty()) {
            DWORD pid = g_processEventQueue.front();
            g_processEventQueue.pop_front();
            if (pid > 4) {
                eventCandidates.insert(pid);
            }
        }

        std::set<DWORD> retryCandidates;
        for (const auto& kv : g_injectionBackoff) {
            if (nowTicks >= kv.second.nextAttemptTick) {
                retryCandidates.insert(kv.first);
            }
        }

        auto evaluateFingerprint = [&](DWORD pid,
                                       const std::wstring& processName,
                                       std::wstring& fingerprintOut,
                                       bool& force,
                                       bool& skip) {
            fingerprintOut.clear();
            force = false;
            skip = false;
            fingerprintOut = ComputeModuleFingerprint(pid);
            if (fingerprintOut.empty()) {
                return;
            }
            bool autoForce = false;
            std::wstring autoToken;
            if (ShouldAutoForceFingerprint(fingerprintOut, autoToken)) {
                autoForce = true;
            }
            if (hasFingerprintRules) {
                if (g_forceFingerprints.count(fingerprintOut)) {
                    force = true;
                }
                if (g_skipFingerprints.count(fingerprintOut)) {
                    skip = true;
                }
            }
            if (skip && g_fingerprintSkipLogged.insert(pid).second) {
                std::wstringstream msg;
                msg << L"[fingerprint] Skipping PID " << pid << L" (" << processName << L") due to skip fingerprint rule";
                Log(msg.str());
                return;
            }
            if (autoForce) {
                force = true;
            }
            if (force && g_fingerprintForceLogged.insert(pid).second) {
                std::wstringstream msg;
                if (autoForce && (!hasFingerprintRules || !g_forceFingerprints.count(fingerprintOut))) {
                    msg << L"[fingerprint] Auto force matched (" << autoToken << L") for PID " << pid
                        << L" (" << processName << L")";
                } else {
                    msg << L"[fingerprint] Force fingerprint matched for PID " << pid << L" (" << processName << L")";
                }
                Log(msg.str());
            }
        };

        auto attemptImmediateInjection = [&](DWORD pid) {
            if (injected.count(pid)) {
                return;
            }

            HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                               PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
                                               FALSE,
                                               pid);
            if (!processHandle) {
                return;
            }

            wchar_t nameBuffer[MAX_PATH] = {};
            if (!GetModuleBaseNameW(processHandle, nullptr, nameBuffer, MAX_PATH) || nameBuffer[0] == L'\0') {
                DWORD length = MAX_PATH;
                if (QueryFullProcessImageNameW(processHandle, 0, nameBuffer, &length) && nameBuffer[0] != L'\0') {
                    std::wstring full(nameBuffer, length);
                    size_t pos = full.find_last_of(L"\\/");
                    std::wstring base = (pos == std::wstring::npos) ? full : full.substr(pos + 1);
                    wcsncpy_s(nameBuffer, base.c_str(), MAX_PATH);
                }
            }
            std::wstring name = nameBuffer;
            if (name.empty()) {
                CloseHandle(processHandle);
                return;
            }
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (systemNames.count(lower) || userBlacklist.count(lower)) {
                CloseHandle(processHandle);
                return;
            }
            if (umh::HasProcessTargetFilter() && !umh::IsTargetProcess(lower)) {
                CloseHandle(processHandle);
                return;
            }

#ifdef _WIN64
            BOOL wow64Process = FALSE;
            IsWow64Process(processHandle, &wow64Process);
            if (wow64Process) {
                CloseHandle(processHandle);
                return;
            }
#else
            BOOL wow64Process = FALSE;
            IsWow64Process(processHandle, &wow64Process);
            if (!wow64Process) {
                CloseHandle(processHandle);
                return;
            }
#endif
            if (IsElevated(processHandle) && !IsElevated(GetCurrentProcess())) {
                CloseHandle(processHandle);
                return;
            }
            CloseHandle(processHandle);

            activePids.insert(pid);

            ProcessIdentityInfo identity = QueryProcessIdentity(pid);
            identity.lastSeen = nowTicks;
            g_processIdentity[pid] = identity;
            ApplyIdentityToTelemetry(pid, identity);

            bool keyboardFlagged = false;
            auto kt = g_keyboardTelemetry.find(pid);
            if (kt != g_keyboardTelemetry.end()) {
                kt->second.lastKnownName = name;
                keyboardFlagged = IsKeyboardFlagged(pid, nowTicks);
            }
            auto dt = g_displayTelemetry.find(pid);
            if (dt != g_displayTelemetry.end()) {
                dt->second.lastKnownName = name;
            }

            auto modules = CollectGraphicsModulesForPid(pid);
            bool graphicsFlagged = !modules.empty();
            if (!modules.empty()) {
                auto& bucket = graphicsModulesSnapshot[pid];
                bucket.insert(bucket.end(), modules.begin(), modules.end());
            }

            auto gfxTelemetry = g_graphicsTelemetry.find(pid);
            if (gfxTelemetry != g_graphicsTelemetry.end()) {
                const auto& tele = gfxTelemetry->second;
                graphicsFlagged = graphicsFlagged ||
                                  !tele.modules.empty() ||
                                  !tele.duplications.empty() ||
                                  !tele.captures.empty();
                if (!tele.modules.empty()) {
                    auto& bucket = graphicsModulesSnapshot[pid];
                    for (const auto& modPair : tele.modules) {
                        std::wstring modName(modPair.first.begin(), modPair.first.end());
                        bucket.push_back(modName);
                    }
                }
            }

            if (graphicsFlagged && graphicsFlaggedSeen.insert(pid).second) {
                FlaggedProcessContext ctx{};
                ctx.pid = pid;
                ctx.name = name;
                ctx.sessionId = identity.sessionId;
                ctx.userSid = identity.userSid;
                ctx.userName = identity.userName;
                graphicsFlaggedSnapshot.emplace_back(std::move(ctx));
                if (g_graphicsEscalated.insert(pid).second) {
                    Log(L"[graphics] Prioritising " + name + L" (PID " + std::to_wstring(pid) + L") due to telemetry fingerprint");
                }
            }

            bool fingerprintForce = false;
            bool fingerprintSkip = false;
            std::wstring fingerprint;
            evaluateFingerprint(pid, name, fingerprint, fingerprintForce, fingerprintSkip);
            if (!fingerprint.empty()) {
                fingerprintSnapshot[pid] = fingerprint;
            }
            if (fingerprintForce && !graphicsFlagged && graphicsFlaggedSeen.insert(pid).second) {
                FlaggedProcessContext ctx{};
                ctx.pid = pid;
                ctx.name = name;
                ctx.sessionId = identity.sessionId;
                ctx.userSid = identity.userSid;
                ctx.userName = identity.userName;
                graphicsFlaggedSnapshot.emplace_back(std::move(ctx));
                if (g_graphicsEscalated.insert(pid).second) {
                    Log(L"[graphics] Prioritising " + name + L" (PID " + std::to_wstring(pid) + L") due to fingerprint policy");
                }
            }
            if (fingerprintSkip) {
                return;
            }

            bool allowByPolicy = aggressive || keyboardFlagged || graphicsFlagged;
            if (fingerprintForce) {
                allowByPolicy = true;
            }
            if (!allowByPolicy) {
                if (!userTargets.empty()) {
                    if (!userTargets.count(lower)) {
                        return;
                    }
                } else if (!targetNames.count(lower)) {
                    return;
                }
            }

            auto backoffIt = g_injectionBackoff.find(pid);
            if (backoffIt != g_injectionBackoff.end() &&
                nowTicks < backoffIt->second.nextAttemptTick) {
                ++suppressedByBackoff;
                return;
            }

            ++seenPids;
            HANDLE injectHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                              PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD,
                                              FALSE,
                                              pid);
            if (!injectHandle) {
                return;
            }
#ifdef _WIN64
            BOOL wow64Target = FALSE;
            IsWow64Process(injectHandle, &wow64Target);
            if (wow64Target) {
                CloseHandle(injectHandle);
                return;
            }
#else
            BOOL wow64Target = FALSE;
            IsWow64Process(injectHandle, &wow64Target);
            if (!wow64Target) {
                CloseHandle(injectHandle);
                return;
            }
#endif
            if (IsElevated(injectHandle) && !IsElevated(GetCurrentProcess())) {
                CloseHandle(injectHandle);
                return;
            }
            CloseHandle(injectHandle);

            InjectionOptions opts{};
            opts.methodOrder = { InjectionMethod::SectionMap, InjectionMethod::ManualMap, InjectionMethod::Standard };
            ++attempts;
            auto res = engine.Inject(pid, dllPath, opts);
            events.push_back(Event{ NowStr(), pid, name, MethodToString(res.method), res.success, res.detail }); if (events.size()>100) events.erase(events.begin());
            if (res.success) {
                ++success;
                injected.insert(pid);
                injectedNames[pid] = name;
                g_injectionBackoff.erase(pid);
                Log(L"[+] Injected into PID " + std::to_wstring(pid) + L" (event) : " + res.detail);
            } else {
                auto& state = g_injectionBackoff[pid];
                if (state.attempts < kMaxBackoffSteps) {
                    state.attempts += 1;
                }
                ULONGLONG delay = ComputeBackoffDelayMs(state.attempts);
                state.nextAttemptTick = nowTicks + delay;
                state.lastError = res.detail;
                std::wstringstream msg;
                msg << L"[inject] Failed to hook " << name
                    << L" (PID " << pid << L") via " << MethodToString(res.method)
                    << L": " << res.detail
                    << L". Next retry in " << (delay / 1000.0) << L"s";
                Log(msg.str());
            }
        };

        for (DWORD pid : eventCandidates) {
            attemptImmediateInjection(pid);
        }

        for (DWORD pid : retryCandidates) {
            if (eventCandidates.count(pid)) {
                continue;
            }
            attemptImmediateInjection(pid);
        }

        auto diffHandles = [](const std::vector<unsigned long long>& handles,
                              const std::set<unsigned long long>& existing) {
            std::vector<unsigned long long> diff;
            for (auto value : handles) {
                if (!value) {
                    continue;
                }
                if (existing.find(value) == existing.end()) {
                    diff.push_back(value);
                }
            }
            return diff;
        };

        auto staleHandles = [](const std::set<unsigned long long>& existing,
                               const std::vector<unsigned long long>& current) {
            std::vector<unsigned long long> stale;
            std::set<unsigned long long> currentSet(current.begin(), current.end());
            for (auto value : existing) {
                if (currentSet.find(value) == currentSet.end()) {
                    stale.push_back(value);
                }
            }
            return stale;
        };

        bool overflowed = g_processEventOverflowed;
        bool watcherReady = (g_wmiProcessEvents != nullptr);
        UnifiedAgentSweepContext sweepContext{};
        sweepContext.initialSweepDone = initialSweepDone;
        sweepContext.watcherReady = watcherReady;
        sweepContext.eventOverflowed = overflowed;
        sweepContext.pendingConfigSweep = pendingConfigSweep;
        sweepContext.pendingFingerprintSweep = pendingFingerprintSweep;
        sweepContext.nowTicks = nowTicks;
        sweepContext.lastSweepTick = lastSweepTick;
        sweepContext.fallbackIntervalMs = kFallbackSweepMs;
        UnifiedAgentSweepDecision sweepDecision = EvaluateSafetySweep(sweepContext);
        if (overflowed) {
            g_processEventOverflowed = false;
        }
        bool performSweep = sweepDecision.run;

        if (performSweep) {
            std::wstring sweepReason = (sweepDecision.reason && sweepDecision.reason[0])
                                           ? std::wstring(sweepDecision.reason)
                                           : std::wstring(L"unspecified");
            std::wstringstream sweepLog;
            sweepLog << L"[sweep] Safety sweep triggered (" << sweepReason << L")";
            Log(sweepLog.str());
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        DWORD pid = pe.th32ProcessID; if (pid <= 4) continue;
                        if (injected.count(pid)) continue;
                        std::wstring name = pe.szExeFile; std::wstring lower = name; std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                        if (systemNames.count(lower)) continue;
                        if (userBlacklist.count(lower)) continue;
                        if (umh::HasProcessTargetFilter() && !umh::IsTargetProcess(lower)) continue;
                        activePids.insert(pid);

                        ProcessIdentityInfo identity = QueryProcessIdentity(pid);
                        identity.lastSeen = nowTicks;
                        g_processIdentity[pid] = identity;
                        ApplyIdentityToTelemetry(pid, identity);

                        bool keyboardFlagged = false;
                        auto kt = g_keyboardTelemetry.find(pid);
                        if (kt != g_keyboardTelemetry.end()) {
                            kt->second.lastKnownName = name;
                            keyboardFlagged = IsKeyboardFlagged(pid, nowTicks);
                        }
                        auto dt = g_displayTelemetry.find(pid);
                        if (dt != g_displayTelemetry.end()) {
                            dt->second.lastKnownName = name;
                        }

                        auto modules = CollectGraphicsModulesForPid(pid);
                        bool graphicsFlagged = !modules.empty();
                        if (!modules.empty()) {
                            auto& bucket = graphicsModulesSnapshot[pid];
                            bucket.insert(bucket.end(), modules.begin(), modules.end());
                        }

                        auto gfxTelemetry = g_graphicsTelemetry.find(pid);
                        if (gfxTelemetry != g_graphicsTelemetry.end()) {
                            const auto& tele = gfxTelemetry->second;
                            graphicsFlagged = graphicsFlagged ||
                                              !tele.modules.empty() ||
                                              !tele.duplications.empty() ||
                                              !tele.captures.empty();
                            if (!tele.modules.empty()) {
                                auto& bucket = graphicsModulesSnapshot[pid];
                                for (const auto& modPair : tele.modules) {
                                    std::wstring modName(modPair.first.begin(), modPair.first.end());
                                    bucket.push_back(modName);
                                }
                            }
                        }

                        if (graphicsFlagged && graphicsFlaggedSeen.insert(pid).second) {
                            FlaggedProcessContext ctx{};
                            ctx.pid = pid;
                            ctx.name = name;
                            ctx.sessionId = identity.sessionId;
                            ctx.userSid = identity.userSid;
                            ctx.userName = identity.userName;
                            graphicsFlaggedSnapshot.emplace_back(std::move(ctx));
                            if (g_graphicsEscalated.insert(pid).second) {
                                Log(L"[graphics] Prioritising " + name + L" (PID " + std::to_wstring(pid) + L") due to telemetry fingerprint");
                            }
                        }

                        bool fingerprintForce = false;
                        bool fingerprintSkip = false;
                        std::wstring fingerprint;
                        evaluateFingerprint(pid, name, fingerprint, fingerprintForce, fingerprintSkip);
                        if (!fingerprint.empty()) {
                            fingerprintSnapshot[pid] = fingerprint;
                        }
                        if (fingerprintForce && !graphicsFlagged && graphicsFlaggedSeen.insert(pid).second) {
                            FlaggedProcessContext ctx{};
                            ctx.pid = pid;
                            ctx.name = name;
                            ctx.sessionId = identity.sessionId;
                            ctx.userSid = identity.userSid;
                            ctx.userName = identity.userName;
                            graphicsFlaggedSnapshot.emplace_back(std::move(ctx));
                            if (g_graphicsEscalated.insert(pid).second) {
                                Log(L"[graphics] Prioritising " + name + L" (PID " + std::to_wstring(pid) + L") due to fingerprint policy");
                            }
                        }
                        if (fingerprintSkip) {
                            continue;
                        }

                        bool allowByPolicy = aggressive || keyboardFlagged || graphicsFlagged;
                        if (fingerprintForce) {
                            allowByPolicy = true;
                        }
                        if (!allowByPolicy) {
                            if (!userTargets.empty()) {
                                if (!userTargets.count(lower)) continue;
                            } else {
                                if (!targetNames.count(lower)) continue;
                            }
                        }

                        auto backoffIt = g_injectionBackoff.find(pid);
                        if (backoffIt != g_injectionBackoff.end() &&
                            nowTicks < backoffIt->second.nextAttemptTick) {
                            ++suppressedByBackoff;
                            continue;
                        }

                        ++seenPids;
                        HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, FALSE, pid);
                        if (!proc) continue;

#ifdef _WIN64
                        BOOL wow64 = FALSE; IsWow64Process(proc, &wow64); if (wow64) { CloseHandle(proc); continue; }
#else
                        BOOL wow64 = FALSE; IsWow64Process(proc, &wow64); if (!wow64) { CloseHandle(proc); continue; }
#endif
                        if (IsElevated(proc) && !IsElevated(GetCurrentProcess())) { CloseHandle(proc); continue; }
                        CloseHandle(proc);

                        InjectionOptions opts{};
                        opts.methodOrder = { InjectionMethod::SectionMap, InjectionMethod::ManualMap, InjectionMethod::Standard };
                        opts.sectionMapFlags = 0;

                        ++attempts;
                        auto res = engine.Inject(pid, dllPath, opts);
                        events.push_back(Event{ NowStr(), pid, name, MethodToString(res.method), res.success, res.detail }); if (events.size()>100) events.erase(events.begin());
                        if (res.success) { ++success;
                            injected.insert(pid);
                            injectedNames[pid] = name;
                            g_injectionBackoff.erase(pid);
                            Log(L"[+] Injected into PID " + std::to_wstring(pid) + L": " + res.detail);
                        } else {
                            auto& state = g_injectionBackoff[pid];
                            if (state.attempts < kMaxBackoffSteps) {
                                state.attempts += 1;
                            }
                            ULONGLONG delay = ComputeBackoffDelayMs(state.attempts);
                            state.nextAttemptTick = nowTicks + delay;
                            state.lastError = res.detail;
                            std::wstringstream msg;
                            msg << L"[inject] Failed to hook " << name
                                << L" (PID " << pid << L") via " << MethodToString(res.method)
                                << L": " << res.detail
                                << L". Next retry in " << (delay / 1000.0) << L"s";
                            Log(msg.str());
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
            initialSweepDone = true;
            pendingConfigSweep = false;
            pendingFingerprintSweep = false;
            lastSafetySweepReason = (sweepDecision.reason && sweepDecision.reason[0])
                                        ? std::wstring(sweepDecision.reason)
                                        : std::wstring(L"unspecified");
            lastSafetySweepTick = nowTicks;
            ++safetySweepCount;
            lastSweepTick = nowTicks;
        }

        std::map<DWORD, bool> pidAliveCache;
        for (DWORD pid : activePids) {
            pidAliveCache[pid] = true;
        }
        auto isPidAliveCached = [&](DWORD pid) -> bool {
            auto it = pidAliveCache.find(pid);
            if (it != pidAliveCache.end()) {
                return it->second;
            }
            bool alive = IsProcessAlive(pid);
            pidAliveCache[pid] = alive;
            return alive;
        };

        if (!injected.empty()) {
            for (auto it = injected.begin(); it != injected.end();) {
                if (!isPidAliveCached(*it)) {
                    injectedNames.erase(*it);
                    it = injected.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (!injectedNames.empty()) {
            for (auto it = injectedNames.begin(); it != injectedNames.end();) {
                if (!isPidAliveCached(it->first)) {
                    it = injectedNames.erase(it);
                } else {
                    ++it;
                }
            }
        }

        if (!g_injectionBackoff.empty()) {
            for (auto it = g_injectionBackoff.begin(); it != g_injectionBackoff.end();) {
                if (!isPidAliveCached(it->first)) {
                    it = g_injectionBackoff.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (!g_fingerprintSkipLogged.empty()) {
            for (auto it = g_fingerprintSkipLogged.begin(); it != g_fingerprintSkipLogged.end();) {
                if (!isPidAliveCached(*it)) {
                    it = g_fingerprintSkipLogged.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (!g_fingerprintForceLogged.empty()) {
            for (auto it = g_fingerprintForceLogged.begin(); it != g_fingerprintForceLogged.end();) {
                if (!isPidAliveCached(*it)) {
                    it = g_fingerprintForceLogged.erase(it);
                } else {
                    ++it;
                }
            }
        }
        if (!g_graphicsEscalated.empty()) {
            for (auto it = g_graphicsEscalated.begin(); it != g_graphicsEscalated.end();) {
                if (!isPidAliveCached(*it)) {
                    it = g_graphicsEscalated.erase(it);
                } else {
                    ++it;
                }
            }
        }
        UnifiedAgentCacheInput cacheInput;
        cacheInput.activePids = activePids;
        cacheInput.flaggedSnapshot = graphicsFlaggedSnapshot;
        cacheInput.fingerprintSnapshot = fingerprintSnapshot;
        cacheInput.moduleSnapshot = graphicsModulesSnapshot;
        UpdateUnifiedAgentCaches(cacheState, cacheInput, isPidAliveCached);

        const ULONGLONG identityExpiry = 3ull * 60ull * 1000ull;
        for (auto it = g_processIdentity.begin(); it != g_processIdentity.end(); ) {
            if (nowTicks - it->second.lastSeen > identityExpiry) {
                it = g_processIdentity.erase(it);
            } else {
                ++it;
            }
        }

        for (const auto& kv : g_keyboardTelemetry) {
            DWORD pid = kv.first;
            const auto& entry = kv.second;
            auto& state = g_policyState[pid];

            ULONGLONG forcedCount = entry.blockForced + entry.ntForced + entry.attachPrevented +
                                    entry.ntAttachPrevented + entry.spiForced + entry.enableForced +
                                    entry.ntSetInfoBlocked + entry.hookBlocked + entry.diSetCoopForced;

            bool hasNewForced = forcedCount > state.keyboardForcedCount;
            state.keyboardLastEventTick = entry.lastTick;
            state.keyboardForcedCount = forcedCount;

            if (hasNewForced && state.forceInput != 1 &&
                nowTicks - state.lastForceInputAttempt > kPolicyAttemptCooldownMs) {
                bool applied = SendPolicyCommand(pid, 1, kPolicyNoChange);
                state.lastForceInputAttempt = nowTicks;
                if (applied) {
                    state.forceInput = 1;
                    state.lastForceInputApplied = nowTicks;
                    std::wstringstream msg;
                    msg << L"[policy] ForceInput enabled for PID " << pid
                        << L" after keyboard tamper escalation";
                    Log(msg.str());
                }
            }

            if (state.forceInput == 1 &&
                nowTicks >= entry.lastTick &&
                nowTicks - entry.lastTick > kKeyboardRelaxMs &&
                nowTicks - state.lastForceInputAttempt > kPolicyAttemptCooldownMs) {
                bool applied = SendPolicyCommand(pid, 0, kPolicyNoChange);
                state.lastForceInputAttempt = nowTicks;
                if (applied) {
                    state.forceInput = 0;
                    state.lastForceInputApplied = nowTicks;
                    std::wstringstream msg;
                    msg << L"[policy] ForceInput reset for PID " << pid
                        << L" after quiet period";
                    Log(msg.str());
                }
            }
        }

        for (const auto& kv : g_displayTelemetry) {
            DWORD pid = kv.first;
            const auto& entry = kv.second;
            auto& state = g_policyState[pid];

            ULONGLONG forcedCount = entry.userModeForced + entry.nativeForced + entry.swapBlocked;
            bool hasNewForced = forcedCount > state.wdaForcedCount;
            state.wdaLastEventTick = entry.lastTick;
            state.wdaForcedCount = forcedCount;

            auto& blockedDup = g_policyBlockedDuplications[pid];
            auto& blockedWindows = g_policyBlockedCaptureWindows[pid];
            auto& blockedMonitors = g_policyBlockedCaptureMonitors[pid];
            auto& blockedSwapChains = g_policyBlockedSwapChains[pid];
            auto dupHandles = CollectDuplicationHandlesForPid(pid);
            auto windowHandles = CollectCaptureWindowTargetsForPid(pid);
            auto monitorHandles = CollectCaptureMonitorTargetsForPid(pid);
            auto swapHandles = CollectSwapChainHandlesForPid(pid);

            if (hasNewForced && state.forceWda != 1 &&
                nowTicks - state.lastForceWdaAttempt > kPolicyAttemptCooldownMs) {
                auto newDup = diffHandles(dupHandles, blockedDup);
                auto newWindows = diffHandles(windowHandles, blockedWindows);
                auto newMonitors = diffHandles(monitorHandles, blockedMonitors);
                auto newSwap = diffHandles(swapHandles, blockedSwapChains);
                bool applied = SendPolicyCommand(pid,
                                                 kPolicyNoChange,
                                                 1,
                                                 newDup,
                                                 {},
                                                 newWindows,
                                                 {},
                                                 newMonitors,
                                                 {},
                                                 newSwap,
                                                 {});
                state.lastForceWdaAttempt = nowTicks;
                if (applied) {
                    state.forceWda = 1;
                    state.lastForceWdaApplied = nowTicks;
                    blockedDup.insert(newDup.begin(), newDup.end());
                    blockedWindows.insert(newWindows.begin(), newWindows.end());
                    blockedMonitors.insert(newMonitors.begin(), newMonitors.end());
                    blockedSwapChains.insert(newSwap.begin(), newSwap.end());
                    std::wstringstream msg;
                    msg << L"[policy] ForceWDA enabled for PID " << pid
                        << L" after display tamper escalation";
                    if (!newDup.empty() || !newWindows.empty() || !newMonitors.empty() || !newSwap.empty()) {
                        msg << L" (capture handles locked: "
                            << (newDup.size() + newWindows.size() + newMonitors.size() + newSwap.size()) << L")";
                    }
                    Log(msg.str());
                }
            }

            if (state.forceWda == 1) {
                auto incrementalDup = diffHandles(dupHandles, blockedDup);
                auto incrementalWindows = diffHandles(windowHandles, blockedWindows);
                auto incrementalMonitors = diffHandles(monitorHandles, blockedMonitors);
                auto incrementalSwap = diffHandles(swapHandles, blockedSwapChains);
                auto staleDup = staleHandles(blockedDup, dupHandles);
                auto staleWindows = staleHandles(blockedWindows, windowHandles);
                auto staleMonitors = staleHandles(blockedMonitors, monitorHandles);
                auto staleSwap = staleHandles(blockedSwapChains, swapHandles);
                if (!incrementalDup.empty() || !incrementalWindows.empty() || !incrementalMonitors.empty() || !incrementalSwap.empty() ||
                    !staleDup.empty() || !staleWindows.empty() || !staleMonitors.empty() || !staleSwap.empty()) {
                    if (SendPolicyCommand(pid,
                                          kPolicyNoChange,
                                          kPolicyNoChange,
                                          incrementalDup,
                                          staleDup,
                                          incrementalWindows,
                                          staleWindows,
                                          incrementalMonitors,
                                          staleMonitors,
                                          incrementalSwap,
                                          staleSwap)) {
                        blockedDup.insert(incrementalDup.begin(), incrementalDup.end());
                        blockedWindows.insert(incrementalWindows.begin(), incrementalWindows.end());
                        blockedMonitors.insert(incrementalMonitors.begin(), incrementalMonitors.end());
                        blockedSwapChains.insert(incrementalSwap.begin(), incrementalSwap.end());
                        for (auto value : staleDup) {
                            blockedDup.erase(value);
                        }
                        for (auto value : staleWindows) {
                            blockedWindows.erase(value);
                        }
                        for (auto value : staleMonitors) {
                            blockedMonitors.erase(value);
                        }
                        for (auto value : staleSwap) {
                            blockedSwapChains.erase(value);
                        }
                        size_t addedCount = incrementalDup.size() + incrementalWindows.size() + incrementalMonitors.size() + incrementalSwap.size();
                        size_t removedCount = staleDup.size() + staleWindows.size() + staleMonitors.size() + staleSwap.size();
                        if (addedCount || removedCount) {
                            std::wstringstream msg;
                            msg << L"[policy] ForceWDA update for PID " << pid;
                            if (addedCount) {
                                msg << L" added=" << addedCount;
                            }
                            if (removedCount) {
                                msg << L" cleared=" << removedCount;
                            }
                            Log(msg.str());
                        }
                    }
                }
            }

            if (state.forceWda == 1 &&
                nowTicks >= entry.lastTick &&
                nowTicks - entry.lastTick > kDisplayRelaxMs &&
                nowTicks - state.lastForceWdaAttempt > kPolicyAttemptCooldownMs) {
                std::vector<unsigned long long> clearDup(blockedDup.begin(), blockedDup.end());
                std::vector<unsigned long long> clearWindows(blockedWindows.begin(), blockedWindows.end());
                std::vector<unsigned long long> clearMonitors(blockedMonitors.begin(), blockedMonitors.end());
                std::vector<unsigned long long> clearSwap(blockedSwapChains.begin(), blockedSwapChains.end());
                bool applied = SendPolicyCommand(pid,
                                                 kPolicyNoChange,
                                                 0,
                                                 {},
                                                 clearDup,
                                                 {},
                                                 clearWindows,
                                                 {},
                                                 clearMonitors,
                                                 {},
                                                 clearSwap);
                state.lastForceWdaAttempt = nowTicks;
                if (applied) {
                    state.forceWda = 0;
                    state.lastForceWdaApplied = nowTicks;
                    blockedDup.clear();
                    blockedWindows.clear();
                    blockedMonitors.clear();
                    blockedSwapChains.clear();
                    std::wstringstream msg;
                    msg << L"[policy] ForceWDA reset for PID " << pid
                        << L" after quiet period";
                    Log(msg.str());
                }
            }
        }

        for (auto it = g_policyState.begin(); it != g_policyState.end(); ) {
            DWORD pid = it->first;
            auto stateItKeyboard = g_keyboardTelemetry.find(pid);
            bool hasKeyboard = (stateItKeyboard != g_keyboardTelemetry.end());
            if (hasKeyboard) {
                it->second.keyboardLastEventTick = stateItKeyboard->second.lastTick;
            }
            auto stateItDisplay = g_displayTelemetry.find(pid);
            bool hasDisplay = (stateItDisplay != g_displayTelemetry.end());
            if (hasDisplay) {
                it->second.wdaLastEventTick = stateItDisplay->second.lastTick;
            }

            if (!hasKeyboard && it->second.forceInput == 1 &&
                nowTicks - it->second.lastForceInputAttempt > kPolicyAttemptCooldownMs) {
                bool applied = SendPolicyCommand(pid, 0, kPolicyNoChange);
                it->second.lastForceInputAttempt = nowTicks;
                if (applied) {
                    it->second.forceInput = 0;
                    it->second.lastForceInputApplied = nowTicks;
                    std::wstringstream msg;
                    msg << L"[policy] ForceInput reset for PID " << pid
                        << L" (no recent keyboard telemetry)";
                    Log(msg.str());
                }
            }

            if (!hasDisplay && it->second.forceWda == 1 &&
                nowTicks - it->second.lastForceWdaAttempt > kPolicyAttemptCooldownMs) {
                auto dupIt = g_policyBlockedDuplications.find(pid);
                auto winIt = g_policyBlockedCaptureWindows.find(pid);
                auto monIt = g_policyBlockedCaptureMonitors.find(pid);
                auto swapIt = g_policyBlockedSwapChains.find(pid);
                std::vector<unsigned long long> clearDup;
                std::vector<unsigned long long> clearWindows;
                std::vector<unsigned long long> clearMonitors;
                std::vector<unsigned long long> clearSwap;
                if (dupIt != g_policyBlockedDuplications.end()) {
                    clearDup.assign(dupIt->second.begin(), dupIt->second.end());
                }
                if (winIt != g_policyBlockedCaptureWindows.end()) {
                    clearWindows.assign(winIt->second.begin(), winIt->second.end());
                }
                if (monIt != g_policyBlockedCaptureMonitors.end()) {
                    clearMonitors.assign(monIt->second.begin(), monIt->second.end());
                }
                if (swapIt != g_policyBlockedSwapChains.end()) {
                    clearSwap.assign(swapIt->second.begin(), swapIt->second.end());
                }
                bool applied = SendPolicyCommand(pid,
                                                 kPolicyNoChange,
                                                 0,
                                                 {},
                                                 clearDup,
                                                 {},
                                                 clearWindows,
                                                 {},
                                                 clearMonitors,
                                                 {},
                                                 clearSwap);
                it->second.lastForceWdaAttempt = nowTicks;
                if (applied) {
                    it->second.forceWda = 0;
                    it->second.lastForceWdaApplied = nowTicks;
                    if (dupIt != g_policyBlockedDuplications.end()) {
                        dupIt->second.clear();
                    }
                    if (winIt != g_policyBlockedCaptureWindows.end()) {
                        winIt->second.clear();
                    }
                    if (monIt != g_policyBlockedCaptureMonitors.end()) {
                        monIt->second.clear();
                    }
                    if (swapIt != g_policyBlockedSwapChains.end()) {
                        swapIt->second.clear();
                    }
                    std::wstringstream msg;
                    msg << L"[policy] ForceWDA reset for PID " << pid
                        << L" (no recent display telemetry)";
                    Log(msg.str());
                }
            }

            auto removeCandidate = (it->second.forceInput == 0 && it->second.forceWda == 0);
            if (removeCandidate) {
                bool inputExpired = (it->second.lastForceInputApplied == 0) ||
                    (nowTicks - it->second.lastForceInputApplied > kPolicyCleanupMs);
                bool wdaExpired = (it->second.lastForceWdaApplied == 0) ||
                    (nowTicks - it->second.lastForceWdaApplied > kPolicyCleanupMs);
                if (inputExpired && wdaExpired) {
                    g_policyBlockedDuplications.erase(pid);
                    g_policyBlockedCaptureWindows.erase(pid);
                    g_policyBlockedCaptureMonitors.erase(pid);
                    g_policyBlockedSwapChains.erase(pid);
                    it = g_policyState.erase(it);
                    continue;
                }
            }

            ++it;
        }

        std::vector<FlaggedProcessContext> graphicsFlaggedOutput;
        graphicsFlaggedOutput.reserve(cacheState.flagged.size());
        for (const auto& kv : cacheState.flagged) {
            graphicsFlaggedOutput.push_back(kv.second);
        }
        // Write status JSON for PS CLI to consume
        {
            std::wofstream st((DataDir() + L"\\agent_status.json").c_str(), std::ios::trunc);
            if (st.is_open()) {
                SYSTEMTIME t{}; GetLocalTime(&t);
                st << L"{\"time\":\"" << t.wHour << L":" << t.wMinute << L":" << t.wSecond << L"\",";
                st << L"\"interval\":" << intervalSec << L",\"aggressive\":" << (aggressive?1:0) << L",";
                st << L"\"dll\":\"" << EscapeJson(dllPath) << L"\",";
                st << L"\"scans\":" << (++totalScans)
                   << L",\"seen\":" << seenPids
                   << L",\"attempts\":" << attempts
                   << L",\"success\":" << success
                   << L",\"backoff_suppressed\":" << suppressedByBackoff
                   << L",";
                ULONGLONG sweepSince = lastSafetySweepTick ? (nowTicks - lastSafetySweepTick) : 0;
                st << L"\"safety_sweep\":{"
                   << L"\"count\":" << safetySweepCount;
                if (lastSafetySweepTick) {
                    st << L",\"last_ms\":" << sweepSince;
                }
                if (!lastSafetySweepReason.empty()) {
                    st << L",\"reason\":\"" << EscapeJson(lastSafetySweepReason) << L"\"";
                }
                st << L"},";
                st << L"\"injected\":[";
                bool first=true; for (const auto& p : injectedNames) { if (!first) st<<L","; first=false; st<<L"{\"pid\":"<<p.first<<L",\"name\":\""<<EscapeJson(p.second)<<L"\"}"; }
                st << L"],\"events\":[";
                for (size_t i=0;i<events.size();++i){ const auto& e=events[i]; if (i) st<<L","; st<<L"{\"ts\":\""<<EscapeJson(e.ts)<<L"\",\"pid\":"<<e.pid<<L",\"name\":\""<<EscapeJson(e.name)<<L"\",\"method\":\""<<EscapeJson(e.method)<<L"\",\"ok\":"<<(e.ok?1:0)<<L",\"detail\":\""<<EscapeJson(e.detail)<<L"\"}"; }
                st << L"],\"telemetry\":{";
                {
                    bool f=true; for (const auto& p : injectedNames) {
                        std::wstring data;
                        {
                            wchar_t pipeName[128] = {};
                            pipes::FormatTelemetryPipe(pipeName, _countof(pipeName), p.first);
                            if (WaitNamedPipeW(pipeName, 50)) {
                                HANDLE h = CreateFileW(pipeName, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                                if (h != INVALID_HANDLE_VALUE) {
                                    const char* req = "GET\n"; DWORD wr=0; WriteFile(h, req, 4, &wr, nullptr);
                                    std::string buf; buf.resize(64*1024);
                                    DWORD rd=0; if (ReadFile(h, buf.data(), (DWORD)buf.size()-1, &rd, nullptr)) { buf[rd]='\0'; data.assign(buf.begin(), buf.begin()+rd); }
                                    CloseHandle(h);
                                }
                            }
                        }
                        if (data.empty()) continue;
                        if (!f) st<<L","; f=false;
                        st << L"\"" << p.first << L"\":\"" << EscapeJson(data) << L"\"";
                    }
                }
                st << L"},\"dx\":{\"d3d9_present\":" << dx_d3d9.load(std::memory_order_relaxed)
                   << L",\"dxgi_present\":" << dx_dxgi.load(std::memory_order_relaxed) << L"},\"hookdll\":{";
                // Lightweight parse of HookDLL log for per-function install and last layer summary
                {
                    std::wifstream in((DataDir() + L"\\api_hooks.log").c_str());
                    std::map<std::wstring,int> installOk;
                    std::map<std::wstring,int> installFail;
                    std::map<std::wstring,std::wstring> lastLayers;
                    if (in.is_open()) {
                        std::wstring line; std::wstring lastFunc;
                        while (std::getline(in, line)) {
                            auto inst = line.find(L"Hook installed: ");
                            if (inst != std::wstring::npos) { lastFunc = line.substr(inst + 16); installOk[lastFunc]++; continue; }
                            auto lay = line.find(L"Layers:");
                            if (lay != std::wstring::npos && !lastFunc.empty()) {
                                std::wstring layers = line.substr(lay + 7);
                                while(!layers.empty() && (layers[0]==L' '||layers[0]==L'\t')) layers.erase(0,1);
                                lastLayers[lastFunc] = layers; lastFunc.clear();
                            }
                            auto umh = line.find(L"umh event=install ");
                            if (umh != std::wstring::npos) {
                                auto fpos = line.find(L" func=", umh);
                                auto spos = line.find(L" status=", umh);
                                if (fpos != std::wstring::npos) {
                                    size_t fstart = fpos + 6; size_t fend = (spos != std::wstring::npos ? spos : line.size());
                                    std::wstring fn = line.substr(fstart, fend - fstart);
                                    if (spos != std::wstring::npos) {
                                        size_t sstart = spos + 8; size_t send = line.find(L' ', sstart);
                                        std::wstring stat = line.substr(sstart, (send==std::wstring::npos ? line.size()-sstart : send - sstart));
                                        if (stat == L"success") installOk[fn]++; else if (stat == L"fail") installFail[fn]++;
                                    }
                                }
                            }
                        }
                        in.close();
                    }
                    // Emit JSON
                    st << L"\"install_ok\":{"; bool f=true; for (auto& kv : installOk){ if(!f) st<<L","; f=false; st<<L"\""<<kv.first<<L"\":"<<kv.second; } st << L"},";
                    st << L"\"install_fail\":{"; f=true; for (auto& kv : installFail){ if(!f) st<<L","; f=false; st<<L"\""<<kv.first<<L"\":"<<kv.second; } st << L"},";
                    st << L"\"last_layers\":{"; f=true; for (auto& kv : lastLayers){ if(!f) st<<L","; f=false; st<<L"\""<<kv.first<<L"\":\""<<kv.second<<L"\""; } st << L"}";
                }
                st << L"}"; // end hookdll
                ULONGLONG nowKeyboard = GetTickCount64();
                st << L",\"keyboard\":{\"flagged\":[";
                {
                    bool firstFlagged = true;
                    for (const auto& kv : g_keyboardTelemetry) {
                        const auto& entry = kv.second;
                        if (nowKeyboard - entry.lastTick > 120000) {
                            continue;
                        }
                        ULONGLONG total = entry.blockRequests + entry.ntRequests + entry.attachRequests +
                                          entry.ntAttachRequests + entry.spiRequests + entry.enableRequests +
                                          entry.ntSetInfoRequests + entry.hookAttempts +
                                          entry.diSetCoop + entry.diAcquire;
                        if (total == 0) {
                            continue;
                        }
                        ULONGLONG forced = entry.blockForced + entry.ntForced + entry.attachPrevented +
                                           entry.ntAttachPrevented + entry.spiForced + entry.enableForced +
                                           entry.ntSetInfoBlocked + entry.hookBlocked +
                                           entry.diSetCoopForced;
                        if (!firstFlagged) st << L",";
                        firstFlagged = false;
                        st << L"{\"pid\":" << kv.first
                           << L",\"total\":" << total
                           << L",\"forced\":" << forced;
                        if (!entry.lastKnownName.empty()) {
                            st << L",\"name\":\"" << EscapeJson(entry.lastKnownName) << L"\"";
                        }
                        if (entry.sessionId != kInvalidSessionId) {
                            st << L",\"session\":" << entry.sessionId;
                        }
                        if (!entry.userSid.empty()) {
                            st << L",\"sid\":\"" << EscapeJson(entry.userSid) << L"\"";
                        }
                        if (!entry.userName.empty()) {
                            st << L",\"user\":\"" << EscapeJson(entry.userName) << L"\"";
                        }
                        st << L",\"breakdown\":{"
                           << L"\"block\":" << entry.blockRequests
                           << L",\"block_forced\":" << entry.blockForced
                           << L",\"nt\":" << entry.ntRequests
                           << L",\"nt_forced\":" << entry.ntForced
                           << L",\"attach\":" << entry.attachRequests
                           << L",\"attach_forced\":" << entry.attachPrevented
                           << L",\"nt_attach\":" << entry.ntAttachRequests
                           << L",\"nt_attach_forced\":" << entry.ntAttachPrevented
                           << L",\"spi\":" << entry.spiRequests
                           << L",\"spi_forced\":" << entry.spiForced
                           << L",\"enable\":" << entry.enableRequests
                           << L",\"enable_forced\":" << entry.enableForced
                           << L",\"nt_setinfo\":" << entry.ntSetInfoRequests
                           << L",\"nt_setinfo_blocked\":" << entry.ntSetInfoBlocked
                           << L",\"hooks\":" << entry.hookAttempts
                           << L",\"hooks_blocked\":" << entry.hookBlocked
                           << L",\"dinput_acquire\":" << entry.diAcquire
                           << L",\"dinput_coop\":" << entry.diSetCoop
                           << L",\"dinput_forced\":" << entry.diSetCoopForced
                           << L"}";
                        st << L"}";
                    }
                }
                st << L"]}";
                ULONGLONG nowDisplay = GetTickCount64();
                st << L",\"display\":{\"flagged\":[";
                {
                    bool firstDisplay = true;
                    for (const auto& kv : g_displayTelemetry) {
                    const auto& entry = kv.second;
                    if (nowDisplay - entry.lastTick > 120000) {
                        continue;
                    }
                    ULONGLONG total = entry.userModeRequests + entry.nativeRequests + entry.swapRequests;
                    if (total == 0 && entry.glFinishCalls == 0) {
                        continue;
                    }
                    ULONGLONG forced = entry.userModeForced + entry.nativeForced + entry.swapBlocked;
                    if (!firstDisplay) st << L",";
                    firstDisplay = false;
                    st << L"{\"pid\":" << kv.first
                       << L",\"total\":" << total
                       << L",\"forced\":" << forced;
                        if (!entry.lastKnownName.empty()) {
                            st << L",\"name\":\"" << EscapeJson(entry.lastKnownName) << L"\"";
                        }
                        if (entry.sessionId != kInvalidSessionId) {
                            st << L",\"session\":" << entry.sessionId;
                        }
                        if (!entry.userSid.empty()) {
                            st << L",\"sid\":\"" << EscapeJson(entry.userSid) << L"\"";
                        }
                        if (!entry.userName.empty()) {
                           st << L",\"user\":\"" << EscapeJson(entry.userName) << L"\"";
                       }
                       st << L",\"breakdown\":{"
                          << L"\"user\":" << entry.userModeRequests
                          << L",\"user_forced\":" << entry.userModeForced
                          << L",\"native\":" << entry.nativeRequests
                          << L",\"native_forced\":" << entry.nativeForced
                          << L",\"swap\":" << entry.swapRequests
                          << L",\"swap_blocked\":" << entry.swapBlocked
                          << L",\"gl_finish\":" << entry.glFinishCalls
                          << L"}";
                       st << L"}";
                    }
                }
                st << L"]}";
                st << L",\"graphics\":{\"flagged\":[";
                bool firstGraphics = true;
                auto formatHex = [](unsigned long long value) {
                    std::wstringstream ss;
                    ss << L"0x" << std::hex << std::uppercase << value;
                    return ss.str();
                };
                for (const auto& entry : graphicsFlaggedOutput) {
                    if (!firstGraphics) st << L",";
                    firstGraphics = false;
                    DWORD pid = entry.pid;
                    st << L"{\"pid\":" << pid
                       << L",\"name\":\"" << EscapeJson(entry.name) << L"\"";
                    if (entry.sessionId != kInvalidSessionId) {
                        st << L",\"session\":" << entry.sessionId;
                    }
                    if (!entry.userSid.empty()) {
                        st << L",\"sid\":\"" << EscapeJson(entry.userSid) << L"\"";
                    }
                    if (!entry.userName.empty()) {
                        st << L",\"user\":\"" << EscapeJson(entry.userName) << L"\"";
                    }

                    std::wstring fingerprintValue;
                    auto fpIt = fingerprintSnapshot.find(pid);
                    if (fpIt != fingerprintSnapshot.end()) {
                        fingerprintValue = fpIt->second;
                    } else {
                        auto cacheIt = cacheState.fingerprints.find(pid);
                        if (cacheIt != cacheState.fingerprints.end()) {
                            fingerprintValue = cacheIt->second;
                        }
                    }
                    if (!fingerprintValue.empty()) {
                        st << L",\"fingerprint\":\"" << EscapeJson(fingerprintValue) << L"\"";
                        if (g_forceFingerprints.count(fingerprintValue)) {
                            st << L",\"fingerprint_force\":1";
                        }
                        if (g_skipFingerprints.count(fingerprintValue)) {
                            st << L",\"fingerprint_skip\":1";
                        }
                    }

                    std::set<std::wstring> moduleNames;
                    auto hostIt = graphicsModulesSnapshot.find(pid);
                    if (hostIt != graphicsModulesSnapshot.end()) {
                        moduleNames.insert(hostIt->second.begin(), hostIt->second.end());
                    }
                    auto cacheModulesIt = cacheState.modules.find(pid);
                    if (cacheModulesIt != cacheState.modules.end()) {
                        moduleNames.insert(cacheModulesIt->second.begin(), cacheModulesIt->second.end());
                    }
                    auto teleIt = g_graphicsTelemetry.find(pid);
                    if (teleIt != g_graphicsTelemetry.end()) {
                        for (const auto& kv : teleIt->second.modules) {
                            std::wstring modName(kv.first.begin(), kv.first.end());
                            moduleNames.insert(modName);
                        }
                    }

                    if (!moduleNames.empty()) {
                        st << L",\"modules\":[";
                        bool firstModule = true;
                        for (const auto& modName : moduleNames) {
                            if (!firstModule) st << L",";
                            firstModule = false;
                            st << L"{\"name\":\"" << EscapeJson(modName) << L"\"";
                            if (teleIt != g_graphicsTelemetry.end()) {
                                std::string lookup(modName.begin(), modName.end());
                                std::transform(lookup.begin(), lookup.end(), lookup.begin(),
                                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                                auto baseIt = teleIt->second.modules.find(lookup);
                                if (baseIt != teleIt->second.modules.end() && baseIt->second) {
                                    st << L",\"base\":\"" << EscapeJson(formatHex(baseIt->second)) << L"\"";
                                }
                            }
                            st << L"}";
                        }
                        st << L"]";
                    }

                    if (teleIt != g_graphicsTelemetry.end()) {
                        const auto& tele = teleIt->second;
                        if (!tele.duplications.empty()) {
                            st << L",\"duplications\":[";
                            bool firstDup = true;
                            for (const auto& dupPair : tele.duplications) {
                                const auto& dup = dupPair.second;
                                if (!firstDup) st << L",";
                                firstDup = false;
                                st << L"{\"handle\":\"" << EscapeJson(formatHex(dupPair.first)) << L"\""
                                   << L",\"create\":" << dup.createCount
                                   << L",\"acquire\":" << dup.acquireCount
                                   << L",\"hr\":\"" << EscapeJson(formatHex(dup.lastHr)) << L"\"";
                                if (dup.outputHandle) {
                                    st << L",\"output\":\"" << EscapeJson(formatHex(dup.outputHandle)) << L"\"";
                                }
                                if (dup.deviceHandle) {
                                    st << L",\"device\":\"" << EscapeJson(formatHex(dup.deviceHandle)) << L"\"";
                                }
                                if (dup.resourceHandle) {
                                    st << L",\"resource\":\"" << EscapeJson(formatHex(dup.resourceHandle)) << L"\"";
                                }
                                if (dup.lastPresentTime) {
                                    st << L",\"last_present\":" << dup.lastPresentTime;
                                }
                                if (dup.lastFrames) {
                                    st << L",\"frames\":" << dup.lastFrames;
                                }
                                st << L",\"pointer_visible\":" << dup.pointerVisible;
                                if (dup.pointerVisible > 0) {
                                    st << L",\"pointer_x\":" << dup.pointerX
                                       << L",\"pointer_y\":" << dup.pointerY;
                                }
                                if (dup.pointerShapeBytes) {
                                    st << L",\"pointer_shape\":" << dup.pointerShapeBytes;
                                }
                                if (dup.lastTimeout) {
                                    st << L",\"timeout\":" << dup.lastTimeout;
                                }
                                st << L"}";
                            }
                            st << L"]";
                        }

                        if (!tele.swapChains.empty()) {
                            st << L",\"swapchains\":[";
                            bool firstSwapEntry = true;
                            for (const auto& swapPair : tele.swapChains) {
                                const auto& swap = swapPair.second;
                                if (!firstSwapEntry) st << L",";
                                firstSwapEntry = false;
                                st << L"{\"handle\":\"" << EscapeJson(formatHex(swapPair.first)) << L"\""
                                   << L",\"present\":" << swap.presentCount
                                   << L",\"blocked\":" << swap.blockedCount
                                   << L",\"hr\":\"" << EscapeJson(formatHex(swap.lastHr)) << L"\"";
                                st << L",\"flags\":\"" << EscapeJson(formatHex(swap.lastFlags)) << L"\"";
                                st << L",\"interval\":" << swap.lastInterval;
                                st << L",\"present1\":" << (swap.lastWasPresent1 ? 1 : 0);
                                st << L",\"d3d12\":" << (swap.lastWasD3D12 ? 1 : 0);
                                st << L"}";
                            }
                            st << L"]";
                        }

                        if (!tele.captures.empty()) {
                            st << L",\"captures\":[";
                            bool firstCapture = true;
                            for (const auto& capPair : tele.captures) {
                                const auto& cap = capPair.second;
                                if (!firstCapture) st << L",";
                                firstCapture = false;
                                st << L"{\"handle\":\"" << EscapeJson(formatHex(capPair.first)) << L"\""
                                   << L",\"count\":" << cap.createCount
                                   << L",\"hr\":\"" << EscapeJson(formatHex(cap.lastHr)) << L"\""
                                   << L",\"monitor\":" << (cap.isMonitor ? 1 : 0);
                                if (cap.itemHandle) {
                                    st << L",\"item\":\"" << EscapeJson(formatHex(cap.itemHandle)) << L"\"";
                                }
                                if (cap.targetHandle) {
                                    st << L",\"target\":\"" << EscapeJson(formatHex(cap.targetHandle)) << L"\"";
                                }
                                if (!cap.iid.empty()) {
                                    st << L",\"iid\":\"" << EscapeJson(cap.iid) << L"\"";
                                }
                                st << L"}";
                            }
                            st << L"]";
                        }
                    }

                    st << L"}";
                }
                st << L"]}";
                st << L",\"policy\":{\"enforced\":[";
                {
                    bool firstPolicy = true;
                    for (const auto& kv : g_policyState) {
                        const auto& ps = kv.second;
                        if (ps.forceInput == 0 && ps.forceWda == 0) {
                            continue;
                        }
                        if (!firstPolicy) st << L",";
                        firstPolicy = false;
                        st << L"{\"pid\":" << kv.first
                           << L",\"force_input\":" << ps.forceInput
                           << L",\"force_wda\":" << ps.forceWda;
                        auto ident = g_processIdentity.find(kv.first);
                        if (ident != g_processIdentity.end()) {
                            if (ident->second.sessionId != kInvalidSessionId) {
                                st << L",\"session\":" << ident->second.sessionId;
                            }
                            if (!ident->second.userSid.empty()) {
                                st << L",\"sid\":\"" << EscapeJson(ident->second.userSid) << L"\"";
                            }
                            if (!ident->second.userName.empty()) {
                                st << L",\"user\":\"" << EscapeJson(ident->second.userName) << L"\"";
                            }
                        }
                        auto dupIt = g_policyBlockedDuplications.find(kv.first);
                        auto winIt = g_policyBlockedCaptureWindows.find(kv.first);
                        auto monIt = g_policyBlockedCaptureMonitors.find(kv.first);
                        auto swapIt = g_policyBlockedSwapChains.find(kv.first);

                        std::vector<unsigned long long> activeDupHandles = CollectDuplicationHandlesForPid(kv.first);
                        std::set<unsigned long long> activeDupSet(activeDupHandles.begin(), activeDupHandles.end());
                        std::vector<unsigned long long> activeWindowHandles = CollectCaptureWindowTargetsForPid(kv.first);
                        std::set<unsigned long long> activeWindowSet(activeWindowHandles.begin(), activeWindowHandles.end());
                        std::vector<unsigned long long> activeMonitorHandles = CollectCaptureMonitorTargetsForPid(kv.first);
                        std::set<unsigned long long> activeMonitorSet(activeMonitorHandles.begin(), activeMonitorHandles.end());
                        std::vector<unsigned long long> activeSwapHandles = CollectSwapChainHandlesForPid(kv.first);
                        std::set<unsigned long long> activeSwapSet(activeSwapHandles.begin(), activeSwapHandles.end());

                        std::vector<unsigned long long> staleDupHandles;
                        if (dupIt != g_policyBlockedDuplications.end()) {
                            for (auto handle : dupIt->second) {
                                if (handle && activeDupSet.find(handle) == activeDupSet.end()) {
                                    staleDupHandles.push_back(handle);
                                }
                            }
                        }
                        std::vector<unsigned long long> staleWindowHandles;
                        if (winIt != g_policyBlockedCaptureWindows.end()) {
                            for (auto handle : winIt->second) {
                                if (handle && activeWindowSet.find(handle) == activeWindowSet.end()) {
                                    staleWindowHandles.push_back(handle);
                                }
                            }
                        }
                        std::vector<unsigned long long> staleMonitorHandles;
                        if (monIt != g_policyBlockedCaptureMonitors.end()) {
                            for (auto handle : monIt->second) {
                                if (handle && activeMonitorSet.find(handle) == activeMonitorSet.end()) {
                                    staleMonitorHandles.push_back(handle);
                                }
                            }
                        }
                        std::vector<unsigned long long> staleSwapHandles;
                        if (swapIt != g_policyBlockedSwapChains.end()) {
                            for (auto handle : swapIt->second) {
                                if (handle && activeSwapSet.find(handle) == activeSwapSet.end()) {
                                    staleSwapHandles.push_back(handle);
                                }
                            }
                        }

                        if (dupIt != g_policyBlockedDuplications.end() && !dupIt->second.empty()) {
                            st << L",\"duplications\":[";
                            bool firstDup = true;
                            for (auto handle : dupIt->second) {
                                if (!firstDup) st << L",";
                                firstDup = false;
                                st << L"\"" << EscapeJson(formatHex(handle)) << L"\"";
                            }
                            st << L"]";
                        }
                        if (swapIt != g_policyBlockedSwapChains.end() && !swapIt->second.empty()) {
                            st << L",\"swapchains\":[";
                            bool firstSwap = true;
                            for (auto handle : swapIt->second) {
                                if (!firstSwap) st << L",";
                                firstSwap = false;
                                st << L"\"" << EscapeJson(formatHex(handle)) << L"\"";
                            }
                            st << L"]";
                        }
                        bool hasWindows = (winIt != g_policyBlockedCaptureWindows.end() && !winIt->second.empty());
                        bool hasMonitors = (monIt != g_policyBlockedCaptureMonitors.end() && !monIt->second.empty());
                        if (hasWindows || hasMonitors) {
                            st << L",\"captures\":{";
                            bool firstType = true;
                            if (hasWindows) {
                                st << L"\"windows\":[";
                                bool firstHandle = true;
                                for (auto handle : winIt->second) {
                                    if (!firstHandle) st << L",";
                                    firstHandle = false;
                                    st << L"\"" << EscapeJson(formatHex(handle)) << L"\"";
                                }
                                st << L"]";
                                firstType = false;
                            }
                            if (hasMonitors) {
                                if (!firstType) {
                                    st << L",";
                                }
                                st << L"\"monitors\":[";
                                bool firstHandle = true;
                                for (auto handle : monIt->second) {
                                    if (!firstHandle) st << L",";
                                    firstHandle = false;
                                    st << L"\"" << EscapeJson(formatHex(handle)) << L"\"";
                                }
                                st << L"]";
                            }
                            st << L"}";
                        }

                        auto emitStaleArray = [&](const wchar_t* key, const std::vector<unsigned long long>& handles) {
                            if (handles.empty()) {
                                return;
                            }
                            st << L"\"" << key << L"\":[";
                            for (size_t i = 0; i < handles.size(); ++i) {
                                if (i) {
                                    st << L",";
                                }
                                st << L"\"" << EscapeJson(formatHex(handles[i])) << L"\"";
                            }
                            st << L"]";
                        };

                        bool hasStale = !staleDupHandles.empty() || !staleWindowHandles.empty() || !staleMonitorHandles.empty() || !staleSwapHandles.empty();
                        if (hasStale) {
                            st << L",\"stale\":{";
                            bool firstStaleField = true;
                            auto emitField = [&](const wchar_t* key, const std::vector<unsigned long long>& handles) {
                                if (handles.empty()) {
                                    return;
                                }
                                if (!firstStaleField) {
                                    st << L",";
                                }
                                firstStaleField = false;
                                emitStaleArray(key, handles);
                            };
                            emitField(L"duplications", staleDupHandles);
                            emitField(L"windows", staleWindowHandles);
                            emitField(L"monitors", staleMonitorHandles);
                            emitField(L"swapchains", staleSwapHandles);
                            st << L"}";
                        }
                        st << L"}";
                    }
                }
                st << L"]}";
                st << L"}";  // end root
                st.flush();
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(intervalSec));
    }

    ShutdownProcessWatcher();
    return 0;
}
