// SystemWideMonitor.cpp - Automatic system-wide API hook monitor
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <mutex>
#include <algorithm>
#include <map>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <functional>
#include <iomanip>
#include <sddl.h>
#include <codecvt>

#include "../include/ProcessTargets.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

class SystemWideMonitor {
private:
    static std::string Narrow(const std::wstring& value) {
        if (value.empty()) {
            return std::string();
        }
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) {
            return std::string();
        }
        std::string result(static_cast<size_t>(sizeNeeded - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), sizeNeeded, nullptr, nullptr);
        return result;
    }

    static std::string FormatDuration(ULONGLONG ms) {
        if (ms == 0) {
            return "0ms";
        }
        std::ostringstream oss;
        if (ms >= 1000) {
            double seconds = static_cast<double>(ms) / 1000.0;
            oss << std::fixed << std::setprecision(seconds >= 100.0 ? 0 : 1) << seconds << "s";
        } else {
            oss << ms << "ms";
        }
        return oss.str();
    }

    static std::wstring FormatHexW(unsigned long long value) {
        std::wstringstream ss;
        ss << L"0x" << std::hex << std::uppercase << value;
        return ss.str();
    }

    static std::wstring GetProgramDataDir() {
        wchar_t buf[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
        std::wstring base = (n && n < MAX_PATH) ? std::wstring(buf, buf + n) : L"C:\\ProgramData";
        std::wstring dir = base + L"\\UserModeHook";
        CreateDirectoryW(dir.c_str(), nullptr);
        return dir;
    }

    static std::string GetApiHookLogPath() {
        std::wstring wpath = GetProgramDataDir() + L"\\api_hooks.log";
        return Narrow(wpath);
    }

    static bool ProcessHasModule(DWORD pid, const wchar_t* moduleName) {
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

    static bool UsesGraphicsModules(DWORD pid) {
        static const wchar_t* kModules[] = {
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
        for (const auto* mod : kModules) {
            if (ProcessHasModule(pid, mod)) {
                return true;
            }
        }
        return false;
    }

    static ProcessIdentityData QueryProcessIdentity(DWORD pid) {
        ProcessIdentityData info{};
        DWORD session = 0;
        if (ProcessIdToSessionId(pid, &session)) {
            info.sessionId = session;
        } else {
            info.sessionId = kInvalidSessionId;
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

    void ApplyIdentityToStats(DWORD pid, const ProcessIdentityData& identity) {
        auto kt = keyboardTelemetry.find(pid);
        if (kt != keyboardTelemetry.end()) {
            kt->second.sessionId = identity.sessionId;
            if (!identity.userSid.empty()) kt->second.userSid = identity.userSid;
            if (!identity.userName.empty()) kt->second.userName = identity.userName;
        }
        auto gt = graphicsTelemetry.find(pid);
        if (gt != graphicsTelemetry.end()) {
            gt->second.sessionId = identity.sessionId;
            if (!identity.userSid.empty()) gt->second.userSid = identity.userSid;
            if (!identity.userName.empty()) gt->second.userName = identity.userName;
        }
    }

    static constexpr DWORD kInvalidSessionId = 0xFFFFFFFFu;
    std::set<DWORD> hookedProcesses;
    std::set<DWORD> blacklistedProcesses;
    std::mutex mtx;
    bool isRunning;
    std::string dllPath;
    struct KeyboardStats {
        ULONGLONG total = 0;
        ULONGLONG forced = 0;
        ULONGLONG lastTick = 0;
        DWORD sessionId = kInvalidSessionId;
        std::wstring userSid;
        std::wstring userName;
    };
    struct DuplicationStats {
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
        ULONGLONG timeout = 0;
        ULONGLONG lastTick = 0;
    };

    struct CaptureStats {
        ULONGLONG createCount = 0;
        ULONGLONG lastHr = 0;
        ULONGLONG targetHandle = 0;
        bool isMonitor = false;
        std::wstring iid;
        ULONGLONG itemHandle = 0;
        ULONGLONG lastTick = 0;
    };

    struct SwapChainStats {
        ULONGLONG presentCount = 0;
        ULONGLONG blockedCount = 0;
        ULONGLONG lastHr = 0;
        ULONGLONG lastFlags = 0;
        ULONGLONG lastInterval = 0;
        bool lastWasPresent1 = false;
        bool lastWasD3D12 = false;
        ULONGLONG lastTick = 0;
        DWORD lastDirtyCount = 0;
        DWORD lastDirtyWidth = 0;
        DWORD lastDirtyHeight = 0;
        ULONGLONG lastDirtyBoundingArea = 0;
        ULONGLONG lastDirtyTotalArea = 0;
        ULONGLONG dirtySampleCount = 0;
        ULONGLONG dirtyAccumBounding = 0;
        ULONGLONG dirtyAccumTotal = 0;
        bool dirtyTruncated = false;
        bool hasScrollRect = false;
        RECT lastScrollRect = {0, 0, 0, 0};
        bool hasScrollOffset = false;
        LONG lastScrollDx = 0;
        LONG lastScrollDy = 0;
    };

    struct GraphicsStats {
        std::map<std::string, unsigned long long> modules;
        std::map<unsigned long long, DuplicationStats> duplications;
        std::map<unsigned long long, CaptureStats> captures;
        std::map<unsigned long long, SwapChainStats> swapChains;
        ULONGLONG lastTick = 0;
        DWORD sessionId = kInvalidSessionId;
        std::wstring userSid;
        std::wstring userName;
    };

    struct PolicyEnforcement {
        int forceInput = 0;
        int forceWda = 0;
        DWORD sessionId = kInvalidSessionId;
        std::wstring userSid;
        std::wstring userName;
        std::vector<std::wstring> dupHandles;
        std::vector<std::wstring> windowHandles;
        std::vector<std::wstring> monitorHandles;
        std::vector<std::wstring> swapHandles;
    };

    struct ProcessIdentityData {
        DWORD sessionId = kInvalidSessionId;
        std::wstring userSid;
        std::wstring userName;
        ULONGLONG lastSeen = 0;
    };
    std::map<DWORD, KeyboardStats> keyboardTelemetry;
    std::map<DWORD, GraphicsStats> graphicsTelemetry;
    std::map<DWORD, ProcessIdentityData> processIdentity;
    std::map<DWORD, std::string> processNames;
    std::set<DWORD> keyboardEscalated;
    std::set<DWORD> keyboardSuppressionIgnored;
    std::set<DWORD> graphicsEscalated;
    std::set<DWORD> graphicsSuppressionIgnored;
    std::map<DWORD, PolicyEnforcement> policyTelemetry;
    ULONGLONG keyboardLogOffset = 0;
    ULONGLONG keyboardLastRefresh = 0;
    ULONGLONG policyLastRefresh = 0;
    ULONGLONG policyLastFileStamp = 0;
    std::ofstream logFile;
    bool aggressiveMode;

    // Critical system processes to skip
    std::set<std::string> systemProcesses = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
        "systemwidemonitor.exe", "advancedinjector.exe", "conhost.exe",
        "audiodg.exe", "searchindexer.exe", "spoolsv.exe"
    };

    // Processes known to use SetWindowDisplayAffinity
    std::set<std::string> targetProcesses = {
        "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
        "obs64.exe", "obs32.exe", "streamlabs.exe", "chrome.exe",
        "firefox.exe", "msedge.exe", "opera.exe", "vlc.exe",
        "spotify.exe", "netflix.exe", "skype.exe", "telegram.exe",
        "signal.exe", "whatsapp.exe", "steam.exe", "epicgameslauncher.exe",
        "gameoverlayui.exe", "nvidia share.exe", "medal.exe", "brave.exe"
    };

    void ApplyTargetOverride() {
        if (!umh::HasProcessTargetFilter()) {
            return;
        }
        targetProcesses.clear();
        const auto& targets = umh::GetProcessTargets();
        for (const auto& entry : targets) {
            std::string narrow = Narrow(entry);
            if (!narrow.empty()) {
                targetProcesses.insert(narrow);
            }
        }
        std::stringstream ss;
        ss << "Process allowlist active (" << targetProcesses.size() << " entries)";
        LogMessage(ss.str());
    }

public:
    static std::string ApiLogPath() {
        return GetApiHookLogPath();
    }

    static constexpr ULONGLONG kKeyboardExpiryMs = 120000; // 2 minutes
    static constexpr size_t kKeyboardMaxEntries = 256;
    static constexpr size_t kGraphicsMaxEntries = 256;

    SystemWideMonitor(const std::string& hookDllPath)
        : dllPath(hookDllPath), isRunning(false), aggressiveMode(false) {

        // Create log directory
        CreateDirectoryA("C:\\Temp", nullptr);
        logFile.open("C:\\Temp\\system_monitor.log", std::ios::app);

        LogMessage("System-Wide Monitor initialized");
        LogMessage("Hook DLL: " + dllPath);
        ApplyTargetOverride();
    }

    ~SystemWideMonitor() {
        Stop();
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    void SetAggressiveMode(bool aggressive) {
        aggressiveMode = aggressive;
        LogMessage(aggressive ? "Aggressive mode ENABLED - hooking ALL processes"
                              : "Targeted mode - hooking known applications only");
    }

    void LogMessage(const std::string& message) {
        std::lock_guard<std::mutex> lock(mtx);

        SYSTEMTIME st;
        GetLocalTime(&st);

        std::stringstream ss;
        ss << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] " << message;

        std::cout << ss.str() << std::endl;

        if (logFile.is_open()) {
            logFile << ss.str() << std::endl;
            logFile.flush();
        }
    }

    bool IsProcessElevated(HANDLE hProcess) {
        HANDLE hToken = nullptr;
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            return false;
        }

        BOOL result = GetTokenInformation(hToken, TokenElevation,
                                         &elevation, sizeof(elevation), &dwSize);
        CloseHandle(hToken);

        return result && elevation.TokenIsElevated;
    }
    static int ExtractIntField(const std::string& line, const char* key) {
        size_t pos = line.find(key);
        if (pos == std::string::npos) {
            return -1;
        }
        pos += std::strlen(key);
        const char* start = line.c_str() + pos;
        char* end = nullptr;
        long value = std::strtol(start, &end, 10);
        if (start == end) {
            return -1;
        }
        return static_cast<int>(value);
    }

    static std::string ExtractStringField(const std::string& line, const char* key) {
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

    static unsigned long long ExtractHexField(const std::string& line, const char* key) {
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

    static unsigned long long ExtractUnsignedField(const std::string& line, const char* key) {
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

    static bool ParseRectString(const std::string& value, RECT& rect) {
        if (value.empty()) {
            return false;
        }
        long components[4] = {};
        const char* ptr = value.c_str();
        for (int i = 0; i < 4; ++i) {
            char* end = nullptr;
            long comp = std::strtol(ptr, &end, 10);
            if (ptr == end) {
                return false;
            }
            components[i] = comp;
            if (i < 3) {
                if (*end != ',') {
                    return false;
                }
                ptr = end + 1;
            } else {
                ptr = end;
            }
        }
        while (*ptr) {
            if (!std::isspace(static_cast<unsigned char>(*ptr))) {
                return false;
            }
            ++ptr;
        }
        rect.left = static_cast<LONG>(components[0]);
        rect.top = static_cast<LONG>(components[1]);
        rect.right = static_cast<LONG>(components[2]);
        rect.bottom = static_cast<LONG>(components[3]);
        return true;
    }

    static unsigned long long ComposeCaptureKey(unsigned long long itemHandle,
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

    void RefreshKeyboardTelemetry() {
        ULONGLONG now = GetTickCount64();
        if (now - keyboardLastRefresh < 1500) {
            return;
        }
        keyboardLastRefresh = now;

        const std::string logPath = GetApiHookLogPath();
        std::ifstream in(logPath, std::ios::binary);
        if (!in.is_open()) {
            std::lock_guard<std::mutex> lock(mtx);
            keyboardTelemetry.clear();
            keyboardLogOffset = 0;
            return;
        }

        in.seekg(0, std::ios::end);
        std::streampos fileSize = in.tellg();
        if (fileSize == std::streampos(-1)) {
            in.close();
            return;
        }
        if (static_cast<ULONGLONG>(fileSize) < keyboardLogOffset) {
            keyboardLogOffset = 0;
        }
        in.seekg(static_cast<std::streamoff>(keyboardLogOffset), std::ios::beg);

        std::map<DWORD, KeyboardStats> delta;
        std::map<DWORD, GraphicsStats> graphicsDelta;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.find("func=") == std::string::npos) {
                continue;
            }
            int pidField = ExtractIntField(line, "pid=");
            if (pidField <= 0) {
                continue;
            }
            DWORD pid = static_cast<DWORD>(pidField);
            bool relevant = false;
            bool forced = false;

            if (line.find("func=GraphicsModule") != std::string::npos) {
                std::string moduleName = ExtractStringField(line, "module=");
                if (!moduleName.empty()) {
                    std::transform(moduleName.begin(),
                                   moduleName.end(),
                                   moduleName.begin(),
                                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    unsigned long long base = ExtractHexField(line, "base=0x");
                    auto& stats = graphicsDelta[pid];
                    stats.modules[moduleName] = base;
                    stats.lastTick = now;
                }
                continue;
            }

            if (line.find("func=DuplicateOutput") != std::string::npos) {
                auto& stats = graphicsDelta[pid];
                stats.lastTick = now;
                unsigned long long dupHandle = ExtractHexField(line, "dup=0x");
                auto& dup = stats.duplications[dupHandle];
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
                auto& stats = graphicsDelta[pid];
                stats.lastTick = now;
                unsigned long long dupHandle = ExtractHexField(line, "dup=0x");
                auto& dup = stats.duplications[dupHandle];
                dup.acquireCount++;
                dup.lastHr = ExtractHexField(line, "hr=0x");
                dup.lastPresentTime = ExtractUnsignedField(line, "last_present=");
                dup.pointerVisible = ExtractUnsignedField(line, "pointer_visible=");
                if (dup.pointerVisible > 0) {
                    dup.pointerX = ExtractIntField(line, "pointer_x=");
                    dup.pointerY = ExtractIntField(line, "pointer_y=");
                }
                dup.pointerShapeBytes = ExtractUnsignedField(line, "pointer_shape=");
                dup.timeout = ExtractUnsignedField(line, "timeout=");
                unsigned long long resourceHandle = ExtractHexField(line, "resource=0x");
                if (resourceHandle) dup.resourceHandle = resourceHandle;
                dup.lastTick = now;
                continue;
            }

            if (line.find("func=DXGI::Present") != std::string::npos) {
                auto& stats = graphicsDelta[pid];
                stats.lastTick = now;
                unsigned long long swapHandle = ExtractHexField(line, "swap=0x");
                auto& swap = stats.swapChains[swapHandle];
                swap.presentCount++;
                if (ExtractIntField(line, "blocked=") == 1) {
                    swap.blockedCount++;
                }
                swap.lastHr = ExtractHexField(line, "hr=0x");
                if (line.find("flags=") != std::string::npos) {
                    swap.lastFlags = ExtractHexField(line, "flags=0x");
                }
                if (line.find("interval=") != std::string::npos) {
                    swap.lastInterval = ExtractUnsignedField(line, "interval=");
                }
                swap.lastWasPresent1 = (line.find("func=DXGI::Present1") != std::string::npos);
                swap.lastWasD3D12 = (ExtractUnsignedField(line, "d3d12=") == 1);
                swap.lastTick = now;
                if (swap.lastWasPresent1) {
                    swap.lastDirtyCount = static_cast<DWORD>(ExtractUnsignedField(line, "dirty="));
                    swap.lastDirtyWidth = static_cast<DWORD>(ExtractUnsignedField(line, "dirty_bbox_w="));
                    swap.lastDirtyHeight = static_cast<DWORD>(ExtractUnsignedField(line, "dirty_bbox_h="));
                    swap.lastDirtyBoundingArea = ExtractUnsignedField(line, "dirty_bbox_area=");
                    swap.lastDirtyTotalArea = ExtractUnsignedField(line, "dirty_total_area=");
                    bool truncFlag = (line.find("dirty_trunc=") != std::string::npos) &&
                                     (ExtractIntField(line, "dirty_trunc=") == 1);
                    swap.dirtyTruncated = truncFlag;
                    swap.dirtySampleCount += 1;
                    swap.dirtyAccumBounding += swap.lastDirtyBoundingArea;
                    swap.dirtyAccumTotal += swap.lastDirtyTotalArea;
                    std::string rectText = ExtractStringField(line, "scroll_rect=");
                    if (!rectText.empty()) {
                        RECT parsed{};
                        if (ParseRectString(rectText, parsed)) {
                            swap.hasScrollRect = true;
                            swap.lastScrollRect = parsed;
                        } else {
                            swap.hasScrollRect = false;
                            swap.lastScrollRect.left = swap.lastScrollRect.top =
                                swap.lastScrollRect.right = swap.lastScrollRect.bottom = 0;
                        }
                    } else {
                        swap.hasScrollRect = false;
                        swap.lastScrollRect.left = swap.lastScrollRect.top =
                            swap.lastScrollRect.right = swap.lastScrollRect.bottom = 0;
                    }
                    if (line.find("scroll_dx=") != std::string::npos ||
                        line.find("scroll_dy=") != std::string::npos) {
                        swap.hasScrollOffset = true;
                        if (line.find("scroll_dx=") != std::string::npos) {
                            swap.lastScrollDx = ExtractIntField(line, "scroll_dx=");
                        } else {
                            swap.lastScrollDx = 0;
                        }
                        if (line.find("scroll_dy=") != std::string::npos) {
                            swap.lastScrollDy = ExtractIntField(line, "scroll_dy=");
                        } else {
                            swap.lastScrollDy = 0;
                        }
                    } else {
                        swap.hasScrollOffset = false;
                        swap.lastScrollDx = 0;
                        swap.lastScrollDy = 0;
                    }
                }
                continue;
            }

            if (line.find("func=GraphicsCaptureForWindow") != std::string::npos) {
                auto& stats = graphicsDelta[pid];
                stats.lastTick = now;
                unsigned long long itemHandle = ExtractHexField(line, "item=0x");
                unsigned long long hwndHandle = ExtractHexField(line, "hwnd=0x");
                unsigned long long key = ComposeCaptureKey(itemHandle, hwndHandle, false);
                auto& cap = stats.captures[key];
                cap.createCount++;
                cap.lastHr = ExtractHexField(line, "hr=0x");
                cap.targetHandle = hwndHandle;
                cap.isMonitor = false;
                if (itemHandle) cap.itemHandle = itemHandle;
                std::string iid = ExtractStringField(line, "iid=");
                if (!iid.empty()) {
                    cap.iid.assign(iid.begin(), iid.end());
                }
                cap.lastTick = now;
                continue;
            }

            if (line.find("func=GraphicsCaptureForMonitor") != std::string::npos) {
                auto& stats = graphicsDelta[pid];
                stats.lastTick = now;
                unsigned long long itemHandle = ExtractHexField(line, "item=0x");
                unsigned long long monitorHandle = ExtractHexField(line, "monitor=0x");
                unsigned long long key = ComposeCaptureKey(itemHandle, monitorHandle, true);
                auto& cap = stats.captures[key];
                cap.createCount++;
                cap.lastHr = ExtractHexField(line, "hr=0x");
                cap.targetHandle = monitorHandle;
                cap.isMonitor = true;
                if (itemHandle) cap.itemHandle = itemHandle;
                std::string iid = ExtractStringField(line, "iid=");
                if (!iid.empty()) {
                    cap.iid.assign(iid.begin(), iid.end());
                }
                cap.lastTick = now;
                continue;
            }

            if (line.find("func=BlockInput") != std::string::npos) {
                relevant = true;
                int requested = ExtractIntField(line, "requested=");
                int applied = ExtractIntField(line, "applied=");
                if (requested == 1 && applied == 0) {
                    forced = true;
                }
            } else if (line.find("func=NtUserBlockInput") != std::string::npos) {
                relevant = true;
                int requested = ExtractIntField(line, "requested=");
                int applied = ExtractIntField(line, "applied=");
                if (requested == 1 && applied == 0) {
                    forced = true;
                }
        } else if (line.find("func=AttachThreadInput") != std::string::npos) {
            relevant = true;
            int attach = ExtractIntField(line, "attach=");
            int applied = ExtractIntField(line, "applied=");
            if (attach == 1 && applied == 0) {
                forced = true;
            }
        } else if (line.find("func=NtUserAttachThreadInput") != std::string::npos) {
            relevant = true;
            int attach = ExtractIntField(line, "attach=");
            int applied = ExtractIntField(line, "applied=");
            int forcedField = ExtractIntField(line, "forced=");
            if ((attach == 1 && applied == 0) || forcedField == 1) {
                forced = true;
            }
        } else if (line.find("func=SystemParametersInfoW") != std::string::npos) {
            relevant = true;
            int forcedField = ExtractIntField(line, "forced=");
            if (forcedField == 1) {
                forced = true;
            }
        } else if (line.find("func=EnableWindow") != std::string::npos) {
            relevant = true;
            int forcedField = ExtractIntField(line, "forced=");
            if (forcedField == 1) {
                forced = true;
            }
        } else if (line.find("func=NtUserSetInformationThread") != std::string::npos) {
            relevant = true;
            int forcedField = ExtractIntField(line, "forced=");
            if (forcedField == 1) {
                forced = true;
            }
        } else if (line.find("func=SetWindowsHookEx") != std::string::npos &&
                   line.find("type=keyboard") != std::string::npos) {
            relevant = true;
            int allowed = ExtractIntField(line, "allowed=");
            int forcedField = ExtractIntField(line, "forced=");
                if (allowed == 0 || forcedField == 1) {
                    forced = true;
                }
            } else if (line.find("func=DirectInput::SetCooperativeLevel") != std::string::npos) {
                relevant = true;
                int forcedField = ExtractIntField(line, "forced=");
                if (forcedField == 1) {
                    forced = true;
                }
            } else if (line.find("func=DirectInput::Acquire") != std::string::npos) {
                relevant = true;
            }

            if (!relevant) {
                continue;
            }

            auto& stats = delta[pid];
            stats.total += 1;
            if (forced) {
                stats.forced += 1;
            }
            stats.lastTick = now;
        }

        std::streampos finalPos = in.tellg();
        if (finalPos == std::streampos(-1)) {
            keyboardLogOffset = static_cast<ULONGLONG>(fileSize);
        } else {
            keyboardLogOffset = static_cast<ULONGLONG>(finalPos);
        }
        in.close();

        if (!delta.empty() || !graphicsDelta.empty()) {
            std::lock_guard<std::mutex> lock(mtx);
            if (!delta.empty()) {
                for (const auto& kv : delta) {
                    auto& stats = keyboardTelemetry[kv.first];
                    stats.total += kv.second.total;
                    stats.forced += kv.second.forced;
                    stats.lastTick = kv.second.lastTick;
                }
            }
            if (!graphicsDelta.empty()) {
                for (const auto& kv : graphicsDelta) {
                    auto& stats = graphicsTelemetry[kv.first];
                    for (const auto& mod : kv.second.modules) {
                        stats.modules[mod.first] = mod.second;
                    }
                    for (const auto& dupPair : kv.second.duplications) {
                        auto& dup = stats.duplications[dupPair.first];
                        const auto& incoming = dupPair.second;
                        dup.createCount += incoming.createCount;
                        dup.acquireCount += incoming.acquireCount;
                        if (incoming.lastHr) {
                            dup.lastHr = incoming.lastHr;
                        }
                        if (incoming.lastPresentTime) {
                            dup.lastPresentTime = incoming.lastPresentTime;
                        }
                        if (incoming.pointerVisible) {
                            dup.pointerVisible = incoming.pointerVisible;
                            dup.pointerX = incoming.pointerX;
                            dup.pointerY = incoming.pointerY;
                        }
                        if (incoming.pointerShapeBytes) {
                            dup.pointerShapeBytes = incoming.pointerShapeBytes;
                        }
                        if (incoming.outputHandle) {
                            dup.outputHandle = incoming.outputHandle;
                        }
                        if (incoming.deviceHandle) {
                            dup.deviceHandle = incoming.deviceHandle;
                        }
                        if (incoming.resourceHandle) {
                            dup.resourceHandle = incoming.resourceHandle;
                        }
                        if (incoming.timeout) {
                            dup.timeout = incoming.timeout;
                        }
                        dup.lastTick = std::max(dup.lastTick, incoming.lastTick);
                    }
                    for (const auto& capPair : kv.second.captures) {
                        auto& cap = stats.captures[capPair.first];
                        const auto& incoming = capPair.second;
                        cap.createCount += incoming.createCount;
                        if (incoming.lastHr) {
                            cap.lastHr = incoming.lastHr;
                        }
                        cap.targetHandle = incoming.targetHandle;
                        cap.isMonitor = incoming.isMonitor;
                        if (!incoming.iid.empty()) {
                            cap.iid = incoming.iid;
                        }
                        if (incoming.itemHandle) {
                            cap.itemHandle = incoming.itemHandle;
                        }
                        cap.lastTick = std::max(cap.lastTick, incoming.lastTick);
                    }
                    for (const auto& swapPair : kv.second.swapChains) {
                        auto& swap = stats.swapChains[swapPair.first];
                        const auto& incoming = swapPair.second;
                        swap.presentCount += incoming.presentCount;
                        swap.blockedCount += incoming.blockedCount;
                        if (incoming.lastHr) {
                            swap.lastHr = incoming.lastHr;
                        }
                        swap.lastFlags = incoming.lastFlags;
                        swap.lastInterval = incoming.lastInterval;
                        swap.lastWasPresent1 = incoming.lastWasPresent1;
                        swap.lastWasD3D12 = incoming.lastWasD3D12;
                        swap.lastTick = std::max(swap.lastTick, incoming.lastTick);
                        swap.dirtySampleCount += incoming.dirtySampleCount;
                        swap.dirtyAccumBounding += incoming.dirtyAccumBounding;
                        swap.dirtyAccumTotal += incoming.dirtyAccumTotal;
                        if (incoming.lastWasPresent1) {
                            swap.lastDirtyCount = incoming.lastDirtyCount;
                            swap.lastDirtyWidth = incoming.lastDirtyWidth;
                            swap.lastDirtyHeight = incoming.lastDirtyHeight;
                            swap.lastDirtyBoundingArea = incoming.lastDirtyBoundingArea;
                            swap.lastDirtyTotalArea = incoming.lastDirtyTotalArea;
                            swap.dirtyTruncated = swap.dirtyTruncated || incoming.dirtyTruncated;
                            if (incoming.hasScrollRect) {
                                swap.hasScrollRect = true;
                                swap.lastScrollRect = incoming.lastScrollRect;
                            } else {
                                swap.hasScrollRect = false;
                                swap.lastScrollRect.left = swap.lastScrollRect.top =
                                    swap.lastScrollRect.right = swap.lastScrollRect.bottom = 0;
                            }
                            if (incoming.hasScrollOffset) {
                                swap.hasScrollOffset = true;
                                swap.lastScrollDx = incoming.lastScrollDx;
                                swap.lastScrollDy = incoming.lastScrollDy;
                            } else {
                                swap.hasScrollOffset = false;
                                swap.lastScrollDx = 0;
                                swap.lastScrollDy = 0;
                            }
                        }
                    }
                    if (kv.second.lastTick > stats.lastTick) {
                        stats.lastTick = kv.second.lastTick;
                    }
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            for (auto it = keyboardTelemetry.begin(); it != keyboardTelemetry.end();) {
                if (now - it->second.lastTick > kKeyboardExpiryMs) {
                    it = keyboardTelemetry.erase(it);
                } else {
                    ++it;
                }
            }
            while (keyboardTelemetry.size() > kKeyboardMaxEntries) {
                auto victim = std::min_element(
                    keyboardTelemetry.begin(), keyboardTelemetry.end(),
                    [](const std::pair<const DWORD, KeyboardStats>& a,
                       const std::pair<const DWORD, KeyboardStats>& b) {
                        return a.second.lastTick < b.second.lastTick;
                    });
                if (victim == keyboardTelemetry.end()) {
                    break;
                }
                keyboardTelemetry.erase(victim);
            }
            for (auto it = graphicsTelemetry.begin(); it != graphicsTelemetry.end();) {
                if (now - it->second.lastTick > kKeyboardExpiryMs) {
                    it = graphicsTelemetry.erase(it);
                } else {
                    ++it;
                }
            }
            while (graphicsTelemetry.size() > kGraphicsMaxEntries) {
                auto victim = std::min_element(
                    graphicsTelemetry.begin(), graphicsTelemetry.end(),
                    [](const std::pair<const DWORD, GraphicsStats>& a,
                       const std::pair<const DWORD, GraphicsStats>& b) {
                        return a.second.lastTick < b.second.lastTick;
                    });
                if (victim == graphicsTelemetry.end()) {
                    break;
                }
                graphicsTelemetry.erase(victim);
            }

            const ULONGLONG expireMs = kKeyboardExpiryMs;
            auto pruneDup = [&](std::map<unsigned long long, DuplicationStats>& container) {
                for (auto it = container.begin(); it != container.end(); ) {
                    if (now - it->second.lastTick > expireMs) {
                        it = container.erase(it);
                    } else {
                        ++it;
                    }
                }
                while (container.size() > 128) {
                    auto victim = std::min_element(
                        container.begin(),
                        container.end(),
                        [](const std::pair<const unsigned long long, DuplicationStats>& a,
                           const std::pair<const unsigned long long, DuplicationStats>& b) {
                            return a.second.lastTick < b.second.lastTick;
                        });
                    if (victim == container.end()) {
                        break;
                    }
                    container.erase(victim);
                }
            };

            auto pruneCap = [&](std::map<unsigned long long, CaptureStats>& container) {
                for (auto it = container.begin(); it != container.end(); ) {
                    if (now - it->second.lastTick > expireMs) {
                        it = container.erase(it);
                    } else {
                        ++it;
                    }
                }
                while (container.size() > 128) {
                    auto victim = std::min_element(
                        container.begin(),
                        container.end(),
                        [](const std::pair<const unsigned long long, CaptureStats>& a,
                           const std::pair<const unsigned long long, CaptureStats>& b) {
                            return a.second.lastTick < b.second.lastTick;
                        });
                    if (victim == container.end()) {
                        break;
                    }
                    container.erase(victim);
                }
            };

            auto pruneSwap = [&](std::map<unsigned long long, SwapChainStats>& container) {
                for (auto it = container.begin(); it != container.end(); ) {
                    if (now - it->second.lastTick > expireMs) {
                        it = container.erase(it);
                    } else {
                        ++it;
                    }
                }
                while (container.size() > 128) {
                    auto victim = std::min_element(
                        container.begin(),
                        container.end(),
                        [](const std::pair<const unsigned long long, SwapChainStats>& a,
                           const std::pair<const unsigned long long, SwapChainStats>& b) {
                            return a.second.lastTick < b.second.lastTick;
                        });
                    if (victim == container.end()) {
                        break;
                    }
                    container.erase(victim);
                }
            };

        for (auto& kv : graphicsTelemetry) {
            pruneDup(kv.second.duplications);
            pruneCap(kv.second.captures);
            pruneSwap(kv.second.swapChains);
        }
    }

    void RefreshPolicySnapshot() {
        ULONGLONG now = GetTickCount64();
        if (now - policyLastRefresh < 1500) {
            return;
        }
        policyLastRefresh = now;

        const std::wstring path = L"C:\\Temp\\agent_status.json";
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
            std::lock_guard<std::mutex> lock(mtx);
            policyTelemetry.clear();
            policyLastFileStamp = 0;
            return;
        }

        ULONGLONG fileStamp = (static_cast<ULONGLONG>(fad.ftLastWriteTime.dwHighDateTime) << 32) |
                              static_cast<ULONGLONG>(fad.ftLastWriteTime.dwLowDateTime);
        if (policyLastFileStamp == fileStamp) {
            return;
        }

        std::wifstream stream(path, std::ios::binary);
        if (!stream.is_open()) {
            return;
        }
        stream.imbue(std::locale(stream.getloc(), new std::codecvt_utf16<wchar_t, 0x10ffff, std::little_endian>));
        std::wstringstream buffer;
        buffer << stream.rdbuf();
        std::wstring json = buffer.str();
        stream.close();
        if (json.empty()) {
            return;
        }

        auto ExtractNumberField = [](const std::wstring& text, const std::wstring& key) -> long long {
            size_t pos = text.find(key);
            if (pos == std::wstring::npos) {
                return 0;
            }
            pos += key.size();
            while (pos < text.size() && iswspace(text[pos])) {
                ++pos;
            }
            bool negative = false;
            if (pos < text.size() && (text[pos] == L'-' || text[pos] == L'+')) {
                negative = (text[pos] == L'-');
                ++pos;
            }
            size_t end = pos;
            while (end < text.size() && iswdigit(text[end])) {
                ++end;
            }
            if (end == pos) {
                return 0;
            }
            try {
                long long value = std::stoll(text.substr(pos, end - pos));
                return negative ? -value : value;
            } catch (...) {
                return 0;
            }
        };

        auto ExtractStringField = [](const std::wstring& text, const std::wstring& key) -> std::wstring {
            size_t pos = text.find(key);
            if (pos == std::wstring::npos) {
                return std::wstring();
            }
            pos += key.size();
            std::wstring result;
            bool escape = false;
            for (size_t i = pos; i < text.size(); ++i) {
                wchar_t ch = text[i];
                if (escape) {
                    result.push_back(ch);
                    escape = false;
                } else if (ch == L'\\') {
                    escape = true;
                } else if (ch == L'"') {
                    break;
                } else {
                    result.push_back(ch);
                }
            }
            return result;
        };

        auto ExtractHandleStrings = [](const std::wstring& text, const std::wstring& key) -> std::vector<std::wstring> {
            std::vector<std::wstring> handles;
            size_t pos = text.find(key);
            if (pos == std::wstring::npos) {
                return handles;
            }
            pos = text.find(L"[", pos);
            if (pos == std::wstring::npos) {
                return handles;
            }
            int depth = 0;
            size_t end = pos;
            for (size_t i = pos; i < text.size(); ++i) {
                wchar_t ch = text[i];
                if (ch == L'[') {
                    depth++;
                } else if (ch == L']') {
                    depth--;
                    if (depth == 0) {
                        end = i;
                        break;
                    }
                }
            }
            if (end <= pos) {
                return handles;
            }
            bool inString = false;
            bool escape = false;
            std::wstring token;
            for (size_t i = pos + 1; i < end; ++i) {
                wchar_t ch = text[i];
                if (!inString) {
                    if (ch == L'"') {
                        inString = true;
                        token.clear();
                    }
                } else {
                    if (escape) {
                        token.push_back(ch);
                        escape = false;
                    } else if (ch == L'\\') {
                        escape = true;
                    } else if (ch == L'"') {
                        inString = false;
                        if (!token.empty()) {
                            handles.push_back(token);
                        }
                    } else {
                        token.push_back(ch);
                    }
                }
            }
            return handles;
        };

        auto NormalizeHandles = [&](const std::vector<std::wstring>& values) -> std::vector<std::wstring> {
            std::vector<std::wstring> normalized;
            for (const auto& raw : values) {
                std::wstring trimmed = raw;
                size_t first = trimmed.find_first_not_of(L" \t\r\n");
                size_t last = trimmed.find_last_not_of(L" \t\r\n");
                if (first == std::wstring::npos || last == std::wstring::npos) {
                    continue;
                }
                trimmed = trimmed.substr(first, last - first + 1);
                if (trimmed.empty()) {
                    continue;
                }
                try {
                    unsigned long long value = 0;
                    if (trimmed.size() > 2 && trimmed[0] == L'0' && (trimmed[1] == L'x' || trimmed[1] == L'X')) {
                        value = std::stoull(trimmed.substr(2), nullptr, 16);
                    } else {
                        value = std::stoull(trimmed, nullptr, 10);
                    }
                    normalized.push_back(FormatHexW(value));
                } catch (...) {
                    // ignore malformed entries
                }
            }
            return normalized;
        };

        std::map<DWORD, PolicyEnforcement> snapshot;

        size_t policyPos = json.find(L"\"policy\"");
        if (policyPos != std::wstring::npos) {
            size_t enforcedPos = json.find(L"\"enforced\":", policyPos);
            if (enforcedPos != std::wstring::npos) {
                size_t arrayStart = json.find(L"[", enforcedPos);
                if (arrayStart != std::wstring::npos) {
                    int depth = 0;
                    size_t arrayEnd = arrayStart;
                    for (size_t i = arrayStart; i < json.size(); ++i) {
                        wchar_t ch = json[i];
                        if (ch == L'[') {
                            depth++;
                        } else if (ch == L']') {
                            depth--;
                            if (depth == 0) {
                                arrayEnd = i;
                                break;
                            }
                        }
                    }
                    size_t pos = arrayStart + 1;
                    while (pos < arrayEnd) {
                        size_t brace = json.find(L"{", pos);
                        if (brace == std::wstring::npos || brace >= arrayEnd) {
                            break;
                        }
                        int objDepth = 0;
                        size_t end = brace;
                        for (size_t i = brace; i <= arrayEnd; ++i) {
                            wchar_t ch = json[i];
                            if (ch == L'{') {
                                objDepth++;
                            } else if (ch == L'}') {
                                objDepth--;
                                if (objDepth == 0) {
                                    end = i;
                                    break;
                                }
                            }
                        }
                        if (end <= brace) {
                            break;
                        }
                        std::wstring entry = json.substr(brace, end - brace + 1);
                        pos = end + 1;

                        long long pidValue = ExtractNumberField(entry, L"\"pid\":");
                        if (pidValue <= 0) {
                            continue;
                        }
                        PolicyEnforcement enforcement;
                        enforcement.forceInput = static_cast<int>(ExtractNumberField(entry, L"\"force_input\":"));
                        enforcement.forceWda = static_cast<int>(ExtractNumberField(entry, L"\"force_wda\":"));
                        enforcement.sessionId = static_cast<DWORD>(ExtractNumberField(entry, L"\"session\":"));
                        enforcement.userSid = ExtractStringField(entry, L"\"sid\":\"");
                        enforcement.userName = ExtractStringField(entry, L"\"user\":\"");
                        enforcement.dupHandles = NormalizeHandles(ExtractHandleStrings(entry, L"\"duplications\":"));
                        enforcement.windowHandles = NormalizeHandles(ExtractHandleStrings(entry, L"\"windows\":"));
                        enforcement.monitorHandles = NormalizeHandles(ExtractHandleStrings(entry, L"\"monitors\":"));
                        enforcement.swapHandles = NormalizeHandles(ExtractHandleStrings(entry, L"\"swapchains\":"));

                        snapshot[static_cast<DWORD>(pidValue)] = std::move(enforcement);
                    }
                }
            }
        }

        {
            std::lock_guard<std::mutex> lock(mtx);
            policyTelemetry = std::move(snapshot);
            policyLastFileStamp = fileStamp;
        }
    }
    }

    bool IsKeyboardAbuser(DWORD pid) {
        RefreshKeyboardTelemetry();
        std::lock_guard<std::mutex> lock(mtx);
        auto it = keyboardTelemetry.find(pid);
        if (it == keyboardTelemetry.end()) {
            return false;
        }
        ULONGLONG now = GetTickCount64();
        if (now - it->second.lastTick > kKeyboardExpiryMs) {
            return false;
        }
        return it->second.forced > 0 || it->second.total >= 3;
    }

    void PrintKeyboardSummaryLocked() {
        ULONGLONG now = GetTickCount64();
        std::vector<std::pair<DWORD, KeyboardStats>> recent;
        for (const auto& kv : keyboardTelemetry) {
            if (now - kv.second.lastTick <= kKeyboardExpiryMs) {
                recent.emplace_back(kv.first, kv.second);
            }
        }
        std::cout << "\nKeyboard telemetry (last 2 minutes):" << std::endl;
        if (recent.empty()) {
            std::cout << "  (no recent keyboard tamper activity)" << std::endl;
            return;
        }
        std::sort(recent.begin(), recent.end(),
                  [](const std::pair<DWORD, KeyboardStats>& a,
                     const std::pair<DWORD, KeyboardStats>& b) {
                      if (a.second.forced != b.second.forced) {
                          return a.second.forced > b.second.forced;
                      }
                      if (a.second.total != b.second.total) {
                          return a.second.total > b.second.total;
                      }
                      return a.first < b.first;
                  });
        size_t limit = std::min<size_t>(recent.size(), 5);
        for (size_t i = 0; i < limit; ++i) {
            const auto& entry = recent[i];
            std::cout << "  PID " << entry.first
                      << " total=" << entry.second.total
                      << " forced=" << entry.second.forced;
            if (entry.second.forced > 0) {
                std::cout << "  <--";
            }
            if (entry.second.sessionId != kInvalidSessionId) {
                std::cout << " session=" << entry.second.sessionId;
            }
            if (!entry.second.userName.empty()) {
                std::cout << " user=" << Narrow(entry.second.userName);
            } else if (!entry.second.userSid.empty()) {
                std::cout << " sid=" << Narrow(entry.second.userSid);
            }
            std::cout << std::endl;
        }
    }

    void PrintGraphicsSummaryLocked() {
        ULONGLONG now = GetTickCount64();
        std::vector<std::pair<DWORD, GraphicsStats>> recent;
        for (const auto& kv : graphicsTelemetry) {
            if (kv.second.modules.empty() &&
                kv.second.duplications.empty() &&
                kv.second.captures.empty() &&
                kv.second.swapChains.empty()) {
                continue;
            }
            if (now - kv.second.lastTick <= kKeyboardExpiryMs) {
                recent.emplace_back(kv.first, kv.second);
            }
        }

        std::cout << "\nGraphics telemetry (last 2 minutes):" << std::endl;
        if (recent.empty()) {
            std::cout << "  (no recent graphics activity)" << std::endl;
            return;
        }
        std::sort(
            recent.begin(),
            recent.end(),
            [&](const std::pair<DWORD, GraphicsStats>& a, const std::pair<DWORD, GraphicsStats>& b) {
                DWORD sessA = (a.second.sessionId == kInvalidSessionId) ? DWORD(0xFFFFFFFEu) : a.second.sessionId;
                DWORD sessB = (b.second.sessionId == kInvalidSessionId) ? DWORD(0xFFFFFFFEu) : b.second.sessionId;
                if (sessA != sessB) {
                    return sessA < sessB;
                }
                return a.first < b.first;
            });

        size_t limit = std::min<size_t>(recent.size(), 6);
        DWORD currentSession = 0xFFFFFFFFu;
        for (size_t i = 0; i < limit; ++i) {
            const auto& entry = recent[i];
            DWORD sessionId = entry.second.sessionId;
            if (sessionId != currentSession) {
                currentSession = sessionId;
                std::cout << "  Session ";
                if (sessionId == kInvalidSessionId) {
                    std::cout << "unknown";
                } else {
                    std::cout << sessionId;
                }
                std::cout << ":" << std::endl;
            }
            std::cout << "    PID " << entry.first << " modules: ";
            bool first = true;
            for (const auto& mod : entry.second.modules) {
                if (!first) {
                    std::cout << ", ";
                }
                first = false;
                std::cout << mod.first;
                if (mod.second) {
                    std::cout << " (0x" << std::hex << std::uppercase << mod.second
                              << std::nouppercase << std::dec << ")";
                }
            }
            if (entry.second.modules.empty()) {
                std::cout << "(none)";
            }

            if (!entry.second.duplications.empty()) {
                auto it = entry.second.duplications.begin();
                ULONGLONG totalCreate = 0;
                ULONGLONG totalAcquire = 0;
                for (const auto& dupPair : entry.second.duplications) {
                    totalCreate += dupPair.second.createCount;
                    totalAcquire += dupPair.second.acquireCount;
                }
                std::cout << " | dup=" << entry.second.duplications.size()
                          << " create=" << totalCreate
                          << " acquire=" << totalAcquire;
                std::cout << " first=0x" << std::hex << std::uppercase << it->first << std::nouppercase << std::dec;
            }

            if (!entry.second.swapChains.empty()) {
                ULONGLONG totalPresent = 0;
                ULONGLONG totalBlocked = 0;
                for (const auto& scPair : entry.second.swapChains) {
                    totalPresent += scPair.second.presentCount;
                    totalBlocked += scPair.second.blockedCount;
                }
                auto it = entry.second.swapChains.begin();
                std::cout << " | swap=" << entry.second.swapChains.size()
                          << " present=" << totalPresent
                          << " blocked=" << totalBlocked;
                std::cout << " first=0x" << std::hex << std::uppercase << it->first << std::nouppercase << std::dec;
                const SwapChainStats& primarySwap = it->second;
                if (primarySwap.lastWasPresent1) {
                    std::cout << " dirty=" << primarySwap.lastDirtyCount;
                    if (primarySwap.lastDirtyWidth || primarySwap.lastDirtyHeight) {
                        std::cout << " bbox=" << primarySwap.lastDirtyWidth
                                  << "x" << primarySwap.lastDirtyHeight;
                    }
                    if (primarySwap.lastDirtyBoundingArea) {
                        std::cout << " area=" << primarySwap.lastDirtyBoundingArea;
                    }
                    if (primarySwap.dirtySampleCount > 0) {
                        ULONGLONG avgBounding = primarySwap.dirtyAccumBounding /
                                                std::max<ULONGLONG>(1, primarySwap.dirtySampleCount);
                        std::cout << " avg_area=" << avgBounding;
                    }
                    if (primarySwap.dirtyTruncated) {
                        std::cout << " trunc=1";
                    }
                    if (primarySwap.hasScrollOffset) {
                        std::cout << " scroll_dx=" << primarySwap.lastScrollDx
                                  << " scroll_dy=" << primarySwap.lastScrollDy;
                    }
                }
            }

            if (!entry.second.captures.empty()) {
                auto it = entry.second.captures.begin();
                std::cout << " | cap=" << entry.second.captures.size()
                          << " count=" << it->second.createCount
                          << " type=" << (it->second.isMonitor ? "monitor" : "window");
                if (it->second.targetHandle) {
                    std::cout << " target=0x" << std::hex << std::uppercase << it->second.targetHandle
                              << std::nouppercase << std::dec;
                }
            }

            if (!entry.second.userName.empty()) {
                std::cout << " user=" << Narrow(entry.second.userName);
            } else if (!entry.second.userSid.empty()) {
                std::cout << " sid=" << Narrow(entry.second.userSid);
            }
            std::cout << std::endl;
        }
    }

    void PrintDwmCoverageLocked() {
        struct SessionAggregate {
            ULONGLONG dupCreate = 0;
            ULONGLONG dupAcquire = 0;
            ULONGLONG swapPresent = 0;
            ULONGLONG swapBlocked = 0;
            ULONGLONG captureCount = 0;
            ULONGLONG lastTick = 0;
            ULONGLONG dirtySamples = 0;
            ULONGLONG dirtyBoundingSum = 0;
            ULONGLONG dirtyTotalSum = 0;
            DWORD lastDirtyCount = 0;
            DWORD lastDirtyWidth = 0;
            DWORD lastDirtyHeight = 0;
            ULONGLONG lastDirtyArea = 0;
            ULONGLONG lastDirtyTotal = 0;
            bool dirtyTruncated = false;
            bool hasDirtySnapshot = false;
            bool hasScrollRect = false;
            RECT lastScrollRect = {0, 0, 0, 0};
            bool hasScrollOffset = false;
            LONG lastScrollDx = 0;
            LONG lastScrollDy = 0;
            std::vector<std::string> details;
        };

        std::map<DWORD, SessionAggregate> sessionData;
        ULONGLONG now = GetTickCount64();

        for (const auto& kv : processNames) {
            const DWORD pid = kv.first;
            std::string name = kv.second;
            std::transform(
                name.begin(),
                name.end(),
                name.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (name != "dwm.exe") {
                continue;
            }

            auto identityIt = processIdentity.find(pid);
            DWORD sessionId = kInvalidSessionId;
            std::wstring userName;
            std::wstring userSid;
            ULONGLONG identityTick = 0;
            if (identityIt != processIdentity.end()) {
                sessionId = identityIt->second.sessionId;
                userName = identityIt->second.userName;
                userSid = identityIt->second.userSid;
                identityTick = identityIt->second.lastSeen;
            }

            bool isHooked = hookedProcesses.find(pid) != hookedProcesses.end();
            bool isBlacklisted = blacklistedProcesses.find(pid) != blacklistedProcesses.end();

            ULONGLONG statsTick = identityTick;
            ULONGLONG dupCreate = 0;
            ULONGLONG dupAcquire = 0;
            ULONGLONG swapPresent = 0;
            ULONGLONG swapBlocked = 0;
            ULONGLONG captureCount = 0;
            ULONGLONG dirtySamples = 0;
            ULONGLONG dirtyBoundingSum = 0;
            ULONGLONG dirtyTotalSum = 0;
            const SwapChainStats* latestSwap = nullptr;

            auto statsIt = graphicsTelemetry.find(pid);
            if (statsIt != graphicsTelemetry.end()) {
                const auto& stats = statsIt->second;
                statsTick = std::max(statsTick, stats.lastTick);
                for (const auto& dupPair : stats.duplications) {
                    dupCreate += dupPair.second.createCount;
                    dupAcquire += dupPair.second.acquireCount;
                }
                for (const auto& swapPair : stats.swapChains) {
                    swapPresent += swapPair.second.presentCount;
                    swapBlocked += swapPair.second.blockedCount;
                    dirtySamples += swapPair.second.dirtySampleCount;
                    dirtyBoundingSum += swapPair.second.dirtyAccumBounding;
                    dirtyTotalSum += swapPair.second.dirtyAccumTotal;
                    if (!latestSwap || swapPair.second.lastTick > latestSwap->lastTick) {
                        latestSwap = &swapPair.second;
                    }
                }
                for (const auto& capPair : stats.captures) {
                    captureCount += capPair.second.createCount;
                }
            }

            SessionAggregate& aggregate = sessionData[sessionId];
            aggregate.dupCreate += dupCreate;
            aggregate.dupAcquire += dupAcquire;
            aggregate.swapPresent += swapPresent;
            aggregate.swapBlocked += swapBlocked;
            aggregate.captureCount += captureCount;
            aggregate.lastTick = std::max(aggregate.lastTick, statsTick);
            aggregate.dirtySamples += dirtySamples;
            aggregate.dirtyBoundingSum += dirtyBoundingSum;
            aggregate.dirtyTotalSum += dirtyTotalSum;
            if (latestSwap && latestSwap->lastWasPresent1) {
                aggregate.hasDirtySnapshot = true;
                aggregate.lastDirtyCount = latestSwap->lastDirtyCount;
                aggregate.lastDirtyWidth = latestSwap->lastDirtyWidth;
                aggregate.lastDirtyHeight = latestSwap->lastDirtyHeight;
                aggregate.lastDirtyArea = latestSwap->lastDirtyBoundingArea;
                aggregate.lastDirtyTotal = latestSwap->lastDirtyTotalArea;
                aggregate.dirtyTruncated = aggregate.dirtyTruncated || latestSwap->dirtyTruncated;
                aggregate.hasScrollOffset = latestSwap->hasScrollOffset;
                if (latestSwap->hasScrollOffset) {
                    aggregate.lastScrollDx = latestSwap->lastScrollDx;
                    aggregate.lastScrollDy = latestSwap->lastScrollDy;
                } else {
                    aggregate.lastScrollDx = 0;
                    aggregate.lastScrollDy = 0;
                }
                aggregate.hasScrollRect = latestSwap->hasScrollRect;
                if (latestSwap->hasScrollRect) {
                    aggregate.lastScrollRect = latestSwap->lastScrollRect;
                } else {
                    aggregate.lastScrollRect.left = aggregate.lastScrollRect.top =
                        aggregate.lastScrollRect.right = aggregate.lastScrollRect.bottom = 0;
                }
            }

            std::ostringstream oss;
            oss << "PID " << pid;

            std::string stateTag;
            if (isHooked) {
                stateTag = "hooked";
            } else if (isBlacklisted) {
                stateTag = "blocked";
            } else if (!aggressiveMode && sessionId == 0) {
                stateTag = "skipped";
            } else {
                stateTag = "pending";
            }
            oss << " [" << stateTag << "]";

            if (dupCreate || dupAcquire) {
                oss << " dup=" << dupCreate << "/" << dupAcquire;
            }
            if (swapPresent || swapBlocked) {
                oss << " swap=" << swapPresent << "/" << swapBlocked;
            }
            if (captureCount) {
                oss << " cap=" << captureCount;
            }
            if (latestSwap && latestSwap->lastWasPresent1) {
                oss << " dirty=" << latestSwap->lastDirtyCount;
                if (latestSwap->lastDirtyWidth || latestSwap->lastDirtyHeight) {
                    oss << " bbox=" << latestSwap->lastDirtyWidth
                        << "x" << latestSwap->lastDirtyHeight;
                }
                if (latestSwap->lastDirtyBoundingArea) {
                    oss << " area=" << latestSwap->lastDirtyBoundingArea;
                }
                if (latestSwap->dirtySampleCount > 0) {
                    ULONGLONG avgBounding = latestSwap->dirtyAccumBounding /
                                            std::max<ULONGLONG>(1, latestSwap->dirtySampleCount);
                    oss << " avg_area=" << avgBounding;
                }
                if (latestSwap->dirtyTruncated) {
                    oss << " trunc=1";
                }
                if (latestSwap->hasScrollOffset) {
                    oss << " scroll_dx=" << latestSwap->lastScrollDx
                        << " scroll_dy=" << latestSwap->lastScrollDy;
                }
            }

            if (statsTick) {
                ULONGLONG age = now - statsTick;
                oss << " last=" << FormatDuration(age) << " ago";
            } else if (identityTick) {
                ULONGLONG age = now - identityTick;
                oss << " seen=" << FormatDuration(age) << " ago";
            } else {
                oss << " seen=unknown";
            }

            if (!userName.empty()) {
                oss << " user=" << Narrow(userName);
            } else if (!userSid.empty()) {
                oss << " sid=" << Narrow(userSid);
            }

            aggregate.details.push_back(oss.str());
        }

        std::cout << "\nDWM session coverage:" << std::endl;
        if (sessionData.empty()) {
            std::cout << "  (no DWM processes observed)" << std::endl;
            return;
        }

        for (const auto& kv : sessionData) {
            DWORD sessionId = kv.first;
            const SessionAggregate& aggregate = kv.second;
            std::cout << "  Session ";
            if (sessionId == kInvalidSessionId) {
                std::cout << "unknown";
            } else {
                std::cout << sessionId;
            }
            if (aggregate.lastTick) {
                ULONGLONG age = now - aggregate.lastTick;
                std::cout << " last=" << FormatDuration(age) << " ago";
            }
            std::cout << " dup=" << aggregate.dupCreate << "/" << aggregate.dupAcquire
                      << " swap=" << aggregate.swapPresent << "/" << aggregate.swapBlocked
                      << " cap=" << aggregate.captureCount;
            if (aggregate.dirtySamples) {
                ULONGLONG avgBounding = aggregate.dirtyBoundingSum /
                                        std::max<ULONGLONG>(1, aggregate.dirtySamples);
                ULONGLONG avgTotal = aggregate.dirtyTotalSum /
                                     std::max<ULONGLONG>(1, aggregate.dirtySamples);
                std::cout << " dirty_samples=" << aggregate.dirtySamples
                          << " dirty_avg_area=" << avgBounding
                          << " dirty_avg_total=" << avgTotal;
            }
            if (aggregate.hasDirtySnapshot) {
                std::cout << " dirty_last=" << aggregate.lastDirtyCount
                          << "@" << aggregate.lastDirtyWidth << "x" << aggregate.lastDirtyHeight;
                if (aggregate.lastDirtyArea) {
                    std::cout << " area=" << aggregate.lastDirtyArea;
                }
                if (aggregate.lastDirtyTotal) {
                    std::cout << " total=" << aggregate.lastDirtyTotal;
                }
                if (aggregate.dirtyTruncated) {
                    std::cout << " trunc=1";
                }
                if (aggregate.hasScrollOffset) {
                    std::cout << " scroll_dx=" << aggregate.lastScrollDx
                              << " scroll_dy=" << aggregate.lastScrollDy;
                }
                if (aggregate.hasScrollRect) {
                    std::cout << " rect=[" << aggregate.lastScrollRect.left << ","
                              << aggregate.lastScrollRect.top << ","
                              << aggregate.lastScrollRect.right << ","
                              << aggregate.lastScrollRect.bottom << "]";
                }
            }
            std::cout << std::endl;
            for (const auto& detail : aggregate.details) {
                std::cout << "    " << detail << std::endl;
            }
        }
    }

    void PrintPolicySummaryLocked() {
        if (policyTelemetry.empty()) {
            std::cout << "\nPolicy overrides: (none)" << std::endl;
            return;
        }

        auto ParseHandle = [](const std::wstring& handle) -> unsigned long long {
            if (handle.empty()) {
                return 0;
            }
            try {
                if (handle.size() > 2 && handle[0] == L'0' &&
                    (handle[1] == L'x' || handle[1] == L'X')) {
                    return std::stoull(handle.substr(2), nullptr, 16);
                }
                return std::stoull(handle, nullptr, 10);
            } catch (...) {
                return 0;
            }
        };

        auto FormatHandleList = [&](const std::vector<std::wstring>& handles,
                                    const std::function<bool(unsigned long long)>& isActive,
                                    size_t& staleCounter) -> std::string {
            if (handles.empty()) {
                return std::string();
            }
            size_t limit = std::min<size_t>(handles.size(), 3);
            std::ostringstream oss;
            for (size_t i = 0; i < handles.size(); ++i) {
                unsigned long long value = ParseHandle(handles[i]);
                bool active = false;
                if (value != 0 && isActive) {
                    active = isActive(value);
                }
                if (!active) {
                    staleCounter++;
                }
                if (i >= limit) {
                    continue;
                }
                if (i) {
                    oss << ", ";
                }
                oss << Narrow(handles[i]);
                if (!active) {
                    oss << " (stale)";
                }
            }
            if (handles.size() > limit) {
                oss << ", ...";
            }
            return oss.str();
        };

        ULONGLONG nowTick = GetTickCount64();

        std::cout << "\nPolicy overrides:" << std::endl;
        for (const auto& kv : policyTelemetry) {
            const auto& enforcement = kv.second;
            std::cout << "  PID " << kv.first
                      << " force_input=" << enforcement.forceInput
                      << " force_wda=" << enforcement.forceWda;
            if (enforcement.sessionId != kInvalidSessionId) {
                std::cout << " session=" << enforcement.sessionId;
            }
            if (!enforcement.userName.empty()) {
                std::cout << " user=" << Narrow(enforcement.userName);
            } else if (!enforcement.userSid.empty()) {
                std::cout << " sid=" << Narrow(enforcement.userSid);
            }

            auto graphicsIt = graphicsTelemetry.find(kv.first);
            auto isDupActive = [&](unsigned long long handle) -> bool {
                if (graphicsIt == graphicsTelemetry.end()) {
                    return false;
                }
                auto dupIt = graphicsIt->second.duplications.find(handle);
                if (dupIt == graphicsIt->second.duplications.end()) {
                    return false;
                }
                return (nowTick - dupIt->second.lastTick) <= kKeyboardExpiryMs;
            };
            auto isWindowActive = [&](unsigned long long handle) -> bool {
                if (graphicsIt == graphicsTelemetry.end()) {
                    return false;
                }
                for (const auto& cap : graphicsIt->second.captures) {
                    if (cap.second.isMonitor) {
                        continue;
                    }
                    if (cap.second.targetHandle == handle) {
                        return (nowTick - cap.second.lastTick) <= kKeyboardExpiryMs;
                    }
                }
                return false;
            };
            auto isMonitorActive = [&](unsigned long long handle) -> bool {
                if (graphicsIt == graphicsTelemetry.end()) {
                    return false;
                }
                for (const auto& cap : graphicsIt->second.captures) {
                    if (!cap.second.isMonitor) {
                        continue;
                    }
                    if (cap.second.targetHandle == handle) {
                        return (nowTick - cap.second.lastTick) <= kKeyboardExpiryMs;
                    }
                }
                return false;
            };
            auto isSwapActive = [&](unsigned long long handle) -> bool {
                if (graphicsIt == graphicsTelemetry.end()) {
                    return false;
                }
                auto swapIt = graphicsIt->second.swapChains.find(handle);
                if (swapIt == graphicsIt->second.swapChains.end()) {
                    return false;
                }
                return (nowTick - swapIt->second.lastTick) <= kKeyboardExpiryMs;
            };

            size_t staleDup = 0;
            size_t staleWindows = 0;
            size_t staleMonitors = 0;
            size_t staleSwap = 0;
            std::string dupSummary = FormatHandleList(enforcement.dupHandles, isDupActive, staleDup);
            std::string winSummary = FormatHandleList(enforcement.windowHandles, isWindowActive, staleWindows);
            std::string monSummary = FormatHandleList(enforcement.monitorHandles, isMonitorActive, staleMonitors);
            std::string swapSummary = FormatHandleList(enforcement.swapHandles, isSwapActive, staleSwap);

            if (!dupSummary.empty()) {
                std::cout << " dup(" << enforcement.dupHandles.size();
                if (staleDup) {
                    std::cout << " stale=" << staleDup;
                }
                std::cout << ")=" << dupSummary;
            }
            if (!winSummary.empty()) {
                std::cout << " win(" << enforcement.windowHandles.size();
                if (staleWindows) {
                    std::cout << " stale=" << staleWindows;
                }
                std::cout << ")=" << winSummary;
            }
            if (!monSummary.empty()) {
                std::cout << " mon(" << enforcement.monitorHandles.size();
                if (staleMonitors) {
                    std::cout << " stale=" << staleMonitors;
                }
                std::cout << ")=" << monSummary;
            }
            if (!swapSummary.empty()) {
                std::cout << " swap(" << enforcement.swapHandles.size();
                if (staleSwap) {
                    std::cout << " stale=" << staleSwap;
                }
                std::cout << ")=" << swapSummary;
            }
            std::cout << std::endl;
        }
    }

    bool ShouldHookProcess(const std::string& processName, DWORD pid) {
        std::string lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        if (umh::HasProcessTargetFilter() && !umh::IsTargetProcessUtf8(lowerName)) {
            return false;
        }

        bool keyboardFlagged = IsKeyboardAbuser(pid);
        bool graphicsFlagged = UsesGraphicsModules(pid);
        {
            std::lock_guard<std::mutex> lock(mtx);
            auto it = graphicsTelemetry.find(pid);
            if (it != graphicsTelemetry.end()) {
                if (!it->second.duplications.empty() ||
                    !it->second.captures.empty() ||
                    !it->second.swapChains.empty()) {
                    graphicsFlagged = true;
                }
            }
        }

        bool isDwm = (lowerName == "dwm.exe");
        DWORD sessionId = kInvalidSessionId;
        ProcessIdToSessionId(pid, &sessionId);

        if (systemProcesses.find(lowerName) != systemProcesses.end() && !isDwm) {
            if (keyboardFlagged && keyboardSuppressionIgnored.insert(pid).second) {
                std::stringstream ss;
                ss << "Keyboard tamper detected in system process " << processName
                   << " (PID: " << pid << "), skipping by policy";
                LogMessage(ss.str());
            }
            if (graphicsFlagged && graphicsSuppressionIgnored.insert(pid).second) {
                std::stringstream ss;
                ss << "Graphics module fingerprint detected in system process " << processName
                   << " (PID: " << pid << "), skipping by policy";
                LogMessage(ss.str());
            }
            return false;
        }

        if (isDwm) {
            if (sessionId == 0 && !aggressiveMode) {
                // Skip the console session DWM unless we are forcing aggressive mode
                return false;
            }
            // Prioritise hooking additional session DWMs for telemetry
            return true;
        }

        if (hookedProcesses.find(pid) != hookedProcesses.end()) {
            return false;
        }

        if (blacklistedProcesses.find(pid) != blacklistedProcesses.end()) {
            return false;
        }

        if (keyboardFlagged) {
            if (keyboardEscalated.insert(pid).second) {
                std::stringstream ss;
                ss << "Prioritising " << processName << " (PID: " << pid
                   << ") due to keyboard suppression telemetry";
                LogMessage(ss.str());
            }
            return true;
        }

        if (graphicsFlagged) {
            if (graphicsEscalated.insert(pid).second) {
                std::stringstream ss;
                ss << "Prioritising " << processName << " (PID: " << pid
                   << ") due to graphics module fingerprint";
                LogMessage(ss.str());
            }
            return true;
        }

        if (aggressiveMode) {
            return true;
        }

        size_t pos = lowerName.find_last_of("\\/");
        if (pos != std::string::npos) {
            lowerName = lowerName.substr(pos + 1);
        }
        return targetProcesses.find(lowerName) != targetProcesses.end();
    }

    bool InjectIntoProcess(DWORD processId, const std::string& processName) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (hProcess == nullptr) {
            // Try with reduced permissions
            hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                                 PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
            if (hProcess == nullptr) {
                return false;
            }
        }

        // Check if it's a 64-bit process
        BOOL isWow64 = FALSE;
        IsWow64Process(hProcess, &isWow64);

#ifdef _WIN64
        if (isWow64) {
            // 64-bit injector can't inject into 32-bit process
            CloseHandle(hProcess);
            return false;
        }
#else
        if (!isWow64) {
            // 32-bit injector can't inject into 64-bit process
            CloseHandle(hProcess);
            return false;
        }
#endif

        // Allocate memory for DLL path
        SIZE_T dllPathSize = dllPath.length() + 1;
        LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, nullptr, dllPathSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (pRemoteDllPath == nullptr) {
            CloseHandle(hProcess);
            return false;
        }

        // Write DLL path
        if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath.c_str(),
                              dllPathSize, nullptr)) {
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Get LoadLibraryA address
        LPVOID pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        // Create remote thread
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                                          (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                          pRemoteDllPath, 0, nullptr);

        if (hThread == nullptr) {
            VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Wait for injection to complete (with timeout)
        WaitForSingleObject(hThread, 1000);

        // Cleanup
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return true;
    }

    void ScanAndHookProcesses() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        RefreshKeyboardTelemetry();
        RefreshPolicySnapshot();
        std::set<DWORD> activePids;
        ULONGLONG nowTick = GetTickCount64();

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                // Convert wide string to narrow string
                std::wstring wProcessName(pe32.szExeFile);
                std::string processName(wProcessName.begin(), wProcessName.end());
                DWORD pid = pe32.th32ProcessID;

                // Skip PID 0 and 4 (System processes)
                if (pid == 0 || pid == 4) {
                    continue;
                }

                activePids.insert(pid);
                ProcessIdentityData identity = QueryProcessIdentity(pid);
                identity.lastSeen = nowTick;
                {
                    std::lock_guard<std::mutex> lock(mtx);
                    processIdentity[pid] = identity;
                    processNames[pid] = processName;
                    ApplyIdentityToStats(pid, identity);
                }

                if (ShouldHookProcess(processName, pid)) {
                    std::stringstream ss;
                    ss << "Attempting to hook: " << processName << " (PID: " << pid << ")";
                    LogMessage(ss.str());

                    if (InjectIntoProcess(pid, processName)) {
                        std::lock_guard<std::mutex> lock(mtx);
                        hookedProcesses.insert(pid);

                        ss.str("");
                        ss << "[+] Successfully hooked: " << processName << " (PID: " << pid << ")";
                        LogMessage(ss.str());
                    } else {
                        std::lock_guard<std::mutex> lock(mtx);
                        blacklistedProcesses.insert(pid);
                    }
                }

            } while (Process32Next(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);

        const ULONGLONG identityExpiry = 3ull * 60ull * 1000ull;
        {
            std::lock_guard<std::mutex> lock(mtx);
            for (auto it = processIdentity.begin(); it != processIdentity.end(); ) {
                if (nowTick - it->second.lastSeen > identityExpiry) {
                    it = processIdentity.erase(it);
                } else {
                    ++it;
                }
            }
            for (auto it = processNames.begin(); it != processNames.end(); ) {
                if (activePids.find(it->first) == activePids.end()) {
                    it = processNames.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    void CleanupTerminatedProcesses() {
        std::lock_guard<std::mutex> lock(mtx);

        auto it = hookedProcesses.begin();
        while (it != hookedProcesses.end()) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, *it);
            if (hProcess == nullptr) {
                // Process no longer exists
                it = hookedProcesses.erase(it);
            } else {
                DWORD exitCode;
                if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                    it = hookedProcesses.erase(it);
                } else {
                    ++it;
                }
                CloseHandle(hProcess);
            }
        }

        // Clean blacklist periodically (processes might restart)
        static int cleanupCounter = 0;
        if (++cleanupCounter > 10) {
            blacklistedProcesses.clear();
            cleanupCounter = 0;
        }
    }

    void MonitoringThread() {
        LogMessage("Monitoring thread started");

        int scanInterval = 2000; // 2 seconds
        int quickScanCounter = 0;

        while (isRunning) {
            // Scan for new processes
            ScanAndHookProcesses();

            // Cleanup terminated processes
            CleanupTerminatedProcesses();

            // Quick scan for first minute, then slower
            if (quickScanCounter++ < 30) {
                scanInterval = 2000;  // 2 seconds for first minute
            } else {
                scanInterval = 5000;  // 5 seconds afterwards
            }

            // Sleep with ability to wake up
            for (int i = 0; i < scanInterval / 100 && isRunning; i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }

        LogMessage("Monitoring thread stopped");
    }

    bool Start() {
        if (isRunning) {
            return false;
        }

        // Verify DLL exists
        if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LogMessage("ERROR: Hook DLL not found at: " + dllPath);
            return false;
        }

        isRunning = true;

        // Start monitoring thread
        std::thread monitorThread(&SystemWideMonitor::MonitoringThread, this);
        monitorThread.detach();

        LogMessage("System-wide monitoring started");
        LogMessage("SetWindowDisplayAffinity bypass is now ACTIVE");
        return true;
    }

    void Stop() {
        if (!isRunning) {
            return;
        }

        isRunning = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        LogMessage("System-wide monitoring stopped");
    }

    void ShowStatus() {
        RefreshKeyboardTelemetry();
        RefreshPolicySnapshot();
        std::lock_guard<std::mutex> lock(mtx);

        std::cout << "\n=== Monitor Status ===" << std::endl;
        std::cout << "Running: " << (isRunning ? "Yes" : "No") << std::endl;
        std::cout << "Mode: " << (aggressiveMode ? "Aggressive" : "Targeted") << std::endl;
        std::cout << "Hooked Processes: " << hookedProcesses.size() << std::endl;
        std::cout << "Blacklisted: " << blacklistedProcesses.size() << std::endl;
        if (!graphicsEscalated.empty()) {
            std::cout << "Graphics escalated: " << graphicsEscalated.size() << std::endl;
        }

        if (!hookedProcesses.empty()) {
            std::cout << "\nHooked PIDs:";
            for (DWORD pid : hookedProcesses) {
                std::cout << " " << pid;
                auto identIt = processIdentity.find(pid);
                if (identIt != processIdentity.end() &&
                    identIt->second.sessionId != kInvalidSessionId) {
                    std::cout << "(s" << identIt->second.sessionId << ")";
                }
            }
            std::cout << std::endl;
        }

        PrintKeyboardSummaryLocked();
        PrintGraphicsSummaryLocked();
        PrintDwmCoverageLocked();
        PrintPolicySummaryLocked();
    }

    size_t GetHookedCount() const {
        return hookedProcesses.size();
    }
};

void PrintUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -d <dll>     Path to hook DLL (required)\n";
    std::cout << "  -a           Aggressive mode (hook ALL processes)\n";
    std::cout << "  -t           Targeted mode (default, known apps only)\n";
    std::cout << "  -s           Run silently in background\n";
    std::cout << "  --snapshot   On exit, append a snapshot to " << SystemWideMonitor::ApiLogPath() << "\n";
    std::cout << "  --duration N Run for N seconds then exit (with --snapshot recommended)\n";
    std::cout << "  -h           Show this help\n";
}

static void AppendStructuredSnapshot(const std::string& apiLogPath) {
    std::ifstream in(apiLogPath);
    if (!in.is_open()) {
        return;
    }
    std::map<std::string, std::map<std::string, std::string>> snapshot; // pid -> func -> layers
    // Optional per-func install tallies from structured lines
    std::map<std::string, int> installOk;
    std::map<std::string, int> installFail;
    std::string line;
    std::string currentPid;
    std::string lastFunc;
    while (std::getline(in, line)) {
        size_t pidPos = line.find("[PID:");
        if (pidPos != std::string::npos) {
            size_t end = line.find(']', pidPos + 5);
            if (end != std::string::npos) {
                currentPid = line.substr(pidPos + 5, end - (pidPos + 5));
            }
        }
        auto instPos = line.find("Hook installed: ");
        if (instPos != std::string::npos) {
            lastFunc = line.substr(instPos + 16);
            continue;
        }
        // Structured install tally: "umh event=install func=<f> layer=<l> status=<s>"
        auto umhPos = line.find("umh event=install ");
        if (umhPos != std::string::npos) {
            // naive parse
            auto fpos = line.find(" func=", umhPos);
            auto lpos = line.find(" layer=", umhPos);
            auto spos = line.find(" status=", umhPos);
            if (fpos != std::string::npos) {
                size_t fstart = fpos + 6;
                size_t fend = (lpos != std::string::npos ? lpos : line.size());
                std::string fn = line.substr(fstart, fend - fstart);
                // trim
                while (!fn.empty() && fn.back()==' ') fn.pop_back();
                if (spos != std::string::npos) {
                    size_t sstart = spos + 8;
                    size_t send = line.find(' ', sstart);
                    std::string status = line.substr(sstart, (send==std::string::npos? line.size()-sstart : send - sstart));
                    if (status == "success") installOk[fn]++; else if (status == "fail") installFail[fn]++;
                }
            }
        }
        if (!lastFunc.empty()) {
            auto layPos = line.find("Layers:");
            if (layPos != std::string::npos) {
                std::string layers = line.substr(layPos + 7);
                while (!layers.empty() && (layers[0] == ' ' || layers[0] == '\t')) layers.erase(0,1);
                while (!layers.empty() && (layers.back() == ' ' || layers.back() == '\r' || layers.back() == '\n')) layers.pop_back();
                snapshot[currentPid][lastFunc] = layers;
                lastFunc.clear();
            }
        }
    }
    in.close();

    std::ofstream out(apiLogPath, std::ios::app);
    if (!out.is_open()) {
        return;
    }
    SYSTEMTIME st{}; GetLocalTime(&st);
    for (const auto& pidEntry : snapshot) {
        const std::string& pid = pidEntry.first;
        for (const auto& fnEntry : pidEntry.second) {
            out << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
                << "umh event=snapshot pid=" << pid
                << " func=" << fnEntry.first
                << " layers=\"" << fnEntry.second << "\"";
            auto okIt = installOk.find(fnEntry.first);
            auto failIt = installFail.find(fnEntry.first);
            if (okIt != installOk.end() || failIt != installFail.end()) {
                out << " install_ok=" << (okIt!=installOk.end()? okIt->second : 0)
                    << " install_fail=" << (failIt!=installFail.end()? failIt->second : 0);
            }
            out << std::endl;
        }
    }
    out.flush();
}

int main(int argc, char* argv[]) {
    std::cout << "==========================================\n";
    std::cout << "    System-Wide API Hook Monitor v3.0    \n";
    std::cout << "    SetWindowDisplayAffinity Bypass      \n";
    std::cout << "==========================================\n\n";

    // Check for admin privileges
    BOOL isElevated = FALSE;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isElevated) {
        std::cout << "[!] WARNING: Not running as Administrator\n";
        std::cout << "[!] Some processes cannot be hooked without elevation\n\n";
    }

    // Parse arguments
    std::string dllPath;
    bool aggressive = false;
    bool silent = false;
    bool emitSnapshot = false;
    int durationSeconds = 0;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-d" && i + 1 < argc) {
            dllPath = argv[++i];
        } else if (arg == "-a") {
            aggressive = true;
        } else if (arg == "-t") {
            aggressive = false;
        } else if (arg == "-s") {
            silent = true;
        } else if (arg == "--snapshot") {
            emitSnapshot = true;
        } else if (arg == "--duration" && i + 1 < argc) {
            durationSeconds = std::max(0, atoi(argv[++i]));
        } else if (arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    // Get DLL path if not provided
    if (dllPath.empty()) {
        // Try default location
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir = exePath;
        size_t pos = exeDir.find_last_of("\\/");
        if (pos != std::string::npos) {
            exeDir = exeDir.substr(0, pos);
        }
        dllPath = exeDir + "\\AdvancedHookDLL.dll";

        if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cout << "Enter path to Hook DLL: ";
            std::getline(std::cin, dllPath);
        }
    }

    // Get absolute path
    char fullPath[MAX_PATH];
    if (GetFullPathNameA(dllPath.c_str(), MAX_PATH, fullPath, nullptr)) {
        dllPath = fullPath;
    }

    std::cout << "[*] Hook DLL: " << dllPath << "\n\n";

    // Create monitor
    SystemWideMonitor monitor(dllPath);
    monitor.SetAggressiveMode(aggressive);

    // Start monitoring
    if (!monitor.Start()) {
        std::cout << "[!] Failed to start monitoring\n";
        return 1;
    }

    std::cout << "[+] Monitoring started successfully!\n";
    std::cout << "[*] Mode: " << (aggressive ? "AGGRESSIVE" : "TARGETED") << "\n";
    std::cout << "[*] Scanning and hooking processes...\n";
    const std::string apiLogPath = SystemWideMonitor::ApiLogPath();
    std::cout << "[*] Check " << apiLogPath << " for hook activity\n\n";

    if (silent) {
        std::cout << "[*] Running in background mode\n";
        std::cout << "[*] Press Ctrl+C to stop\n\n";

        if (durationSeconds > 0) {
            auto endTime = std::chrono::steady_clock::now() + std::chrono::seconds(durationSeconds);
            while (std::chrono::steady_clock::now() < endTime) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                std::cout << "\r[*] Status: " << monitor.GetHookedCount() << " processes hooked";
                std::cout.flush();
            }
        } else {
            // Run until interrupted
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                std::cout << "\r[*] Status: " << monitor.GetHookedCount() << " processes hooked";
                std::cout.flush();
            }
        }
    } else {
        // Interactive mode
        std::cout << "Commands:\n";
        std::cout << "  s - Show status\n";
        std::cout << "  r - Rescan all processes\n";
        std::cout << "  a - Toggle aggressive mode\n";
        std::cout << "  q - Quit\n\n";

        bool running = true;
        while (running) {
            std::cout << "> ";

            char command;
            std::cin >> command;

            switch (command) {
                case 's':
                case 'S':
                    monitor.ShowStatus();
                    break;

                case 'r':
                case 'R':
                    std::cout << "[*] Rescanning all processes...\n";
                    monitor.ScanAndHookProcesses();
                    break;

                case 'a':
                case 'A':
                    aggressive = !aggressive;
                    monitor.SetAggressiveMode(aggressive);
                    std::cout << "[*] Mode changed to: " << (aggressive ? "AGGRESSIVE" : "TARGETED") << "\n";
                    break;

                case 'q':
                case 'Q':
                    running = false;
                    break;

                default:
                    std::cout << "[!] Unknown command\n";
            }
        }
    }

    std::cout << "\n[*] Shutting down...\n";
    monitor.Stop();

    if (emitSnapshot) {
        AppendStructuredSnapshot(apiLogPath);
    }
    return 0;
}
