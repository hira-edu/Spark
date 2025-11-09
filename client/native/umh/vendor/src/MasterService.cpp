// MasterService.cpp - Windows Service for Advanced Ring 3 Hook Framework
#include <Windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <algorithm>
#include <memory>
#include <atomic>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Wtsapi32.h>
#include <UserEnv.h>
#include <Shlwapi.h>
#include <wintrust.h>
#include <Softpub.h>
#include <Rpc.h>
#include <fstream>
#include <string>
#include <thread>
#include <map>
#include <cstring>

#include "../include/InjectionEngine.h"
#include "../include/ManualMapInjector.h"
#include "../include/ETWMonitor.h"
#include "../include/ControlServer.h"
#include "../include/Policy.h"
#include "../include/EtwApiWatch.h"
#include "../include/PipeNames.h"
#include "../include/ProcessTargets.h"
#include "../include/UmhResources.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Rpcrt4.lib")

// Service configuration
#define SERVICE_NAME L"AdvancedHookService"

static std::wstring GenerateRandomToken(const wchar_t* prefix) {
    GUID guid{};
    if (UuidCreate(&guid) != RPC_S_OK) {
        return std::wstring(prefix ? prefix : L"S") + std::to_wstring(GetTickCount64());
    }
    RPC_WSTR rpcStr = nullptr;
    if (UuidToStringW(&guid, &rpcStr) != RPC_S_OK) {
        return std::wstring(prefix ? prefix : L"S") + std::to_wstring(GetTickCount64());
    }
    std::wstring token(reinterpret_cast<const wchar_t*>(rpcStr));
    RpcStringFreeW(&rpcStr);
    token.erase(std::remove(token.begin(), token.end(), L'-'), token.end());
    std::wstring result;
    if (prefix && *prefix) {
        result.assign(prefix);
        if (result.back() != L'_') {
            result.push_back(L'_');
        }
    } else {
        result = L"S_";
    }
    result.append(token);
    return result;
}
#define SERVICE_DISPLAY_NAME L"Advanced Ring 3 Hook Framework"
#define SERVICE_START_TYPE SERVICE_AUTO_START
#define SERVICE_ACCOUNT L"LocalSystem"

class MasterService {
private:
    SERVICE_STATUS serviceStatus;
    SERVICE_STATUS_HANDLE statusHandle;
    HANDLE stopEvent;
    std::atomic<bool> isRunning;
    std::mutex serviceMutex;
    std::mutex processListMutex;

    // ETW session data

    // Process monitoring
    std::vector<DWORD> monitoredProcesses;
    std::wstring hookDllPath;
    std::wstring agentPath_;
    std::wstring agentArgs_;
    HANDLE agentProcess_ = nullptr;
    bool multiSession_ = false;
    std::map<DWORD, HANDLE> agentsBySession_;
    HANDLE pipeThread_ = nullptr;
    injection::InjectionEngine injectionEngine;
    std::unique_ptr<etw::ETWMonitor> processMonitor;
    ControlServer control_;
    UmhPolicy policy_;
    std::map<DWORD,int> attemptsByPid_;
    std::wstring artifactsBasePath_;
    std::wstring embeddedHookDllPath_;
    std::wstring embeddedAgentPath_;
    std::wstring embeddedInjectorPath_;
    std::wstring embeddedCliPath_;
    std::wstring embeddedDriverPath_;

    std::wstring ResolveArtifactsBaseDir() const;
    bool EnsureDirectoryExists(const std::wstring& path);
    bool MaterializeResourceToFile(int resourceId,
                                   const std::wstring& fileName,
                                   std::wstring* outPath,
                                   bool optional = false,
                                   bool* wroteFile = nullptr);
    bool MaterializeEmbeddedArtifacts();

public:
    static MasterService* instance;

    MasterService() : stopEvent(nullptr), isRunning(false) {
        instance = this;
        injectionEngine.SetLogger([this](const std::wstring& message) {
            LogEvent(message, EVENTLOG_INFORMATION_TYPE);
        });
    }

    ~MasterService() {
        if (stopEvent) {
            CloseHandle(stopEvent);
        }
    }

    // Service control handler
    static DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
                                           LPVOID eventData, LPVOID context) {
        UNREFERENCED_PARAMETER(eventType);
        UNREFERENCED_PARAMETER(eventData);
        UNREFERENCED_PARAMETER(context);
        switch (control) {
            case SERVICE_CONTROL_STOP:
            case SERVICE_CONTROL_SHUTDOWN:
                if (instance) {
                    instance->StopService();
                }
                return NO_ERROR;

            case SERVICE_CONTROL_INTERROGATE:
                return NO_ERROR;

            default:
                return ERROR_CALL_NOT_IMPLEMENTED;
        }
    }

    // Service main function
    static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
        if (instance) {
            instance->Run(argc, argv);
        }
    }

    void Run(DWORD argc, LPWSTR* argv) {
        UNREFERENCED_PARAMETER(argc);
        UNREFERENCED_PARAMETER(argv);
        // Register service control handler
        statusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceCtrlHandler, this);
        if (!statusHandle) {
            LogEvent(L"Failed to register service control handler", EVENTLOG_ERROR_TYPE);
            return;
        }

        // Initialize service status
        serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        serviceStatus.dwCurrentState = SERVICE_START_PENDING;
        serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        serviceStatus.dwWin32ExitCode = 0;
        serviceStatus.dwServiceSpecificExitCode = 0;
        serviceStatus.dwCheckPoint = 0;
        serviceStatus.dwWaitHint = 0;

        SetServiceStatus(statusHandle, &serviceStatus);

        // Create stop event
        stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!stopEvent) {
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            serviceStatus.dwWin32ExitCode = GetLastError();
            SetServiceStatus(statusHandle, &serviceStatus);
            return;
        }

        // Initialize components
        if (!Initialize()) {
            serviceStatus.dwCurrentState = SERVICE_STOPPED;
            serviceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
            serviceStatus.dwServiceSpecificExitCode = 1;
            SetServiceStatus(statusHandle, &serviceStatus);
            return;
        }

        // Report running status
        serviceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(statusHandle, &serviceStatus);

        LogEvent(L"Advanced Hook Service started successfully", EVENTLOG_INFORMATION_TYPE);

        // Start control server for remote GUI/CLI integration
        control_.Start(stopEvent, hookDllPath, &injectionEngine);

        // Main service loop
        ServiceLoop();

        // Cleanup
        Cleanup();
        control_.Stop();

        // Report stopped status
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(statusHandle, &serviceStatus);
    }

bool Initialize() {
        if (!MaterializeEmbeddedArtifacts()) {
            LogEvent(L"Failed to materialize embedded UMH artifacts", EVENTLOG_ERROR_TYPE);
            return false;
        }
        hookDllPath = GetHookDllPath();
        LoadAgentConfig(embeddedAgentPath_);

        if (!InitializeInjectionEngine()) {
            return false;
        }
        // Ensure default policy exists (first run)
        {
            wchar_t pd[MAX_PATH] = {};
            DWORD n = GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH);
            std::wstring base = (n && n<MAX_PATH) ? std::wstring(pd, pd+n) : L"C:\\ProgramData";
            std::wstring dir = base + L"\\UserModeHook";
            CreateDirectoryW(dir.c_str(), nullptr);
            std::wstring polPath = dir + L"\\policy.json";
            if (GetFileAttributesW(polPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
                wchar_t mod[MAX_PATH] = {};
                if (GetModuleFileNameW(nullptr, mod, MAX_PATH)) {
                    PathRemoveFileSpecW(mod);
                    std::wstring def = std::wstring(mod) + L"\\configs\\policy.default.json";
                    if (GetFileAttributesW(def.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        CopyFileW(def.c_str(), polPath.c_str(), TRUE);
                    }
                }
            }
        }
        // Load policy and apply process allowlist overrides
        policy_ = policy::LoadPolicy();
        if (umh::HasProcessTargetFilter()) {
            auto targets = umh::GetProcessTargets();
            policy_.includePatterns = targets;
            LogEvent(L"Process allowlist active (" + std::to_wstring(targets.size()) + L" entries)",
                     EVENTLOG_INFORMATION_TYPE);
        }
        // Prefer spawning UnifiedAgent in active user session. Fallback to ETW if spawn fails.
        if (multiSession_) {
            SpawnAgentsForAllSessions();
            // Supervisor per-session
            std::thread([this]() {
                while (WaitForSingleObject(stopEvent, 1000) == WAIT_TIMEOUT) {
                    // Detect new sessions and spawn
                    DWORD count = 0; PWTS_SESSION_INFO pSessions = nullptr;
                    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count)) {
                        std::map<DWORD, bool> seen;
                        for (DWORD i = 0; i < count; ++i) {
                            DWORD sid = pSessions[i].SessionId;
                            if (pSessions[i].State != WTSActive) continue;
                            seen[sid] = true;
                            if (agentsBySession_.find(sid) == agentsBySession_.end()) {
                                SpawnUnifiedAgentForSession(sid);
                            }
                        }
                        // Reap exited agents and remove for sessions not seen
                        for (auto it = agentsBySession_.begin(); it != agentsBySession_.end(); ) {
                            if (!seen[it->first]) {
                                if (it->second) { TerminateProcess(it->second, 0); CloseHandle(it->second); }
                                it = agentsBySession_.erase(it);
                            } else {
                                DWORD code = STILL_ACTIVE;
                                if (it->second && GetExitCodeProcess(it->second, &code) && code != STILL_ACTIVE) {
                                    CloseHandle(it->second);
                                    it = agentsBySession_.erase(it);
                                } else {
                                    ++it;
                                }
                            }
                        }
                        WTSFreeMemory(pSessions);
                    }
                }
                // Cleanup on stop
                for (auto& kv : agentsBySession_) { if (kv.second) { TerminateProcess(kv.second, 0); CloseHandle(kv.second); } }
                agentsBySession_.clear();
            }).detach();
        } else if (!SpawnUnifiedAgent()) {
            LogEvent(L"UnifiedAgent spawn failed; falling back to ETW-based monitoring", EVENTLOG_WARNING_TYPE);
            processMonitor = std::make_unique<etw::ETWMonitor>(L"AdvancedHookETW");
            processMonitor->SetProcessCreateCallback([this](DWORD pid, const std::wstring&, DWORD) {
                if (!isRunning.load(std::memory_order_acquire)) { return; }
                if (!ShouldInjectIntoProcess(pid)) { return; }
                std::thread([this, pid]() { if (!isRunning.load(std::memory_order_acquire)) return; InjectIntoProcess(pid); }).detach();
            });
            processMonitor->SetProcessTerminateCallback([this](DWORD pid, const std::wstring&, DWORD) {
                std::lock_guard<std::mutex> lock(processListMutex);
                auto it = std::remove(monitoredProcesses.begin(), monitoredProcesses.end(), pid);
                if (it != monitoredProcesses.end()) { monitoredProcesses.erase(it, monitoredProcesses.end()); }
            });
            if (!processMonitor->Start()) {
                LogEvent(L"Failed to start ETW monitor; no monitoring active", EVENTLOG_ERROR_TYPE);
                processMonitor.reset();
            }
            std::thread monitorThread(&MasterService::MonitoringThread, this);
            monitorThread.detach();
        } else {
            // Supervisor thread to restart agent if it exits
            std::thread([this]() {
                while (WaitForSingleObject(stopEvent, 1000) == WAIT_TIMEOUT) {
                    if (agentProcess_) {
                        DWORD code = STILL_ACTIVE;
                        if (GetExitCodeProcess(agentProcess_, &code) && code != STILL_ACTIVE) {
                            CloseHandle(agentProcess_); agentProcess_ = nullptr;
                            SpawnUnifiedAgent();
                        }
                    }
                }
                if (agentProcess_) { TerminateProcess(agentProcess_, 0); CloseHandle(agentProcess_); agentProcess_ = nullptr; }
            }).detach();
        }

        // Start service telemetry pipe server (aggregates HookDLL pipes)
        std::thread([this]() {
            const wchar_t* pipeName = L"\\\\.\\pipe\\umh_service";
            while (WaitForSingleObject(stopEvent, 0) == WAIT_TIMEOUT) {
                OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                HANDLE pipe = CreateNamedPipeW(pipeName,
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1, 64 * 1024, 64 * 1024, 5000, nullptr);
                if (pipe == INVALID_HANDLE_VALUE) {
                    if (ov.hEvent) CloseHandle(ov.hEvent);
                    Sleep(250);
                    continue;
                }
                BOOL ok = ConnectNamedPipe(pipe, &ov);
                DWORD gle = ok ? ERROR_SUCCESS : GetLastError();
                if (!ok && gle == ERROR_IO_PENDING) {
                    HANDLE waitObjs[2] = { stopEvent, ov.hEvent };
                    DWORD wr = WaitForMultipleObjects(2, waitObjs, FALSE, 5000);
                    if (wr == WAIT_OBJECT_0) {
                        CancelIoEx(pipe, &ov);
                        CloseHandle(pipe);
                        CloseHandle(ov.hEvent);
                        break;
                    }
                } else if (!ok && gle != ERROR_PIPE_CONNECTED) {
                    CloseHandle(pipe); if (ov.hEvent) CloseHandle(ov.hEvent); continue;
                }

                // Read request (ignored for now)
                char req[32] = {};
                DWORD rb = 0; ReadFile(pipe, req, sizeof(req)-1, &rb, nullptr);

                // Aggregate telemetry by probing HookDLL pipes per process
                // JSON: { "time":"...","telemetry":{ pid: <json>, ... } }
                SYSTEMTIME st{}; GetLocalTime(&st);
                std::wstring out = L"{\"time\":\"" +
                    std::to_wstring(st.wHour) + L":" + std::to_wstring(st.wMinute) + L":" + std::to_wstring(st.wSecond) + L"\",\"telemetry\":{";

                std::vector<DWORD> snapshotPids;
                {
                    std::lock_guard<std::mutex> lock(processListMutex);
                    snapshotPids = monitoredProcesses;
                }

                bool first = true;
                for (DWORD pid : snapshotPids) {
                    wchar_t pname[128] = {};
                    pipes::FormatTelemetryPipe(pname, _countof(pname), pid);
                    if (!WaitNamedPipeW(pname, 10)) {
                        continue;
                    }
                    HANDLE ph = CreateFileW(pname, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (ph == INVALID_HANDLE_VALUE) {
                        continue;
                    }
                    const char* g = "GET\n"; DWORD wr = 0; WriteFile(ph, g, 4, &wr, nullptr);
                    std::string buf; buf.resize(64 * 1024);
                    DWORD rd = 0;
                    if (ReadFile(ph, buf.data(), (DWORD)buf.size() - 1, &rd, nullptr)) {
                        buf[rd] = '\0';
                        std::wstring wbuf(buf.begin(), buf.begin() + rd);
                        std::wstring esc; esc.reserve(wbuf.size() + 8);
                        for (wchar_t c : wbuf) {
                            if (c == L'\\') esc += L"\\\\";
                            else if (c == L'"') esc += L"\\\"";
                            else if (c == L'\n') esc += L"\\n";
                            else if (c == L'\r') esc += L"\\r";
                            else esc += c;
                        }
                        if (!first) out += L","; first = false;
                        out += L"\"" + std::to_wstring(pid) + L"\":\"" + esc + L"\"";
                    }
                    CloseHandle(ph);
                }

                out += L"}}";
                // Write wide JSON as UTF-8
                int need = WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), nullptr, 0, nullptr, nullptr);
                if (need > 0) {
                    std::string jsonA((size_t)need, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), jsonA.data(), need, nullptr, nullptr);
                    DWORD wb = 0; WriteFile(pipe, jsonA.data(), (DWORD)jsonA.size(), &wb, nullptr);
                }
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                if (ov.hEvent) CloseHandle(ov.hEvent);
            }
        }).detach();

        // Start ETW API watches based on policy
        for (const auto& w : policy_.watches) {
            if (w.providerGuid.empty()) continue;
            std::wstring sessionName = GenerateRandomToken(L"ETW");
            auto cb = [this, label=w.label](DWORD pid, USHORT eventId){
                std::wstring msg = L"ETW watch hit (" + label + L") pid=" + std::to_wstring(pid) + L" eid=" + std::to_wstring(eventId);
                LogEvent(msg, EVENTLOG_INFORMATION_TYPE);
                if (ShouldInjectIntoProcess(pid)) {
                    InjectIntoProcess(pid);
                }
            };
            auto watcher = std::make_unique<EtwApiWatch>();
            // keep watcher alive by allocating and leaking intentionally for service lifetime (or store in a vector member if desired)
            if (watcher->Start(sessionName, w.providerGuid, w.eventIds, cb, w.contains)) {
                watcher.release();
            }
        }

        isRunning.store(true, std::memory_order_release);
        return true;
    }

    bool InitializeInjectionEngine() {
        // Initialize various injection methods
        LogEvent(L"Initializing advanced injection engine", EVENTLOG_INFORMATION_TYPE);

        // Verify hook DLL exists
        if (GetFileAttributesW(hookDllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LogEvent(L"Hook DLL not found: " + hookDllPath, EVENTLOG_ERROR_TYPE);
            return false;
        }

        // Optional signature enforcement
        if (policy_.requireSignedDll) {
            WINTRUST_FILE_INFO fileInfo{}; fileInfo.cbStruct = sizeof(fileInfo); fileInfo.pcwszFilePath = hookDllPath.c_str();
            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA data{}; data.cbStruct = sizeof(data); data.dwUIChoice = WTD_UI_NONE; data.fdwRevocationChecks = WTD_REVOKE_NONE; data.dwUnionChoice = WTD_CHOICE_FILE; data.pFile = &fileInfo; data.dwStateAction = 0; data.dwProvFlags = WTD_SAFER_FLAG;
            LONG st = WinVerifyTrust(nullptr, &action, &data);
            if (st != ERROR_SUCCESS) {
                LogEvent(L"Hook DLL signature verification failed", EVENTLOG_ERROR_TYPE);
                return false;
            }
        }

        return true;
    }

    void ServiceLoop() {
        while (WaitForSingleObject(stopEvent, 1000) == WAIT_TIMEOUT) {
            // Process any pending injection requests
            ProcessInjectionQueue();

            // Clean up terminated processes
            CleanupTerminatedProcesses();

            // Check service health
            PerformHealthCheck();
        }
    }

    void MonitoringThread() {
        LogEvent(L"Monitoring thread started", EVENTLOG_INFORMATION_TYPE);

        while (isRunning.load(std::memory_order_acquire)) {
            // Scan for new processes
            ScanAndInjectProcesses();

            // Sleep with interruption capability
            for (int i = 0; i < 20 && isRunning.load(std::memory_order_acquire); i++) {
                Sleep(100);
            }
        }

        LogEvent(L"Monitoring thread stopped", EVENTLOG_INFORMATION_TYPE);
    }

    void ScanAndInjectProcesses() {
        DWORD processes[1024], bytesNeeded, processCount;

        if (!EnumProcesses(processes, sizeof(processes), &bytesNeeded)) {
            return;
        }

        processCount = bytesNeeded / sizeof(DWORD);

        for (unsigned int i = 0; i < processCount; i++) {
            if (processes[i] == 0 || processes[i] == 4) {
                continue; // Skip system processes
            }

            bool alreadyMonitored = false;
            {
                std::lock_guard<std::mutex> lock(processListMutex);
                alreadyMonitored = std::find(monitoredProcesses.begin(),
                                             monitoredProcesses.end(), processes[i]) != monitoredProcesses.end();
            }

            if (!alreadyMonitored && ShouldInjectIntoProcess(processes[i])) {
                InjectIntoProcess(processes[i]);
            }
        }
    }

    bool ShouldInjectIntoProcess(DWORD pid) {
        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            return false;
        }

        WCHAR processName[MAX_PATH];
        DWORD size = MAX_PATH;

        if (!QueryFullProcessImageNameW(hProcess, 0, processName, &size)) {
            CloseHandle(hProcess);
            return false;
        }

        CloseHandle(hProcess);

        // Check against policy include/exclude patterns
        std::wstring procName = processName;
        std::transform(procName.begin(), procName.end(), procName.begin(), [](wchar_t c){ return static_cast<wchar_t>(towlower(c)); });

        // Skip critical system processes
        if (procName.find(L"csrss.exe") != std::wstring::npos ||
            procName.find(L"smss.exe") != std::wstring::npos ||
            procName.find(L"wininit.exe") != std::wstring::npos ||
            procName.find(L"services.exe") != std::wstring::npos ||
            procName.find(L"lsass.exe") != std::wstring::npos ||
            procName.find(L"advancedhookservice") != std::wstring::npos) {
            return false;
        }

        if (umh::HasProcessTargetFilter() && !umh::IsTargetProcess(procName)) {
            return false;
        }

        // Exclude patterns take precedence
        for (const auto& pat : policy_.excludePatterns) {
            std::wstring p = pat; std::transform(p.begin(), p.end(), p.begin(), ::towlower);
            if (procName.find(p) != std::wstring::npos) return false;
        }
        if (!policy_.includePatterns.empty()) {
            for (const auto& pat : policy_.includePatterns) {
                std::wstring p = pat; std::transform(p.begin(), p.end(), p.begin(), ::towlower);
                if (procName.find(p) != std::wstring::npos) return true;
            }
            return false; // nothing matched include
        }
        return true;
    }

    std::wstring DescribeInjectionMethod(injection::InjectionMethod method) const {
        switch (method) {
        case injection::InjectionMethod::Standard:
            return L"standard";
        case injection::InjectionMethod::ManualMap:
            return L"manual-map";
        case injection::InjectionMethod::Reflective:
            return L"reflective";
        case injection::InjectionMethod::DirectSyscall:
            return L"direct-syscall";
        default:
            return L"unknown";
        }
    }

void InjectIntoProcess(DWORD pid) {
        injection::InjectionOptions options;
        // escalate methods if attempts exceed thresholds: try SectionMap/Standard earlier
        int attempts = 0; if (attemptsByPid_.count(pid)) attempts = attemptsByPid_[pid];
        if (attempts == 0) {
            options.methodOrder = { injection::InjectionMethod::SectionMap, injection::InjectionMethod::Standard };
        } else if (attempts == 1) {
            options.methodOrder = { injection::InjectionMethod::Standard, injection::InjectionMethod::ManualMap };
        } else {
            options.methodOrder = { injection::InjectionMethod::ManualMap, injection::InjectionMethod::Reflective, injection::InjectionMethod::DirectSyscall };
        }
        options.manualMapFlags = static_cast<DWORD>(injection::kManualMapHideFromPeb |
                                                    injection::kManualMapEraseHeaders);

        {
            std::lock_guard<std::mutex> lock(processListMutex);
            if (std::find(monitoredProcesses.begin(), monitoredProcesses.end(), pid) != monitoredProcesses.end()) {
                return;
            }
        }

        auto result = injectionEngine.Inject(pid, hookDllPath, options);
        if (result.success) {
            LogEvent(L"Injection succeeded (" + DescribeInjectionMethod(result.method) +
                     L") for PID " + std::to_wstring(pid) + L": " + result.detail,
                     EVENTLOG_INFORMATION_TYPE);
            std::lock_guard<std::mutex> lock(processListMutex);
            monitoredProcesses.push_back(pid);
            attemptsByPid_.erase(pid);
        } else {
            LogEvent(L"Injection failed for PID " + std::to_wstring(pid) + L": " + result.detail,
                     EVENTLOG_WARNING_TYPE);
            int att = attemptsByPid_[pid] + 1;
            attemptsByPid_[pid] = att;
            if (att >= policy_.maxRetries) {
                LogEvent(L"Injection failed after max retries for PID " + std::to_wstring(pid), EVENTLOG_WARNING_TYPE);
            }
        }
    }

    void ProcessInjectionQueue() {
        // Process any pending injection requests from IPC
    }

    void CleanupTerminatedProcesses() {
        std::lock_guard<std::mutex> lock(processListMutex);
        auto it = monitoredProcesses.begin();
        while (it != monitoredProcesses.end()) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, *it);
            if (!hProcess) {
                it = monitoredProcesses.erase(it);
            } else {
                DWORD exitCode;
                if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                    it = monitoredProcesses.erase(it);
                } else {
                    ++it;
                }
                CloseHandle(hProcess);
            }
        }
    }

    void PerformHealthCheck() {
        // Verify service components are functioning
        static int counter = 0;
        if (++counter >= 60) { // Every minute
            size_t tracked = 0;
            {
                std::lock_guard<std::mutex> lock(processListMutex);
                tracked = monitoredProcesses.size();
            }
            LogEvent(L"Health check: " + std::to_wstring(tracked) +
                    L" processes monitored", EVENTLOG_INFORMATION_TYPE);
            counter = 0;
        }
    }

    void StopService() {
        isRunning.store(false, std::memory_order_release);
        SetEvent(stopEvent);
    }

    void Cleanup() {
        if (processMonitor) {
            processMonitor->Stop();
            processMonitor.reset();
        }

        LogEvent(L"Advanced Hook Service stopped", EVENTLOG_INFORMATION_TYPE);
    }


    std::wstring GetHookDllPath() {
        // Try to read from registry
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SYSTEM\\CurrentControlSet\\Services\\AdvancedHookService",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR path[MAX_PATH];
            DWORD size = sizeof(path);
            if (RegQueryValueExW(hKey, L"HookDllPath", nullptr, nullptr,
                               (LPBYTE)path, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return path;
            }
            RegCloseKey(hKey);
        }

        if (!embeddedHookDllPath_.empty()) {
            return embeddedHookDllPath_;
        }

        // Use default path
        WCHAR modulePath[MAX_PATH];
        GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
        std::wstring path = modulePath;
        size_t pos = path.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            path = path.substr(0, pos + 1);
        }
        return path + L"AdvancedHookDLL.dll";
    }

    void LoadAgentConfig(const std::wstring& defaultAgentPath) {
        // Read AgentPath/AgentArgs from service key if present
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\AdvancedHookService",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR path[MAX_PATH] = {0}; DWORD size = sizeof(path);
            if (RegQueryValueExW(hKey, L"AgentPath", nullptr, nullptr, (LPBYTE)path, &size) == ERROR_SUCCESS) {
                agentPath_ = path;
            }
            WCHAR args[512] = {0}; size = sizeof(args);
            if (RegQueryValueExW(hKey, L"AgentArgs", nullptr, nullptr, (LPBYTE)args, &size) == ERROR_SUCCESS) {
                agentArgs_ = args;
            }
            DWORD multi = 0; DWORD msize = sizeof(multi);
            if (RegQueryValueExW(hKey, L"AgentMultiSession", nullptr, nullptr, (LPBYTE)&multi, &msize) == ERROR_SUCCESS) {
                multiSession_ = (multi != 0);
            } else {
                // String value alternative
                WCHAR ms[16] = {0}; DWORD ss = sizeof(ms);
                if (RegQueryValueExW(hKey, L"AgentMultiSession", nullptr, nullptr, (LPBYTE)ms, &ss) == ERROR_SUCCESS) {
                    std::wstring v(ms); for (auto& c : v) c = (wchar_t)towlower(c);
                    multiSession_ = (v == L"1" || v == L"true" || v == L"yes" || v == L"on");
                }
            }
            RegCloseKey(hKey);
        }
        if (agentPath_.empty()) {
            if (!defaultAgentPath.empty()) {
                agentPath_ = defaultAgentPath;
                return;
            }
            // Default to UnifiedAgent.exe next to service
            WCHAR modulePath[MAX_PATH]; GetModuleFileNameW(nullptr, modulePath, MAX_PATH);
            std::wstring path = modulePath; size_t pos = path.find_last_of(L"\\/");
            if (pos != std::wstring::npos) path = path.substr(0, pos + 1);
            agentPath_ = path + L"UnifiedAgent.exe";
        }
    }

    bool SpawnUnifiedAgent() {
        // Try to obtain user token from the active console session
        DWORD sessionId = WTSGetActiveConsoleSessionId();
        HANDLE userToken = nullptr;
        if (sessionId != 0xFFFFFFFF && WTSQueryUserToken(sessionId, &userToken)) {
            HANDLE primary = nullptr;
            if (DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &primary)) {
                LPVOID env = nullptr; CreateEnvironmentBlock(&env, primary, FALSE);
                std::wstring cmd = L"\"" + agentPath_ + L"\"" + (agentArgs_.empty()? L"" : (L" " + agentArgs_));
                STARTUPINFOW si{}; si.cb = sizeof(si);
                PROCESS_INFORMATION pi{};
                BOOL ok = CreateProcessAsUserW(primary, agentPath_.c_str(), (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, env, nullptr, &si, &pi);
                if (ok) {
                    if (agentProcess_) CloseHandle(agentProcess_);
                    agentProcess_ = pi.hProcess; CloseHandle(pi.hThread);
                    if (env) DestroyEnvironmentBlock(env);
                    CloseHandle(primary); CloseHandle(userToken);
                    LogEvent(L"UnifiedAgent spawned in active session", EVENTLOG_INFORMATION_TYPE);
                    return true;
                }
                if (env) DestroyEnvironmentBlock(env);
                CloseHandle(primary);
            }
            CloseHandle(userToken);
        }
        // Fallback: start in service session (may have limited effect)
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmd = L"\"" + agentPath_ + L"\"" + (agentArgs_.empty()? L"" : (L" " + agentArgs_));
        if (CreateProcessW(agentPath_.c_str(), (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            if (agentProcess_) CloseHandle(agentProcess_);
            agentProcess_ = pi.hProcess; CloseHandle(pi.hThread);
            LogEvent(L"UnifiedAgent spawned in service session", EVENTLOG_INFORMATION_TYPE);
            return true;
        }
        LogEvent(L"Failed to spawn UnifiedAgent", EVENTLOG_ERROR_TYPE);
        return false;
    }

    bool SpawnUnifiedAgentForSession(DWORD sessionId) {
        HANDLE userToken = nullptr;
        if (!WTSQueryUserToken(sessionId, &userToken)) {
            return false;
        }
        HANDLE primary = nullptr; bool okAll = false;
        if (DuplicateTokenEx(userToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &primary)) {
            LPVOID env = nullptr; CreateEnvironmentBlock(&env, primary, FALSE);
            std::wstring cmd = L"\"" + agentPath_ + L"\"" + (agentArgs_.empty()? L"" : (L" " + agentArgs_));
            STARTUPINFOW si{}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            BOOL ok = CreateProcessAsUserW(primary, agentPath_.c_str(), (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, env, nullptr, &si, &pi);
            if (ok) {
                if (agentsBySession_.count(sessionId)) {
                    if (agentsBySession_[sessionId]) CloseHandle(agentsBySession_[sessionId]);
                }
                agentsBySession_[sessionId] = pi.hProcess;
                CloseHandle(pi.hThread);
                okAll = true;
            }
            if (env) DestroyEnvironmentBlock(env);
            CloseHandle(primary);
        }
        CloseHandle(userToken);
        return okAll;
    }

    void SpawnAgentsForAllSessions() {
        DWORD count = 0; PWTS_SESSION_INFO pSessions = nullptr;
        if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count)) {
            for (DWORD i = 0; i < count; ++i) {
                if (pSessions[i].State != WTSActive) continue;
                SpawnUnifiedAgentForSession(pSessions[i].SessionId);
            }
            WTSFreeMemory(pSessions);
        } else {
            // Fallback to single active console
            DWORD sid = WTSGetActiveConsoleSessionId();
            if (sid != 0xFFFFFFFF) SpawnUnifiedAgentForSession(sid);
        }
    }

    void LogEvent(const std::wstring& message, WORD type) {
        HANDLE hEventLog = RegisterEventSourceW(nullptr, SERVICE_NAME);
        if (hEventLog) {
            LPCWSTR messages[1] = { message.c_str() };
            ReportEventW(hEventLog, type, 0, 0, nullptr, 1, 0, messages, nullptr);
            DeregisterEventSource(hEventLog);
        }
    }
};

MasterService* MasterService::instance = nullptr;

std::wstring MasterService::ResolveArtifactsBaseDir() const {
    wchar_t buffer[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"ProgramData", buffer, MAX_PATH);
    std::wstring base = (len && len < MAX_PATH) ? std::wstring(buffer, buffer + len) : L"C:\\ProgramData";
    if (!base.empty() && base.back() != L'\\') {
        base.push_back(L'\\');
    }
    base += L"UserModeHook\\";
    base += umh::resources::kArtifactsSubdir;
    return base;
}

bool MasterService::EnsureDirectoryExists(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    size_t slash = path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        if (!EnsureDirectoryExists(path.substr(0, slash))) {
            return false;
        }
    }
    if (CreateDirectoryW(path.c_str(), nullptr)) {
        return true;
    }
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

bool MasterService::MaterializeResourceToFile(int resourceId,
                                              const std::wstring& fileName,
                                              std::wstring* outPath,
                                              bool optional,
                                              bool* wroteFile) {
    if (wroteFile) {
        *wroteFile = false;
    }
    HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!resource) {
        if (optional) {
            return true;
        }
        LogEvent(L"Missing embedded resource id " + std::to_wstring(resourceId), EVENTLOG_ERROR_TYPE);
        return false;
    }
    DWORD size = SizeofResource(nullptr, resource);
    HGLOBAL handle = LoadResource(nullptr, resource);
    if (!handle) {
        LogEvent(L"Failed to load embedded resource id " + std::to_wstring(resourceId), EVENTLOG_ERROR_TYPE);
        return false;
    }
    const BYTE* data = static_cast<const BYTE*>(LockResource(handle));
    if (!data && size > 0) {
        LogEvent(L"Failed to lock embedded resource id " + std::to_wstring(resourceId), EVENTLOG_ERROR_TYPE);
        return false;
    }

    std::wstring targetPath = artifactsBasePath_;
    if (!targetPath.empty() && targetPath.back() != L'\\') {
        targetPath.push_back(L'\\');
    }
    targetPath += fileName;

    if (!EnsureDirectoryExists(artifactsBasePath_)) {
        LogEvent(L"Unable to prepare artifact directory: " + artifactsBasePath_, EVENTLOG_ERROR_TYPE);
        return false;
    }

    bool needsWrite = true;
    HANDLE existing = CreateFileW(targetPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (existing != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fileSize{};
        if (GetFileSizeEx(existing, &fileSize) && fileSize.QuadPart == static_cast<LONGLONG>(size)) {
            if (size == 0) {
                needsWrite = false;
            } else {
                std::vector<BYTE> buffer(size);
                DWORD bytesRead = 0;
                if (ReadFile(existing, buffer.data(), size, &bytesRead, nullptr) && bytesRead == size) {
                    if (memcmp(buffer.data(), data, size) == 0) {
                        needsWrite = false;
                    }
                }
            }
        }
        CloseHandle(existing);
    }

    if (!needsWrite) {
        if (outPath) {
            *outPath = targetPath;
        }
        return true;
    }

    HANDLE file = CreateFileW(targetPath.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LogEvent(L"Failed to materialize embedded artifact at " + targetPath, EVENTLOG_ERROR_TYPE);
        return false;
    }
    DWORD written = 0;
    BOOL ok = TRUE;
    if (size > 0) {
        ok = WriteFile(file, data, size, &written, nullptr);
    }
    CloseHandle(file);
    if ((!ok) || (size > 0 && written != size)) {
        DeleteFileW(targetPath.c_str());
        LogEvent(L"Short write while materializing embedded artifact at " + targetPath, EVENTLOG_ERROR_TYPE);
        return false;
    }
    if (wroteFile) {
        *wroteFile = true;
    }
    if (outPath) {
        *outPath = targetPath;
    }
    return true;
}

bool MasterService::MaterializeEmbeddedArtifacts() {
    artifactsBasePath_ = ResolveArtifactsBaseDir();
    if (!EnsureDirectoryExists(artifactsBasePath_)) {
        LogEvent(L"Unable to prepare artifact directory: " + artifactsBasePath_, EVENTLOG_ERROR_TYPE);
        return false;
    }

    bool hookUpdated = false;
    bool agentUpdated = false;
    bool injectorUpdated = false;
    bool cliUpdated = false;
    bool driverUpdated = false;

    if (!MaterializeResourceToFile(umh::resources::kResourceHookDll,
                                   umh::resources::kHookDllFileName,
                                   &embeddedHookDllPath_,
                                   false,
                                   &hookUpdated)) {
        return false;
    }

    if (!MaterializeResourceToFile(umh::resources::kResourceUnifiedAgent,
                                   umh::resources::kUnifiedAgentFileName,
                                   &embeddedAgentPath_,
                                   false,
                                   &agentUpdated)) {
        return false;
    }

    MaterializeResourceToFile(umh::resources::kResourceInjector,
                              umh::resources::kInjectorFileName,
                              &embeddedInjectorPath_,
                              true,
                              &injectorUpdated);

    MaterializeResourceToFile(umh::resources::kResourceCli,
                              umh::resources::kCliFileName,
                              &embeddedCliPath_,
                              true,
                              &cliUpdated);

    MaterializeResourceToFile(umh::resources::kResourceDriver,
                              umh::resources::kDriverFileName,
                              &embeddedDriverPath_,
                              true,
                              &driverUpdated);

    if (hookUpdated || agentUpdated || injectorUpdated || cliUpdated || driverUpdated) {
        LogEvent(L"Embedded artifacts refreshed in " + artifactsBasePath_, EVENTLOG_INFORMATION_TYPE);
    }
    if (!embeddedDriverPath_.empty()) {
        LogEvent(L"Embedded driver staged at " + embeddedDriverPath_, EVENTLOG_INFORMATION_TYPE);
    }
    return true;
}

// Service installation function
bool InstallService() {
    SC_HANDLE schSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!schSCManager) {
        std::wcout << L"Failed to open service manager. Run as administrator." << std::endl;
        return false;
    }

    WCHAR path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    SC_HANDLE schService = CreateServiceW(
        schSCManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_START_TYPE,
        SERVICE_ERROR_NORMAL,
        path,
        nullptr,
        nullptr,
        nullptr,
        SERVICE_ACCOUNT,
        nullptr
    );

    if (!schService) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            std::wcout << L"Service already installed." << std::endl;
        } else {
            std::wcout << L"Failed to create service. Error: " << error << std::endl;
        }
        CloseServiceHandle(schSCManager);
        return false;
    }

    std::wcout << L"Service installed successfully." << std::endl;

    // Set service description
    SERVICE_DESCRIPTIONW sd;
    sd.lpDescription = (LPWSTR)L"Advanced Ring 3 Hook Framework for security research";
    ChangeServiceConfig2W(schService, SERVICE_CONFIG_DESCRIPTION, &sd);

    // Start the service
    if (StartService(schService, 0, nullptr)) {
        std::wcout << L"Service started successfully." << std::endl;
    } else {
        std::wcout << L"Failed to start service. Start manually from services.msc" << std::endl;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// Service uninstallation function
bool UninstallService() {
    SC_HANDLE schSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::wcout << L"Failed to open service manager. Run as administrator." << std::endl;
        return false;
    }

    SC_HANDLE schService = OpenServiceW(schSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!schService) {
        std::wcout << L"Service not found." << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }

    // Stop the service
    SERVICE_STATUS status;
    if (ControlService(schService, SERVICE_CONTROL_STOP, &status)) {
        std::wcout << L"Stopping service..." << std::endl;
        Sleep(2000);
    }

    // Delete the service
    if (DeleteService(schService)) {
        std::wcout << L"Service uninstalled successfully." << std::endl;
    } else {
        std::wcout << L"Failed to delete service." << std::endl;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

bool IsServiceInstalled() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }
    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (service) {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return true;
    }
    CloseServiceHandle(scm);
    return false;
}

bool EnsureServiceInstalledInteractive(bool& alreadyInstalled) {
    if (IsServiceInstalled()) {
        alreadyInstalled = true;
        return true;
    }
    alreadyInstalled = false;
    std::wcout << L"Installing " << SERVICE_NAME << L"..." << std::endl;
    return InstallService();
}

bool StartServiceInteractive() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        std::wcout << L"Failed to open service manager (" << GetLastError() << L")" << std::endl;
        return false;
    }
    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        std::wcout << L"Failed to open service (" << GetLastError() << L")" << std::endl;
        CloseServiceHandle(scm);
        return false;
    }
    bool alreadyRunning = false;
    if (!StartServiceW(service, 0, nullptr)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            alreadyRunning = true;
        } else {
            std::wcout << L"Failed to start service (" << error << L")" << std::endl;
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return false;
        }
    }

    if (alreadyRunning) {
        std::wcout << L"Service already running." << std::endl;
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return true;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    const DWORD kMaxWaitMs = 10000;
    DWORD waited = 0;
    bool running = false;
    std::wcout << L"Waiting for service to reach running state..." << std::endl;
    while (QueryServiceStatusEx(service,
                                SC_STATUS_PROCESS_INFO,
                                reinterpret_cast<LPBYTE>(&status),
                                sizeof(status),
                                &bytesNeeded)) {
        if (status.dwCurrentState == SERVICE_RUNNING) {
            running = true;
            break;
        }
        if (status.dwCurrentState != SERVICE_START_PENDING) {
            break;
        }
        if (waited >= kMaxWaitMs) {
            break;
        }
        Sleep(500);
        waited += 500;
    }

    if (running) {
        std::wcout << L"Service started successfully." << std::endl;
    } else {
        std::wcout << L"Service failed to reach running state. Current state: "
                   << status.dwCurrentState << std::endl;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return running;
}

bool HandleInteractiveLaunch() {
    std::wcout << L"Interactive launch detected. Preparing service install/start..." << std::endl;

    bool alreadyInstalled = false;
    if (!EnsureServiceInstalledInteractive(alreadyInstalled)) {
        std::wcout << L"Failed to install service. Try running as administrator." << std::endl;
        return false;
    }

    if (alreadyInstalled) {
        std::wcout << L"Service already installed. Attempting to start it..." << std::endl;
    } else {
        std::wcout << L"Service installed successfully. Starting it now..." << std::endl;
    }

    if (!StartServiceInteractive()) {
        std::wcout << L"Failed to start service." << std::endl;
        return false;
    }

    std::wcout << L"Advanced Hook Service is running in the background. You can close this window."
               << std::endl;
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc > 1) {
        if (wcscmp(argv[1], L"/install") == 0 || wcscmp(argv[1], L"-install") == 0) {
            return InstallService() ? 0 : 1;
        } else if (wcscmp(argv[1], L"/uninstall") == 0 || wcscmp(argv[1], L"-uninstall") == 0) {
            return UninstallService() ? 0 : 1;
        } else if (wcscmp(argv[1], L"/help") == 0 || wcscmp(argv[1], L"-h") == 0) {
            std::wcout << L"Advanced Hook Service" << std::endl;
            std::wcout << L"Usage:" << std::endl;
            std::wcout << L"  /install   - Install the service" << std::endl;
            std::wcout << L"  /uninstall - Uninstall the service" << std::endl;
            std::wcout << L"  (no args)  - Run as service" << std::endl;
            return 0;
        }
    }

    // Run as service
    MasterService service;

    SERVICE_TABLE_ENTRYW serviceTable[] = {
        { (LPWSTR)SERVICE_NAME, MasterService::ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return HandleInteractiveLaunch() ? 0 : 1;
        }
        std::wcout << L"Service dispatcher failed (" << error << L")" << std::endl;
        return 1;
    }

    return 0;
}


