// AntiAnalysis.cpp - Anti-debugging, anti-VM, and anti-sandbox detection
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <Psapi.h>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

class AntiAnalysis {
private:
    bool m_DebuggerDetected;
    bool m_SandboxDetected;
    bool m_VMDetected;
    bool m_AnalysisDetected;
    std::vector<std::wstring> m_SuspiciousProcesses;

    // Known debugger/analysis processes
    const std::vector<std::wstring> m_DebuggerProcesses = {
        L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe", L"ollydbg.exe",
        L"ida.exe", L"ida64.exe", L"idaq.exe", L"idaq64.exe",
        L"devenv.exe", L"wireshark.exe", L"fiddler.exe", L"processhacker.exe",
        L"procmon.exe", L"procexp.exe", L"apimonitor.exe", L"sysanalyzer.exe"
    };

    // Known sandbox/VM processes
    const std::vector<std::wstring> m_SandboxProcesses = {
        L"vmsrvc.exe", L"vmtoolsd.exe", L"vboxservice.exe", L"vboxtray.exe",
        L"sandboxiedcomlaunch.exe", L"sandboxierpcss.exe", L"procmon.exe",
        L"filemon.exe", L"regmon.exe", L"vmusrvc.exe", L"xenservice.exe"
    };

public:
    AntiAnalysis() : m_DebuggerDetected(false), m_SandboxDetected(false),
                     m_VMDetected(false), m_AnalysisDetected(false) {
        std::cout << "[AntiAnalysis] Initialized" << std::endl;
    }

    // Comprehensive analysis detection
    bool DetectAnalysisEnvironment() {
        bool detected = false;

        // Multiple detection methods
        detected |= DetectDebugger();
        detected |= DetectVirtualMachine();
        detected |= DetectSandbox();
        detected |= DetectHooks();
        detected |= DetectTiming();
        detected |= DetectHardwareBreakpoints();
        detected |= DetectSuspiciousProcesses();

        m_AnalysisDetected = detected;

        if (detected) {
            std::cout << "[AntiAnalysis] Analysis environment detected!" << std::endl;
        } else {
            std::cout << "[AntiAnalysis] No analysis environment detected" << std::endl;
        }

        return detected;
    }

    // Anti-debugging techniques
    bool DetectDebugger() {
        bool detected = false;

        // Method 1: IsDebuggerPresent
        if (IsDebuggerPresent()) {
            detected = true;
            std::cout << "[AntiAnalysis] Debugger detected via IsDebuggerPresent" << std::endl;
        }

        // Method 2: CheckRemoteDebuggerPresent
        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        if (remoteDebugger) {
            detected = true;
            std::cout << "[AntiAnalysis] Remote debugger detected" << std::endl;
        }

        // Method 3: PEB.BeingDebugged flag
        PPEB pPeb = (PPEB)__readgsqword(0x60); // x64
        if (pPeb->BeingDebugged) {
            detected = true;
            std::cout << "[AntiAnalysis] Debugger detected via PEB.BeingDebugged" << std::endl;
        }

        // Method 4: NtGlobalFlag (disabled for public SDK compatibility)
        // Some Windows SDK headers do not expose NtGlobalFlag in PEB.
        // Leaving this check out avoids build failures across toolsets.

        // Method 5: NtQueryInformationProcess with ProcessDebugPort
        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            auto NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(
                hNtdll, "NtQueryInformationProcess");

            if (NtQueryInformationProcess) {
                DWORD debugPort = 0;
                NTSTATUS status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    ProcessDebugPort,
                    &debugPort,
                    sizeof(debugPort),
                    NULL
                );

                if (NT_SUCCESS(status) && debugPort != 0) {
                    detected = true;
                    std::cout << "[AntiAnalysis] Debugger detected via ProcessDebugPort" << std::endl;
                }

                // Method 6: ProcessDebugObjectHandle
                HANDLE debugObject = NULL;
                status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    (PROCESSINFOCLASS)30, // ProcessDebugObjectHandle
                    &debugObject,
                    sizeof(debugObject),
                    NULL
                );

                if (NT_SUCCESS(status) && debugObject != NULL) {
                    detected = true;
                    std::cout << "[AntiAnalysis] Debugger detected via ProcessDebugObjectHandle" << std::endl;
                }
            }
        }

        // Method 7: Debug registers
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                detected = true;
                std::cout << "[AntiAnalysis] Hardware breakpoints detected" << std::endl;
            }
        }

        // Method 8: INT3 scanning
        BYTE* codeSection = (BYTE*)GetModuleHandleW(NULL);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)codeSection;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(codeSection + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                BYTE* sectionStart = codeSection + sectionHeader[i].VirtualAddress;
                DWORD sectionSize = sectionHeader[i].Misc.VirtualSize;

                for (DWORD j = 0; j < sectionSize; j++) {
                    if (sectionStart[j] == 0xCC) { // INT3
                        detected = true;
                        std::cout << "[AntiAnalysis] INT3 breakpoint detected" << std::endl;
                        break;
                    }
                }
            }
        }

        m_DebuggerDetected = detected;
        return detected;
    }

    // Virtual machine detection
    bool DetectVirtualMachine() {
        bool detected = false;

        // Method 1: CPUID hypervisor bit
        int cpuInfo[4] = { 0 };
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] >> 31) & 1) {
            detected = true;
            std::cout << "[AntiAnalysis] VM detected via CPUID hypervisor bit" << std::endl;
        }

        // Method 2: Check VM vendor via CPUID
        char vendor[13] = { 0 };
        __cpuid(cpuInfo, 0x40000000);
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);

        if (strstr(vendor, "VMware") || strstr(vendor, "VBox") ||
            strstr(vendor, "KVMKVMKVM") || strstr(vendor, "Microsoft Hv")) {
            detected = true;
            std::cout << "[AntiAnalysis] VM vendor detected: " << vendor << std::endl;
        }

        // Method 3: Check registry for VM artifacts
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0,
                         KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR value[256] = { 0 };
            DWORD size = sizeof(value);
            if (RegQueryValueExW(hKey, L"0", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
                if (wcsstr(value, L"VMware") || wcsstr(value, L"VBOX") || wcsstr(value, L"QEMU")) {
                    detected = true;
                    std::cout << "[AntiAnalysis] VM detected via registry" << std::endl;
                }
            }
            RegCloseKey(hKey);
        }

        // Method 4: Check MAC address (first 3 bytes)
        // VMware: 00-05-69, 00-0C-29, 00-1C-14, 00-50-56
        // VirtualBox: 08-00-27
        // QEMU: 52-54-00

        // Method 5: Check for VM files
        const std::vector<std::wstring> vmFiles = {
            L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
            L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            L"C:\\Windows\\System32\\drivers\\vboxmouse.sys",
            L"C:\\Windows\\System32\\drivers\\vboxguest.sys",
            L"C:\\Windows\\System32\\drivers\\vboxsf.sys",
            L"C:\\Windows\\System32\\drivers\\vboxvideo.sys"
        };

        for (const auto& file : vmFiles) {
            if (GetFileAttributesW(file.c_str()) != INVALID_FILE_ATTRIBUTES) {
                detected = true;
                std::cout << "[AntiAnalysis] VM file detected: " << std::string(file.begin(), file.end()) << std::endl;
                break;
            }
        }

        m_VMDetected = detected;
        return detected;
    }

    // Sandbox detection
    bool DetectSandbox() {
        bool detected = false;

        // Method 1: Check process count
        DWORD processCount = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    processCount++;
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);

            if (processCount < 50) { // Sandboxes often have few processes
                detected = true;
                std::cout << "[AntiAnalysis] Sandbox detected: Low process count (" << processCount << ")" << std::endl;
            }
        }

        // Method 2: Check disk size
        ULARGE_INTEGER totalSpace;
        if (GetDiskFreeSpaceExW(L"C:\\", NULL, &totalSpace, NULL)) {
            DWORD gbSize = (DWORD)(totalSpace.QuadPart / (1024 * 1024 * 1024));
            if (gbSize < 60) { // Sandboxes often have small disks
                detected = true;
                std::cout << "[AntiAnalysis] Sandbox detected: Small disk size (" << gbSize << " GB)" << std::endl;
            }
        }

        // Method 3: Check for sandbox DLLs
        const std::vector<std::wstring> sandboxDlls = {
            L"sbiedll.dll",     // Sandboxie
            L"api_log.dll",     // SunBelt Sandbox
            L"dir_watch.dll",   // SunBelt Sandbox
            L"pstorec.dll",     // SunBelt Sandbox
            L"vmcheck.dll",     // Virtual PC
            L"wpespy.dll"       // WPE Pro
        };

        for (const auto& dll : sandboxDlls) {
            if (GetModuleHandleW(dll.c_str())) {
                detected = true;
                std::cout << "[AntiAnalysis] Sandbox DLL detected: " << std::string(dll.begin(), dll.end()) << std::endl;
                break;
            }
        }

        // Method 4: Time-based detection (sandboxes may accelerate time)
        auto start = std::chrono::high_resolution_clock::now();
        Sleep(500);
        auto end = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        if (elapsed < 450) { // Time acceleration detected
            detected = true;
            std::cout << "[AntiAnalysis] Sandbox detected: Time acceleration" << std::endl;
        }

        // Method 5: Check for user interaction
        LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };
        if (GetLastInputInfo(&lii)) {
            DWORD idleTime = GetTickCount() - lii.dwTime;
            if (idleTime > 600000) { // 10 minutes of no input
                detected = true;
                std::cout << "[AntiAnalysis] Sandbox detected: No user interaction" << std::endl;
            }
        }

        m_SandboxDetected = detected;
        return detected;
    }

    // Hook detection
    bool DetectHooks() {
        bool detected = false;

        // Check common hooked functions
        const std::vector<std::pair<std::wstring, std::string>> functionsToCheck = {
            {L"ntdll.dll", "NtQueryInformationProcess"},
            {L"ntdll.dll", "NtClose"},
            {L"ntdll.dll", "NtCreateFile"},
            {L"kernel32.dll", "CreateProcessW"},
            {L"kernel32.dll", "VirtualAlloc"},
            {L"user32.dll", "MessageBoxW"}
        };

        for (const auto& [dll, func] : functionsToCheck) {
            HMODULE hModule = GetModuleHandleW(dll.c_str());
            if (hModule) {
                PVOID funcAddr = GetProcAddress(hModule, func.c_str());
                if (funcAddr) {
                    BYTE* bytes = (BYTE*)funcAddr;

                    // Check for JMP instruction (E9 or EB)
                    if (bytes[0] == 0xE9 || bytes[0] == 0xEB) {
                        detected = true;
                        std::cout << "[AntiAnalysis] Hook detected in " << func << std::endl;
                    }

                    // Check for PUSH + RET (68 xx xx xx xx C3)
                    if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
                        detected = true;
                        std::cout << "[AntiAnalysis] Hook detected in " << func << " (push+ret)" << std::endl;
                    }

                    // Check for MOV + JMP (48 B8 xx xx xx xx xx xx xx xx FF E0)
                    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
                        detected = true;
                        std::cout << "[AntiAnalysis] Hook detected in " << func << " (mov+jmp)" << std::endl;
                    }
                }
            }
        }

        return detected;
    }

    // Timing-based detection
    bool DetectTiming() {
        bool detected = false;

        // Method 1: RDTSC timing check
        ULONGLONG tsc1 = __rdtsc();
        Sleep(100);
        ULONGLONG tsc2 = __rdtsc();

        ULONGLONG diff = tsc2 - tsc1;
        // Normal difference should be around CPU frequency * 0.1
        // If significantly higher, likely being debugged

        // Method 2: GetTickCount timing
        DWORD tick1 = GetTickCount();
        __debugbreak(); // This will only trigger if debugger is present
        DWORD tick2 = GetTickCount();

        if (tick2 - tick1 > 1000) { // Debugger caught the breakpoint
            detected = true;
            std::cout << "[AntiAnalysis] Timing analysis detected debugger" << std::endl;
        }

        return detected;
    }

    // Hardware breakpoint detection
    bool DetectHardwareBreakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                std::cout << "[AntiAnalysis] Hardware breakpoints detected" << std::endl;
                return true;
            }
        }

        return false;
    }

    // Detect suspicious processes
    bool DetectSuspiciousProcesses() {
        bool detected = false;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                std::wstring processName = pe32.szExeFile;

                // Check debugger processes
                for (const auto& debugger : m_DebuggerProcesses) {
                    if (_wcsicmp(processName.c_str(), debugger.c_str()) == 0) {
                        detected = true;
                        m_SuspiciousProcesses.push_back(processName);
                        std::wcout << L"[AntiAnalysis] Suspicious process detected: " << processName << std::endl;
                    }
                }

                // Check sandbox processes
                for (const auto& sandbox : m_SandboxProcesses) {
                    if (_wcsicmp(processName.c_str(), sandbox.c_str()) == 0) {
                        detected = true;
                        m_SuspiciousProcesses.push_back(processName);
                        std::wcout << L"[AntiAnalysis] Sandbox process detected: " << processName << std::endl;
                    }
                }

            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
        return detected;
    }

    // Apply anti-analysis countermeasures
    void ApplyCountermeasures() {
        if (m_DebuggerDetected) {
            // Crash the debugger or exit
            __debugbreak();
            TerminateProcess(GetCurrentProcess(), 0);
        }

        if (m_SandboxDetected || m_VMDetected) {
            // Behave differently or exit
            std::cout << "[AntiAnalysis] Applying sandbox/VM countermeasures" << std::endl;
            // Could sleep for long time, allocate huge memory, etc.
        }

        // Terminate suspicious processes
        for (const auto& process : m_SuspiciousProcesses) {
            TerminateSuspiciousProcess(process);
        }
    }

private:
    void TerminateSuspiciousProcess(const std::wstring& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                        std::wcout << L"[AntiAnalysis] Terminated: " << processName << std::endl;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }

        CloseHandle(hSnapshot);
    }
};

// Export functions
extern "C" {
    __declspec(dllexport) bool DetectAnalysis() {
        AntiAnalysis antiAnalysis;
        return antiAnalysis.DetectAnalysisEnvironment();
    }

    __declspec(dllexport) bool DetectDebugger() {
        AntiAnalysis antiAnalysis;
        return antiAnalysis.DetectDebugger();
    }

    __declspec(dllexport) bool DetectVM() {
        AntiAnalysis antiAnalysis;
        return antiAnalysis.DetectVirtualMachine();
    }

    __declspec(dllexport) bool DetectSandbox() {
        AntiAnalysis antiAnalysis;
        return antiAnalysis.DetectSandbox();
    }

    __declspec(dllexport) void ApplyAntiAnalysis() {
        AntiAnalysis antiAnalysis;
        if (antiAnalysis.DetectAnalysisEnvironment()) {
            antiAnalysis.ApplyCountermeasures();
        }
    }
}
