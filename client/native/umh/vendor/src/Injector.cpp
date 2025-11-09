// Injector.cpp - Advanced DLL Injection utility
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <Psapi.h>
#include <memory>

#include "../include/InjectionEngine.h"
#include "../include/ManualMapInjector.h"

#pragma comment(lib, "psapi.lib")

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

namespace {

class UniqueHandle {
public:
    UniqueHandle() noexcept : handle_(nullptr) {}
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const noexcept {
        return handle_;
    }

    HANDLE release() noexcept {
        HANDLE value = handle_;
        handle_ = nullptr;
        return value;
    }

    void reset(HANDLE handle = nullptr) noexcept {
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

    explicit operator bool() const noexcept {
        return handle_ && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

class UniqueModule {
public:
    UniqueModule() noexcept : module_(nullptr), owns_(false) {}
    explicit UniqueModule(HMODULE module, bool owns = true) noexcept : module_(module), owns_(owns) {}
    ~UniqueModule() { reset(); }

    UniqueModule(const UniqueModule&) = delete;
    UniqueModule& operator=(const UniqueModule&) = delete;

    UniqueModule(UniqueModule&& other) noexcept : module_(other.module_), owns_(other.owns_) {
        other.module_ = nullptr;
        other.owns_ = false;
    }

    UniqueModule& operator=(UniqueModule&& other) noexcept {
        if (this != &other) {
            reset();
            module_ = other.module_;
            owns_ = other.owns_;
            other.module_ = nullptr;
            other.owns_ = false;
        }
        return *this;
    }

    HMODULE get() const noexcept {
        return module_;
    }

    HMODULE release() noexcept {
        owns_ = false;
        HMODULE value = module_;
        module_ = nullptr;
        return value;
    }

    void reset(HMODULE module = nullptr, bool owns = true) noexcept {
        if (module_ && owns_) {
            FreeLibrary(module_);
        }
        module_ = module;
        owns_ = module != nullptr ? owns : false;
    }

    explicit operator bool() const noexcept {
        return module_ != nullptr;
    }

private:
    HMODULE module_;
    bool owns_;
};

class RemoteMemory {
public:
    RemoteMemory() noexcept : process_(nullptr), address_(nullptr) {}
    RemoteMemory(HANDLE process, LPVOID address) noexcept : process_(process), address_(address) {}
    ~RemoteMemory() { release(); }

    RemoteMemory(const RemoteMemory&) = delete;
    RemoteMemory& operator=(const RemoteMemory&) = delete;

    RemoteMemory(RemoteMemory&& other) noexcept : process_(other.process_), address_(other.address_) {
        other.process_ = nullptr;
        other.address_ = nullptr;
    }

    RemoteMemory& operator=(RemoteMemory&& other) noexcept {
        if (this != &other) {
            release();
            process_ = other.process_;
            address_ = other.address_;
            other.process_ = nullptr;
            other.address_ = nullptr;
        }
        return *this;
    }

    void reset(HANDLE process, LPVOID address) noexcept {
        release();
        process_ = process;
        address_ = address;
    }

    void release() noexcept {
        if (process_ && address_) {
            VirtualFreeEx(process_, address_, 0, MEM_RELEASE);
        }
        process_ = nullptr;
        address_ = nullptr;
    }

    LPVOID get() const noexcept {
        return address_;
    }

    explicit operator bool() const noexcept {
        return address_ != nullptr;
    }

private:
    HANDLE process_;
    LPVOID address_;
};

void LogSystemError(const char* context, DWORD error) {
    std::cerr << "[!] " << context << " (error " << error << ")\n";
}

void LogSystemError(const char* context) {
    LogSystemError(context, GetLastError());
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return std::wstring();
    }

    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (required <= 0) {
        return std::wstring();
    }

    std::wstring result(static_cast<size_t>(required - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), required);
    return result;
}

bool InjectWithEngine(DWORD processId,
                      const std::wstring& dllPath,
                      const injection::InjectionOptions& options,
                      const char* label) {
    injection::InjectionEngine engine;
    engine.SetLogger([](const std::wstring& message) {
        std::wcout << L"[engine] " << message << std::endl;
    });

    auto result = engine.Inject(processId, dllPath, options);
    if (!result.success) {
        std::wcerr << L"[!] " << Utf8ToWide(label) << L" injection failed: " << result.detail << std::endl;
        return false;
    }

    std::wcout << L"[+] " << Utf8ToWide(label) << L" injection succeeded: " << result.detail << std::endl;
    return true;
}

} // anonymous namespace

class Injector {
public:
    enum InjectionMethod {
        CREATE_REMOTE_THREAD,
        SET_WINDOWS_HOOK,
        MANUAL_MAP,
        QUEUE_USER_APC
    };

    // Find process ID by name
    static DWORD GetProcessIdByName(const std::string& processName) {
        UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot) {
            LogSystemError("CreateToolhelp32Snapshot");
            return 0;
        }

        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        auto normalizeWide = [](std::wstring& value) {
            std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(std::towlower(ch));
            });
        };

        std::wstring normalizedTarget = Utf8ToWide(processName);
        normalizeWide(normalizedTarget);

        DWORD processId = 0;
        if (Process32First(snapshot.get(), &processEntry)) {
            do {
                // Convert wide string to narrow string
                std::wstring currentProcess(processEntry.szExeFile);
                normalizeWide(currentProcess);

                if (currentProcess == normalizedTarget ||
                    currentProcess.find(normalizedTarget) != std::wstring::npos) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot.get(), &processEntry));
        }

        return processId;
    }

    // List all running processes
    static void ListProcesses() {
        UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot) {
            LogSystemError("CreateToolhelp32Snapshot");
            return;
        }

        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        std::cout << "PID\t\tProcess Name\n";
        std::cout << "===================================\n";

        if (Process32First(snapshot.get(), &processEntry)) {
            do {
                std::cout << processEntry.th32ProcessID << "\t\t"
                          << processEntry.szExeFile << std::endl;
            } while (Process32Next(snapshot.get(), &processEntry));
        }
    }

    // CreateRemoteThread injection method
    static bool InjectViaCreateRemoteThread(DWORD processId, const std::string& dllPath) {
        std::cout << "[*] Using CreateRemoteThread injection method\n";

        constexpr DWORD kMinimalAccess =
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

        UniqueHandle process(OpenProcess(kMinimalAccess, FALSE, processId));
        if (!process) {
            LogSystemError("OpenProcess (minimal rights)");
            process.reset(OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId));
            if (!process) {
                LogSystemError("OpenProcess (PROCESS_ALL_ACCESS)");
                return false;
            }
        }

        const SIZE_T dllPathSize = dllPath.length() + 1;
        LPVOID remoteAddress = VirtualAllocEx(process.get(), nullptr, dllPathSize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteAddress) {
            LogSystemError("VirtualAllocEx");
            return false;
        }

        RemoteMemory remoteMemory(process.get(), remoteAddress);

        if (!WriteProcessMemory(process.get(), remoteMemory.get(), dllPath.c_str(),
                                dllPathSize, nullptr)) {
            LogSystemError("WriteProcessMemory");
            return false;
        }

        UniqueModule kernel32(GetModuleHandleW(L"kernel32.dll"), false);
        if (!kernel32) {
            kernel32.reset(LoadLibraryW(L"kernel32.dll"), true);
        }
        if (!kernel32) {
            LogSystemError("Resolve kernel32.dll");
            return false;
        }

        FARPROC loadLibrary = GetProcAddress(kernel32.get(), "LoadLibraryA");
        if (!loadLibrary) {
            LogSystemError("GetProcAddress(LoadLibraryA)");
            return false;
        }

        UniqueHandle remoteThread(CreateRemoteThread(
            process.get(),
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary),
            remoteMemory.get(),
            0,
            nullptr));
        if (!remoteThread) {
            LogSystemError("CreateRemoteThread");
            return false;
        }

        std::cout << "[*] Waiting for remote thread to complete...\n";

        DWORD waitResult = WaitForSingleObject(remoteThread.get(), INFINITE);
        if (waitResult != WAIT_OBJECT_0) {
            std::cerr << "[!] WaitForSingleObject returned " << waitResult << '\n';
        }

        DWORD exitCode = 0;
        if (GetExitCodeThread(remoteThread.get(), &exitCode)) {
            std::cout << "[*] Remote thread exit code: " << exitCode << std::endl;
        } else {
            LogSystemError("GetExitCodeThread");
        }

        remoteMemory.release();

        return true;
    }

    // SetWindowsHookEx injection method
    static bool InjectViaSetWindowsHook(DWORD processId, const std::string& dllPath) {
        std::cout << "[*] Using SetWindowsHookEx injection method\n";

        UniqueModule module(LoadLibraryA(dllPath.c_str()), true);
        if (!module) {
            LogSystemError("LoadLibraryA (hook DLL)");
            return false;
        }

        HOOKPROC hookProc = reinterpret_cast<HOOKPROC>(
            GetProcAddress(module.get(), "GlobalHookProc"));
        if (hookProc == nullptr) {
            std::cerr << "[!] Failed to find GlobalHookProc in DLL\n";
            std::cerr << "[!] Make sure the DLL exports this function\n";
            return false;
        }

        // Enumerate windows to find one belonging to our process
        WindowThreadLookupContext context{processId};
        if (!EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&context)) &&
            GetLastError() != ERROR_SUCCESS) {
            LogSystemError("EnumWindows");
            return false;
        }

        if (!context.foundWindow) {
            std::cerr << "[!] Could not find thread ID for process\n";
            return false;
        }

        // Set the hook
        HHOOK hookHandle = SetWindowsHookEx(WH_GETMESSAGE, hookProc, module.get(), context.threadId);
        if (hookHandle == nullptr) {
            LogSystemError("SetWindowsHookEx");
            return false;
        }

        std::cout << "[+] Windows hook set successfully!\n";
        std::cout << "[*] Hook will be triggered when target window receives messages\n";

        // Trigger the hook by posting a message
        if (!PostThreadMessage(context.threadId, WM_NULL, 0, 0)) {
            LogSystemError("PostThreadMessage");
        }

        // Keep hook active for a moment
        Sleep(1000);

        // Remove hook
        if (!UnhookWindowsHookEx(hookHandle)) {
            LogSystemError("UnhookWindowsHookEx");
        }

        return true;
    }

    // Check if process is running with elevated privileges
    static bool IsElevated() {
        UniqueHandle token;
        HANDLE rawToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
            LogSystemError("OpenProcessToken");
            return false;
        }

        token.reset(rawToken);

        TOKEN_ELEVATION elevation{};
        DWORD returned = 0;
        if (!GetTokenInformation(token.get(), TokenElevation, &elevation,
                                 sizeof(elevation), &returned)) {
            LogSystemError("GetTokenInformation(TokenElevation)");
            return false;
        }

        return elevation.TokenIsElevated != 0;
    }

    // Check if target process is 64-bit
    static bool IsProcess64Bit(DWORD processId, bool& is64Bit) {
        UniqueHandle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
        if (!process) {
            process.reset(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId));
        }
        if (!process) {
            LogSystemError("OpenProcess (query information)");
            return false;
        }

        BOOL isWow64 = FALSE;
        typedef BOOL (WINAPI *IsWow64ProcessFunc)(HANDLE, PBOOL);

        UniqueModule kernel32(GetModuleHandleW(L"kernel32.dll"), false);
        if (!kernel32) {
            kernel32.reset(LoadLibraryW(L"kernel32.dll"), true);
        }
        if (!kernel32) {
            LogSystemError("Resolve kernel32.dll");
            return false;
        }

        IsWow64ProcessFunc isWow64Process = reinterpret_cast<IsWow64ProcessFunc>(
            GetProcAddress(kernel32.get(), "IsWow64Process"));
        if (!isWow64Process) {
            std::cerr << "[!] Failed to locate IsWow64Process\n";
            return false;
        }

        if (!isWow64Process(process.get(), &isWow64)) {
            LogSystemError("IsWow64Process");
            return false;
        }

        // If running under WOW64, it's a 32-bit process on 64-bit Windows
#ifdef _WIN64
        is64Bit = (isWow64 == FALSE);
        return true;  // 64-bit injector, target is 64-bit if NOT WOW64
#else
        BOOL isHostWow64 = FALSE;
        if (!isWow64Process(GetCurrentProcess(), &isHostWow64)) {
            LogSystemError("IsWow64Process (self)");
            return false;
        }

        if (isHostWow64 == FALSE) {
            // 32-bit Windows, all processes are 32-bit
            is64Bit = false;
            return true;
        }

        is64Bit = (isWow64 == FALSE);
        return true;
#endif
    }

    // Get process name from PID
    static std::string GetProcessName(DWORD processId) {
        UniqueHandle process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId));
        if (process) {
            char processName[MAX_PATH];
            if (GetModuleFileNameExA(process.get(), nullptr, processName, MAX_PATH)) {
                std::string name = processName;
                size_t pos = name.find_last_of("\\/");
                if (pos != std::string::npos) {
                    return name.substr(pos + 1);
                }
                return name;
            }
        }
        return "<unknown>";
    }

private:
    struct WindowThreadLookupContext {
        DWORD processId;
        DWORD threadId = 0;
        bool foundWindow = false;

        explicit WindowThreadLookupContext(DWORD pid) : processId(pid) {}
    };

    static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
        auto* context = reinterpret_cast<WindowThreadLookupContext*>(lParam);
        if (context == nullptr) {
            return TRUE;
        }

        DWORD windowProcessId = 0;
        DWORD windowThreadId = GetWindowThreadProcessId(hwnd, &windowProcessId);

        if (windowThreadId != 0 && windowProcessId == context->processId) {
            context->threadId = windowThreadId;
            context->foundWindow = true;
            return FALSE; // Stop enumeration
        }

        return TRUE; // Continue enumeration
    }

};

void PrintUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -p <process>    Target process name or PID\n";
    std::cout << "  -d <dll>        Path to DLL to inject\n";
    std::cout << "  -m <method>     Injection method:\n";
    std::cout << "                    1=Standard LoadLibrary\n";
    std::cout << "                    2=SetWindowsHookEx\n";
    std::cout << "                    3=Manual-map\n";
    std::cout << "                    4=Reflective loader\n";
    std::cout << "                    5=Direct syscalls\n";
    std::cout << "                    6=Auto (manual->reflective->syscall->standard)\n";
    std::cout << "  -l              List all running processes\n";
    std::cout << "  -h              Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " -l\n";
    std::cout << "  " << programName << " -p notepad.exe -d C:\\hook.dll\n";
    std::cout << "  " << programName << " -p 1234 -d C:\\hook.dll -m 1\n";
}

int main(int argc, char* argv[]) {
    std::cout << "=========================================\n";
    std::cout << "     Advanced DLL Injector v3.0         \n";
    std::cout << "     SetWindowDisplayAffinity Bypass    \n";
    std::cout << "=========================================\n\n";

    // Check for administrator privileges
    if (!Injector::IsElevated()) {
        std::cout << "[!] WARNING: Not running with administrator privileges\n";
        std::cout << "[!] Some injection methods may fail\n\n";
    }

    // Parse command line arguments
    std::string targetProcess;
    std::string dllPath;
    int injectionMethod = 1;
    bool listProcesses = false;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-l") {
            listProcesses = true;
        } else if (arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        } else if (arg == "-p" && i + 1 < argc) {
            targetProcess = argv[++i];
        } else if (arg == "-d" && i + 1 < argc) {
            dllPath = argv[++i];
        } else if (arg == "-m" && i + 1 < argc) {
            try {
                injectionMethod = std::stoi(argv[++i]);
            } catch (...) {
                std::cerr << "[!] Invalid injection method value\n";
                return 1;
            }
        }
    }

    // List processes if requested
    if (listProcesses) {
        Injector::ListProcesses();
        return 0;
    }

    // Check if required arguments are provided
    if (targetProcess.empty() || dllPath.empty()) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Normalize DLL path
    DWORD requiredLength = GetFullPathNameA(dllPath.c_str(), 0, nullptr, nullptr);
    if (requiredLength == 0) {
        LogSystemError("GetFullPathNameA");
        return 1;
    }

    std::string normalizedPath(requiredLength, '\0');
    DWORD copied = GetFullPathNameA(dllPath.c_str(), requiredLength, normalizedPath.data(), nullptr);
    if (copied == 0 || copied >= requiredLength) {
        LogSystemError("GetFullPathNameA");
        return 1;
    }
    normalizedPath.resize(copied);
    dllPath = normalizedPath;

    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "[!] DLL file not found: " << dllPath << std::endl;
        return 1;
    }

    std::cout << "[*] DLL Path: " << dllPath << std::endl;

    // Get process ID
    DWORD processId;
    try {
        processId = std::stoi(targetProcess);
        std::cout << "[*] Using Process ID: " << processId << std::endl;
        std::string procName = Injector::GetProcessName(processId);
        std::cout << "[*] Process Name: " << procName << std::endl;
    } catch (...) {
        processId = Injector::GetProcessIdByName(targetProcess);
        if (processId == 0) {
            std::cerr << "[!] Process not found: " << targetProcess << std::endl;
            return 1;
        }
        std::cout << "[*] Found process: " << targetProcess << " (PID: " << processId << ")\n";
    }

    // Check process architecture
    bool is64Bit = false;
    if (!Injector::IsProcess64Bit(processId, is64Bit)) {
        std::cerr << "[!] Unable to determine target process architecture (see message above)\n";
        return 1;
    }
    std::cout << "[*] Target process architecture: " << (is64Bit ? "64-bit" : "32-bit") << std::endl;

#ifdef _WIN64
    if (!is64Bit) {
        std::cerr << "[!] Target process is 32-bit but injector is 64-bit\n";
        std::cerr << "[!] Use 32-bit injector for 32-bit processes\n";
        return 1;
    }
#else
    if (is64Bit) {
        std::cerr << "[!] Target process is 64-bit but injector is 32-bit\n";
        std::cerr << "[!] Use 64-bit injector for 64-bit processes\n";
        return 1;
    }
#endif

    std::wstring dllPathWide = Utf8ToWide(dllPath);
    if (dllPathWide.empty()) {
        std::cerr << "[!] Failed to convert DLL path to Unicode.\n";
        return 1;
    }

    // Perform injection
    std::cout << "\n[*] Starting injection...\n";

    bool success = false;
    injection::InjectionOptions options;

    switch (injectionMethod) {
        case 1: {
            options.methodOrder = {injection::InjectionMethod::Standard};
            options.allowDirectSyscall = false;
            success = InjectWithEngine(processId, dllPathWide, options, "standard");
            break;
        }
        case 2:
            success = Injector::InjectViaSetWindowsHook(processId, dllPath);
            break;
        case 3: {
            options.methodOrder = {injection::InjectionMethod::ManualMap};
            options.manualMapFlags = static_cast<DWORD>(injection::kManualMapHideFromPeb |
                                                        injection::kManualMapEraseHeaders);
            success = InjectWithEngine(processId, dllPathWide, options, "manual-map");
            break;
        }
        case 4: {
            options.methodOrder = {injection::InjectionMethod::Reflective};
            success = InjectWithEngine(processId, dllPathWide, options, "reflective");
            break;
        }
        case 5: {
            options.methodOrder = {injection::InjectionMethod::DirectSyscall};
            success = InjectWithEngine(processId, dllPathWide, options, "direct-syscall");
            break;
        }
        case 6: {
            options.methodOrder = {
                injection::InjectionMethod::ManualMap,
                injection::InjectionMethod::Reflective,
                injection::InjectionMethod::DirectSyscall,
                injection::InjectionMethod::Standard
            };
            options.manualMapFlags = static_cast<DWORD>(injection::kManualMapHideFromPeb |
                                                        injection::kManualMapEraseHeaders);
            success = InjectWithEngine(processId, dllPathWide, options, "auto");
            break;
        }
        default:
            std::cerr << "[!] Invalid injection method\n";
            return 1;
    }

    if (success) {
        std::cout << "\n[+] Injection completed successfully!\n";
        std::cout << "[+] SetWindowDisplayAffinity bypass should now be active\n";
        std::cout << "[*] Check C:\\Temp\\api_hooks.log for hooked API calls\n";
    } else {
        std::cout << "\n[!] Injection failed\n";
        std::cout << "[!] Try running as administrator or using a different method\n";
    }

    return success ? 0 : 1;
}
