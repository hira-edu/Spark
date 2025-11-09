// ManualMapInjector.cpp - Manual Map DLL Injection (Stealth)
#include "../include/ManualMapInjector.h"

#include <winternl.h>
#include <TlHelp32.h>
#include <fstream>

#include <algorithm>
#include <cwctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <random>
#include <array>
#include <bcrypt.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Bcrypt.lib")

#ifndef BCRYPT_CHAIN_MODE_CTR
#define BCRYPT_CHAIN_MODE_CTR L"ChainingModeCTR"
#endif

namespace injection {

namespace {

std::wstring FormatSystemError(DWORD error) {
    if (error == 0) {
        return L"";
    }

    wchar_t buffer[512] = {0};
    DWORD length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                  nullptr,
                                  error,
                                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                  buffer,
                                  static_cast<DWORD>(std::size(buffer)),
                                  nullptr);
    if (length == 0) {
        return L"Unknown error (" + std::to_wstring(error) + L")";
    }

    std::wstring message(buffer, buffer + length);
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
}

std::wstring AnsiToWide(const std::string& value) {
    if (value.empty()) {
        return L"";
    }

    const UINT codePages[] = {CP_UTF8, CP_ACP};
    for (UINT codePage : codePages) {
        int length = MultiByteToWideChar(codePage, 0, value.c_str(), -1, nullptr, 0);
        if (length <= 0) {
            continue;
        }

        std::wstring result(static_cast<size_t>(length - 1), L'\0');
        if (length > 1) {
            MultiByteToWideChar(codePage, 0, value.c_str(), -1, result.data(), length);
        }
        return result;
    }

    return L"";
}

std::wstring ToLowerCopy(std::wstring value) {
    std::transform(value.begin(),
                   value.end(),
                   value.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

std::wstring ExtractBaseName(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

std::string EnsureDllExtension(std::string name) {
    if (name.find('.') == std::string::npos) {
        name += ".dll";
    }
    return name;
}

constexpr SIZE_T kPageSize = 0x1000;
constexpr SIZE_T kRandomPadding = 0x20000; // 128 KB guard window
constexpr SIZE_T kEncryptChunk = 0x1000;

SIZE_T AlignUp(SIZE_T value, SIZE_T alignment = kPageSize) {
    return (value + alignment - 1) & ~(alignment - 1);
}

SIZE_T RandomAlignedOffset() {
    const SIZE_T maxSlots = kRandomPadding / kPageSize;
    if (maxSlots == 0) {
        return 0;
    }
    static std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<SIZE_T> dist(1, maxSlots);
    return dist(rng) * kPageSize;
}

DWORD RandomXorKey() {
    static std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<DWORD> dist(1, 0xFFFFFFFFu);
    return dist(rng) | 0x01010101u;
}

} // namespace

ManualMapInjector::ManualMapInjector()
    : ntHeaders_(nullptr),
      dosHeader_(nullptr),
      lastRemoteBase_(nullptr),
      lastRandomOffset_(0),
      lastReservationSize_(0),
      config_{} {}

bool ManualMapInjector::LoadFromFile(const std::wstring& dllPath) {
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

bool ManualMapInjector::LoadFromMemory(const BYTE* buffer, size_t size) {
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

bool ManualMapInjector::InjectIntoProcess(DWORD processId, DWORD flags) {
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!process) {
        SetLastErrorFromWin32(L"OpenProcess");
        return false;
    }

    bool result = PerformManualMap(process, flags);
    CloseHandle(process);
    return result;
}

bool ManualMapInjector::InjectIntoProcess(HANDLE processHandle, DWORD flags) {
    if (!processHandle) {
        SetLastErrorMessage(L"InjectIntoProcess received null process handle.");
        return false;
    }

    return PerformManualMap(processHandle, flags);
}

size_t ManualMapInjector::ImageSize() const noexcept {
    if (!ntHeaders_) {
        return 0;
    }
    return ntHeaders_->OptionalHeader.SizeOfImage;
}

bool ManualMapInjector::ValidatePE() {
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

bool ManualMapInjector::PerformManualMap(HANDLE process, DWORD flags) {
    if (!ntHeaders_) {
        SetLastErrorMessage(L"ManualMapInjector not initialised with a valid image.");
        return false;
    }

    lastRemoteBase_ = nullptr;
    lastRandomOffset_ = 0;
    lastReservationSize_ = 0;

    const SIZE_T imageSize = ntHeaders_->OptionalHeader.SizeOfImage;
    const SIZE_T reserveSize = imageSize + (config_.randomizeOffset ? kRandomPadding : 0);

    LPVOID reservation = VirtualAllocEx(process,
                                        nullptr,
                                        reserveSize,
                                        MEM_RESERVE,
                                        PAGE_NOACCESS);
    LPVOID allocationBase = nullptr;
    LPVOID targetBase = nullptr;

    if (reservation && config_.randomizeOffset) {
        SIZE_T offset = RandomAlignedOffset();
        if (offset + imageSize > reserveSize) {
            offset = 0;
        }

        LPBYTE commitBase = static_cast<LPBYTE>(reservation) + offset;
        if (VirtualAllocEx(process,
                           commitBase,
                           imageSize,
                           MEM_COMMIT,
                           PAGE_EXECUTE_READWRITE)) {
            targetBase = commitBase;
            allocationBase = reservation;

            if (config_.guardPages && offset >= kPageSize) {
                VirtualAllocEx(process,
                               commitBase - kPageSize,
                               kPageSize,
                               MEM_COMMIT,
                               PAGE_NOACCESS);
            }

            SIZE_T postOffset = offset + imageSize;
            if (config_.guardPages && postOffset + kPageSize <= reserveSize) {
                VirtualAllocEx(process,
                               commitBase + imageSize,
                               kPageSize,
                               MEM_COMMIT,
                               PAGE_NOACCESS);
            }
        } else {
            VirtualFreeEx(process, reservation, 0, MEM_RELEASE);
            reservation = nullptr;
        }
    } else if (reservation) {
        VirtualFreeEx(process, reservation, 0, MEM_RELEASE);
        reservation = nullptr;
    }

    if (!targetBase) {
        targetBase = VirtualAllocEx(process,
                                    nullptr,
                                    imageSize,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
        if (!targetBase) {
            SetLastErrorFromWin32(L"VirtualAllocEx");
            return false;
        }
        allocationBase = targetBase;
    }

    auto releaseAllocation = [&]() {
        if (allocationBase) {
            VirtualFreeEx(process, allocationBase, 0, MEM_RELEASE);
            allocationBase = nullptr;
        }
    };

    const SIZE_T headersSize = ntHeaders_->OptionalHeader.SizeOfHeaders;
    if (!WriteProcessMemory(process, targetBase, dllBuffer_.data(), headersSize, nullptr)) {
        SetLastErrorFromWin32(L"WriteProcessMemory (headers)");
        releaseAllocation();
        return false;
    }

    if (!CopySections(process, targetBase)) {
        releaseAllocation();
        return false;
    }

    if (!ProcessRelocations(process, targetBase)) {
        releaseAllocation();
        return false;
    }

    bool importsResolved = false;
    if (!config_.deferImports) {
        if (!ResolveImports(process, targetBase)) {
            releaseAllocation();
            return false;
        }
        importsResolved = true;
    }

    if (config_.neutralizeTls) {
        NeutralizeTlsDirectory(process, targetBase);
    }

    std::vector<std::pair<DWORD, DWORD>> encryptSlices;
    std::array<BYTE, 32> aesKey{};
    std::array<BYTE, 16> aesIv{};
    bool encrypted = false;
    bool decrypted = false;
    bool aesReady = false;

    if (config_.encryptSections) {
        CollectEncryptionSlices(encryptSlices);
        if (!encryptSlices.empty()) {
            if (!GenerateAesKey(aesKey, aesIv)) {
                releaseAllocation();
                return false;
            }
            if (!EncryptRemoteSectionsAes(process, targetBase, encryptSlices, aesKey, aesIv)) {
                releaseAllocation();
                return false;
            }
            encrypted = true;
            aesReady = true;
        }
    }

    if (!AdjustProtections(process, targetBase)) {
        // Continue; protections are best-effort.
    }

    if (encrypted && aesReady) {
        decrypted = EncryptRemoteSectionsAes(process, targetBase, encryptSlices, aesKey, aesIv);
        if (!decrypted) {
            releaseAllocation();
            return false;
        }
    }

    if (!importsResolved) {
        if (!ResolveImports(process, targetBase)) {
            releaseAllocation();
            return false;
        }
        importsResolved = true;
    }

    if (!config_.neutralizeTls) {
        if (!ExecuteTLSCallbacks(process, targetBase)) {
            // Continue; TLS callbacks are best-effort.
        }
    }

    if (!CallDllMain(process, targetBase, DLL_PROCESS_ATTACH)) {
        // Continue; some modules omit DllMain.
    }

    if (config_.shredHeaders || (flags & kManualMapEraseHeaders)) {
        EraseHeaders(process, targetBase);
    }

    if (config_.reencryptAfterInit && encrypted && decrypted && aesReady) {
        EncryptRemoteSectionsAes(process, targetBase, encryptSlices, aesKey, aesIv);
    }

    if (flags & kManualMapHideFromPeb) {
        HideFromPEB(process, targetBase);
    }

    if (flags & kManualMapUnlinkFromVad) {
        UnlinkFromVAD(process, targetBase);
    }

    lastRemoteBase_ = targetBase;
    if (allocationBase && allocationBase != targetBase) {
        lastRandomOffset_ = static_cast<SIZE_T>(static_cast<LPBYTE>(targetBase) - static_cast<LPBYTE>(allocationBase));
        lastReservationSize_ = reserveSize;
    } else {
        lastRandomOffset_ = 0;
        lastReservationSize_ = imageSize;
    }

    return true;
}

bool ManualMapInjector::CopySections(HANDLE process, LPVOID targetBase) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders_);
    for (WORD i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
        if (sectionHeader[i].SizeOfRawData == 0) {
            continue;
        }

        LPVOID destination = static_cast<LPBYTE>(targetBase) + sectionHeader[i].VirtualAddress;
        const BYTE* source = dllBuffer_.data() + sectionHeader[i].PointerToRawData;
        SIZE_T size = sectionHeader[i].SizeOfRawData;

        if (!WriteProcessMemory(process, destination, source, size, nullptr)) {
            SetLastErrorFromWin32(L"WriteProcessMemory (section)");
            return false;
        }
    }
    return true;
}

bool ManualMapInjector::ProcessRelocations(HANDLE process, LPVOID targetBase) {
    DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(targetBase) - ntHeaders_->OptionalHeader.ImageBase;
    if (delta == 0) {
        return true;
    }

    const auto& directory = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory.Size == 0) {
        return true;
    }

    auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(dllBuffer_.data() + directory.VirtualAddress);
    while (reloc && reloc->VirtualAddress && reloc->SizeOfBlock) {
        const DWORD entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const PWORD relocEntries = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < entryCount; ++i) {
            const WORD typeOffset = relocEntries[i];
            const WORD type = typeOffset >> 12;
            const WORD offset = typeOffset & 0x0FFF;

            if (type == 0) {
                continue;
            }

            LPVOID patchAddress = static_cast<LPBYTE>(targetBase) + reloc->VirtualAddress + offset;

#ifdef _WIN64
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG value = 0;
                ReadProcessMemory(process, patchAddress, &value, sizeof(value), nullptr);
                value += delta;
                WriteProcessMemory(process, patchAddress, &value, sizeof(value), nullptr);
            }
#else
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD value = 0;
                ReadProcessMemory(process, patchAddress, &value, sizeof(value), nullptr);
                value += static_cast<DWORD>(delta);
                WriteProcessMemory(process, patchAddress, &value, sizeof(value), nullptr);
            }
#endif
        }

        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(reloc) + reloc->SizeOfBlock);
    }

    return true;
}

bool ManualMapInjector::ResolveImports(HANDLE process, LPVOID targetBase) {
    const auto& directory = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.Size == 0) {
        return true;
    }

    auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dllBuffer_.data() + directory.VirtualAddress);
    while (importDescriptor && importDescriptor->Name) {
        const char* moduleNameAnsi = reinterpret_cast<const char*>(dllBuffer_.data() + importDescriptor->Name);
        if (!moduleNameAnsi || *moduleNameAnsi == '\0') {
            break;
        }

        std::string moduleName(moduleNameAnsi);
        HMODULE localModule = LoadLibraryA(moduleName.c_str());
        if (!localModule) {
            SetLastErrorMessage(L"ResolveImports failed to load dependency locally: " + AnsiToWide(moduleName));
            return false;
        }

        HMODULE remoteModule = nullptr;
        if (!EnsureRemoteModule(process, moduleName, remoteModule)) {
            FreeLibrary(localModule);
            return false;
        }

        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(dllBuffer_.data() +
                         (importDescriptor->OriginalFirstThunk != 0 ? importDescriptor->OriginalFirstThunk
                                                                    : importDescriptor->FirstThunk));

        auto funcThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(static_cast<PBYTE>(targetBase) + importDescriptor->FirstThunk);

        while (thunk && thunk->u1.AddressOfData) {
            uintptr_t resolvedAddress = 0;
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                WORD ordinal = static_cast<WORD>(IMAGE_ORDINAL(thunk->u1.Ordinal));
                if (!ResolveExportAddress(process, localModule, remoteModule, moduleName, nullptr, ordinal, resolvedAddress)) {
                    FreeLibrary(localModule);
                    return false;
                }
            } else {
                auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(dllBuffer_.data() + thunk->u1.AddressOfData);
                if (!importByName || !importByName->Name[0]) {
                    SetLastErrorMessage(L"ResolveImports encountered invalid import name in module: " + AnsiToWide(moduleName));
                    FreeLibrary(localModule);
                    return false;
                }

                if (!ResolveExportAddress(process,
                                          localModule,
                                          remoteModule,
                                          moduleName,
                                          reinterpret_cast<const char*>(importByName->Name),
                                          0,
                                          resolvedAddress)) {
                    FreeLibrary(localModule);
                    return false;
                }
            }

            if (!WriteProcessMemory(process, funcThunk, &resolvedAddress, sizeof(resolvedAddress), nullptr)) {
                SetLastErrorFromWin32(L"WriteProcessMemory (import thunk)");
                FreeLibrary(localModule);
                return false;
            }

            ++thunk;
            ++funcThunk;
        }

        FreeLibrary(localModule);
        ++importDescriptor;
    }

    return true;
}

bool ManualMapInjector::AdjustProtections(HANDLE process, LPVOID targetBase) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders_);
    for (WORD i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
        DWORD protection = PAGE_NOACCESS;
        const DWORD characteristics = sectionHeader[i].Characteristics;

        const bool isExecutable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool isReadable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool isWritable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (isExecutable) {
            protection = isReadable ? (isWritable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
                                    : (isWritable ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE);
        } else if (isReadable) {
            protection = isWritable ? PAGE_READWRITE : PAGE_READONLY;
        } else if (isWritable) {
            protection = PAGE_WRITECOPY;
        }

        LPVOID sectionAddress = static_cast<LPBYTE>(targetBase) + sectionHeader[i].VirtualAddress;
        DWORD oldProtection = 0;
        if (!VirtualProtectEx(process,
                              sectionAddress,
                              sectionHeader[i].Misc.VirtualSize,
                              protection,
                              &oldProtection)) {
            SetLastErrorFromWin32(L"VirtualProtectEx");
            return false;
        }
    }

    return true;
}

bool ManualMapInjector::ExecuteTLSCallbacks(HANDLE process, LPVOID targetBase) {
    const auto& directory = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (directory.Size == 0) {
        return true;
    }

    auto tlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(dllBuffer_.data() + directory.VirtualAddress);
    if (!tlsDirectory->AddressOfCallBacks) {
        return true;
    }

    auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsDirectory->AddressOfCallBacks);
    while (*callbacks) {
        HANDLE thread = CreateRemoteThread(process,
                                           nullptr,
                                           0,
                                           reinterpret_cast<LPTHREAD_START_ROUTINE>(*callbacks),
                                           targetBase,
                                           0,
                                           nullptr);
        if (thread) {
            WaitForSingleObject(thread, 1000);
            CloseHandle(thread);
        }
        ++callbacks;
    }

    return true;
}

bool ManualMapInjector::CallDllMain(HANDLE process, LPVOID targetBase, DWORD reason) {
    if (ntHeaders_->OptionalHeader.AddressOfEntryPoint == 0) {
        return true;
    }

    LPVOID entryPoint = static_cast<LPBYTE>(targetBase) + ntHeaders_->OptionalHeader.AddressOfEntryPoint;
    LPVOID shellcode = VirtualAllocEx(process, nullptr, 0x200, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode) {
        SetLastErrorFromWin32(L"VirtualAllocEx (shellcode)");
        return false;
    }

#ifdef _WIN64
    BYTE stub[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
        0xBA, 0, 0, 0, 0,
        0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };

    *reinterpret_cast<ULONGLONG*>(&stub[6]) = reinterpret_cast<ULONGLONG>(targetBase);
    *reinterpret_cast<DWORD*>(&stub[15]) = reason;
    *reinterpret_cast<ULONGLONG*>(&stub[21]) = 0;
    *reinterpret_cast<ULONGLONG*>(&stub[31]) = reinterpret_cast<ULONGLONG>(entryPoint);
#else
    BYTE stub[] = {
        0x68, 0, 0, 0, 0,
        0x68, 0, 0, 0, 0,
        0x68, 0, 0, 0, 0,
        0xB8, 0, 0, 0, 0,
        0xFF, 0xD0,
        0xC3
    };

    *reinterpret_cast<DWORD*>(&stub[1]) = 0;
    *reinterpret_cast<DWORD*>(&stub[6]) = reason;
    *reinterpret_cast<DWORD*>(&stub[11]) = reinterpret_cast<DWORD>(targetBase);
    *reinterpret_cast<DWORD*>(&stub[16]) = reinterpret_cast<DWORD>(entryPoint);
#endif

    if (!WriteProcessMemory(process, shellcode, stub, sizeof(stub), nullptr)) {
        SetLastErrorFromWin32(L"WriteProcessMemory (DllMain stub)");
        VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process,
                                       nullptr,
                                       0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
                                       nullptr,
                                       0,
                                       nullptr);
    if (!thread) {
        SetLastErrorFromWin32(L"CreateRemoteThread (DllMain stub)");
        VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
    return true;
}

void ManualMapInjector::EraseHeaders(HANDLE process, LPVOID targetBase) {
    const SIZE_T headerSize = ntHeaders_->OptionalHeader.SizeOfHeaders;
    if (headerSize == 0) {
        return;
    }

    std::vector<BYTE> shred(headerSize);
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : shred) {
        byte = static_cast<BYTE>(dist(rng));
    }

    WriteProcessMemory(process, targetBase, shred.data(), shred.size(), nullptr);

    DWORD oldProtect = 0;
    LPVOID protectBase = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(targetBase) & ~(kPageSize - 1));
    SIZE_T protectSize = (headerSize + (kPageSize - 1)) & ~(kPageSize - 1);
    VirtualProtectEx(process,
                     protectBase,
                     protectSize,
                     PAGE_NOACCESS,
                     &oldProtect);
}

void ManualMapInjector::HideFromPEB(HANDLE process, LPVOID targetBase) {
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(targetBase);
    // Intentionally left unimplemented: PEB unlinking is highly context specific and unsafe
    // without robust per-process heuristics. Consumers should rely on external stealth layers
    // when required.
}

void ManualMapInjector::UnlinkFromVAD(HANDLE process, LPVOID targetBase) {
    UNREFERENCED_PARAMETER(process);
    UNREFERENCED_PARAMETER(targetBase);
    // VAD unlinking requires kernel-mode support; placeholder maintained to preserve API shape.
}

void ManualMapInjector::NeutralizeTlsDirectory(HANDLE process, LPVOID targetBase) {
    auto& directory = ntHeaders_->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (directory.VirtualAddress == 0 || directory.Size == 0) {
        return;
    }

#if defined(_WIN64)
    using TlsDir = IMAGE_TLS_DIRECTORY64;
#else
    using TlsDir = IMAGE_TLS_DIRECTORY32;
#endif

    if (directory.Size < sizeof(TlsDir)) {
        return;
    }

    LPBYTE remoteDirectory = static_cast<LPBYTE>(targetBase) + directory.VirtualAddress;
    TlsDir tlsDirectory{};
    if (!ReadProcessMemory(process, remoteDirectory, &tlsDirectory, sizeof(tlsDirectory), nullptr)) {
        return;
    }

    // Wipe the TLS raw data region if present.
    if (tlsDirectory.StartAddressOfRawData != 0 && tlsDirectory.EndAddressOfRawData > tlsDirectory.StartAddressOfRawData) {
        SIZE_T rawSize = static_cast<SIZE_T>(tlsDirectory.EndAddressOfRawData - tlsDirectory.StartAddressOfRawData);
        std::vector<BYTE> zeros(rawSize, 0);
        WriteProcessMemory(process,
                           reinterpret_cast<LPVOID>(tlsDirectory.StartAddressOfRawData),
                           zeros.data(),
                           zeros.size(),
                           nullptr);
    }

    // Walk and clear TLS callback table.
#if defined(_WIN64)
    ULONGLONG callbacks = tlsDirectory.AddressOfCallBacks;
    const ULONGLONG zeroValue = 0;
#else
    DWORD callbacks = tlsDirectory.AddressOfCallBacks;
    const DWORD zeroValue = 0;
#endif
    if (callbacks != 0) {
        uintptr_t entryPtr = static_cast<uintptr_t>(callbacks);
        while (entryPtr != 0) {
#if defined(_WIN64)
            ULONGLONG callback = 0;
#else
            DWORD callback = 0;
#endif
            if (!ReadProcessMemory(process,
                                   reinterpret_cast<LPCVOID>(entryPtr),
                                   &callback,
                                   sizeof(callback),
                                   nullptr)) {
                break;
            }

            WriteProcessMemory(process,
                               reinterpret_cast<LPVOID>(entryPtr),
                               &zeroValue,
                               sizeof(zeroValue),
                               nullptr);

            if (callback == 0) {
                break;
            }

            entryPtr += sizeof(callback);
        }
    }

    // Overwrite the TLS directory itself.
    TlsDir zeroDir{};
    WriteProcessMemory(process, remoteDirectory, &zeroDir, sizeof(zeroDir), nullptr);
}

void ManualMapInjector::CollectEncryptionSlices(std::vector<std::pair<DWORD, DWORD>>& slices) const {
    slices.clear();
    if (!ntHeaders_) {
        return;
    }
    DWORD headerSize = ntHeaders_->OptionalHeader.SizeOfHeaders;
    if (headerSize) {
        slices.emplace_back(0u, headerSize);
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders_);
    for (WORD i = 0; i < ntHeaders_->FileHeader.NumberOfSections; ++i) {
        DWORD size = sectionHeader[i].Misc.VirtualSize ? sectionHeader[i].Misc.VirtualSize : sectionHeader[i].SizeOfRawData;
        if (size == 0) {
            continue;
        }
        slices.emplace_back(sectionHeader[i].VirtualAddress, size);
    }
}

bool ManualMapInjector::GenerateAesKey(std::array<BYTE, 32>& key, std::array<BYTE, 16>& iv) {
    if (BCryptGenRandom(nullptr, key.data(), static_cast<ULONG>(key.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        SetLastErrorMessage(L"BCryptGenRandom (AES key)");
        return false;
    }
    if (BCryptGenRandom(nullptr, iv.data(), static_cast<ULONG>(iv.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        SetLastErrorMessage(L"BCryptGenRandom (AES iv)");
        return false;
    }
    return true;
}

void ManualMapInjector::AddBlocksToCounter(std::array<BYTE, 16>& counter, uint64_t blocks) {
    for (int i = static_cast<int>(counter.size()) - 1; i >= 0 && blocks != 0; --i) {
        unsigned int sum = static_cast<unsigned int>(counter[i]) + static_cast<unsigned int>(blocks & 0xFF);
        counter[i] = static_cast<BYTE>(sum & 0xFF);
        blocks = (blocks >> 8) + (sum >> 8);
    }
}

bool ManualMapInjector::EncryptRemoteSectionsAes(HANDLE process,
                                                 LPVOID targetBase,
                                                 const std::vector<std::pair<DWORD, DWORD>>& slices,
                                                 const std::array<BYTE, 32>& key,
                                                 const std::array<BYTE, 16>& iv) {
    if (!process || !targetBase || slices.empty()) {
        return true;
    }

    struct AlgHandle {
        BCRYPT_ALG_HANDLE handle{nullptr};
        ~AlgHandle() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
    } alg;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.handle, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        SetLastErrorMessage(L"BCryptOpenAlgorithmProvider");
        return false;
    }

    if (!NT_SUCCESS(BCryptSetProperty(alg.handle,
                                      BCRYPT_CHAINING_MODE,
                                      reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CTR)),
                                      static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_CTR)),
                                      0))) {
        SetLastErrorMessage(L"BCryptSetProperty (CTR)");
        return false;
    }

    DWORD objectLen = 0;
    DWORD resultLen = 0;
    if (!NT_SUCCESS(BCryptGetProperty(alg.handle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLen), sizeof(objectLen), &resultLen, 0))) {
        SetLastErrorMessage(L"BCryptGetProperty (object length)");
        return false;
    }

    std::vector<BYTE> keyObject(objectLen);
    struct KeyHandle {
        BCRYPT_KEY_HANDLE handle{nullptr};
        ~KeyHandle() { if (handle) BCryptDestroyKey(handle); }
    } keyHandle;

    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg.handle,
                                               &keyHandle.handle,
                                               keyObject.data(),
                                               objectLen,
                                               const_cast<PUCHAR>(key.data()),
                                               static_cast<ULONG>(key.size()),
                                               0))) {
        SetLastErrorMessage(L"BCryptGenerateSymmetricKey");
        return false;
    }

    std::vector<BYTE> buffer(kEncryptChunk);
    uint64_t blockIndex = 0;

    for (const auto& slice : slices) {
        BYTE* base = static_cast<BYTE*>(targetBase) + slice.first;
        SIZE_T regionSize = AlignUp(slice.second);
        DWORD oldProtect = 0;
        VirtualProtectEx(process, base, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

        SIZE_T processed = 0;
        DWORD restoreProt = 0;
        while (processed < slice.second) {
            SIZE_T chunk = std::min<SIZE_T>(buffer.size(), slice.second - processed);
            SIZE_T bytesRead = 0;
            if (!ReadProcessMemory(process, base + processed, buffer.data(), chunk, &bytesRead) || bytesRead != chunk) {
                SetLastErrorFromWin32(L"ReadProcessMemory (manual-map AES)");
                if (oldProtect != 0) {
                    VirtualProtectEx(process, base, regionSize, oldProtect, &restoreProt);
                }
                return false;
            }

            std::array<BYTE, 16> ctr = iv;
            AddBlocksToCounter(ctr, blockIndex);

            ULONG transformed = 0;
            if (!NT_SUCCESS(BCryptEncrypt(keyHandle.handle,
                                          buffer.data(),
                                          static_cast<ULONG>(chunk),
                                          nullptr,
                                          ctr.data(),
                                          static_cast<ULONG>(ctr.size()),
                                          buffer.data(),
                                          static_cast<ULONG>(chunk),
                                          &transformed,
                                          0)) || transformed != chunk) {
                SetLastErrorMessage(L"BCryptEncrypt (manual-map AES)");
                if (oldProtect != 0) {
                    VirtualProtectEx(process, base, regionSize, oldProtect, &restoreProt);
                }
                return false;
            }

            SIZE_T bytesWritten = 0;
            if (!WriteProcessMemory(process, base + processed, buffer.data(), chunk, &bytesWritten) || bytesWritten != chunk) {
                SetLastErrorFromWin32(L"WriteProcessMemory (manual-map AES)");
                if (oldProtect != 0) {
                    VirtualProtectEx(process, base, regionSize, oldProtect, &restoreProt);
                }
                return false;
            }

            processed += chunk;
            blockIndex += (chunk + 15) / 16;
        }

        DWORD tmpProt = 0;
        if (oldProtect != 0) {
            VirtualProtectEx(process, base, regionSize, oldProtect, &tmpProt);
        }
    }

    return true;
}

void ManualMapInjector::SetLastErrorMessage(const std::wstring& message) {
    lastError_ = message;
}

void ManualMapInjector::SetLastErrorFromWin32(const wchar_t* context) {
    const DWORD error = ::GetLastError();
    lastError_ = context ? std::wstring(context) + L": " + FormatSystemError(error)
                         : FormatSystemError(error);
}

HMODULE ManualMapInjector::FindRemoteModuleHandle(HANDLE process, const std::wstring& moduleName) const {
    if (!process || moduleName.empty()) {
        return nullptr;
    }

    DWORD pid = GetProcessId(process);
    if (pid == 0) {
        return nullptr;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    const std::wstring targetLower = ToLowerCopy(moduleName);
    const std::wstring targetBaseLower = ToLowerCopy(ExtractBaseName(moduleName));

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snapshot, &entry)) {
        do {
            std::wstring entryModule(entry.szModule);
            std::wstring entryLower = ToLowerCopy(entryModule);
            std::wstring entryBaseLower = ToLowerCopy(ExtractBaseName(entryModule));

            if (entryLower == targetLower || entryLower == targetBaseLower ||
                entryBaseLower == targetLower || entryBaseLower == targetBaseLower) {
                CloseHandle(snapshot);
                return entry.hModule;
            }

            if (entry.szExePath[0] != L'\0') {
                std::wstring entryPath(entry.szExePath);
                std::wstring pathLower = ToLowerCopy(entryPath);
                std::wstring pathBaseLower = ToLowerCopy(ExtractBaseName(entryPath));

                if (pathLower == targetLower || pathLower == targetBaseLower ||
                    pathBaseLower == targetLower || pathBaseLower == targetBaseLower) {
                    CloseHandle(snapshot);
                    return entry.hModule;
                }
            }
        } while (Module32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return nullptr;
}

HMODULE ManualMapInjector::LoadRemoteModule(HANDLE process, const std::string& moduleName) {
    if (!process) {
        SetLastErrorMessage(L"LoadRemoteModule received null process handle.");
        return nullptr;
    }

    std::string normalized = EnsureDllExtension(moduleName);

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        SetLastErrorFromWin32(L"GetModuleHandleW(kernel32.dll)");
        return nullptr;
    }

    auto loadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryA"));
    if (!loadLibrary) {
        SetLastErrorFromWin32(L"GetProcAddress(LoadLibraryA)");
        return nullptr;
    }

    SIZE_T payloadSize = normalized.size() + 1;
    LPVOID remoteBuffer = VirtualAllocEx(process, nullptr, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuffer) {
        SetLastErrorFromWin32(L"VirtualAllocEx(module name)");
        return nullptr;
    }

    if (!WriteProcessMemory(process, remoteBuffer, normalized.c_str(), payloadSize, nullptr)) {
        SetLastErrorFromWin32(L"WriteProcessMemory(module name)");
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        return nullptr;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, loadLibrary, remoteBuffer, 0, nullptr);
    if (!thread) {
        SetLastErrorFromWin32(L"CreateRemoteThread(LoadLibraryA)");
        VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);
        return nullptr;
    }

    DWORD waitResult = WaitForSingleObject(thread, 10000);
    DWORD exitCode = 0;
    if (!GetExitCodeThread(thread, &exitCode)) {
        SetLastErrorFromWin32(L"GetExitCodeThread(LoadLibraryA)");
    }
    CloseHandle(thread);

    VirtualFreeEx(process, remoteBuffer, 0, MEM_RELEASE);

    if (waitResult == WAIT_TIMEOUT) {
        SetLastErrorMessage(L"Timed out waiting for remote LoadLibraryA for module: " + AnsiToWide(normalized));
        return nullptr;
    }
    if (waitResult == WAIT_FAILED) {
        SetLastErrorFromWin32(L"WaitForSingleObject(LoadLibraryA)");
        return nullptr;
    }
    if (exitCode == 0) {
        SetLastErrorMessage(L"Remote LoadLibraryA failed for module: " + AnsiToWide(normalized));
        return nullptr;
    }

    std::wstring wideName = AnsiToWide(normalized);
    HMODULE remoteModule = FindRemoteModuleHandle(process, wideName);
    if (!remoteModule) {
        SetLastErrorMessage(L"Module not located in target process after LoadLibraryA: " + wideName);
    }
    return remoteModule;
}

bool ManualMapInjector::EnsureRemoteModule(HANDLE process, const std::string& moduleName, HMODULE& remoteModule) {
    if (!process) {
        SetLastErrorMessage(L"EnsureRemoteModule received null process handle.");
        return false;
    }

    std::string normalized = EnsureDllExtension(moduleName);
    std::wstring wideName = AnsiToWide(normalized);
    if (wideName.empty()) {
        SetLastErrorMessage(L"Failed to convert dependency name to wide string: " + AnsiToWide(normalized));
        return false;
    }

    remoteModule = FindRemoteModuleHandle(process, wideName);
    if (remoteModule) {
        return true;
    }

    remoteModule = LoadRemoteModule(process, normalized);
    return remoteModule != nullptr;
}

bool ManualMapInjector::ResolveExportAddress(HANDLE process,
                                             HMODULE localModule,
                                             HMODULE remoteModule,
                                             const std::string& moduleName,
                                             const char* importName,
                                             WORD ordinal,
                                             uintptr_t& remoteAddress,
                                             int depth) {
    if (!localModule || !remoteModule) {
        SetLastErrorMessage(L"ResolveExportAddress received invalid module handles for: " + AnsiToWide(moduleName));
        return false;
    }

    if (depth > 16) {
        SetLastErrorMessage(L"Exceeded forwarder resolution depth while resolving imports for: " + AnsiToWide(moduleName));
        return false;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(localModule);
    const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastErrorMessage(L"Invalid DOS header while resolving exports for: " + AnsiToWide(moduleName));
        return false;
    }

    const auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        SetLastErrorMessage(L"Invalid NT header while resolving exports for: " + AnsiToWide(moduleName));
        return false;
    }

    const auto& exportDirectoryInfo = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirectoryInfo.VirtualAddress == 0 || exportDirectoryInfo.Size == 0) {
        SetLastErrorMessage(L"Module lacks export directory: " + AnsiToWide(moduleName));
        return false;
    }

    const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + exportDirectoryInfo.VirtualAddress);
    if (!exportDirectory) {
        SetLastErrorMessage(L"Failed to map export directory for module: " + AnsiToWide(moduleName));
        return false;
    }

    DWORD ordinalIndex = 0;
    if (importName) {
        const auto nameTable = reinterpret_cast<PDWORD>(base + exportDirectory->AddressOfNames);
        const auto ordinalTable = reinterpret_cast<PWORD>(base + exportDirectory->AddressOfNameOrdinals);
        bool found = false;
        for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
            const char* exportName = reinterpret_cast<const char*>(base + nameTable[i]);
            if (exportName && std::strcmp(exportName, importName) == 0) {
                ordinalIndex = ordinalTable[i];
                found = true;
                break;
            }
        }
        if (!found) {
            SetLastErrorMessage(L"Failed to locate import '" + AnsiToWide(std::string(importName)) + L"' in module: " + AnsiToWide(moduleName));
            return false;
        }
    } else {
        if (ordinal < exportDirectory->Base) {
            SetLastErrorMessage(L"Import ordinal below export base for module: " + AnsiToWide(moduleName));
            return false;
        }
        ordinalIndex = ordinal - exportDirectory->Base;
        if (ordinalIndex >= exportDirectory->NumberOfFunctions) {
            SetLastErrorMessage(L"Import ordinal exceeds export table in module: " + AnsiToWide(moduleName));
            return false;
        }
    }

    const auto functionTable = reinterpret_cast<PDWORD>(base + exportDirectory->AddressOfFunctions);
    DWORD functionRva = functionTable[ordinalIndex];
    if (functionRva == 0) {
        SetLastErrorMessage(L"Export RVA is zero in module: " + AnsiToWide(moduleName));
        return false;
    }

    const DWORD exportStart = exportDirectoryInfo.VirtualAddress;
    const DWORD exportEnd = exportDirectoryInfo.VirtualAddress + exportDirectoryInfo.Size;
    if (functionRva >= exportStart && functionRva < exportEnd) {
        const char* forwarder = reinterpret_cast<const char*>(base + functionRva);
        if (!forwarder || *forwarder == '\0') {
            SetLastErrorMessage(L"Invalid forwarder string in module: " + AnsiToWide(moduleName));
            return false;
        }
        return ResolveForwarder(process, forwarder, remoteAddress, depth + 1);
    }

    remoteAddress = reinterpret_cast<uintptr_t>(remoteModule) + functionRva;
    return true;
}

bool ManualMapInjector::ResolveForwarder(HANDLE process,
                                         const std::string& forwarder,
                                         uintptr_t& remoteAddress,
                                         int depth) {
    if (depth > 16) {
        SetLastErrorMessage(L"Forwarder resolution depth exceeded while processing: " + AnsiToWide(forwarder));
        return false;
    }

    const size_t dot = forwarder.find('.');
    if (dot == std::string::npos || dot == forwarder.size() - 1) {
        SetLastErrorMessage(L"Malformed forwarder string: " + AnsiToWide(forwarder));
        return false;
    }

    std::string modulePart = forwarder.substr(0, dot);
    std::string functionPart = forwarder.substr(dot + 1);
    if (modulePart.empty() || functionPart.empty()) {
        SetLastErrorMessage(L"Malformed forwarder string: " + AnsiToWide(forwarder));
        return false;
    }

    modulePart = EnsureDllExtension(modulePart);

    HMODULE localModule = LoadLibraryA(modulePart.c_str());
    if (!localModule) {
        SetLastErrorMessage(L"Failed to load forwarded dependency locally: " + AnsiToWide(modulePart));
        return false;
    }

    HMODULE remoteModule = nullptr;
    if (!EnsureRemoteModule(process, modulePart, remoteModule)) {
        FreeLibrary(localModule);
        return false;
    }

    bool success = false;
    if (!functionPart.empty() && functionPart[0] == '#') {
        WORD forwardedOrdinal = static_cast<WORD>(std::strtoul(functionPart.c_str() + 1, nullptr, 10));
        success = ResolveExportAddress(process, localModule, remoteModule, modulePart, nullptr, forwardedOrdinal, remoteAddress, depth);
    } else {
        success = ResolveExportAddress(process, localModule, remoteModule, modulePart, functionPart.c_str(), 0, remoteAddress, depth);
    }

    FreeLibrary(localModule);
    return success;
}

} // namespace injection
