#include "../include/InjectionEngine.h"

#include "../include/ManualMapInjector.h"
#include "../include/SectionMapInjector.h"
#include "../include/DirectSyscall.h"

#include <TlHelp32.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace injection {

namespace {

class ScopedHandle {
public:
    ScopedHandle() noexcept : handle_(nullptr) {}
    explicit ScopedHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~ScopedHandle() {
        if (handle_) {
            CloseHandle(handle_);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            if (handle_) {
                CloseHandle(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    HANDLE get() const noexcept { return handle_; }
    HANDLE release() noexcept {
        HANDLE tmp = handle_;
        handle_ = nullptr;
        return tmp;
    }

    explicit operator bool() const noexcept { return handle_ != nullptr; }

private:
    HANDLE handle_;
};

std::wstring FormatWin32Error(const wchar_t* context, DWORD error) {
    wchar_t buffer[512] = {};
    DWORD len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr,
                               error,
                               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                               buffer,
                               static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])),
                               nullptr);
    std::wstring message;
    if (len) {
        message.assign(buffer, buffer + len);
        while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
            message.pop_back();
        }
    } else {
        message = L"Unknown error";
    }

    if (context && *context) {
        return std::wstring(context) + L": " + message + L" (" + std::to_wstring(error) + L")";
    }

    return message + L" (" + std::to_wstring(error) + L")";
}

bool ReadFileToBuffer(const std::wstring& path, std::vector<uint8_t>& buffer, std::wstring& detail) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        detail = L"Failed to open DLL: " + path;
        return false;
    }

    const std::streamoff size = file.tellg();
    if (size <= 0) {
        detail = L"Empty DLL file: " + path;
        return false;
    }

    buffer.resize(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        detail = L"Failed to read DLL content: " + path;
        buffer.clear();
        return false;
    }

    return true;
}

std::optional<uintptr_t> GetRemoteModuleBase(DWORD processId, const std::wstring& moduleName) {
    ScopedHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId));
    if (!snapshot) {
        return std::nullopt;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
        return std::nullopt;
    }

    do {
        if (_wcsicmp(entry.szModule, moduleName.c_str()) == 0) {
            return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
        }
    } while (Module32NextW(snapshot.get(), &entry));

    return std::nullopt;
}

uintptr_t ComputeRemoteFunction(uintptr_t remoteBase, HMODULE localModule, const char* functionName) {
    FARPROC localAddress = GetProcAddress(localModule, functionName);
    if (!localAddress) {
        return 0;
    }
    uintptr_t localBase = reinterpret_cast<uintptr_t>(localModule);
    uintptr_t offset = reinterpret_cast<uintptr_t>(localAddress) - localBase;
    return remoteBase + offset;
}

bool WriteRemoteMemory(HANDLE process, LPVOID destination, const void* data, SIZE_T size, std::wstring& detail) {
    if (!WriteProcessMemory(process, destination, data, size, nullptr)) {
        detail = FormatWin32Error(L"WriteProcessMemory", GetLastError());
        return false;
    }
    return true;
}

struct alignas(8) ReflectiveLoaderContext {
    uint8_t* imageBase;
    DWORD flags;
    FARPROC loadLibraryA;
    FARPROC getProcAddress;
    FARPROC virtualAlloc;
    FARPROC virtualProtect;
    FARPROC virtualFree;
};

using LoadLibraryAFn = HMODULE (WINAPI*)(LPCSTR);
using GetProcAddressFn = FARPROC (WINAPI*)(HMODULE, LPCSTR);
using VirtualAllocFn = LPVOID (WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using VirtualProtectFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
using VirtualFreeFn = BOOL (WINAPI*)(LPVOID, SIZE_T, DWORD);

#pragma optimize("", off)
#pragma code_seg(push, ".refstub")
extern "C" DWORD WINAPI ReflectiveLoaderStub(ReflectiveLoaderContext* context) {
    if (!context || !context->imageBase) {
        return 0;
    }

    auto loadLibraryA = reinterpret_cast<LoadLibraryAFn>(context->loadLibraryA);
    auto getProcAddress = reinterpret_cast<GetProcAddressFn>(context->getProcAddress);
    auto virtualAlloc = reinterpret_cast<VirtualAllocFn>(context->virtualAlloc);
    auto virtualProtect = reinterpret_cast<VirtualProtectFn>(context->virtualProtect);
    auto virtualFree = reinterpret_cast<VirtualFreeFn>(context->virtualFree);

    if (!loadLibraryA || !getProcAddress || !virtualAlloc || !virtualProtect) {
        return 0;
    }

    uint8_t* image = context->imageBase;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }

    BYTE* mapped = static_cast<BYTE*>(virtualAlloc(nullptr,
                                                   nt->OptionalHeader.SizeOfImage,
                                                   MEM_COMMIT | MEM_RESERVE,
                                                   PAGE_EXECUTE_READWRITE));
    if (!mapped) {
        return 0;
    }

    memcpy(mapped, image, nt->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (section[i].SizeOfRawData == 0) {
            continue;
        }

        memcpy(mapped + section[i].VirtualAddress,
               image + section[i].PointerToRawData,
               section[i].SizeOfRawData);
    }

    ULONGLONG delta =
#ifdef _WIN64
        reinterpret_cast<ULONGLONG>(mapped) - nt->OptionalHeader.ImageBase;
#else
        static_cast<ULONGLONG>(reinterpret_cast<DWORD>(mapped) - nt->OptionalHeader.ImageBase);
#endif
    if (delta != 0) {
        auto relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress != 0) {
            auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(image + relocDir.VirtualAddress);
            while (reloc && reloc->SizeOfBlock) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto entry = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < count; ++j) {
                    WORD typeOffset = entry[j];
                    WORD type = typeOffset >> 12;
                    WORD offset = typeOffset & 0x0FFF;
                    if (type == IMAGE_REL_BASED_ABSOLUTE) {
                        continue;
                    }
#ifdef _WIN64
                    if (type == IMAGE_REL_BASED_DIR64) {
                        auto patch = reinterpret_cast<ULONGLONG*>(mapped + reloc->VirtualAddress + offset);
                        *patch += delta;
                    }
#else
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        auto patch = reinterpret_cast<DWORD*>(mapped + reloc->VirtualAddress + offset);
                        *patch += static_cast<DWORD>(delta);
                    }
#endif
                }
                reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<PBYTE>(reloc) + reloc->SizeOfBlock);
            }
        }
    }

    auto importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0) {
        auto import = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(image + importDir.VirtualAddress);
        while (import->Name) {
            auto moduleName = reinterpret_cast<const char*>(image + import->Name);
            HMODULE module = loadLibraryA(moduleName);
            if (!module) {
                return 0;
            }

            auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                image + (import->OriginalFirstThunk ? import->OriginalFirstThunk : import->FirstThunk));
            auto func = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + import->FirstThunk);

            while (thunk && thunk->u1.AddressOfData) {
                FARPROC proc = nullptr;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    proc = getProcAddress(module, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunk->u1.Ordinal)));
                } else {
                    auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(image + thunk->u1.AddressOfData);
                    proc = getProcAddress(module, reinterpret_cast<LPCSTR>(name->Name));
                }
                func->u1.Function = reinterpret_cast<ULONG_PTR>(proc);
                ++thunk;
                ++func;
            }
            ++import;
        }
    }

    PIMAGE_SECTION_HEADER sectionProtect = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD protect = PAGE_NOACCESS;
        DWORD characteristics = sectionProtect[i].Characteristics;
        bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

        if (executable) {
            protect = readable ? (writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
                               : (writable ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE);
        } else if (readable) {
            protect = writable ? PAGE_READWRITE : PAGE_READONLY;
        } else if (writable) {
            protect = PAGE_WRITECOPY;
        }

        if (protect != PAGE_NOACCESS) {
            DWORD oldProtect = 0;
            virtualProtect(mapped + sectionProtect[i].VirtualAddress,
                           sectionProtect[i].Misc.VirtualSize,
                           protect,
                           &oldProtect);
        }
    }

    if (nt->OptionalHeader.AddressOfEntryPoint != 0) {
        auto dllMain = reinterpret_cast<BOOL (WINAPI*)(LPVOID, DWORD, LPVOID)>(
            mapped + nt->OptionalHeader.AddressOfEntryPoint);
        dllMain(mapped, DLL_PROCESS_ATTACH, nullptr);
    }

    if (virtualFree) {
        virtualFree(context->imageBase, 0, MEM_RELEASE);
    }

    return reinterpret_cast<DWORD>(mapped);
}

extern "C" void ReflectiveLoaderStubEnd() {}
#pragma code_seg(pop)
#pragma optimize("", on)

} // namespace

InjectionEngine::InjectionEngine() = default;

void InjectionEngine::SetLogger(LogCallback callback) {
    logger_ = std::move(callback);
}

void InjectionEngine::SetManualMapConfig(const ManualMapConfig& config) {
    manualMapConfigOverride_ = config;
}

void InjectionEngine::SetSectionMapConfig(const SectionMapConfig& config) {
    sectionMapConfigOverride_ = config;
}

InjectionResult InjectionEngine::Inject(DWORD processId,
                                        const std::wstring& dllPath,
                                        const InjectionOptions& options) {
    InjectionResult result{};
    result.detail = L"No injection methods attempted.";

    std::vector<InjectionMethod> order = options.methodOrder;
    if (order.empty()) {
        const auto envEnabledW = [](const wchar_t* name) -> bool {
            if (!name) return false; wchar_t b[32] = {}; DWORD n = GetEnvironmentVariableW(name, b, 32);
            if (!n || n >= 32) return false; std::wstring v(b, b+n); for (auto& c : v) c = (wchar_t)towlower(c);
            return (v == L"1" || v == L"true" || v == L"yes" || v == L"on");
        };
        const bool disableSection = envEnabledW(L"MLHOOK_DISABLE_SECTION_MAP");
        order.clear();
        if (!disableSection) order.push_back(InjectionMethod::SectionMap);
        order.push_back(InjectionMethod::ManualMap);
        order.push_back(InjectionMethod::Reflective);
        order.push_back(InjectionMethod::DirectSyscall);
        order.push_back(InjectionMethod::Standard);
    }

    for (InjectionMethod method : order) {
        std::wstring detail;
        bool success = false;

        switch (method) {
        case InjectionMethod::Standard: {
            auto process = OpenTargetProcess(processId,
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
            if (!process) {
                detail = L"Standard injection: unable to open process.";
                break;
            }
            ScopedHandle handle(process.value());
            success = InjectStandard(handle.get(), processId, dllPath, detail);
            break;
        }
        case InjectionMethod::SectionMap: {
            auto process = OpenTargetProcess(processId,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD);
            if (!process) {
                detail = L"Section map: unable to open process.";
                break;
            }
            ScopedHandle handle(process.value());
            {
                DWORD flags = options.sectionMapFlags;
                if (flags == 0) {
                    const auto envEnabledW = [](const wchar_t* name) -> bool {
                        if (!name) return false; wchar_t b[32] = {}; DWORD n = GetEnvironmentVariableW(name, b, 32);
                        if (!n || n >= 32) return false; std::wstring v(b, b+n); for (auto& c : v) c = (wchar_t)towlower(c);
                        return (v == L"1" || v == L"true" || v == L"yes" || v == L"on");
                    };
                    if (envEnabledW(L"MLHOOK_SECTION_RWX")) flags |= kSectionMapRWXDebug;
                    if (envEnabledW(L"MLHOOK_SECTION_NOTLS")) flags |= kSectionMapNoTLS;
                }
                success = InjectSectionMap(handle.get(), processId, dllPath, flags, detail);
            }
            break;
        }
        case InjectionMethod::ManualMap: {
            auto process = OpenTargetProcess(processId,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD);
            if (!process) {
                detail = L"Manual map: unable to open process.";
                break;
            }
            ScopedHandle handle(process.value());
            success = InjectManualMap(handle.get(), processId, dllPath, options.manualMapFlags, detail);
            break;
        }
        case InjectionMethod::Reflective: {
            auto process = OpenTargetProcess(processId,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD);
            if (!process) {
                detail = L"Reflective injection: unable to open process.";
                break;
            }
            ScopedHandle handle(process.value());
            success = InjectReflective(handle.get(), processId, dllPath, detail);
            break;
        }
        case InjectionMethod::DirectSyscall: {
            if (!options.allowDirectSyscall) {
                detail = L"Direct syscall injection disabled via options.";
                break;
            }
            success = InjectDirectSyscall(processId, dllPath, detail);
            break;
        }
        }

        Log(detail);

        if (success) {
            result.success = true;
            result.method = method;
            result.detail = detail;
            return result;
        }

        result.detail = detail;
    }

    return result;
}

bool InjectionEngine::InjectStandard(HANDLE process,
                                     DWORD /*processId*/,
                                     const std::wstring& dllPath,
                                     std::wstring& detail) const {
    if (!process) {
        detail = L"InjectStandard received null process handle.";
        return false;
    }

    const SIZE_T bytes = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        detail = FormatWin32Error(L"VirtualAllocEx", GetLastError());
        return false;
    }

    if (!WriteProcessMemory(process, remotePath, dllPath.c_str(), bytes, nullptr)) {
        detail = FormatWin32Error(L"WriteProcessMemory", GetLastError());
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
    if (!loadLibraryW) {
        detail = L"Failed to resolve LoadLibraryW locally.";
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        return false;
    }

    ScopedHandle thread(CreateRemoteThread(process,
                                           nullptr,
                                           0,
                                           loadLibraryW,
                                           remotePath,
                                           0,
                                           nullptr));
    if (!thread) {
        detail = FormatWin32Error(L"CreateRemoteThread", GetLastError());
        VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread.get(), INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(thread.get(), &exitCode);
    VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);

    if (exitCode == 0) {
        detail = L"LoadLibraryW returned null.";
        return false;
    }

    detail = L"Standard LoadLibraryW injection succeeded.";
    return true;
}

bool InjectionEngine::InjectManualMap(HANDLE process,
                                      DWORD /*processId*/,
                                      const std::wstring& dllPath,
                                      DWORD manualMapFlags,
                                      std::wstring& detail) {
    ManualMapInjector injector;
    if (manualMapConfigOverride_) {
        injector.SetConfig(*manualMapConfigOverride_);
    }
    if (!injector.LoadFromFile(dllPath)) {
        detail = injector.GetLastError();
        return false;
    }

    if (!injector.InjectIntoProcess(process, manualMapFlags)) {
        detail = injector.GetLastError();
        return false;
    }

    std::wostringstream oss;
    oss << L"Manual map injection succeeded (image size " << injector.ImageSize() << L" bytes";
    if (injector.LastRemoteBase()) {
        oss << L", base=0x" << std::hex << reinterpret_cast<uintptr_t>(injector.LastRemoteBase()) << std::dec;
        if (injector.LastRandomOffset() != 0) {
            oss << L", offset=" << injector.LastRandomOffset() << L" bytes";
        }
    }
    oss << L").";
    detail = oss.str();
    return true;
}

bool InjectionEngine::InjectReflective(HANDLE process,
                                       DWORD processId,
                                       const std::wstring& dllPath,
                                       std::wstring& detail) {
    std::vector<uint8_t> buffer;
    if (!ReadFileToBuffer(dllPath, buffer, detail)) {
        return false;
    }

    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        detail = L"Reflective injection: buffer too small for DOS header.";
        return false;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        detail = L"Reflective injection: invalid DOS signature.";
        return false;
    }

    if (buffer.size() < static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS)) {
        detail = L"Reflective injection: buffer too small for NT headers.";
        return false;
    }

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        detail = L"Reflective injection: invalid NT signature.";
        return false;
    }

    LPVOID remoteImage = VirtualAllocEx(process,
                                        nullptr,
                                        buffer.size(),
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!remoteImage) {
        detail = FormatWin32Error(L"VirtualAllocEx (image)", GetLastError());
        return false;
    }

    if (!WriteRemoteMemory(process, remoteImage, buffer.data(), buffer.size(), detail)) {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return false;
    }

    auto remoteKernel32 = GetRemoteModuleBase(processId, L"kernel32.dll");
    if (!remoteKernel32) {
        detail = L"Reflective injection: unable to locate kernel32.dll in target.";
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return false;
    }

    HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
    uintptr_t loadLibraryAAddr = ComputeRemoteFunction(*remoteKernel32, localKernel32, "LoadLibraryA");
    uintptr_t getProcAddressAddr = ComputeRemoteFunction(*remoteKernel32, localKernel32, "GetProcAddress");
    uintptr_t virtualAllocAddr = ComputeRemoteFunction(*remoteKernel32, localKernel32, "VirtualAlloc");
    uintptr_t virtualProtectAddr = ComputeRemoteFunction(*remoteKernel32, localKernel32, "VirtualProtect");
    uintptr_t virtualFreeAddr = ComputeRemoteFunction(*remoteKernel32, localKernel32, "VirtualFree");

    if (!loadLibraryAAddr || !getProcAddressAddr || !virtualAllocAddr || !virtualProtectAddr) {
        detail = L"Reflective injection: failed to resolve kernel32 exports in target.";
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return false;
    }

    ReflectiveLoaderContext context{};
    context.imageBase = static_cast<uint8_t*>(remoteImage);
    context.flags = 0;
    context.loadLibraryA = reinterpret_cast<FARPROC>(loadLibraryAAddr);
    context.getProcAddress = reinterpret_cast<FARPROC>(getProcAddressAddr);
    context.virtualAlloc = reinterpret_cast<FARPROC>(virtualAllocAddr);
    context.virtualProtect = reinterpret_cast<FARPROC>(virtualProtectAddr);
    context.virtualFree = reinterpret_cast<FARPROC>(virtualFreeAddr);

    LPVOID remoteContext = VirtualAllocEx(process,
                                          nullptr,
                                          sizeof(context),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remoteContext) {
        detail = FormatWin32Error(L"VirtualAllocEx (context)", GetLastError());
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteRemoteMemory(process, remoteContext, &context, sizeof(context), detail)) {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteContext, 0, MEM_RELEASE);
        return false;
    }

    const uint8_t* stubStart = reinterpret_cast<const uint8_t*>(&ReflectiveLoaderStub);
    const uint8_t* stubEnd = reinterpret_cast<const uint8_t*>(&ReflectiveLoaderStubEnd);
    SIZE_T stubSize = static_cast<SIZE_T>(stubEnd - stubStart);

    LPVOID remoteStub = VirtualAllocEx(process,
                                       nullptr,
                                       stubSize,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!remoteStub) {
        detail = FormatWin32Error(L"VirtualAllocEx (stub)", GetLastError());
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteContext, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteRemoteMemory(process, remoteStub, stubStart, stubSize, detail)) {
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteContext, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
        return false;
    }

    ScopedHandle thread(CreateRemoteThread(process,
                                           nullptr,
                                           0,
                                           reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub),
                                           remoteContext,
                                           0,
                                           nullptr));
    if (!thread) {
        detail = FormatWin32Error(L"CreateRemoteThread (reflective)", GetLastError());
        VirtualFreeEx(process, remoteImage, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteContext, 0, MEM_RELEASE);
        VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread.get(), INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(thread.get(), &exitCode);

    VirtualFreeEx(process, remoteContext, 0, MEM_RELEASE);
    VirtualFreeEx(process, remoteStub, 0, MEM_RELEASE);

    if (exitCode == 0) {
        detail = L"Reflective loader reported failure.";
        return false;
    }

    detail = L"Reflective injection succeeded.";
    return true;
}

bool InjectionEngine::InjectSectionMap(HANDLE process,
                                       DWORD /*processId*/,
                                       const std::wstring& dllPath,
                                       DWORD sectionMapFlags,
                                       std::wstring& detail) {
    std::vector<uint8_t> buffer;
    if (!ReadFileToBuffer(dllPath, buffer, detail)) {
        return false;
    }

    SectionMapInjector injector;
    if (sectionMapConfigOverride_) {
        injector.SetConfig(*sectionMapConfigOverride_);
    }
    if (!injector.LoadFromMemory(buffer.data(), buffer.size())) {
        detail = L"Section map: " + injector.GetLastError();
        return false;
    }

    if (!injector.InjectIntoProcess(process, sectionMapFlags)) {
        detail = L"Section map failed: " + injector.GetLastError();
        return false;
    }

    detail = L"Section map injection succeeded.";
    return true;
}

bool InjectionEngine::InjectDirectSyscall(DWORD processId,
                                          const std::wstring& dllPath,
                                          std::wstring& detail) {
    if (!EnsureDirectSyscallInitialized()) {
        detail = L"Direct syscall engine failed to initialize.";
        return false;
    }

    if (!InjectDllViaDirectSyscall(processId, dllPath)) {
        detail = L"Direct syscall injection failed.";
        return false;
    }

    detail = L"Direct syscall injection succeeded.";
    return true;
}

std::optional<HANDLE> InjectionEngine::OpenTargetProcess(DWORD processId, DWORD accessMask) const {
    HANDLE handle = OpenProcess(accessMask, FALSE, processId);
    if (!handle) {
        handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!handle) {
            return std::nullopt;
        }
    }
    return handle;
}

void InjectionEngine::Log(const std::wstring& message) const {
    if (logger_) {
        logger_(message);
    }
}

} // namespace injection
