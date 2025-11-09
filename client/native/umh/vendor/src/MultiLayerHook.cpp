#pragma warning(push)
#pragma warning(disable:4201)
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "../include/MultiLayerHook.h"
#include "../include/HookEngine.h"

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <VersionHelpers.h>
#include <winnt.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <memory>
#include <shared_mutex>
#include <sstream>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef UNW_FLAG_NHANDLER
#define UNW_FLAG_NHANDLER 0x0
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef ThreadInstrumentationCallback
#define ThreadInstrumentationCallback static_cast<THREAD_INFORMATION_CLASS>(40)
#endif

#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

namespace {

constexpr size_t kMaxSnapshotBytes = 32;
constexpr size_t kSyscallPatchLength = 14;
constexpr size_t kSyscallBackupLength = 32;
constexpr ULONGLONG kVehPendingTimeoutMs = 250;
constexpr uint32_t kVehMaxFaults = 4;
constexpr DWORD kSyntheticUnwindSpan = 64;
constexpr size_t kShadowAlignment = 16;

#if defined(_WIN64) && !defined(UNWIND_INFO)
typedef union _UNWIND_CODE {
    struct {
        UCHAR CodeOffset;
        UCHAR UnwindOp : 4;
        UCHAR OpInfo : 4;
    } DUMMYSTRUCTNAME;
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UCHAR Version : 3;
    UCHAR Flags : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    union {
        ULONG ExceptionHandler;
        ULONG FunctionEntry;
    } DUMMYUNIONNAME;
    ULONG ExceptionData[1];
} UNWIND_INFO, *PUNWIND_INFO;
#endif

struct ModuleExportContext {
    HMODULE module = nullptr;
    PIMAGE_EXPORT_DIRECTORY directory = nullptr;
    PDWORD nameTable = nullptr;
    PDWORD addressTable = nullptr;
    PWORD ordinalTable = nullptr;
    DWORD exportDirRva = 0;
    DWORD exportDirSize = 0;
};

struct InstrumentationCallbackInformation {
    ULONG Version = 0;
    ULONG Reserved = 0;
    PVOID Callback = nullptr;
};

struct InstrumentationCallbackData {
    ULONG Version;
    ULONG Reserved;
    ULONG_PTR ProgramCounter;
    ULONG_PTR StackPointer;
    ULONG_PTR FramePointer;
    ULONG_PTR ReturnAddress;
    ULONG_PTR Reserved1;
    ULONG_PTR Reserved2;
};

using NtSetInformationThread_t = NTSTATUS (NTAPI*)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG);
using NtQueryInformationThread_t = NTSTATUS (NTAPI*)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::wstring ToLower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    return value;
}

bool CaseInsensitiveEquals(const std::string& lhs, const std::string& rhs) {
    return ToLower(lhs) == ToLower(rhs);
}

bool CaseInsensitiveEquals(const std::wstring& lhs, const std::wstring& rhs) {
    return ToLower(lhs) == ToLower(rhs);
}

bool IsEnvFlagEnabled(const wchar_t* name) {
    if (!name || !*name) {
        return false;
    }

    // 1) Check environment
    constexpr DWORD kBuffer = 32;
    wchar_t buffer[kBuffer] = {};
    DWORD len = GetEnvironmentVariableW(name, buffer, kBuffer);
    if (len != 0 && len < kBuffer) {
        std::wstring value(buffer, buffer + len);
        value = ToLower(value);
        if (value == L"1" || value == L"true" || value == L"yes" || value == L"on") {
            return true;
        }
        if (value == L"0" || value == L"false" || value == L"no" || value == L"off") {
            return false;
        }
    }

    // 2) Fallback to registry: HKCU\Software\UserModeHook\Flags\<name>
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\UserModeHook\\Flags", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
        wchar_t val[32] = {};
        DWORD type = 0, size = sizeof(val);
        if (RegQueryValueExW(hKey, name, nullptr, &type, reinterpret_cast<LPBYTE>(val), &size) == ERROR_SUCCESS) {
            std::wstring s(val);
            s = ToLower(s);
            RegCloseKey(hKey);
            return s == L"1" || s == L"true" || s == L"yes" || s == L"on";
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool ShouldDisableLayer(HookLayer layer) {
    switch (layer) {
    case HookLayer::Inline: {
        static const bool disabled = IsEnvFlagEnabled(L"MLHOOK_DISABLE_INLINE");
        return disabled;
    }
    case HookLayer::IAT: {
        static const bool disabled = IsEnvFlagEnabled(L"MLHOOK_DISABLE_IAT");
        return disabled;
    }
    case HookLayer::EAT: {
        static const bool disabled = IsEnvFlagEnabled(L"MLHOOK_DISABLE_EAT");
        return disabled;
    }
    case HookLayer::VEH: {
        static const bool disabled = IsEnvFlagEnabled(L"MLHOOK_DISABLE_VEH");
        return disabled;
    }
    case HookLayer::Instrumentation: {
        static const bool disabled = IsEnvFlagEnabled(L"MLHOOK_DISABLE_INSTRUMENTATION");
        return disabled;
    }
    case HookLayer::Syscall: {
        static const bool disabled = IsEnvFlagEnabled(L"MLHOOK_DISABLE_SYSCALL");
        return disabled;
    }
    default:
        return false;
    }
}

bool ShouldForceEATShadow() {
    static const bool forceShadow = IsEnvFlagEnabled(L"MLHOOK_FORCE_EAT_SHADOW");
    return forceShadow;
}

size_t AlignUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

#if defined(_WIN64)
using RtlAddFunctionTable_t = BOOLEAN (WINAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
using RtlDeleteFunctionTable_t = BOOLEAN (WINAPI*)(PRUNTIME_FUNCTION);
using RtlLookupFunctionEntry_t = PRUNTIME_FUNCTION (WINAPI*)(DWORD64, PDWORD64, PUNWIND_HISTORY_TABLE);
#endif

#if defined(_WIN64)
struct SyscallStubInfo {
    DWORD syscallNumber = 0;
    BYTE returnOpcode = 0xC3;
    WORD returnOperand = 0;
};

bool DecodeCanonicalSyscallStub(LPBYTE address, SyscallStubInfo& info) {
    if (!address) {
        return false;
    }

    // Canonical x64 Nt/Xx stubs use:
    // mov r10, rcx
    // mov eax, <syscall>
    // syscall
    // ret / ret imm16
    if (address[0] != 0x4C || address[1] != 0x8B || address[2] != 0xD1) {
        return false;
    }

    if (address[3] != 0xB8) {
        return false;
    }

    DWORD number = 0;
    memcpy(&number, address + 4, sizeof(DWORD));

    if (address[8] != 0x0F || address[9] != 0x05) {
        return false;
    }

    BYTE retOpcode = address[10];
    WORD retOperand = 0;
    if (retOpcode == 0xC2) {
        memcpy(&retOperand, address + 11, sizeof(WORD));
    } else if (retOpcode != 0xC3) {
        return false;
    }

    info.syscallNumber = number;
    info.returnOpcode = retOpcode;
    info.returnOperand = retOperand;
    return true;
}

bool BuildSyscallTrampoline(const SyscallStubInfo& info,
                            LPBYTE& trampolineOut,
                            SIZE_T& trampolineSizeOut) {
    constexpr SIZE_T kAllocSize = 64;
    LPBYTE buffer = static_cast<LPBYTE>(VirtualAlloc(nullptr,
                                                     kAllocSize,
                                                     MEM_COMMIT | MEM_RESERVE,
                                                     PAGE_EXECUTE_READWRITE));
    if (!buffer) {
        return false;
    }

    SIZE_T offset = 0;
    buffer[offset++] = 0x4C; // mov r10, rcx
    buffer[offset++] = 0x8B;
    buffer[offset++] = 0xD1;
    buffer[offset++] = 0xB8; // mov eax, imm32
    memcpy(buffer + offset, &info.syscallNumber, sizeof(DWORD));
    offset += sizeof(DWORD);
    buffer[offset++] = 0x0F; // syscall
    buffer[offset++] = 0x05;

    if (info.returnOpcode == 0xC2) {
        buffer[offset++] = 0xC2;
        memcpy(buffer + offset, &info.returnOperand, sizeof(WORD));
        offset += sizeof(WORD);
    } else {
        buffer[offset++] = 0xC3;
    }

    DWORD oldProtect = 0;
    VirtualProtect(buffer, kAllocSize, PAGE_EXECUTE_READ, &oldProtect);

    trampolineOut = buffer;
    trampolineSizeOut = offset;
    return true;
}
#endif

LPBYTE AllocateNearAddress(LPVOID target, SIZE_T size) {
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);
    size = AlignUp(size, sysInfo.dwAllocationGranularity);

    LPBYTE base = reinterpret_cast<LPBYTE>(target);
    const SIZE_T step = sysInfo.dwAllocationGranularity;
    const SIZE_T maxAttempts = 512;

    for (SIZE_T attempt = 1; attempt <= maxAttempts; ++attempt) {
        LPBYTE candidate = base + attempt * step;
        LPVOID allocation = VirtualAlloc(candidate, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocation) {
            return reinterpret_cast<LPBYTE>(allocation);
        }
    }

    return nullptr;
}

LPBYTE AllocateShadowForModule(HMODULE module, SIZE_T size, DWORD& outRva) {
    SYSTEM_INFO sysInfo = {};
    GetSystemInfo(&sysInfo);
    size = AlignUp(size, sysInfo.dwAllocationGranularity);

    LPBYTE base = reinterpret_cast<LPBYTE>(module);
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);

    SIZE_T imageSize = AlignUp(nt->OptionalHeader.SizeOfImage, sysInfo.dwAllocationGranularity);
    LPBYTE start = base + imageSize;
    const SIZE_T step = sysInfo.dwAllocationGranularity;
    const SIZE_T maxAttempts = 512;

    for (SIZE_T attempt = 0; attempt < maxAttempts; ++attempt) {
        LPBYTE candidate = start + attempt * step;
        LPVOID allocation = VirtualAlloc(candidate, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!allocation) {
            continue;
        }

        LPBYTE allocated = reinterpret_cast<LPBYTE>(allocation);
        if (allocated < base) {
            VirtualFree(allocation, 0, MEM_RELEASE);
            continue;
        }

        SIZE_T relative = static_cast<SIZE_T>(allocated - base);
        if (relative + size <= MAXDWORD) {
            outRva = static_cast<DWORD>(relative);
            return allocated;
        }

        VirtualFree(allocation, 0, MEM_RELEASE);
    }

    return nullptr;
}

HMODULE ResolveModule(const std::wstring& moduleName) {
    if (moduleName.empty()) {
        return nullptr;
    }

    HMODULE module = GetModuleHandleW(moduleName.c_str());
    if (!module) {
        module = LoadLibraryW(moduleName.c_str());
    }
    return module;
}

void LogDebug(const std::string& message) {
#if defined(_DEBUG)
    OutputDebugStringA(message.c_str());
#else
    (void)message;
#endif
}

// Minimal structured audit logger for api_hooks.log (shared with HookDLL)
void LogStructuredAudit(const std::string& event,
                        const std::string& func,
                        const char* layer,
                        const char* status,
                        const std::string& extra = std::string()) {
    // Ensure directory
    CreateDirectoryW(L"C:\\Temp", nullptr);

    // Coordinate with HookDLL logger if present
    HANDLE mutexHandle = CreateMutexW(nullptr, FALSE, L"HookDLLLogMutex");
    DWORD waitResult = WAIT_FAILED;
    if (mutexHandle) {
        waitResult = WaitForSingleObject(mutexHandle, 2000);
    }

    SYSTEMTIME st{};
    GetLocalTime(&st);

    std::ostringstream line;
    line << "[" << std::setfill('0')
         << std::setw(2) << st.wHour << ":"
         << std::setw(2) << st.wMinute << ":"
         << std::setw(2) << st.wSecond << "."
         << std::setw(3) << st.wMilliseconds << "] "
         << "umh event=" << event
         << " func=" << func
         << " pid=" << GetCurrentProcessId()
         << " tid=" << GetCurrentThreadId();
    if (layer && *layer) {
        line << " layer=" << layer;
    }
    if (status && *status) {
        line << " status=" << status;
    }
    if (!extra.empty()) {
        line << " " << extra;
    }

    std::ofstream logFile("C:\\Temp\\api_hooks.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << line.str() << std::endl;
        logFile.flush();
    }

    if (mutexHandle) {
        ReleaseMutex(mutexHandle);
        CloseHandle(mutexHandle);
    }
}

const char* LayerToStr(HookLayer layer) {
    switch (layer) {
    case HookLayer::Inline: return "inline";
    case HookLayer::IAT: return "iat";
    case HookLayer::EAT: return "eat";
    case HookLayer::VEH: return "veh";
    case HookLayer::Instrumentation: return "instrumentation";
    case HookLayer::Syscall: return "syscall";
    default: return "unknown";
    }
}

class CachedProcessInfo {
public:
    static CachedProcessInfo& Instance() {
        static CachedProcessInfo info;
        return info;
    }

    void Refresh() {
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {};
        if (GetProcessMitigationPolicy(GetCurrentProcess(),
                                       ProcessControlFlowGuardPolicy,
                                       &cfg,
                                       sizeof(cfg))) {
            cfgEnabled_ = cfg.EnableControlFlowGuard;
        }

        #if !defined(_WIN64)
        BOOL wow64 = FALSE;
        #endif
#if defined(_WIN64)
        wow64Process_ = FALSE;
#else
        if (IsWow64Process(GetCurrentProcess(), &wow64)) {
            wow64Process_ = wow64;
        }
#endif

        instrumentationSupported_ = IsWindows10OrGreater();
        if (!instrumentationSupported_) {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (!ntdll) {
                ntdll = LoadLibraryW(L"ntdll.dll");
            }
            if (ntdll) {
                auto setInfo = reinterpret_cast<NtSetInformationThread_t>(
                    GetProcAddress(ntdll, "NtSetInformationThread"));
                instrumentationSupported_ = (setInfo != nullptr);
            }
        }
    }

    bool ControlFlowGuardEnabled() const { return cfgEnabled_; }
    bool Wow64Process() const { return wow64Process_; }
    bool InstrumentationSupported() const { return instrumentationSupported_; }

private:
    CachedProcessInfo() { Refresh(); }

    bool cfgEnabled_ = false;
    bool wow64Process_ = false;
    bool instrumentationSupported_ = false;
};

ModuleExportContext BuildExportContext(HMODULE module) {
    ModuleExportContext ctx{};
    ctx.module = module;
    if (!module) {
        return ctx;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(module) + dos->e_lfanew);

    ULONG size = 0;
    ctx.directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        ImageDirectoryEntryToData(module, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size));
    if (!ctx.directory) {
        return ctx;
    }

    ctx.exportDirRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ctx.exportDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ctx.nameTable = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(module) + ctx.directory->AddressOfNames);
    ctx.addressTable = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(module) + ctx.directory->AddressOfFunctions);
    ctx.ordinalTable = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(module) + ctx.directory->AddressOfNameOrdinals);
    return ctx;
}

bool IsForwardedExport(const ModuleExportContext& ctx, DWORD rva) {
    if (!ctx.module) {
        return false;
    }
    return rva >= ctx.exportDirRva && rva < (ctx.exportDirRva + ctx.exportDirSize);
}

class PageGuard {
public:
    PageGuard(LPVOID address, SIZE_T size, DWORD protection)
        : address_(address), size_(size) {
        if (!address_ || size_ == 0) {
            return;
        }
        success_ = VirtualProtect(address_, size_, protection, &originalProtection_) == TRUE;
    }

    ~PageGuard() {
        if (!success_) {
            return;
        }
        DWORD ignored = 0;
        VirtualProtect(address_, size_, originalProtection_, &ignored);
    }

    bool Succeeded() const { return success_; }

private:
    LPVOID address_ = nullptr;
    SIZE_T size_ = 0;
    DWORD originalProtection_ = 0;
    bool success_ = false;
};

} // namespace

// ============================================================
// HookRegistry implementation
// ============================================================

HookRegistry& HookRegistry::instance() {
    static HookRegistry registry;
    return registry;
}

HookRegistry::HookRegistry() {
    detectCapabilities();
}

HookCapabilities HookRegistry::capabilities() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return capabilities_;
}

HookContext* HookRegistry::find(const std::string& functionName) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = ToLower(functionName);
    auto it = hooksByName_.find(key);
    if (it == hooksByName_.end()) {
        return nullptr;
    }
    return &it->second;
}

HookContext* HookRegistry::findByAddress(LPVOID address) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooksByAddress_.find(address);
    if (it != hooksByAddress_.end()) {
        auto ctxIt = hooksByName_.find(it->second);
        if (ctxIt != hooksByName_.end()) {
            return &ctxIt->second;
        }
    }

    for (auto& pair : hooksByName_) {
        HookContext& context = pair.second;
        if (context.targetAddress == address || context.detour == address) {
            hooksByAddress_[address] = pair.first;
            return &context;
        }
    }

    return nullptr;
}

HookContext& HookRegistry::add(const HookTargetDescriptor& descriptor, LPVOID detour) {
    std::lock_guard<std::mutex> lock(mutex_);

    HookContext context;
    context.target = descriptor;
    context.detour = detour;
    context.layers = {
        {HookLayer::Inline},
        {HookLayer::IAT},
        {HookLayer::EAT},
        {HookLayer::VEH},
        {HookLayer::Instrumentation},
        {HookLayer::Syscall}
    };

    auto key = ToLower(descriptor.functionName);
    hooksByName_[key] = context;
    hooksByAddress_[detour] = key;
    return hooksByName_[key];
}

void HookRegistry::remove(const std::string& functionName) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = ToLower(functionName);
    auto it = hooksByName_.find(key);
    if (it == hooksByName_.end()) {
        return;
    }

    if (it->second.detour) {
        hooksByAddress_.erase(it->second.detour);
    }
    if (it->second.targetAddress) {
        hooksByAddress_.erase(it->second.targetAddress);
    }

    hooksByName_.erase(it);
}

void HookRegistry::bindAddress(const std::string& functionName, LPVOID address) {
    if (!address) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = ToLower(functionName);
    if (hooksByName_.find(key) == hooksByName_.end()) {
        return;
    }
    hooksByAddress_[address] = key;
}

LPVOID HookRegistry::getOriginal(const std::string& functionName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = ToLower(functionName);
    auto it = hooksByName_.find(key);
    if (it == hooksByName_.end()) {
        return nullptr;
    }
    return it->second.original;
}

std::vector<HookContext> HookRegistry::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HookContext> result;
    result.reserve(hooksByName_.size());
    for (const auto& pair : hooksByName_) {
        result.push_back(pair.second);
    }
    return result;
}

void HookRegistry::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    hooksByName_.clear();
    hooksByAddress_.clear();
}

void HookRegistry::disableInstrumentationSupport() {
    std::lock_guard<std::mutex> lock(mutex_);
    capabilities_.supportsInstrumentation = false;
}

void HookRegistry::disableSyscallSupport() {
    std::lock_guard<std::mutex> lock(mutex_);
    capabilities_.supportsSyscall = false;
}

void HookRegistry::detectCapabilities() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (capabilitiesDetected_) {
        return;
    }

    CachedProcessInfo::Instance().Refresh();

    capabilities_.cfgEnabled = CachedProcessInfo::Instance().ControlFlowGuardEnabled();
    capabilities_.wow64Process = CachedProcessInfo::Instance().Wow64Process();
    capabilities_.supportsInstrumentation = CachedProcessInfo::Instance().InstrumentationSupported();
    capabilities_.supportsVEH = true;
#if defined(_WIN64)
    capabilities_.supportsSyscall = !capabilities_.wow64Process;
#else
    capabilities_.supportsSyscall = false;
#endif
    capabilities_.supportsEATPatch = !capabilities_.cfgEnabled;

    if (IsEnvFlagEnabled(L"MLHOOK_FORCE_CFG_ON")) {
        capabilities_.cfgEnabled = true;
    } else if (IsEnvFlagEnabled(L"MLHOOK_FORCE_CFG_OFF")) {
        capabilities_.cfgEnabled = false;
    }

    if (IsEnvFlagEnabled(L"MLHOOK_DISABLE_INSTRUMENTATION")) {
        capabilities_.supportsInstrumentation = false;
    }
    if (IsEnvFlagEnabled(L"MLHOOK_DISABLE_VEH")) {
        capabilities_.supportsVEH = false;
    }
    if (IsEnvFlagEnabled(L"MLHOOK_DISABLE_SYSCALL")) {
        capabilities_.supportsSyscall = false;
    }
    if (IsEnvFlagEnabled(L"MLHOOK_DISABLE_EAT")) {
        capabilities_.supportsEATPatch = false;
    } else {
        capabilities_.supportsEATPatch = !capabilities_.cfgEnabled && capabilities_.supportsEATPatch;
    }

    capabilitiesDetected_ = true;

    std::cout << "[Capabilities] cfgEnabled=" << (capabilities_.cfgEnabled ? "true" : "false")
              << " wow64=" << (capabilities_.wow64Process ? "true" : "false")
              << " instrumentation=" << (capabilities_.supportsInstrumentation ? "true" : "false")
              << " syscall=" << (capabilities_.supportsSyscall ? "true" : "false")
              << std::endl;
}

// ============================================================
// ScopedProtect implementation
// ============================================================

ScopedProtect::ScopedProtect(LPVOID address, SIZE_T size, DWORD newProtect)
    : address_(address), size_(size) {
    if (!address_ || size_ == 0) {
        return;
    }

    success_ = VirtualProtect(address_, size_, newProtect, &oldProtect_) == TRUE;
}

ScopedProtect::~ScopedProtect() {
    if (!success_) {
        return;
    }
    DWORD ignored = 0;
    VirtualProtect(address_, size_, oldProtect_, &ignored);
}

// ============================================================
// Thread enumeration helper
// ============================================================

void ForEachThread(const ThreadEnumerationCallback& callback) {
    if (!callback) {
        return;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return;
    }

    DWORD pid = GetCurrentProcessId();
    do {
        if (entry.th32OwnerProcessID != pid) {
            continue;
        }

        HANDLE threadHandle = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION,
                                         FALSE,
                                         entry.th32ThreadID);
        if (!threadHandle) {
            continue;
        }

        callback(entry.th32ThreadID, threadHandle);
        CloseHandle(threadHandle);
    } while (Thread32Next(snapshot, &entry));

    CloseHandle(snapshot);
}

// ============================================================
// MultiLayerHookEngine declaration
// ============================================================

class MultiLayerHookEngine {
public:
    static MultiLayerHookEngine& instance();

    bool initialize();
    void shutdown();

    bool installHook(const HookTargetDescriptor& descriptor,
                     LPVOID detour,
                     LPVOID* originalOut,
                     const std::vector<HookLayer>& preferredLayers);

    bool uninstallHook(const std::string& functionName);
    void monitorAndRepair();

    LPVOID lookupPreviousInstrumentationCallback(DWORD threadId);

    static VOID NTAPI InstrumentationCallbackEntry(ULONG_PTR returnValue,
                                                   InstrumentationCallbackData* data);

private:
    MultiLayerHookEngine();

    MultiLayerHookEngine(const MultiLayerHookEngine&) = delete;
    MultiLayerHookEngine& operator=(const MultiLayerHookEngine&) = delete;

    HookLayerState* findLayerState(HookContext& context, HookLayer layer);

    bool installInline(HookContext& context);
    bool installIAT(HookContext& context);
    bool installEAT(HookContext& context);
    bool installEATShadow(HookContext& context,
                          ModuleExportContext& exports,
                          WORD ordinal,
                          DWORD newRva,
                          HookContext::EATMetadata& metadata);
    bool installVEH(HookContext& context);
    bool installInstrumentation(HookContext& context);
    bool installSyscall(HookContext& context);

    bool verifyInline(const HookContext& context);
    bool verifyIAT(const HookContext& context);
    bool verifyEAT(const HookContext& context);
    bool verifyVEH(const HookContext& context);
    bool verifyInstrumentation(HookContext& context);
    bool verifySyscall(const HookContext& context);

    bool restoreIAT(HookContext& context);
    bool restoreEAT(HookContext& context);
    bool restoreVEH(HookContext& context);
    bool restoreInstrumentation(HookContext& context);
    bool restoreSyscall(HookContext& context);

    bool ensureVehHandler();
    bool resolveInstrumentationProcedures();
    bool resolveUnwindProcedures();
    bool registerDetourUnwindIfNeeded(HookContext& context);

    // Forward declare structs
    struct VehEntry {
        LPBYTE address = nullptr;
        LPVOID detour = nullptr;
        BYTE originalByte = 0;
        HookContext::VEHMetadata* metadata = nullptr;
    };

    LONG handleVehBreakpoint(PEXCEPTION_POINTERS exceptionPointers);
    LONG handleVehSingleStep(PEXCEPTION_POINTERS exceptionPointers);
    void autoDisableVehEntryLocked(const VehEntry& entry,
                                   HookContext::VEHMetadata* metadata);

    static LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS exceptionPointers);
    void handleInstrumentationCallback(ULONG_PTR returnValue, InstrumentationCallbackData* data);

    std::mutex mutex_;
    PVOID vehHandle_ = nullptr;
    bool initialized_ = false;

    NtSetInformationThread_t ntSetInformationThread_ = nullptr;
    NtQueryInformationThread_t ntQueryInformationThread_ = nullptr;
    bool instrumentationProceduresResolved_ = false;
    bool unwindProceduresResolved_ = false;

#if defined(_WIN64)
    RtlAddFunctionTable_t rtlAddFunctionTable_ = nullptr;
    RtlDeleteFunctionTable_t rtlDeleteFunctionTable_ = nullptr;
    RtlLookupFunctionEntry_t rtlLookupFunctionEntry_ = nullptr;
#endif

    struct PendingRearm {
        LPBYTE address = nullptr;
        BYTE originalByte = 0;
        HookContext::VEHMetadata* metadata = nullptr;
    };

    std::unordered_map<LPVOID, VehEntry> vehEntries_;
    std::unordered_map<DWORD, PendingRearm> vehPendingRearm_;
    std::mutex vehPendingMutex_;

    struct InstrumentationThreadState {
        DWORD threadId = 0;
        PVOID previousCallback = nullptr;
        uint32_t refCount = 0;
    };

    std::unordered_map<DWORD, InstrumentationThreadState> instrumentationThreads_;
    std::unordered_map<LPVOID, LPVOID> instrumentationTargets_;
    std::shared_mutex instrumentationMutex_;
};

MultiLayerHookEngine::MultiLayerHookEngine() = default;

MultiLayerHookEngine& MultiLayerHookEngine::instance() {
    static MultiLayerHookEngine engine;
    return engine;
}

bool MultiLayerHookEngine::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return true;
    }

    HookEngine::getInstance();
    ensureVehHandler();
    resolveInstrumentationProcedures();
    initialized_ = true;
    return true;
}

void MultiLayerHookEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (vehHandle_) {
        RemoveVectoredExceptionHandler(vehHandle_);
        vehHandle_ = nullptr;
    }

    instrumentationThreads_.clear();
    instrumentationTargets_.clear();
    {
        std::lock_guard<std::mutex> rearmLock(vehPendingMutex_);
        vehPendingRearm_.clear();
    }
    vehEntries_.clear();
    HookRegistry::instance().clear();
    initialized_ = false;
}

HookLayerState* MultiLayerHookEngine::findLayerState(HookContext& context, HookLayer layer) {
    for (auto& state : context.layers) {
        if (state.layer == layer) {
            return &state;
        }
    }
    context.layers.push_back({layer});
    return &context.layers.back();
}

bool MultiLayerHookEngine::installHook(const HookTargetDescriptor& descriptor,
                                       LPVOID detour,
                                       LPVOID* originalOut,
                                       const std::vector<HookLayer>& preferredLayers) {
    if (!detour) {
        return false;
    }

    if (!initialize()) {
        return false;
    }

    std::vector<HookLayer> order = preferredLayers;
    if (order.empty()) {
        order = {
            HookLayer::Inline,
            HookLayer::IAT,
            HookLayer::EAT,
            HookLayer::VEH,
            HookLayer::Instrumentation,
            HookLayer::Syscall
        };
    }

    HookContext& context = HookRegistry::instance().add(descriptor, detour);

    HMODULE module = ResolveModule(descriptor.moduleName);
    if (!module) {
        LogDebug("[MultiLayerHook] Unable to resolve target module.\n");
        HookRegistry::instance().remove(descriptor.functionName);
        return false;
    }

    FARPROC proc = nullptr;
    if (!descriptor.functionName.empty()) {
        proc = GetProcAddress(module, descriptor.functionName.c_str());
    }

    if (!proc && descriptor.resolvedRva != 0) {
        proc = reinterpret_cast<FARPROC>(reinterpret_cast<uintptr_t>(module) + descriptor.resolvedRva);
    }

    if (!proc) {
        std::ostringstream oss;
        oss << "[MultiLayerHook] Failed to resolve address for " << descriptor.functionName << "\n";
        LogDebug(oss.str());
        HookRegistry::instance().remove(descriptor.functionName);
        return false;
    }

    context.targetAddress = reinterpret_cast<LPVOID>(proc);
    SIZE_T snapshotSize = (std::min)(kMaxSnapshotBytes, static_cast<size_t>(16));
    memcpy(context.originalBytes.data(), context.targetAddress, snapshotSize);
    context.originalSize = snapshotSize;
    HookRegistry::instance().bindAddress(context.target.functionName, context.targetAddress);

    bool anySuccess = false;
    for (HookLayer layer : order) {
        HookLayerState* state = findLayerState(context, layer);
        if (ShouldDisableLayer(layer)) {
            state->installed = false;
            state->verified = false;
            continue;
        }
        state->lastAttemptTick = GetTickCount64();

        bool success = false;
        switch (layer) {
        case HookLayer::Inline:
            success = installInline(context);
            break;
        case HookLayer::IAT:
            success = installIAT(context);
            break;
        case HookLayer::EAT:
            success = installEAT(context);
            break;
        case HookLayer::VEH:
            success = installVEH(context);
            break;
        case HookLayer::Instrumentation:
            success = installInstrumentation(context);
            break;
        case HookLayer::Syscall:
            success = installSyscall(context);
            break;
        default:
            success = false;
            break;
        }

        if (success) {
            state->installed = true;
            state->verified = true;
            state->lastSuccessTick = GetTickCount64();
            anySuccess = true;
            LogStructuredAudit("install", context.target.functionName,
                               LayerToStr(layer), "success");
        } else {
            state->failureCount++;
            LogStructuredAudit("install", context.target.functionName,
                               LayerToStr(layer), "fail");
        }
    }

    context.isActive = anySuccess;
    if (originalOut) {
        *originalOut = context.original;
    }

    if (!context.original && anySuccess) {
        context.original = context.targetAddress;
    }

    return anySuccess;
}

bool MultiLayerHookEngine::uninstallHook(const std::string& functionName) {
    HookContext* context = HookRegistry::instance().find(functionName);
    if (!context) {
        return false;
    }

    for (auto& state : context->layers) {
        if (!state.installed) {
            continue;
        }

        switch (state.layer) {
        case HookLayer::Inline:
            HookEngine::getInstance().removeHook(context->targetAddress);
            state.installed = false;
            break;
        case HookLayer::IAT:
            restoreIAT(*context);
            state.installed = false;
            break;
        case HookLayer::EAT:
            restoreEAT(*context);
            state.installed = false;
            break;
        case HookLayer::VEH:
            restoreVEH(*context);
            state.installed = false;
            break;
        case HookLayer::Instrumentation:
            restoreInstrumentation(*context);
            state.installed = false;
            break;
        case HookLayer::Syscall:
            restoreSyscall(*context);
            state.installed = false;
            break;
        default:
            break;
        }
    }

    HookRegistry::instance().remove(functionName);
    return true;
}

void MultiLayerHookEngine::monitorAndRepair() {
    auto snapshot = HookRegistry::instance().snapshot();
    for (auto& context : snapshot) {
        if (!context.isActive) {
            continue;
        }

        for (auto& state : context.layers) {
            if (!state.installed) {
                continue;
            }

            bool healthy = true;
            switch (state.layer) {
            case HookLayer::Inline:
                healthy = verifyInline(context);
                break;
            case HookLayer::IAT:
                healthy = verifyIAT(context);
                break;
            case HookLayer::EAT:
                healthy = verifyEAT(context);
                break;
            case HookLayer::VEH:
                healthy = verifyVEH(context);
                break;
            case HookLayer::Instrumentation:
                healthy = verifyInstrumentation(context);
                break;
            case HookLayer::Syscall:
                healthy = verifySyscall(context);
                break;
            default:
                healthy = true;
                break;
            }

            if (!healthy) {
                HookContext* liveContext = HookRegistry::instance().find(context.target.functionName);
                if (!liveContext) {
                    continue;
                }

                bool reinstalled = false;
                switch (state.layer) {
                case HookLayer::Inline:
                    reinstalled = installInline(*liveContext);
                    break;
                case HookLayer::IAT:
                    reinstalled = installIAT(*liveContext);
                    break;
                case HookLayer::EAT:
                    reinstalled = installEAT(*liveContext);
                    break;
                case HookLayer::VEH:
                    if (liveContext->vehMetadata.has_value() &&
                        liveContext->vehMetadata->autoDisabled) {
                        restoreVEH(*liveContext);
                        state.installed = false;
                        state.verified = false;
                        reinstalled = false;
                    } else {
                        reinstalled = installVEH(*liveContext);
                    }
                    break;
                case HookLayer::Instrumentation:
                    reinstalled = installInstrumentation(*liveContext);
                    break;
                case HookLayer::Syscall:
                    reinstalled = installSyscall(*liveContext);
                    break;
                default:
                    break;
                }

                HookLayerState* liveState = findLayerState(*liveContext, state.layer);
                if (reinstalled) {
                    liveState->installed = true;
                    liveState->verified = true;
                    liveState->lastSuccessTick = GetTickCount64();
                } else {
                    liveState->failureCount++;
                    liveState->verified = false;
                }
            }
        }
    }
}

bool MultiLayerHookEngine::ensureVehHandler() {
    if (vehHandle_) {
        return true;
    }
    vehHandle_ = AddVectoredExceptionHandler(1, VectoredHandler);
    return vehHandle_ != nullptr;
}

bool MultiLayerHookEngine::resolveInstrumentationProcedures() {
    if (instrumentationProceduresResolved_) {
        return ntSetInformationThread_ != nullptr && ntQueryInformationThread_ != nullptr;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    if (!ntdll) {
        instrumentationProceduresResolved_ = true;
        return false;
    }

    ntSetInformationThread_ = reinterpret_cast<NtSetInformationThread_t>(
        GetProcAddress(ntdll, "NtSetInformationThread"));
    ntQueryInformationThread_ = reinterpret_cast<NtQueryInformationThread_t>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));

    instrumentationProceduresResolved_ = true;
    return ntSetInformationThread_ != nullptr;
}

bool MultiLayerHookEngine::resolveUnwindProcedures() {
#if !defined(_WIN64)
    return true;
#else
    if (unwindProceduresResolved_) {
        return rtlAddFunctionTable_ != nullptr &&
               rtlDeleteFunctionTable_ != nullptr &&
               rtlLookupFunctionEntry_ != nullptr;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    if (!ntdll) {
        unwindProceduresResolved_ = true;
        return false;
    }

    rtlAddFunctionTable_ = reinterpret_cast<RtlAddFunctionTable_t>(
        GetProcAddress(ntdll, "RtlAddFunctionTable"));
    rtlDeleteFunctionTable_ = reinterpret_cast<RtlDeleteFunctionTable_t>(
        GetProcAddress(ntdll, "RtlDeleteFunctionTable"));
    rtlLookupFunctionEntry_ = reinterpret_cast<RtlLookupFunctionEntry_t>(
        GetProcAddress(ntdll, "RtlLookupFunctionEntry"));

    unwindProceduresResolved_ = true;
    return rtlAddFunctionTable_ && rtlDeleteFunctionTable_ && rtlLookupFunctionEntry_;
#endif
}

bool MultiLayerHookEngine::installInline(HookContext& context) {
    HookEngine& engine = HookEngine::getInstance();

    HookInfo existing = {};
    if (engine.queryHookByTarget(context.targetAddress, existing)) {
        if (existing.hookFunction != context.detour) {
            if (!engine.removeHook(context.targetAddress)) {
                return false;
            }
        } else {
            if (!engine.enableHook(context.targetAddress, true)) {
                return false;
            }
            context.original = existing.originalFunction;
            return context.original != nullptr;
        }
    }

    LPVOID original = nullptr;
    if (!engine.installHook(context.targetAddress,
                            context.detour,
                            &original,
                            context.target.functionName)) {
        return false;
    }
    context.original = original;
    return context.original != nullptr;
}

bool MultiLayerHookEngine::installIAT(HookContext& context) {
    HMODULE hostModule = GetModuleHandleW(nullptr);
    if (!hostModule) {
        return false;
    }

    ULONG importSize = 0;
    auto importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        ImageDirectoryEntryToData(hostModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &importSize));
    if (!importDesc) {
        return false;
    }

    const std::wstring targetModuleLower = ToLower(context.target.moduleName);

    for (; importDesc->Name != 0; ++importDesc) {
        const char* moduleNameA = reinterpret_cast<const char*>(
            reinterpret_cast<const BYTE*>(hostModule) + importDesc->Name);
        if (!moduleNameA) {
            continue;
        }

        std::wstring moduleNameW(moduleNameA, moduleNameA + std::strlen(moduleNameA));
        if (!CaseInsensitiveEquals(ToLower(moduleNameW), targetModuleLower)) {
            continue;
        }

        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(hostModule) + importDesc->FirstThunk);
        auto originalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(hostModule) + importDesc->OriginalFirstThunk);
        if (!thunk || !originalThunk) {
            continue;
        }

        for (; originalThunk->u1.AddressOfData != 0; ++thunk, ++originalThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal)) {
                continue;
            }

            auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                reinterpret_cast<BYTE*>(hostModule) + originalThunk->u1.AddressOfData);
            if (!importByName || !importByName->Name) {
                continue;
            }

            if (!CaseInsensitiveEquals(context.target.functionName,
                                       reinterpret_cast<const char*>(importByName->Name))) {
                continue;
            }

            auto slot = reinterpret_cast<LPVOID*>(&thunk->u1.Function);
            if (!slot) {
                continue;
            }

            HookContext::IATMetadata metadata;
            metadata.slot = slot;
            metadata.originalTarget = *slot;
            metadata.owningModule = hostModule;

            ScopedProtect protect(slot, sizeof(LPVOID), PAGE_READWRITE);
            if (!protect.succeeded()) {
                LogDebug("[MultiLayerHook] Failed to change IAT protections.\n");
                return false;
            }

            InterlockedExchangePointer(slot, context.detour);
            FlushInstructionCache(GetCurrentProcess(), slot, sizeof(LPVOID));

            context.iatMetadata = metadata;
            return true;
        }
    }

    return false;
}

bool MultiLayerHookEngine::installEAT(HookContext& context) {
    HMODULE module = ResolveModule(context.target.moduleName);
    if (!module) {
        return false;
    }

    ModuleExportContext exports = BuildExportContext(module);
    if (!exports.directory) {
        return false;
    }

    const HookCapabilities capabilities = HookRegistry::instance().capabilities();
    const bool forceShadow = ShouldForceEATShadow();
    const bool allowDirectPatch = capabilities.supportsEATPatch && !forceShadow;

    for (DWORD i = 0; i < exports.directory->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(
            reinterpret_cast<BYTE*>(module) + exports.nameTable[i]);
        if (!name) {
            continue;
        }

        if (!CaseInsensitiveEquals(context.target.functionName, name)) {
            continue;
        }

        WORD ordinal = exports.ordinalTable[i];
        if (ordinal >= exports.directory->NumberOfFunctions) {
            continue;
        }

        PDWORD entry = exports.addressTable + ordinal;
        if (!entry) {
            continue;
        }

        DWORD originalRva = *entry;
        if (IsForwardedExport(exports, originalRva)) {
            LogDebug("[MultiLayerHook] Skipping forwarded export for EAT patch.\n");
            return false;
        }

        uintptr_t detourOffset = reinterpret_cast<uintptr_t>(context.detour) -
                                 reinterpret_cast<uintptr_t>(module);
        DWORD newRva = static_cast<DWORD>(detourOffset);

        HookContext::EATMetadata metadata{};
        bool patched = false;

        if (allowDirectPatch) {
            PageGuard guard(entry, sizeof(DWORD), PAGE_READWRITE);
            if (guard.Succeeded()) {
                *entry = newRva;
                FlushInstructionCache(GetCurrentProcess(), entry, sizeof(DWORD));
                metadata.exportEntry = entry;
                patched = true;
            } else {
                LogDebug("[MultiLayerHook] Direct EAT patch denied, falling back to shadow copy.\n");
            }
        }

        if (!patched) {
            if (!installEATShadow(context, exports, ordinal, newRva, metadata)) {
                return false;
            }
            patched = true;
        }

        metadata.originalRva = originalRva;
        metadata.owningModule = module;
        context.eatMetadata = metadata;

#if defined(_WIN64)
        registerDetourUnwindIfNeeded(context);
#endif
        return patched;
    }

    return false;
}

bool MultiLayerHookEngine::installEATShadow(HookContext& context,
                                             ModuleExportContext& exports,
                                             WORD ordinal,
                                             DWORD newRva,
                                             HookContext::EATMetadata& metadata) {
    UNREFERENCED_PARAMETER(context);
    HMODULE module = exports.module;
    if (!module || !exports.directory) {
        return false;
    }

    const DWORD functionCount = exports.directory->NumberOfFunctions;
    if (functionCount == 0) {
        return false;
    }

    SIZE_T directoryBytes = exports.exportDirSize;
    SIZE_T functionsBytes = static_cast<SIZE_T>(functionCount) * sizeof(DWORD);
    SIZE_T namesBytes = static_cast<SIZE_T>(exports.directory->NumberOfNames) * sizeof(DWORD);
    SIZE_T ordinalsBytes = static_cast<SIZE_T>(exports.directory->NumberOfNames) * sizeof(WORD);

    SIZE_T offset = AlignUp(directoryBytes, kShadowAlignment);
    const SIZE_T functionsOffset = offset;
    offset += AlignUp(functionsBytes, kShadowAlignment);
    const SIZE_T namesOffset = offset;
    offset += AlignUp(namesBytes, kShadowAlignment);
    const SIZE_T ordinalsOffset = offset;
    offset += AlignUp(ordinalsBytes, kShadowAlignment);
    SIZE_T totalSize = AlignUp(offset, kShadowAlignment);

    DWORD shadowRva = 0;
    LPBYTE shadow = AllocateShadowForModule(module, totalSize, shadowRva);
    if (!shadow) {
        LogDebug("[MultiLayerHook] Failed to allocate shadow export directory.\n");
        return false;
    }

    LPBYTE moduleBase = reinterpret_cast<LPBYTE>(module);
    memcpy(shadow, moduleBase + exports.exportDirRva, exports.exportDirSize);

    auto shadowDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(shadow);
    LPBYTE shadowFunctionsBytes = shadow + functionsOffset;
    LPBYTE shadowNamesBytes = shadow + namesOffset;
    LPBYTE shadowOrdinalsBytes = shadow + ordinalsOffset;

    if (functionsBytes) {
        memcpy(shadowFunctionsBytes,
               moduleBase + shadowDir->AddressOfFunctions,
               functionsBytes);
    }
    if (namesBytes) {
        memcpy(shadowNamesBytes,
               moduleBase + shadowDir->AddressOfNames,
               namesBytes);
    }
    if (ordinalsBytes) {
        memcpy(shadowOrdinalsBytes,
               moduleBase + shadowDir->AddressOfNameOrdinals,
               ordinalsBytes);
    }

    shadowDir->AddressOfFunctions = shadowRva + static_cast<DWORD>(functionsOffset);
    shadowDir->AddressOfNames = shadowRva + static_cast<DWORD>(namesOffset);
    shadowDir->AddressOfNameOrdinals = shadowRva + static_cast<DWORD>(ordinalsOffset);

    PDWORD shadowFunctions = reinterpret_cast<PDWORD>(shadowFunctionsBytes);
    shadowFunctions[ordinal] = newRva;

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dataDirectory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    ScopedProtect headerGuard(nt, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE);
    if (!headerGuard.succeeded()) {
        VirtualFree(shadow, 0, MEM_RELEASE);
        LogDebug("[MultiLayerHook] Failed to update export data directory protections.\n");
        return false;
    }

    metadata.originalDirectoryRva = dataDirectory->VirtualAddress;
    metadata.originalDirectorySize = dataDirectory->Size;

    dataDirectory->VirtualAddress = shadowRva;
    dataDirectory->Size = static_cast<DWORD>(totalSize);

    metadata.exportEntry = shadowFunctions + ordinal;
    metadata.shadowActive = true;
    metadata.shadowCopy = shadow;
    metadata.shadowSize = totalSize;
    metadata.shadowRva = shadowRva;

    FlushInstructionCache(GetCurrentProcess(), metadata.exportEntry, sizeof(DWORD));
    return true;
}

bool MultiLayerHookEngine::registerDetourUnwindIfNeeded(HookContext& context) {
#if !defined(_WIN64)
    (void)context;
    return true;
#else
    if (!context.eatMetadata.has_value()) {
        return true;
    }

    HookContext::EATMetadata& metadata = context.eatMetadata.value();
    if (metadata.unwindRegistered) {
        return true;
    }

    if (!resolveUnwindProcedures()) {
        return false;
    }

    if (!context.detour || !rtlLookupFunctionEntry_) {
        return false;
    }

    DWORD64 imageBase = 0;
    if (rtlLookupFunctionEntry_(reinterpret_cast<DWORD64>(context.detour), &imageBase, nullptr)) {
        return true;
    }

    const SIZE_T runtimeSize = AlignUp(sizeof(RUNTIME_FUNCTION), kShadowAlignment);
    const SIZE_T unwindSize = AlignUp(sizeof(UNWIND_INFO), kShadowAlignment);
    const SIZE_T totalSize = runtimeSize + unwindSize;

    LPBYTE allocation = AllocateNearAddress(context.detour, totalSize);
    if (!allocation) {
        return false;
    }

    auto runtime = reinterpret_cast<PRUNTIME_FUNCTION>(allocation);
    auto unwindInfo = reinterpret_cast<PUNWIND_INFO>(allocation + runtimeSize);
    std::memset(runtime, 0, sizeof(RUNTIME_FUNCTION));
    std::memset(unwindInfo, 0, sizeof(UNWIND_INFO));

    unwindInfo->Version = 1;
    unwindInfo->Flags = UNW_FLAG_NHANDLER;
    unwindInfo->SizeOfProlog = 0;
    unwindInfo->CountOfCodes = 0;
    unwindInfo->FrameRegister = 0;
    unwindInfo->FrameOffset = 0;

    DWORD64 base = reinterpret_cast<DWORD64>(context.detour);
    DWORD unwindRva = static_cast<DWORD>(reinterpret_cast<LPBYTE>(unwindInfo) - reinterpret_cast<LPBYTE>(context.detour));

    runtime->BeginAddress = 0;
    runtime->EndAddress = kSyntheticUnwindSpan;
    runtime->UnwindData = unwindRva;

    if (!rtlAddFunctionTable_ ||
        !rtlAddFunctionTable_(runtime, 1, base)) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        return false;
    }

    metadata.unwindRegistered = true;
    metadata.runtimeFunction = runtime;
    metadata.runtimeAllocation = allocation;
    metadata.runtimeBase = base;
    return true;
#endif
}

bool MultiLayerHookEngine::installVEH(HookContext& context) {
    if (!ensureVehHandler()) {
        return false;
    }

    auto target = reinterpret_cast<LPBYTE>(context.targetAddress);
    if (!target) {
        return false;
    }

    PageGuard guard(target, sizeof(BYTE), PAGE_EXECUTE_READWRITE);
    if (!guard.Succeeded()) {
        LogDebug("[MultiLayerHook] Failed to modify target for VEH.\n");
        return false;
    }

    BYTE original = *target;
    *target = 0xCC;
    FlushInstructionCache(GetCurrentProcess(), target, sizeof(BYTE));

    HookContext::VEHMetadata metadata;
    metadata.patchedAddress = target;
    metadata.originalByte = original;
    metadata.armed = true;
    metadata.pendingRearm = false;
    metadata.hitCount = 0;
    metadata.rearmCount = 0;
    metadata.lastThreadId = 0;
    metadata.pendingSinceTick = 0;
    metadata.consecutiveFaults = 0;
    metadata.autoDisabled = false;
    context.vehMetadata = metadata;

    VehEntry entry;
    entry.address = target;
    entry.originalByte = original;
    entry.detour = context.detour;
    entry.metadata = &context.vehMetadata.value();

    std::lock_guard<std::mutex> lock(mutex_);
    vehEntries_[context.targetAddress] = entry;

    return true;
}

bool MultiLayerHookEngine::installInstrumentation(HookContext& context) {
#if !defined(_WIN64)
    (void)context;
    return false;
#else
    if (!HookRegistry::instance().capabilities().supportsInstrumentation) {
        return false;
    }

    if (!resolveInstrumentationProcedures()) {
        return false;
    }

    bool installed = false;

    ForEachThread([&](DWORD threadId, HANDLE threadHandle) {
        bool alreadyInstrumented = false;
        {
            std::shared_lock<std::shared_mutex> readLock(instrumentationMutex_);
            alreadyInstrumented = instrumentationThreads_.find(threadId) != instrumentationThreads_.end();
        }

        if (alreadyInstrumented) {
            std::unique_lock<std::shared_mutex> writeLock(instrumentationMutex_);
            auto& state = instrumentationThreads_[threadId];
            state.refCount++;
            installed = true;
            return;
        }

        ULONG returned = 0;

        InstrumentationThreadState state{};
        state.threadId = threadId;
        state.previousCallback = nullptr;
        state.refCount = 1;

        if (ntQueryInformationThread_) {
            InstrumentationCallbackInformation existing = {};
            NTSTATUS queryStatus = ntQueryInformationThread_(threadHandle,
                                                             ThreadInstrumentationCallback,
                                                             &existing,
                                                             sizeof(existing),
                                                             &returned);
            if (NT_SUCCESS(queryStatus)) {
                state.previousCallback = existing.Callback;
            }
        }

        InstrumentationCallbackInformation setInfo = {};
        setInfo.Callback = reinterpret_cast<PVOID>(&MultiLayerHookEngine::InstrumentationCallbackEntry);
        NTSTATUS status = ntSetInformationThread_(threadHandle,
                                                  ThreadInstrumentationCallback,
                                                  &setInfo,
                                                  sizeof(setInfo));
        if (!NT_SUCCESS(status)) {
            static std::atomic<bool> instrumentationLogged{false};
            if (!instrumentationLogged.exchange(true)) {
                std::cout << "[Instrumentation] NtSetInformationThread failed: 0x"
                          << std::hex << status << std::dec << std::endl;
            }
            if (status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_IMPLEMENTED) {
                HookRegistry::instance().disableInstrumentationSupport();
            }
            return;
        }

        {
            std::unique_lock<std::shared_mutex> writeLock(instrumentationMutex_);
            instrumentationThreads_[threadId] = state;
        }

        installed = true;
    });

    if (installed) {
        std::unique_lock<std::shared_mutex> lock(instrumentationMutex_);
        instrumentationTargets_[context.targetAddress] = context.detour;
        context.instrumentation.installed = true;
    }

    return installed;
#endif
}

bool MultiLayerHookEngine::installSyscall(HookContext& context) {
#if !defined(_WIN64)
    (void)context;
    return false;
#else
    if (!HookRegistry::instance().capabilities().supportsSyscall) {
        return false;
    }

    if (!context.targetAddress) {
        std::cout << "[Syscall] target address unavailable" << std::endl;
        return false;
    }

    if (context.syscallMetadata.has_value()) {
        restoreSyscall(context);
    }

    if (context.target.functionName.size() < 2) {
        std::cout << "[Syscall] function name too short" << std::endl;
        return false;
    }

    std::string nameLower = ToLower(context.target.functionName);
    if (!(nameLower.rfind("nt", 0) == 0 || nameLower.rfind("zw", 0) == 0)) {
        std::cout << "[Syscall] function name not Nt/Zw prefix" << std::endl;
        return false;
    }

    HookContext::SyscallMetadata metadata;
    metadata.stubAddress = reinterpret_cast<LPBYTE>(context.targetAddress);
    metadata.patchLength = kSyscallPatchLength;

    SyscallStubInfo info{};
    if (!DecodeCanonicalSyscallStub(metadata.stubAddress, info)) {
        static std::atomic<bool> syscallLogged{false};
        if (!syscallLogged.exchange(true)) {
            std::cout << "[Syscall] Unsupported stub pattern at "
                      << static_cast<const void*>(metadata.stubAddress)
                      << "; disabling syscall support" << std::endl;
        }
        HookRegistry::instance().disableSyscallSupport();
        return false;
    }

    metadata.syscallNumber = info.syscallNumber;
    metadata.returnOpcode = info.returnOpcode;
    metadata.returnOperand = info.returnOperand;

    memcpy(metadata.originalBytes.data(), metadata.stubAddress, metadata.patchLength);

    LPBYTE trampoline = nullptr;
    SIZE_T trampolineSize = 0;
    if (!BuildSyscallTrampoline(info, trampoline, trampolineSize)) {
        return false;
    }

    metadata.trampoline = trampoline;
    metadata.trampolineSize = trampolineSize;

    ScopedProtect protect(metadata.stubAddress, metadata.patchLength, PAGE_EXECUTE_READWRITE);
    if (!protect.succeeded()) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return false;
    }

    BYTE patch[kSyscallPatchLength] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
    };
    uint64_t detourPtr = reinterpret_cast<uint64_t>(context.detour);
    memcpy(patch + 6, &detourPtr, sizeof(uint64_t));

    memcpy(metadata.stubAddress, patch, kSyscallPatchLength);
    FlushInstructionCache(GetCurrentProcess(), metadata.stubAddress, metadata.patchLength);

    context.syscallMetadata = metadata;
    if (!context.original || context.original == context.targetAddress) {
        context.original = metadata.trampoline;
    }

    return true;
#endif
}

bool MultiLayerHookEngine::verifyInline(const HookContext& context) {
    if (!context.targetAddress || context.originalSize == 0) {
        return false;
    }

    BYTE snapshot[kMaxSnapshotBytes] = {};
    memcpy(snapshot, context.targetAddress, context.originalSize);

#if defined(_WIN64)
    bool isJump = (snapshot[0] == 0xE9) ||
                  (snapshot[0] == 0xFF && snapshot[1] == 0x25);
#else
    bool isJump = (snapshot[0] == 0xE9);
#endif
    return isJump;
}

bool MultiLayerHookEngine::verifyIAT(const HookContext& context) {
    if (!context.iatMetadata.has_value()) {
        return false;
    }

    LPVOID* slot = context.iatMetadata->slot;
    if (!slot) {
        return false;
    }

    return *slot == context.detour;
}

bool MultiLayerHookEngine::verifyEAT(const HookContext& context) {
    if (!context.eatMetadata.has_value()) {
        return false;
    }

    PDWORD entry = context.eatMetadata->exportEntry;
    if (!entry) {
        return false;
    }

    DWORD expected = static_cast<DWORD>(
        reinterpret_cast<BYTE*>(context.detour) -
        reinterpret_cast<BYTE*>(context.eatMetadata->owningModule));
    return *entry == expected;
}

bool MultiLayerHookEngine::verifyVEH(const HookContext& context) {
    if (!context.vehMetadata.has_value()) {
        return false;
    }
    const auto& metadata = context.vehMetadata.value();

    if (metadata.autoDisabled) {
        return false;
    }

    if (metadata.pendingRearm) {
        if (metadata.pendingSinceTick != 0) {
            ULONGLONG elapsed = GetTickCount64() - metadata.pendingSinceTick;
            if (elapsed > kVehPendingTimeoutMs) {
                return false;
            }
        }
        return true;
    }

    if (!metadata.armed || !metadata.patchedAddress) {
        return false;
    }

    return *metadata.patchedAddress == 0xCC;
}

bool MultiLayerHookEngine::verifyInstrumentation(HookContext& context) {
    if (!context.instrumentation.installed) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(instrumentationMutex_);
    return instrumentationTargets_.find(context.targetAddress) != instrumentationTargets_.end();
}

bool MultiLayerHookEngine::verifySyscall(const HookContext& context) {
#if !defined(_WIN64)
    (void)context;
    return false;
#else
    if (!context.syscallMetadata.has_value()) {
        return false;
    }

    const auto& metadata = context.syscallMetadata.value();
    if (!metadata.stubAddress || metadata.patchLength != kSyscallPatchLength) {
        return false;
    }

    BYTE current[kSyscallPatchLength] = {};
    memcpy(current, metadata.stubAddress, kSyscallPatchLength);

    if (current[0] != 0xFF || current[1] != 0x25) {
        return false;
    }

    if (*reinterpret_cast<const uint32_t*>(current + 2) != 0) {
        return false;
    }

    uint64_t target = 0;
    memcpy(&target, current + 6, sizeof(uint64_t));
    return target == reinterpret_cast<uint64_t>(context.detour);
#endif
}

bool MultiLayerHookEngine::restoreIAT(HookContext& context) {
    if (!context.iatMetadata.has_value()) {
        return false;
    }

    LPVOID* slot = context.iatMetadata->slot;
    if (!slot) {
        return false;
    }

    ScopedProtect protect(slot, sizeof(LPVOID), PAGE_READWRITE);
    if (!protect.succeeded()) {
        return false;
    }

    InterlockedExchangePointer(slot, context.iatMetadata->originalTarget);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(LPVOID));

    context.iatMetadata.reset();
    return true;
}

bool MultiLayerHookEngine::restoreEAT(HookContext& context) {
    if (!context.eatMetadata.has_value()) {
        return false;
    }

    HookContext::EATMetadata& metadata = context.eatMetadata.value();

#if defined(_WIN64)
    if (metadata.unwindRegistered) {
        if (rtlDeleteFunctionTable_) {
            rtlDeleteFunctionTable_(metadata.runtimeFunction);
        }
        if (metadata.runtimeAllocation) {
            VirtualFree(metadata.runtimeAllocation, 0, MEM_RELEASE);
        }
        metadata.unwindRegistered = false;
        metadata.runtimeFunction = nullptr;
        metadata.runtimeAllocation = nullptr;
        metadata.runtimeBase = 0;
    }
#endif

    if (metadata.shadowActive) {
        if (metadata.shadowCopy) {
            VirtualFree(metadata.shadowCopy, 0, MEM_RELEASE);
        }

        if (metadata.owningModule) {
            auto moduleBase = reinterpret_cast<LPBYTE>(metadata.owningModule);
            auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(metadata.owningModule);
            auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(moduleBase + dos->e_lfanew);
            ScopedProtect headerGuard(nt, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE);
            if (headerGuard.succeeded()) {
                auto dataDirectory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                dataDirectory->VirtualAddress = metadata.originalDirectoryRva;
                dataDirectory->Size = metadata.originalDirectorySize;
            }
        }
    } else {
        PDWORD entry = metadata.exportEntry;
        if (!entry) {
            context.eatMetadata.reset();
            return false;
        }

        PageGuard guard(entry, sizeof(DWORD), PAGE_READWRITE);
        if (!guard.Succeeded()) {
            return false;
        }

        *entry = metadata.originalRva;
        FlushInstructionCache(GetCurrentProcess(), entry, sizeof(DWORD));
    }

    context.eatMetadata.reset();
    return true;
}

bool MultiLayerHookEngine::restoreVEH(HookContext& context) {
    if (!context.vehMetadata.has_value()) {
        return false;
    }

    HookContext::VEHMetadata* metadata = &context.vehMetadata.value();

    PageGuard guard(metadata->patchedAddress, sizeof(BYTE), PAGE_EXECUTE_READWRITE);
    if (!guard.Succeeded()) {
        return false;
    }

    *metadata->patchedAddress = metadata->originalByte;
    FlushInstructionCache(GetCurrentProcess(), metadata->patchedAddress, sizeof(BYTE));

    metadata->armed = false;
    metadata->pendingRearm = false;
    metadata->pendingSinceTick = 0;
    metadata->consecutiveFaults = 0;
    metadata->autoDisabled = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::lock_guard<std::mutex> rearmLock(vehPendingMutex_);
        vehEntries_.erase(context.targetAddress);
        for (auto it = vehPendingRearm_.begin(); it != vehPendingRearm_.end();) {
            if (it->second.metadata == metadata) {
                it = vehPendingRearm_.erase(it);
            } else {
                ++it;
            }
        }
    }

    context.vehMetadata.reset();
    return true;
}

bool MultiLayerHookEngine::restoreInstrumentation(HookContext& context) {
    if (!context.instrumentation.installed) {
        return true;
    }

    if (!resolveInstrumentationProcedures()) {
        return false;
    }

    std::vector<std::pair<DWORD, PVOID>> toRestore;

    {
        std::unique_lock<std::shared_mutex> lock(instrumentationMutex_);
        instrumentationTargets_.erase(context.targetAddress);

        for (auto it = instrumentationThreads_.begin(); it != instrumentationThreads_.end();) {
            if (it->second.refCount > 0 && --it->second.refCount == 0) {
                toRestore.emplace_back(it->first, it->second.previousCallback);
                it = instrumentationThreads_.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (const auto& entry : toRestore) {
        HANDLE threadHandle = OpenThread(THREAD_SET_INFORMATION, FALSE, entry.first);
        if (!threadHandle) {
            continue;
        }

        InstrumentationCallbackInformation info = {};
        info.Callback = entry.second;
        ntSetInformationThread_(threadHandle,
                                ThreadInstrumentationCallback,
                                &info,
                                sizeof(info));
        CloseHandle(threadHandle);
    }

    context.instrumentation.installed = false;
    return true;
}

bool MultiLayerHookEngine::restoreSyscall(HookContext& context) {
#if !defined(_WIN64)
    (void)context;
    return false;
#else
    if (!context.syscallMetadata.has_value()) {
        return false;
    }

    auto metadata = context.syscallMetadata.value();
    bool restored = false;

    if (metadata.stubAddress) {
        ScopedProtect protect(metadata.stubAddress, metadata.patchLength, PAGE_EXECUTE_READWRITE);
        if (protect.succeeded()) {
            memcpy(metadata.stubAddress, metadata.originalBytes.data(), metadata.patchLength);
            FlushInstructionCache(GetCurrentProcess(), metadata.stubAddress, metadata.patchLength);
            restored = true;
        }
    }

    if (metadata.trampoline) {
        if (metadata.trampolineSize != 0) {
            SecureZeroMemory(metadata.trampoline, metadata.trampolineSize);
        }
        VirtualFree(metadata.trampoline, 0, MEM_RELEASE);
    }

    if (context.original == metadata.trampoline) {
        context.original = context.targetAddress;
    }

    context.syscallMetadata.reset();
    return restored;
#endif
}

LONG CALLBACK MultiLayerHookEngine::VectoredHandler(PEXCEPTION_POINTERS exceptionPointers) {
    if (!exceptionPointers || !exceptionPointers->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    switch (exceptionPointers->ExceptionRecord->ExceptionCode) {
    case EXCEPTION_BREAKPOINT:
        return instance().handleVehBreakpoint(exceptionPointers);
    case EXCEPTION_SINGLE_STEP:
        return instance().handleVehSingleStep(exceptionPointers);
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }
}

void MultiLayerHookEngine::autoDisableVehEntryLocked(const VehEntry& entry,
                                                     HookContext::VEHMetadata* metadata) {
    ScopedProtect guard(entry.address, sizeof(BYTE), PAGE_EXECUTE_READWRITE);
    if (guard.succeeded()) {
        *entry.address = entry.originalByte;
        FlushInstructionCache(GetCurrentProcess(), entry.address, sizeof(BYTE));
    }

    for (auto it = vehEntries_.begin(); it != vehEntries_.end();) {
        if (it->second.address == entry.address) {
            it = vehEntries_.erase(it);
        } else {
            ++it;
        }
    }

    {
        std::lock_guard<std::mutex> rearmLock(vehPendingMutex_);
        for (auto it = vehPendingRearm_.begin(); it != vehPendingRearm_.end();) {
            if (it->second.address == entry.address || it->second.metadata == metadata) {
                it = vehPendingRearm_.erase(it);
            } else {
                ++it;
            }
        }
    }

    if (metadata) {
        metadata->armed = false;
        metadata->pendingRearm = false;
        metadata->pendingSinceTick = 0;
        metadata->consecutiveFaults = 0;
        metadata->autoDisabled = true;
    }
}

LONG MultiLayerHookEngine::handleVehBreakpoint(PEXCEPTION_POINTERS exceptionPointers) {
    LPVOID address = exceptionPointers->ExceptionRecord->ExceptionAddress;
    DWORD threadId = GetCurrentThreadId();

    VehEntry entry{};
    HookContext::VEHMetadata* metadata = nullptr;
    bool resumeOriginal = false;

    {
        std::scoped_lock<std::mutex, std::mutex> lock(mutex_, vehPendingMutex_);
        auto it = vehEntries_.find(address);
        if (it == vehEntries_.end()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        entry = it->second;
        metadata = entry.metadata;
        if (metadata && metadata->autoDisabled) {
            resumeOriginal = true;
        } else if (vehPendingRearm_.find(threadId) != vehPendingRearm_.end()) {
            if (metadata) {
                metadata->consecutiveFaults++;
                metadata->pendingRearm = true;
                metadata->pendingSinceTick = GetTickCount64();
                if (metadata->consecutiveFaults >= kVehMaxFaults) {
                    autoDisableVehEntryLocked(entry, metadata);
                    resumeOriginal = true;
                }
            } else {
                resumeOriginal = true;
            }
        } else {
            if (metadata) {
                metadata->hitCount++;
                metadata->lastThreadId = threadId;
                metadata->armed = false;
                metadata->pendingRearm = true;
                metadata->pendingSinceTick = GetTickCount64();
                // Structured per-hit log for VEH
                {
                    HookContext* ctx = HookRegistry::instance().findByAddress(entry.address);
                    LogStructuredAudit("veh_hit",
                                       ctx ? ctx->target.functionName : std::string("unknown"),
                                       "veh",
                                       "hit",
                                       (std::stringstream() << "count=" << metadata->hitCount).str());
                }
            }

            vehPendingRearm_[threadId] = {entry.address, entry.originalByte, metadata};
        }
    }

    if (resumeOriginal) {
#if defined(_WIN64)
        exceptionPointers->ContextRecord->Rip = reinterpret_cast<DWORD64>(entry.address);
#else
        exceptionPointers->ContextRecord->Eip = reinterpret_cast<DWORD>(entry.address);
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    ScopedProtect protect(entry.address, sizeof(BYTE), PAGE_EXECUTE_READWRITE);
    if (!protect.succeeded()) {
        std::scoped_lock<std::mutex, std::mutex> lock(mutex_, vehPendingMutex_);
        vehPendingRearm_.erase(threadId);
        if (metadata) {
            metadata->pendingRearm = false;
            metadata->pendingSinceTick = 0;
            metadata->consecutiveFaults++;
            if (metadata->consecutiveFaults >= kVehMaxFaults) {
                autoDisableVehEntryLocked(entry, metadata);
                resumeOriginal = true;
            }
        }
        if (resumeOriginal) {
#if defined(_WIN64)
            exceptionPointers->ContextRecord->Rip = reinterpret_cast<DWORD64>(entry.address);
#else
            exceptionPointers->ContextRecord->Eip = reinterpret_cast<DWORD>(entry.address);
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    *entry.address = entry.originalByte;
    FlushInstructionCache(GetCurrentProcess(), entry.address, sizeof(BYTE));

    auto* context = exceptionPointers->ContextRecord;
#if defined(_WIN64)
    context->Rip = reinterpret_cast<DWORD64>(entry.detour);
    context->EFlags |= 0x100;
#else
    context->Eip = reinterpret_cast<DWORD>(entry.detour);
    context->EFlags |= 0x100;
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG MultiLayerHookEngine::handleVehSingleStep(PEXCEPTION_POINTERS exceptionPointers) {
    DWORD threadId = GetCurrentThreadId();

    PendingRearm pending{};
    HookContext::VEHMetadata* metadata = nullptr;

    {
        std::scoped_lock<std::mutex, std::mutex> lock(mutex_, vehPendingMutex_);
        auto it = vehPendingRearm_.find(threadId);
        if (it == vehPendingRearm_.end()) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        pending = it->second;
        metadata = pending.metadata;
        vehPendingRearm_.erase(it);
    }

    bool rearmSuccess = false;
    {
        ScopedProtect protect(pending.address, sizeof(BYTE), PAGE_EXECUTE_READWRITE);
        if (protect.succeeded()) {
            *pending.address = 0xCC;
            FlushInstructionCache(GetCurrentProcess(), pending.address, sizeof(BYTE));
            rearmSuccess = true;
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (metadata) {
            metadata->pendingRearm = false;
            if (rearmSuccess) {
                metadata->armed = true;
                metadata->rearmCount++;
                metadata->pendingSinceTick = 0;
                metadata->consecutiveFaults = 0;
            }
            else {
                metadata->consecutiveFaults++;
                if (metadata->consecutiveFaults >= kVehMaxFaults) {
                    VehEntry entry{};
                    entry.address = pending.address;
                    entry.originalByte = pending.originalByte;
                    autoDisableVehEntryLocked(entry, metadata);
                }
            }
        }
    }

    exceptionPointers->ContextRecord->EFlags &= ~0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

VOID NTAPI MultiLayerHookEngine::InstrumentationCallbackEntry(ULONG_PTR returnValue,
                                                              InstrumentationCallbackData* data) {
    instance().handleInstrumentationCallback(returnValue, data);
}

void MultiLayerHookEngine::handleInstrumentationCallback(ULONG_PTR /*returnValue*/,
                                                         InstrumentationCallbackData* data) {
    if (!data) {
        return;
    }

    LPVOID programCounter = reinterpret_cast<LPVOID>(data->ProgramCounter);
    HookContext* context = HookRegistry::instance().findByAddress(programCounter);
    if (context) {
        data->ProgramCounter = reinterpret_cast<ULONG_PTR>(context->detour);
        data->ReturnAddress = reinterpret_cast<ULONG_PTR>(context->detour);
    }

    DWORD threadId = GetCurrentThreadId();
    PVOID previous = lookupPreviousInstrumentationCallback(threadId);
    if (previous) {
        auto routine = reinterpret_cast<void (NTAPI*)(ULONG_PTR, InstrumentationCallbackData*)>(previous);
        routine(0, data);
    }
}

LPVOID MultiLayerHookEngine::lookupPreviousInstrumentationCallback(DWORD threadId) {
    std::shared_lock<std::shared_mutex> lock(instrumentationMutex_);
    auto it = instrumentationThreads_.find(threadId);
    if (it == instrumentationThreads_.end()) {
        return nullptr;
    }
    return it->second.previousCallback;
}

// Global functions (not in anonymous namespace)
bool InstallMultiLayerHook(const HookTargetDescriptor& descriptor,
                           LPVOID detour,
                           LPVOID* original,
                           const std::vector<HookLayer>& preferredLayers) {
    return MultiLayerHookEngine::instance().installHook(descriptor, detour, original, preferredLayers);
}

bool UninstallMultiLayerHook(const std::string& functionName) {
    return MultiLayerHookEngine::instance().uninstallHook(functionName);
}

std::vector<HookContext> QueryInstalledHooks() {
    return HookRegistry::instance().snapshot();
}

void MonitorAndRepairHooks() {
    MultiLayerHookEngine::instance().monitorAndRepair();
}

MultiLayerHookEngine& GetMultiLayerHookEngine() {
    return MultiLayerHookEngine::instance();
}

#pragma warning(pop)

