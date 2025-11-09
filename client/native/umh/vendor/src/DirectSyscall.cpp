// DirectSyscall.cpp - Direct System Call Implementation to Bypass All Hooks
#include "../include/DirectSyscall.h"

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <optional>

namespace fs = std::filesystem;

#pragma comment(lib, "ntdll.lib")

// Define NT status codes if not already defined
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#ifdef _WIN64

namespace injection {

StructuredLogFn g_directSyscallStructuredLogger = nullptr;

namespace {

std::string Narrow(const std::wstring& value) {
    if (value.empty()) {
        return std::string();
    }
    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return std::string();
    }
    std::string result(static_cast<size_t>(required - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), required, nullptr, nullptr);
    return result;
}

void LogDirectSyscall(const std::string& message) {
    std::cerr << "[DirectSyscall] " << message << std::endl;
}

void LogDirectSyscall(const char* message) {
    std::cerr << "[DirectSyscall] " << message << std::endl;
}

void EmitStructured(const std::string& event,
                    const std::string& func,
                    const std::string& details) {
    if (g_directSyscallStructuredLogger) {
        g_directSyscallStructuredLogger(event, func, details);
    } else {
        std::ostringstream line;
        line << "[structured] event=" << event << " func=" << func;
        if (!details.empty()) {
            line << " " << details;
        }
        LogDirectSyscall(line.str());
    }
}

std::wstring ReadEnvironmentVariable(const wchar_t* name) {
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) {
        return std::wstring();
    }
    std::wstring value(needed, L'\0');
    DWORD written = GetEnvironmentVariableW(name, value.data(), needed);
    if (written == 0) {
        return std::wstring();
    }
    if (!value.empty() && value.back() == L'\0') {
        value.pop_back();
    }
    return value;
}

fs::path GetSyscallCacheDirectory() {
    std::wstring overrideDir = ReadEnvironmentVariable(L"UMH_SYSCALL_CACHE_DIR");
    if (!overrideDir.empty()) {
        return fs::path(overrideDir);
    }

    std::wstring localAppData = ReadEnvironmentVariable(L"LOCALAPPDATA");
    if (!localAppData.empty()) {
        return fs::path(localAppData) / L"UserModeHook" / L"cache" / L"syscalls";
    }

    std::wstring programData = ReadEnvironmentVariable(L"ProgramData");
    if (programData.empty()) {
        programData.assign(L"C:\\ProgramData");
    }
    return fs::path(programData) / L"UserModeHook" / L"cache" / L"syscalls";
}

fs::path GetSyscallCacheFile(DWORD buildNumber) {
    std::wstringstream name;
    name << L"syscalls_" << buildNumber << L".cache";
    return GetSyscallCacheDirectory() / name.str();
}

std::string TrimCopy(const std::string& input) {
    size_t begin = 0;
    while (begin < input.size() && std::isspace(static_cast<unsigned char>(input[begin]))) {
        ++begin;
    }
    size_t end = input.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        --end;
    }
    return input.substr(begin, end - begin);
}

bool LoadCachedSyscallCache(DWORD buildNumber,
                            std::unordered_map<std::string, DWORD>& out) {
    out.clear();

    fs::path cacheFile = GetSyscallCacheFile(buildNumber);
    std::error_code ec;
    if (!fs::exists(cacheFile, ec) || ec) {
        std::ostringstream detail;
        detail << "build=" << buildNumber << " status=miss";
        if (ec) {
            detail << " error=" << ec.value();
        }
        EmitStructured("syscall_cache_miss", "DirectSyscallEngine", detail.str());
        return false;
    }

    std::ifstream in(cacheFile, std::ios::in | std::ios::binary);
    if (!in.good()) {
        std::ostringstream detail;
        detail << "build=" << buildNumber
               << " path=" << Narrow(cacheFile.wstring())
               << " status=open_fail";
        EmitStructured("syscall_cache_load_fail", "DirectSyscallEngine", detail.str());
        return false;
    }

    std::string line;
    size_t parsed = 0;
    size_t skipped = 0;
    while (std::getline(in, line)) {
        auto comment = line.find('#');
        if (comment != std::string::npos) {
            line.resize(comment);
        }
        std::string trimmed = TrimCopy(line);
        if (trimmed.empty()) {
            continue;
        }
        auto delim = trimmed.find('=');
        if (delim == std::string::npos) {
            ++skipped;
            continue;
        }
        std::string name = TrimCopy(trimmed.substr(0, delim));
        std::string value = TrimCopy(trimmed.substr(delim + 1));
        if (name.empty() || value.empty()) {
            ++skipped;
            continue;
        }
        try {
            size_t consumed = 0;
            DWORD number = static_cast<DWORD>(std::stoul(value, &consumed, 0));
            if (consumed != value.size()) {
                ++skipped;
                continue;
            }
            out[name] = number;
            ++parsed;
        } catch (...) {
            ++skipped;
            std::ostringstream detail;
            detail << "build=" << buildNumber
                   << " name=" << name
                   << " value=" << value;
            EmitStructured("syscall_cache_parse_error", "DirectSyscallEngine", detail.str());
        }
    }

    if (!in.eof()) {
        std::ostringstream detail;
        detail << "build=" << buildNumber
               << " path=" << Narrow(cacheFile.wstring());
        EmitStructured("syscall_cache_load_truncated", "DirectSyscallEngine", detail.str());
    }

    if (out.empty()) {
        std::ostringstream detail;
        detail << "build=" << buildNumber
               << " path=" << Narrow(cacheFile.wstring())
               << " parsed=" << parsed
               << " skipped=" << skipped;
        EmitStructured("syscall_cache_empty", "DirectSyscallEngine", detail.str());
        return false;
    }

    std::ostringstream detail;
    detail << "build=" << buildNumber
           << " path=" << Narrow(cacheFile.wstring())
           << " parsed=" << parsed
           << " skipped=" << skipped;
    EmitStructured("syscall_cache_load", "DirectSyscallEngine", detail.str());
    return true;
}

void PersistSyscallCache(DWORD buildNumber,
                         const std::unordered_map<std::string, DWORD>& snapshot) {
    if (snapshot.empty()) {
        return;
    }

    fs::path dir = GetSyscallCacheDirectory();
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        fs::create_directories(dir, ec);
        if (ec) {
            std::ostringstream detail;
            detail << "build=" << buildNumber
                   << " path=" << Narrow(dir.wstring())
                   << " error=" << ec.value();
            EmitStructured("syscall_cache_persist_fail", "DirectSyscallEngine", detail.str());
            return;
        }
    }

    fs::path target = GetSyscallCacheFile(buildNumber);
    fs::path temp = target;
    temp += L".tmp";

    std::ofstream out(temp, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.good()) {
        std::ostringstream detail;
        detail << "build=" << buildNumber
               << " path=" << Narrow(temp.wstring())
               << " status=open_fail";
        EmitStructured("syscall_cache_persist_fail", "DirectSyscallEngine", detail.str());
        return;
    }

    std::vector<std::pair<std::string, DWORD>> entries(snapshot.begin(), snapshot.end());
    std::sort(entries.begin(), entries.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    for (const auto& kv : entries) {
        out << kv.first << "=0x"
            << std::uppercase << std::hex << kv.second
            << std::nouppercase << std::dec << "\n";
    }
    out.flush();

    if (!out.good()) {
        out.close();
        std::ostringstream detail;
        detail << "build=" << buildNumber
               << " path=" << Narrow(temp.wstring())
               << " status=write_fail";
        EmitStructured("syscall_cache_persist_fail", "DirectSyscallEngine", detail.str());
        fs::remove(temp, ec);
        return;
    }
    out.close();

    fs::rename(temp, target, ec);
    if (ec) {
        fs::remove(temp, ec);
        std::ostringstream detail;
        detail << "build=" << buildNumber
               << " from=" << Narrow(temp.wstring())
               << " to=" << Narrow(target.wstring())
               << " error=" << ec.value();
        EmitStructured("syscall_cache_persist_fail", "DirectSyscallEngine", detail.str());
        return;
    }

    std::ostringstream detail;
    detail << "build=" << buildNumber
           << " path=" << Narrow(target.wstring())
           << " entries=" << entries.size();
    EmitStructured("syscall_cache_persist", "DirectSyscallEngine", detail.str());
}

} // namespace

class DirectSyscallEngine {
private:
    struct SyscallEntry {
        DWORD number = 0;
        void* stub = nullptr;
    };

    std::map<std::string, SyscallEntry> syscallEntries;
    std::vector<void*> allocatedStubs;
    BOOL is64bit;
    DWORD osVersion;
    DWORD osBuildNumber;
    bool ready;

public:
    DirectSyscallEngine() : ready(false) {
        ready = Initialize();
    }

    ~DirectSyscallEngine() {
        CleanupStubs();
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
        return false; // Direct syscalls currently implemented for x64 only
#endif

        // Get OS version for correct syscall numbers
        if (!DetectOSVersion()) {
            LogDirectSyscall("Failed to detect operating system version.");
            return false;
        }

        // Populate syscall numbers based on OS version
        if (!PopulateSyscallNumbers()) {
            LogDirectSyscall("Failed to populate syscall table – direct syscalls unavailable.");
            return false;
        }

        ready = true;
        return true;
    }

    bool IsReady() const {
        return ready;
    }

    bool DetectOSVersion() {
        osVersion = 0;
        osBuildNumber = 0;

        using RtlGetVersion_t = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            LogDirectSyscall("GetModuleHandleW(ntdll.dll) failed.");
            return false;
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

        // Fallback to GetVersionExW (best effort; may require manifest)
        OSVERSIONINFOW legacyInfo = {};
        legacyInfo.dwOSVersionInfoSize = sizeof(legacyInfo);
        if (GetVersionExW(&legacyInfo)) {
            osVersion = legacyInfo.dwMajorVersion;
            osBuildNumber = legacyInfo.dwBuildNumber;
            return true;
        }

        LogDirectSyscall("Unable to determine OS version via RtlGetVersion or GetVersionEx.");
        return false;
    }

    bool PopulateSyscallNumbers() {
        static const char* kRequired[] = {
            "NtCreateFile",
            "NtOpenProcess",
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtClose"
        };

        std::unordered_map<std::string, DWORD> cache;
        bool cacheLoaded = LoadCachedSyscallCache(osBuildNumber, cache);
        if (cacheLoaded) {
            LogDirectSyscall("Loaded syscall cache for current build.");
        }

        std::unordered_map<std::string, DWORD> discovered;
        bool extracted = ExtractSyscallNumbersFromNtdll(discovered);
        if (!extracted) {
            LogDirectSyscall("Falling back to static syscall table (dynamic extraction failed).");
            EmitStructured("syscall_extract_fail", "ntdll", "source=export_scan");
        }

        auto registerFromMap = [&](const std::unordered_map<std::string, DWORD>& map,
                                   const char* name) -> std::optional<DWORD> {
            auto it = map.find(name);
            if (it != map.end()) {
                if (RegisterStaticSyscall(name, it->second)) {
                    return it->second;
                }
            }
            return std::nullopt;
        };

        std::unordered_map<std::string, DWORD> fallback;
        if (osBuildNumber >= 22000) { // Windows 11
            fallback.emplace("NtCreateFile", 0x0055);
            fallback.emplace("NtOpenProcess", 0x0026);
            fallback.emplace("NtAllocateVirtualMemory", 0x0018);
            fallback.emplace("NtWriteVirtualMemory", 0x003A);
            fallback.emplace("NtProtectVirtualMemory", 0x0050);
            fallback.emplace("NtCreateThreadEx", 0x00B3);
            fallback.emplace("NtClose", 0x000F);
        } else if (osBuildNumber >= 19041) { // Windows 10 20H1+
            fallback.emplace("NtCreateFile", 0x0055);
            fallback.emplace("NtOpenProcess", 0x0026);
            fallback.emplace("NtAllocateVirtualMemory", 0x0018);
            fallback.emplace("NtWriteVirtualMemory", 0x003A);
            fallback.emplace("NtProtectVirtualMemory", 0x0050);
            fallback.emplace("NtCreateThreadEx", 0x00AF);
            fallback.emplace("NtClose", 0x000F);
        }

        bool allRegistered = true;
        for (const char* name : kRequired) {
            std::string source = "discovered";
            std::optional<DWORD> number = registerFromMap(discovered, name);
            if (!number) {
                source = "cache";
                number = registerFromMap(cache, name);
            }
            if (!number) {
                source = "fallback";
                auto fbIt = fallback.find(name);
                if (fbIt != fallback.end()) {
                    if (RegisterStaticSyscall(name, fbIt->second)) {
                        number = fbIt->second;
                    }
                }
            }

            if (!number) {
                LogDirectSyscall(std::string("Missing syscall after initialization: ") + name);
                std::ostringstream detail;
                detail << "build=" << osBuildNumber << " fn=" << name;
                EmitStructured("syscall_init_fail", name, detail.str());
                allRegistered = false;
            } else {
                std::ostringstream detail;
                detail << "build=" << osBuildNumber
                       << " source=" << source
                       << " number=0x" << std::hex << std::uppercase << *number;
                EmitStructured("syscall_register", name, detail.str());
            }
        }

        if (!allRegistered) {
            EmitStructured("syscall_table_incomplete", "DirectSyscallEngine", "status=missing_entries");
            return false;
        }

        auto snapshot = SnapshotRegisteredSyscalls();
        PersistSyscallCache(osBuildNumber, snapshot);

        return HasRequiredSyscalls();
    }

    bool ExtractSyscallNumbersFromNtdll(std::unordered_map<std::string, DWORD>& out) {
        bool unloadOnExit = false;
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) {
            hNtdll = LoadLibraryW(L"ntdll.dll");
            if (!hNtdll) {
                LogDirectSyscall("LoadLibraryW(ntdll.dll) failed.");
                return false;
            }
            unloadOnExit = true;
        }

        BYTE* base = reinterpret_cast<BYTE*>(hNtdll);
        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
            if (unloadOnExit) {
                FreeLibrary(hNtdll);
            }
            LogDirectSyscall("Invalid DOS header in ntdll.");
            return false;
        }

        auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
            if (unloadOnExit) {
                FreeLibrary(hNtdll);
            }
            LogDirectSyscall("Invalid NT headers in ntdll.");
            return false;
        }

        const auto& exportDirInfo = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDirInfo.VirtualAddress == 0 || exportDirInfo.Size == 0) {
            if (unloadOnExit) {
                FreeLibrary(hNtdll);
            }
            LogDirectSyscall("ntdll export directory is empty.");
            return false;
        }

        auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + exportDirInfo.VirtualAddress);
        auto nameTable = reinterpret_cast<PDWORD>(base + exportDirectory->AddressOfNames);
        auto ordinalTable = reinterpret_cast<PWORD>(base + exportDirectory->AddressOfNameOrdinals);
        auto functionTable = reinterpret_cast<PDWORD>(base + exportDirectory->AddressOfFunctions);

        DWORD exportStart = exportDirInfo.VirtualAddress;
        DWORD exportEnd = exportDirInfo.VirtualAddress + exportDirInfo.Size;

        for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
            const char* exportName = reinterpret_cast<const char*>(base + nameTable[i]);
            if (!exportName) {
                continue;
            }
            if (exportName[0] != 'N' || exportName[1] != 't') {
                continue;
            }

            WORD ordinal = ordinalTable[i];
            if (ordinal >= exportDirectory->NumberOfFunctions) {
                continue;
            }

            DWORD functionRva = functionTable[ordinal];
            if (functionRva == 0) {
                continue;
            }

            if (functionRva >= exportStart && functionRva < exportEnd) {
                continue;
            }

            BYTE* functionPtr = base + functionRva;
            DWORD syscallNum = DecodeSyscallStub(functionPtr);
            if (syscallNum == 0) {
                std::ostringstream detail;
                detail << "build=" << osBuildNumber << " fn=" << exportName;
                EmitStructured("syscall_decode_fail", exportName, detail.str());
                continue;
            }

            out.emplace(exportName, syscallNum);
        }

        if (unloadOnExit) {
            FreeLibrary(hNtdll);
        }

        return !out.empty();
    }

    // Direct syscall wrappers
    NTSTATUS NtCreateFile_Direct(
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
        ULONG EaLength) {

#ifdef _WIN64
        using NtCreateFile_t = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                                 PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG,
                                                 ULONG, ULONG, ULONG, PVOID, ULONG);
        NtCreateFile_t fn = ResolveSyscallStub<NtCreateFile_t>("NtCreateFile");
        if (!fn) {
            return STATUS_NOT_SUPPORTED;
        }
        return fn(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                  AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                  CreateOptions, EaBuffer, EaLength);
#else
        // x86 implementation would be different
        return STATUS_NOT_IMPLEMENTED;
#endif
    }

    NTSTATUS NtOpenProcess_Direct(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        CLIENT_ID* ClientId) {

#ifdef _WIN64
        using NtOpenProcess_t = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
        NtOpenProcess_t fn = ResolveSyscallStub<NtOpenProcess_t>("NtOpenProcess");
        if (!fn) {
            return STATUS_NOT_SUPPORTED;
        }
        return fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
#else
        return STATUS_NOT_IMPLEMENTED;
#endif
    }

    NTSTATUS NtAllocateVirtualMemory_Direct(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect) {

#ifdef _WIN64
        using NtAllocateVirtualMemory_t = NTSTATUS (NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        NtAllocateVirtualMemory_t fn = ResolveSyscallStub<NtAllocateVirtualMemory_t>("NtAllocateVirtualMemory");
        if (!fn) {
            return STATUS_NOT_SUPPORTED;
        }
        return fn(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
#else
        return STATUS_NOT_IMPLEMENTED;
#endif
    }

    // Process injection using direct syscalls only
    bool InjectViaSyscalls(DWORD processId, const std::wstring& dllPath) {
        if (!ready) {
            return false;
        }

        // Open process using direct syscall
        HANDLE hProcess = nullptr;
        CLIENT_ID clientId = { 0 };
        clientId.UniqueProcess = (HANDLE)(ULONG_PTR)processId;

        OBJECT_ATTRIBUTES objAttr = { 0 };
        objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

        NTSTATUS status = NtOpenProcess_Direct(&hProcess, PROCESS_ALL_ACCESS,
                                              &objAttr, &clientId);

        if (!NT_SUCCESS(status) || hProcess == nullptr) {
            return false;
        }

        // Allocate memory using direct syscall
        SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(WCHAR);
        PVOID pRemoteMem = nullptr;

        status = NtAllocateVirtualMemory_Direct(hProcess, &pRemoteMem, 0,
                                               &dllPathSize, MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE);

        if (!NT_SUCCESS(status) || pRemoteMem == nullptr) {
            CloseHandle(hProcess);
            return false;
        }

        // Write DLL path using direct syscall
        status = NtWriteVirtualMemory_Direct(hProcess, pRemoteMem,
                                            (PVOID)dllPath.c_str(), dllPathSize, nullptr);

        if (!NT_SUCCESS(status)) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC loadLibraryW = hKernel32 ? GetProcAddress(hKernel32, "LoadLibraryW") : nullptr;
        if (!loadLibraryW) {
            VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Create remote thread using direct syscall
        HANDLE hThread = nullptr;
        status = NtCreateThreadEx_Direct(&hThread, THREAD_ALL_ACCESS, nullptr,
                                        hProcess, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryW),
                                        pRemoteMem, FALSE, 0, 0, 0, nullptr);

        bool injectionSuccessful = false;
        if (NT_SUCCESS(status) && hThread != nullptr) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            injectionSuccessful = true;
        }

        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return injectionSuccessful;
    }

public:
    NTSTATUS NtWriteVirtualMemory_Direct(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T BufferSize,
        PSIZE_T NumberOfBytesWritten) {

#ifdef _WIN64
        using NtWriteVirtualMemory_t = NTSTATUS (NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        NtWriteVirtualMemory_t fn = ResolveSyscallStub<NtWriteVirtualMemory_t>("NtWriteVirtualMemory");
        if (!fn) {
            return STATUS_NOT_SUPPORTED;
        }
        return fn(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
#else
        return STATUS_NOT_IMPLEMENTED;
#endif
    }

    NTSTATUS NtCreateThreadEx_Direct(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE StartRoutine,
        LPVOID Argument,
        ULONG CreateFlags,
        ULONG_PTR ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        LPVOID AttributeList) {

#ifdef _WIN64
        using NtCreateThreadEx_t = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                                     LPTHREAD_START_ROUTINE, LPVOID, ULONG,
                                                     ULONG_PTR, SIZE_T, SIZE_T, LPVOID);
        NtCreateThreadEx_t fn = ResolveSyscallStub<NtCreateThreadEx_t>("NtCreateThreadEx");
        if (!fn) {
            return STATUS_NOT_SUPPORTED;
        }
        return fn(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine,
                  Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
#else
        return STATUS_NOT_IMPLEMENTED;
#endif
    }

private:
    bool HasRequiredSyscalls() const {
        static const char* required[] = {
            "NtOpenProcess",
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx"
        };

        for (const char* name : required) {
            auto it = syscallEntries.find(name);
            if (it == syscallEntries.end() || it->second.number == 0) {
                return false;
            }
#ifdef _WIN64
            if (is64bit && it->second.stub == nullptr) {
                return false;
            }
#endif
        }
        return true;
    }

    void CleanupStubs() {
#ifdef _WIN64
        for (void* stub : allocatedStubs) {
            if (stub) {
                VirtualFree(stub, 0, MEM_RELEASE);
            }
        }
#endif
        allocatedStubs.clear();
    }

    std::unordered_map<std::string, DWORD> SnapshotRegisteredSyscalls() const {
        std::unordered_map<std::string, DWORD> snapshot;
        for (const auto& kv : syscallEntries) {
            if (kv.second.number != 0) {
                snapshot.emplace(kv.first, kv.second.number);
            }
        }
        return snapshot;
    }

    bool RegisterStaticSyscall(const std::string& name, DWORD number) {
        if (number == 0) {
            return false;
        }

#ifdef _WIN64
        if (!is64bit) {
            syscallEntries[name].number = number;
            syscallEntries[name].stub = nullptr;
            return true;
        }

        void* stub = BuildSyscallStub(number);
        if (stub == nullptr) {
            LogDirectSyscall(std::string("Failed to build syscall stub for ") + name);
            return false;
        }

        auto it = syscallEntries.find(name);
        if (it != syscallEntries.end()) {
            ReleaseStub(it->second.stub);
            it->second.number = number;
            it->second.stub = stub;
        } else {
            SyscallEntry entry{};
            entry.number = number;
            entry.stub = stub;
            syscallEntries[name] = entry;
        }

        allocatedStubs.push_back(stub);
        return true;
#else
        syscallEntries[name].number = number;
        syscallEntries[name].stub = nullptr;
        return true;
#endif
    }

    const SyscallEntry* GetEntry(const std::string& name) const {
        auto it = syscallEntries.find(name);
        if (it == syscallEntries.end() || it->second.number == 0) {
            return nullptr;
        }
#ifdef _WIN64
        if (is64bit && it->second.stub == nullptr) {
            return nullptr;
        }
#endif
        return &it->second;
    }

    void ReleaseStub(void* stub) {
#ifdef _WIN64
        if (!stub) {
            return;
        }
        auto it = std::find(allocatedStubs.begin(), allocatedStubs.end(), stub);
        if (it != allocatedStubs.end()) {
            allocatedStubs.erase(it);
        }
        VirtualFree(stub, 0, MEM_RELEASE);
#else
        UNREFERENCED_PARAMETER(stub);
#endif
    }

    template <typename Fn>
    Fn ResolveSyscallStub(const std::string& name) const {
#ifdef _WIN64
        if (!ready || !is64bit) {
            return nullptr;
        }
        const SyscallEntry* entry = GetEntry(name);
        if (!entry) {
            return nullptr;
        }
        return reinterpret_cast<Fn>(entry->stub);
#else
        UNREFERENCED_PARAMETER(name);
        return nullptr;
#endif
    }

    DWORD DecodeSyscallStub(void* function) const {
        if (!function) {
            return 0;
        }
        BYTE* pBytes = reinterpret_cast<BYTE*>(function);
#ifdef _WIN64
        if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 && pBytes[3] == 0xB8) {
            DWORD number = 0;
            memcpy(&number, &pBytes[4], sizeof(DWORD));
            return number;
        }
#else
        if (pBytes[0] == 0xB8) {
            DWORD number = 0;
            memcpy(&number, &pBytes[1], sizeof(DWORD));
            return number;
        }
#endif
        return 0;
    }

#ifdef _WIN64
    void* BuildSyscallStub(DWORD number) {
        static constexpr BYTE stubTemplate[] = {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, imm32
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };

        BYTE stubBytes[sizeof(stubTemplate)];
        memcpy(stubBytes, stubTemplate, sizeof(stubTemplate));
        memcpy(&stubBytes[4], &number, sizeof(DWORD));

        void* stub = VirtualAlloc(nullptr, sizeof(stubBytes),
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
        if (!stub) {
            return nullptr;
        }

        memcpy(stub, stubBytes, sizeof(stubBytes));
        FlushInstructionCache(GetCurrentProcess(), stub, sizeof(stubBytes));

        DWORD oldProtect = 0;
        if (!VirtualProtect(stub, sizeof(stubBytes), PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(stub, 0, MEM_RELEASE);
            return nullptr;
        }

        return stub;
    }
#endif
};

class HeavensGate {
private:
    BOOL isWow64 = FALSE;

public:
    HeavensGate() {
        IsWow64Process(GetCurrentProcess(), &isWow64);
    }

    bool CanUseHeavensGate() const {
        return isWow64 == TRUE;
    }

    NTSTATUS CallSyscall64(DWORD syscallNumber, DWORD64 arg1 = 0, DWORD64 arg2 = 0,
                          DWORD64 arg3 = 0, DWORD64 arg4 = 0) {
        UNREFERENCED_PARAMETER(syscallNumber);
        UNREFERENCED_PARAMETER(arg1);
        UNREFERENCED_PARAMETER(arg2);
        UNREFERENCED_PARAMETER(arg3);
        UNREFERENCED_PARAMETER(arg4);
        return STATUS_NOT_SUPPORTED;
    }
};

// Syscall unhooking - restore original syscall stubs
class SyscallUnhooker {
public:
    bool UnhookAll() {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return false;

        // Map a clean copy of ntdll from disk
        HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
                                  GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, 0, nullptr);

        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        CloseHandle(hFile);

        if (!hMapping) {
            return false;
        }

        LPVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(hMapping);

        if (!pCleanNtdll) {
            return false;
        }

        // Get NT headers
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pCleanNtdll;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pCleanNtdll + pDosHeader->e_lfanew);

        // Find .text section
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        PIMAGE_SECTION_HEADER pTextHeader = nullptr;

        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (std::strncmp(reinterpret_cast<const char*>(pSectionHeader[i].Name), ".text", IMAGE_SIZEOF_SHORT_NAME) == 0) {
                pTextHeader = &pSectionHeader[i];
                break;
            }
        }

        if (pTextHeader) {
            BYTE* destination = reinterpret_cast<BYTE*>(hNtdll) + pTextHeader->VirtualAddress;
            BYTE* source = reinterpret_cast<BYTE*>(pCleanNtdll) + pTextHeader->PointerToRawData;
            DWORD copySize = std::min<DWORD>(pTextHeader->Misc.VirtualSize, pTextHeader->SizeOfRawData);

            DWORD oldProtect = 0;
            if (VirtualProtect(destination, copySize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(destination, source, copySize);
                DWORD ignored;
                VirtualProtect(destination, copySize, oldProtect, &ignored);
            }
        }

        UnmapViewOfFile(pCleanNtdll);
        return true;
    }
};

static DirectSyscallEngine& GetDirectSyscallEngine() {
    static DirectSyscallEngine instance;
    return instance;
}

bool EnsureDirectSyscallInitialized() {
    auto& engine = GetDirectSyscallEngine();
    return engine.IsReady() || engine.Initialize();
}

NTSTATUS DirectNtOpenProcess(PHANDLE ProcessHandle,
                             ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes,
                             CLIENT_ID* ClientId) {
    if (!EnsureDirectSyscallInitialized()) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return GetDirectSyscallEngine().NtOpenProcess_Direct(ProcessHandle,
                                                         DesiredAccess,
                                                         ObjectAttributes,
                                                         ClientId);
}

NTSTATUS DirectNtAllocateVirtualMemory(HANDLE ProcessHandle,
                                       PVOID* BaseAddress,
                                       ULONG_PTR ZeroBits,
                                       PSIZE_T RegionSize,
                                       ULONG AllocationType,
                                       ULONG Protect) {
    if (!EnsureDirectSyscallInitialized()) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return GetDirectSyscallEngine().NtAllocateVirtualMemory_Direct(ProcessHandle,
                                                                   BaseAddress,
                                                                   ZeroBits,
                                                                   RegionSize,
                                                                   AllocationType,
                                                                   Protect);
}

NTSTATUS DirectNtWriteVirtualMemory(HANDLE ProcessHandle,
                                    PVOID BaseAddress,
                                    PVOID Buffer,
                                    SIZE_T BufferSize,
                                    PSIZE_T NumberOfBytesWritten) {
    if (!EnsureDirectSyscallInitialized()) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return GetDirectSyscallEngine().NtWriteVirtualMemory_Direct(ProcessHandle,
                                                                BaseAddress,
                                                                Buffer,
                                                                BufferSize,
                                                                NumberOfBytesWritten);
}

NTSTATUS DirectNtCreateThreadEx(PHANDLE ThreadHandle,
                                ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes,
                                HANDLE ProcessHandle,
                                LPTHREAD_START_ROUTINE StartRoutine,
                                LPVOID Argument,
                                ULONG CreateFlags,
                                ULONG_PTR ZeroBits,
                                SIZE_T StackSize,
                                SIZE_T MaximumStackSize,
                                LPVOID AttributeList) {
    if (!EnsureDirectSyscallInitialized()) {
        return STATUS_NOT_IMPLEMENTED;
    }
    return GetDirectSyscallEngine().NtCreateThreadEx_Direct(ThreadHandle,
                                                            DesiredAccess,
                                                            ObjectAttributes,
                                                            ProcessHandle,
                                                            StartRoutine,
                                                            Argument,
                                                            CreateFlags,
                                                            ZeroBits,
                                                            StackSize,
                                                            MaximumStackSize,
                                                            AttributeList);
}

bool InjectDllViaDirectSyscall(DWORD processId, const std::wstring& dllPath) {
    if (!EnsureDirectSyscallInitialized()) {
        return false;
    }
    return GetDirectSyscallEngine().InjectViaSyscalls(processId, dllPath);
}

void SetDirectSyscallStructuredLogger(StructuredLogFn logger) {
    g_directSyscallStructuredLogger = logger;
}

} // namespace injection

#else

namespace injection {

bool EnsureDirectSyscallInitialized() {
    return false;
}

NTSTATUS DirectNtOpenProcess(PHANDLE ProcessHandle,
                             ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes,
                             CLIENT_ID* ClientId) {
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(ClientId);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS DirectNtAllocateVirtualMemory(HANDLE ProcessHandle,
                                       PVOID* BaseAddress,
                                       ULONG_PTR ZeroBits,
                                       PSIZE_T RegionSize,
                                       ULONG AllocationType,
                                       ULONG Protect) {
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(BaseAddress);
    UNREFERENCED_PARAMETER(ZeroBits);
    UNREFERENCED_PARAMETER(RegionSize);
    UNREFERENCED_PARAMETER(AllocationType);
    UNREFERENCED_PARAMETER(Protect);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS DirectNtWriteVirtualMemory(HANDLE ProcessHandle,
                                    PVOID BaseAddress,
                                    PVOID Buffer,
                                    SIZE_T BufferSize,
                                    PSIZE_T NumberOfBytesWritten) {
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(BaseAddress);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferSize);
    UNREFERENCED_PARAMETER(NumberOfBytesWritten);
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS DirectNtCreateThreadEx(PHANDLE ThreadHandle,
                                ACCESS_MASK DesiredAccess,
                                POBJECT_ATTRIBUTES ObjectAttributes,
                                HANDLE ProcessHandle,
                                LPTHREAD_START_ROUTINE StartRoutine,
                                LPVOID Argument,
                                ULONG CreateFlags,
                                ULONG_PTR ZeroBits,
                                SIZE_T StackSize,
                                SIZE_T MaximumStackSize,
                                LPVOID AttributeList) {
    UNREFERENCED_PARAMETER(ThreadHandle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(StartRoutine);
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(CreateFlags);
    UNREFERENCED_PARAMETER(ZeroBits);
    UNREFERENCED_PARAMETER(StackSize);
    UNREFERENCED_PARAMETER(MaximumStackSize);
    UNREFERENCED_PARAMETER(AttributeList);
    return STATUS_NOT_IMPLEMENTED;
}

bool InjectDllViaDirectSyscall(DWORD processId, const std::wstring& dllPath) {
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(dllPath);
    return false;
}

} // namespace injection

#endif
