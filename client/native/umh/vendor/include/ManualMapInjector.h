#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <utility>
#include <array>

namespace injection {

struct ManualMapConfig {
    bool randomizeOffset = true;
    bool guardPages = true;
    bool shredHeaders = true;
    bool neutralizeTls = true;
    bool encryptSections = true;
    bool deferImports = true;
    bool reencryptAfterInit = false;
};

enum ManualMapFlags : DWORD {
    kManualMapHideFromPeb = 0x01,
    kManualMapEraseHeaders = 0x02,
    kManualMapFakeHeader = 0x04,
    kManualMapUnlinkFromVad = 0x08,
    kManualMapNoExceptions = 0x10
};

class ManualMapInjector {
public:
    ManualMapInjector();

    bool LoadFromFile(const std::wstring& dllPath);
    bool LoadFromMemory(const BYTE* buffer, size_t size);

    bool InjectIntoProcess(DWORD processId, DWORD flags = 0);
    bool InjectIntoProcess(HANDLE processHandle, DWORD flags = 0);

    void SetConfig(const ManualMapConfig& config) { config_ = config; }
    const ManualMapConfig& GetConfig() const noexcept { return config_; }

    const std::wstring& GetLastError() const noexcept { return lastError_; }
    size_t ImageSize() const noexcept;
    LPVOID LastRemoteBase() const noexcept { return lastRemoteBase_; }
    SIZE_T LastRandomOffset() const noexcept { return lastRandomOffset_; }
    SIZE_T LastReservationSize() const noexcept { return lastReservationSize_; }

private:
    bool ValidatePE();
    bool PerformManualMap(HANDLE process, DWORD flags);
    bool CopySections(HANDLE process, LPVOID targetBase);
    bool ProcessRelocations(HANDLE process, LPVOID targetBase);
    bool ResolveImports(HANDLE process, LPVOID targetBase);
    bool AdjustProtections(HANDLE process, LPVOID targetBase);
    bool ExecuteTLSCallbacks(HANDLE process, LPVOID targetBase);
    bool CallDllMain(HANDLE process, LPVOID targetBase, DWORD fdwReason);
    void EraseHeaders(HANDLE process, LPVOID targetBase);
    void HideFromPEB(HANDLE process, LPVOID targetBase);
    void UnlinkFromVAD(HANDLE process, LPVOID targetBase);
    void NeutralizeTlsDirectory(HANDLE process, LPVOID targetBase);
    void CollectEncryptionSlices(std::vector<std::pair<DWORD, DWORD>>& slices) const;
    bool GenerateAesKey(std::array<BYTE, 32>& key, std::array<BYTE, 16>& iv);
    static void AddBlocksToCounter(std::array<BYTE, 16>& counter, uint64_t blocks);
    bool EncryptRemoteSectionsAes(HANDLE process,
                                  LPVOID targetBase,
                                  const std::vector<std::pair<DWORD, DWORD>>& slices,
                                  const std::array<BYTE, 32>& key,
                                  const std::array<BYTE, 16>& iv);
    void SetLastErrorMessage(const std::wstring& message);
    void SetLastErrorFromWin32(const wchar_t* context);

    HMODULE FindRemoteModuleHandle(HANDLE process, const std::wstring& moduleName) const;
    HMODULE LoadRemoteModule(HANDLE process, const std::string& moduleName);
    bool EnsureRemoteModule(HANDLE process, const std::string& moduleName, HMODULE& remoteModule);
    bool ResolveExportAddress(HANDLE process,
                              HMODULE localModule,
                              HMODULE remoteModule,
                              const std::string& moduleName,
                              const char* importName,
                              WORD ordinal,
                              uintptr_t& remoteAddress,
                              int depth = 0);
    bool ResolveForwarder(HANDLE process,
                          const std::string& forwarder,
                          uintptr_t& remoteAddress,
                          int depth);

    std::vector<BYTE> dllBuffer_;
    PIMAGE_NT_HEADERS ntHeaders_;
    PIMAGE_DOS_HEADER dosHeader_;
    std::wstring lastError_;
    LPVOID lastRemoteBase_;
    SIZE_T lastRandomOffset_;
    SIZE_T lastReservationSize_;
    ManualMapConfig config_;
};

} // namespace injection
