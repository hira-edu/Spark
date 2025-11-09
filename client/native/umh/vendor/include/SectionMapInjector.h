#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <utility>

namespace injection {

struct SectionMapConfig {
    bool randomSectionName = true;
    bool entropyPadding = true;
    bool unmapLocalViewEarly = true;
    bool encryptSections = true;
    bool deferEntryPoint = true;
    bool shredHeaders = true;
    bool neutralizeTls = true;
    bool reencryptAfterInit = false;
};

enum SectionMapFlags : DWORD {
    kSectionMapEraseHeaders = 0x01,
    kSectionMapRWXDebug     = 0x02,
    kSectionMapNoTLS        = 0x04,
};

class SectionMapInjector {
public:
    SectionMapInjector();

    bool LoadFromFile(const std::wstring& dllPath);
   bool LoadFromMemory(const BYTE* buffer, size_t size);

    bool InjectIntoProcess(DWORD processId, DWORD flags = 0);
    bool InjectIntoProcess(HANDLE processHandle, DWORD flags = 0);

    void SetConfig(const SectionMapConfig& config) { config_ = config; }
    const SectionMapConfig& GetConfig() const noexcept { return config_; }

    const std::wstring& GetLastError() const noexcept { return lastError_; }
    size_t ImageSize() const noexcept;

private:
    bool ValidatePE();
    bool CreateSectionAndViews(HANDLE process, DWORD flags, HANDLE& outSection, LPVOID& outLocal, LPVOID& outRemote);
    bool PopulateImage(LPVOID localView, LPVOID remoteView);
    bool ApplyRelocations(LPVOID localView, LPVOID remoteView);
    bool ResolveImports(LPVOID localView, LPVOID remoteView);
    bool ProtectSections(HANDLE process, LPVOID remoteView, DWORD flags);
    bool ExecuteTLS(HANDLE process, LPVOID remoteView, DWORD flags);
    bool CallRemoteDllMain(HANDLE process, LPVOID remoteView, DWORD reason);
    bool QueueDeferredDllMain(HANDLE process, LPVOID remoteView, DWORD reason);
    void NeutralizeTlsLocal(LPVOID localView);
    void CollectEncryptionSlices(std::vector<std::pair<DWORD, DWORD>>& slices) const;
    DWORD GenerateXorKey();
    void ApplyXorLocal(LPVOID localView, const std::vector<std::pair<DWORD, DWORD>>& slices, DWORD key);
    bool ApplyXorRemote(HANDLE process, LPVOID remoteView, const std::vector<std::pair<DWORD, DWORD>>& slices, DWORD key);
    void RandomizeHeadersRemote(HANDLE process, LPVOID remoteView);
    void EraseHeadersRemote(HANDLE process, LPVOID remoteView);
    void SetLastErrorMessage(const std::wstring& message);
    void SetLastErrorFromWin32(const wchar_t* context);

    std::vector<BYTE> dllBuffer_;
    PIMAGE_NT_HEADERS ntHeaders_ = nullptr;
    PIMAGE_DOS_HEADER dosHeader_ = nullptr;
    std::wstring lastError_;
    SectionMapConfig config_;
};

} // namespace injection
