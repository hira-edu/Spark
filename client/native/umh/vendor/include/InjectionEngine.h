#pragma once

#include <Windows.h>

#include "ManualMapInjector.h"
#include "SectionMapInjector.h"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace injection {

enum class InjectionMethod {
    Standard,
    ManualMap,
    SectionMap,
    Reflective,
    DirectSyscall
};

struct InjectionOptions {
    std::vector<InjectionMethod> methodOrder;
    DWORD manualMapFlags = 0;
    DWORD sectionMapFlags = 0;
    bool suspendDuringInjection = false;
    bool allowDirectSyscall = true;
};

struct InjectionResult {
    bool success = false;
    InjectionMethod method = InjectionMethod::Standard;
    std::wstring detail;
};

class InjectionEngine {
public:
    using LogCallback = std::function<void(const std::wstring&)>;

    InjectionEngine();

    void SetLogger(LogCallback callback);

    void SetManualMapConfig(const ManualMapConfig& config);
    void SetSectionMapConfig(const SectionMapConfig& config);

    InjectionResult Inject(DWORD processId,
                           const std::wstring& dllPath,
                           const InjectionOptions& options);

private:
    bool InjectStandard(HANDLE process,
                        DWORD processId,
                        const std::wstring& dllPath,
                        std::wstring& detail) const;
    bool InjectManualMap(HANDLE process,
                         DWORD processId,
                         const std::wstring& dllPath,
                         DWORD manualMapFlags,
                         std::wstring& detail);
    bool InjectSectionMap(HANDLE process,
                          DWORD processId,
                          const std::wstring& dllPath,
                          DWORD sectionMapFlags,
                          std::wstring& detail);
    bool InjectReflective(HANDLE process,
                          DWORD processId,
                          const std::wstring& dllPath,
                          std::wstring& detail);
    bool InjectDirectSyscall(DWORD processId,
                             const std::wstring& dllPath,
                             std::wstring& detail);

    std::optional<HANDLE> OpenTargetProcess(DWORD processId, DWORD accessMask) const;
    void Log(const std::wstring& message) const;

    LogCallback logger_;
    std::optional<ManualMapConfig> manualMapConfigOverride_;
    std::optional<SectionMapConfig> sectionMapConfigOverride_;
};

} // namespace injection
