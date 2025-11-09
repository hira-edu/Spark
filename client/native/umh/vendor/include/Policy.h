#pragma once
#include <Windows.h>
#include <string>
#include <vector>

struct UmhPolicy {
    bool requireSignedDll = false;
    int  maxRetries = 3;
    std::vector<std::wstring> includePatterns; // if empty → include all
    std::vector<std::wstring> excludePatterns; // precedence over include
    struct Watch {
        std::wstring providerGuid; // e.g., {8c416c79-d49b-4f01-a467-e56d3aa8234c}
        std::vector<USHORT> eventIds; // trigger event IDs
        std::wstring label; // human-readable, e.g., NtUserSetWindowDisplayAffinity
        std::wstring contains; // optional wide substring to match in payload (e.g., L"SetWindowDisplayAffinity")
    };
    std::vector<Watch> watches; // ETW watches
};

namespace policy {
// Loads %ProgramData%\UserModeHook\policy.json if present; otherwise returns defaults.
UmhPolicy LoadPolicy();
// Persists policy to %ProgramData%\UserModeHook\policy.json
bool SavePolicy(const std::wstring& jsonUtf8OrUtf16);
// Serializes current policy as compact JSON string (UTF-8)
std::string ExportPolicyJson(const UmhPolicy& p);
}
