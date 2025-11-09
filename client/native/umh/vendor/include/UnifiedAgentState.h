#pragma once

#include <Windows.h>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <functional>

struct FlaggedProcessContext {
    DWORD pid = 0;
    std::wstring name;
    DWORD sessionId = 0xFFFFFFFFu;
    std::wstring userSid;
    std::wstring userName;
};

struct UnifiedAgentSweepContext {
    bool initialSweepDone = false;
    bool watcherReady = false;
    bool eventOverflowed = false;
    bool pendingConfigSweep = false;
    bool pendingFingerprintSweep = false;
    ULONGLONG nowTicks = 0;
    ULONGLONG lastSweepTick = 0;
    ULONGLONG fallbackIntervalMs = 0;
};

struct UnifiedAgentSweepDecision {
    bool run = false;
    const wchar_t* reason = L"";
};

UnifiedAgentSweepDecision EvaluateSafetySweep(const UnifiedAgentSweepContext& context);

struct UnifiedAgentCacheState {
    std::map<DWORD, FlaggedProcessContext> flagged;
    std::map<DWORD, std::wstring> fingerprints;
    std::map<DWORD, std::vector<std::wstring>> modules;
};

struct UnifiedAgentCacheInput {
    std::set<DWORD> activePids;
    std::vector<FlaggedProcessContext> flaggedSnapshot;
    std::map<DWORD, std::wstring> fingerprintSnapshot;
    std::map<DWORD, std::vector<std::wstring>> moduleSnapshot;
};

void UpdateUnifiedAgentCaches(UnifiedAgentCacheState& state,
                              const UnifiedAgentCacheInput& input,
                              const std::function<bool(DWORD)>& isPidAlive);

