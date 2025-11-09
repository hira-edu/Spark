#include "../include/UnifiedAgentState.h"

#include <algorithm>
UnifiedAgentSweepDecision EvaluateSafetySweep(const UnifiedAgentSweepContext& context) {
    UnifiedAgentSweepDecision decision{};
    if (!context.initialSweepDone) {
        decision.run = true;
        decision.reason = L"initial";
        return decision;
    }

    if (!context.watcherReady) {
        if (context.fallbackIntervalMs == 0 ||
            context.nowTicks - context.lastSweepTick >= context.fallbackIntervalMs) {
            decision.run = true;
            decision.reason = L"watcher_down";
        }
        return decision;
    }

    if (context.eventOverflowed) {
        decision.run = true;
        decision.reason = L"overflow";
        return decision;
    }

    if (context.pendingConfigSweep) {
        decision.run = true;
        decision.reason = L"config_reload";
        return decision;
    }

    if (context.pendingFingerprintSweep) {
        decision.run = true;
        decision.reason = L"fingerprint_reload";
        return decision;
    }

    return decision;
}

static bool IsAlive(const std::set<DWORD>& active,
                    const std::function<bool(DWORD)>& isPidAlive,
                    DWORD pid) {
    if (active.find(pid) != active.end()) {
        return true;
    }
    if (!isPidAlive) {
        return true;
    }
    return isPidAlive(pid);
}

void UpdateUnifiedAgentCaches(UnifiedAgentCacheState& state,
                              const UnifiedAgentCacheInput& input,
                              const std::function<bool(DWORD)>& isPidAlive) {
    auto aliveCheck = [&](DWORD pid) {
        return IsAlive(input.activePids, isPidAlive, pid);
    };

    for (auto it = state.flagged.begin(); it != state.flagged.end();) {
        if (!aliveCheck(it->first)) {
            state.modules.erase(it->first);
            state.fingerprints.erase(it->first);
            it = state.flagged.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = state.fingerprints.begin(); it != state.fingerprints.end();) {
        if (!aliveCheck(it->first)) {
            it = state.fingerprints.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = state.modules.begin(); it != state.modules.end();) {
        if (!aliveCheck(it->first) || state.flagged.find(it->first) == state.flagged.end()) {
            it = state.modules.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto& ctx : input.flaggedSnapshot) {
        state.flagged[ctx.pid] = ctx;
    }

    for (const auto& kv : input.fingerprintSnapshot) {
        state.fingerprints[kv.first] = kv.second;
    }

    for (const auto& kv : input.moduleSnapshot) {
        if (kv.second.empty()) {
            continue;
        }
        std::set<std::wstring> unique(kv.second.begin(), kv.second.end());
        state.modules[kv.first] = std::vector<std::wstring>(unique.begin(), unique.end());
    }
}
