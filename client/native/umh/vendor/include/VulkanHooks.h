#pragma once

#include <functional>

namespace vkhooks {

struct Stats {
    unsigned long long queuePresent = 0;
    unsigned long long acquireNextImage = 0;
};

struct HookStatus {
    bool instanceProc = false;
    bool deviceProc = false;
    bool queuePresent = false;
    bool acquireNextImage = false;
};

void Initialize();
void Shutdown();
Stats GetStats();
void SetPresentCallback(std::function<void()> cb);
HookStatus GetHookStatus();

} // namespace vkhooks
