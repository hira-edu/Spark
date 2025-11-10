#ifdef _WIN32

#include <functional>

#include "../vendor/include/VulkanHooks.h"

namespace vkhooks {

void Initialize() {}

void Shutdown() {}

Stats GetStats() {
    return Stats{};
}

void SetPresentCallback(std::function<void()> cb) {
    (void)cb;
}

HookStatus GetHookStatus() {
    return HookStatus{};
}

}  // namespace vkhooks

#endif  // _WIN32

