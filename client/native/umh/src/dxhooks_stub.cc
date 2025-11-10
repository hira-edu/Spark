#ifdef _WIN32

#include <functional>

#include "../vendor/include/DirectXHooks.h"

namespace dxhooks {

void Initialize() {}

void Shutdown() {}

Stats GetStats() {
    return Stats{};
}

void SetPresentCallback(std::function<void(const char* api)> cb) {
    (void)cb;
}

void SetTelemetryCallback(TelemetryCallback cb) {
    (void)cb;
}

void SetPolicyCallback(PolicyCallback cb) {
    (void)cb;
}

bool GraphicsCaptureHooksActive() {
    return false;
}

bool GraphicsCaptureHooksFailed() {
    return false;
}

}  // namespace dxhooks

#endif  // _WIN32

