#ifdef _WIN32

#include <functional>

#include "../vendor/include/OpenXRHooks.h"

namespace openxrhooks {

void Initialize() {}

void Shutdown() {}

Stats GetStats() {
    return Stats{};
}

void SetTelemetryCallback(TelemetryCallback cb) {
    (void)cb;
}

void SetPolicyCallback(PolicyCallback cb) {
    (void)cb;
}

}  // namespace openxrhooks

#endif  // _WIN32

