#ifdef _WIN32

#include <cstdint>

extern "C" {

bool DetectAnalysis() {
    return false;
}

void ApplyAntiAnalysis() {}

void* CreateTimingEvasion() {
    return nullptr;
}

bool DetectTiming(void* /*instance*/) {
    return false;
}

void DestroyTimingEvasion(void* /*instance*/) {}

}  // extern "C"

#endif  // _WIN32

