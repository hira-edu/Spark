#ifdef _WIN32

#define SPARK_UMH_STATIC_BUILD
#define NOMINMAX

#include "../../../native/umh/src/dxhooks_stub.cc"
#include "../../../native/umh/src/vkhooks_stub.cc"
#include "../../../native/umh/src/openxr_hooks_stub.cc"
#include "../../../native/umh/src/antidetection_stub.cc"

extern "C" {
#include "../../../native/umh/vendor/third_party/minhook/src/buffer.c"
#include "../../../native/umh/vendor/third_party/minhook/src/hde/hde32.c"
#include "../../../native/umh/vendor/third_party/minhook/src/hde/hde64.c"
#include "../../../native/umh/vendor/third_party/minhook/src/hook.c"
#include "../../../native/umh/vendor/third_party/minhook/src/trampoline.c"
}

#include "../../../native/umh/vendor/src/Config.cpp"
#include "../../../native/umh/vendor/src/ProcessTargets.cpp"
#include "../../../native/umh/vendor/src/Policy.cpp"
#include "../../../native/umh/vendor/src/SelfProtection.cpp"
#include "../../../native/umh/vendor/src/DirectSyscall.cpp"
#include "../../../native/umh/vendor/src/HookEngine.cpp"
#include "../../../native/umh/vendor/src/MultiLayerHook.cpp"
#include "../../../native/umh/vendor/src/MinHookWrapper.cpp"
#include "../../../native/umh/vendor/src/HookDLL.cpp"

#include "../../../native/umh/src/bridge.cc"

#endif  // _WIN32

