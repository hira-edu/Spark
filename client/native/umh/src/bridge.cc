#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <atomic>
#include <mutex>
#include <cstdio>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "../include/spark_umh.h"

extern "C" void sparkHookbridgeEmit(const char* kind, const char* detail, uint32_t pid, uint32_t sessionId);

// Forward declarations from HookDLL.cpp
bool InstallHooks();
void UninstallHooks();
extern std::atomic<int> g_forceInputPolicy;
extern std::atomic<int> g_forceWdaPolicy;
void ApplyPolicyOverride(std::atomic<int>& storage, int state, const char* name);

namespace spark {
namespace umh {

namespace {

struct SessionPolicy {
    bool forceInput = false;
    bool forceCapture = false;
};

constexpr int kErrNotInitialized = -2;
constexpr int kErrInstallFailed = -3;

class Bridge {
public:
    static Bridge& Instance() {
        static Bridge instance;
        return instance;
    }

    int Init() {
        std::lock_guard<std::mutex> lock(mu_);
        if (initialized_) {
            return 0;
        }
        if (!InstallHooks()) {
            return kErrInstallFailed;
        }
        initialized_ = true;
        return 0;
    }

    int Apply(const char* connection_id, int force_input, int force_capture) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialized_) {
            return kErrNotInitialized;
        }
        const std::string key = connection_id ? connection_id : std::string();
        SessionPolicy& policy = sessions_[key];
        policy.forceInput = force_input != 0;
        policy.forceCapture = force_capture != 0;
        ReconcileLocked();
        return 0;
    }

    int Release(const char* connection_id) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialized_) {
            return kErrNotInitialized;
        }
        if (connection_id) {
            sessions_.erase(connection_id);
        }
        ReconcileLocked();
        return 0;
    }

    void Shutdown() {
        std::lock_guard<std::mutex> lock(mu_);
        if (!initialized_) {
            return;
        }
        sessions_.clear();
        ReconcileLocked();
        UninstallHooks();
        initialized_ = false;
    }

private:
    Bridge() = default;
    ~Bridge() = default;

    void EmitStateLocked(bool forceInput, bool forceCapture) {
        if (forceInput == lastForceInput_ && forceCapture == lastForceCapture_) {
            return;
        }
        lastForceInput_ = forceInput;
        lastForceCapture_ = forceCapture;
        char detail[128];
        _snprintf_s(detail,
                    _TRUNCATE,
                    "{\"forceInput\":%s,\"forceCapture\":%s}",
                    forceInput ? "true" : "false",
                    forceCapture ? "true" : "false");
        DWORD session = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &session);
        sparkHookbridgeEmit("policy_state", detail, GetCurrentProcessId(), session);
    }

    void ReconcileLocked() {
        bool forceInput = false;
        bool forceCapture = false;
        for (const auto& entry : sessions_) {
            forceInput = forceInput || entry.second.forceInput;
            forceCapture = forceCapture || entry.second.forceCapture;
            if (forceInput && forceCapture) {
                break;
            }
        }
        ApplyPolicyOverride(g_forceInputPolicy, forceInput ? 1 : 0, "force_input");
        ApplyPolicyOverride(g_forceWdaPolicy, forceCapture ? 1 : 0, "force_wda");
        EmitStateLocked(forceInput, forceCapture);
    }

    std::mutex mu_;
    bool initialized_ = false;
    std::unordered_map<std::string, SessionPolicy> sessions_;
    bool lastForceInput_ = false;
    bool lastForceCapture_ = false;
};

}  // namespace

}  // namespace umh
}  // namespace spark

extern "C" {

int spark_umh_init(void) {
    return spark::umh::Bridge::Instance().Init();
}

int spark_umh_apply(const char* connection_id, int force_input, int force_capture) {
    return spark::umh::Bridge::Instance().Apply(connection_id, force_input, force_capture);
}

int spark_umh_release(const char* connection_id) {
    return spark::umh::Bridge::Instance().Release(connection_id);
}

void spark_umh_shutdown(void) {
    spark::umh::Bridge::Instance().Shutdown();
}

}  // extern "C"

#endif  // _WIN32
