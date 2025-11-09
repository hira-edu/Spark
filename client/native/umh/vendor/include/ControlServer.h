#pragma once
#include <Windows.h>
#include <string>
#include <thread>
#include <atomic>
#include "InjectionEngine.h"

class ControlServer {
public:
    ControlServer();
    ~ControlServer();

    bool Start(HANDLE stopEvent,
               const std::wstring& hookDllPath,
               injection::InjectionEngine* engine);
    void Stop();

private:
    void ServerThread();
    void HandleClient(HANDLE pipe);

    std::wstring hookDllPath_;
    injection::InjectionEngine* engine_ = nullptr;
    HANDLE stopEvent_ = nullptr;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

