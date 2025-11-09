#pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>

class EtwApiWatch {
public:
    using EventCallback = std::function<void(DWORD pid, USHORT eventId)>;

    EtwApiWatch();
    ~EtwApiWatch();

    bool Start(const std::wstring& sessionName,
               const std::wstring& providerGuidStr,
               const std::vector<USHORT>& eventIds,
               EventCallback cb,
               const std::wstring& payloadContains = L"");
    void Stop();

private:
    static VOID WINAPI EventRecordStatic(PEVENT_RECORD rec);
    VOID OnEvent(PEVENT_RECORD rec);

    bool EnableProvider();

    TRACEHANDLE sessionHandle_ = 0;
    TRACEHANDLE traceHandle_ = INVALID_PROCESSTRACE_HANDLE;
    EVENT_TRACE_PROPERTIES* props_ = nullptr;
    std::vector<BYTE> propBuf_;
    std::wstring sessionName_;
    GUID provider_{};
    std::vector<USHORT> eventIds_;
    std::wstring payloadContains_;
    EventCallback callback_;
    std::thread thread_;
    std::atomic<bool> running_{false};
};
