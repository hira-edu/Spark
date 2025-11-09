#pragma once

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace etw {

class ETWMonitor {
public:
    using ProcessCallback = std::function<void(DWORD processId, const std::wstring& imageName, DWORD parentProcessId)>;

    explicit ETWMonitor(const std::wstring& sessionName);
    ~ETWMonitor();

    void SetProcessCreateCallback(ProcessCallback callback);
    void SetProcessTerminateCallback(ProcessCallback callback);

    bool Start();
    void Stop();

private:
    TRACEHANDLE sessionHandle_;
    TRACEHANDLE traceHandle_;
    EVENT_TRACE_PROPERTIES* sessionProperties_;
    std::wstring sessionName_;
    ProcessCallback onProcessCreate_;
    ProcessCallback onProcessTerminate_;
    std::thread processingThread_;
    std::atomic<bool> isRunning_;
    std::mutex callbackMutex_;
    std::vector<BYTE> sessionPropertyBuffer_;

    bool EnableProcessProvider();
    void ProcessingThread();
    void ProcessEventRecord(PEVENT_RECORD eventRecord);
    void HandleProcessStart(PEVENT_RECORD eventRecord);
    void HandleProcessStop(PEVENT_RECORD eventRecord);
    bool ExtractProcessEventInfo(PEVENT_RECORD eventRecord,
                                 DWORD& processId,
                                 DWORD& parentProcessId,
                                 std::wstring& imageName);
    ULONG64 ExtractPropertyUInt64(PEVENT_RECORD record, const wchar_t* propertyName) const;
    std::wstring ExtractPropertyString(PEVENT_RECORD record, const wchar_t* propertyName) const;
    void FreeSessionProperties();

    static VOID WINAPI EventRecordCallback(PEVENT_RECORD eventRecord);
};

} // namespace etw
