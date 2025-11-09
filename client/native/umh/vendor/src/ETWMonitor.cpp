#include "../include/ETWMonitor.h"

#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <iostream>
#include <vector>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace etw {

namespace {

const GUID kKernelProcessProviderGuid =
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

constexpr USHORT kProcessStartEventId = 1;
constexpr USHORT kProcessStopEventId = 2;

} // namespace

ETWMonitor::ETWMonitor(const std::wstring& sessionName)
    : sessionHandle_(0),
      traceHandle_(INVALID_PROCESSTRACE_HANDLE),
      sessionProperties_(nullptr),
      sessionName_(sessionName),
      isRunning_(false) {}

ETWMonitor::~ETWMonitor() {
    Stop();
    FreeSessionProperties();
}

void ETWMonitor::SetProcessCreateCallback(ProcessCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onProcessCreate_ = std::move(callback);
}

void ETWMonitor::SetProcessTerminateCallback(ProcessCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onProcessTerminate_ = std::move(callback);
}

bool ETWMonitor::Start() {
    if (isRunning_) {
        return true;
    }

    traceHandle_ = INVALID_PROCESSTRACE_HANDLE;
    sessionHandle_ = 0;

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
                       static_cast<ULONG>((sessionName_.length() + 2) * sizeof(WCHAR));

    sessionPropertyBuffer_.assign(bufferSize, 0);
    sessionProperties_ = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(sessionPropertyBuffer_.data());

    sessionProperties_->Wnode.BufferSize = bufferSize;
    sessionProperties_->Wnode.ClientContext = 1;
    sessionProperties_->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties_->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    sessionProperties_->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    sessionProperties_->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    WCHAR* loggerName = reinterpret_cast<WCHAR*>(
        reinterpret_cast<BYTE*>(sessionProperties_) + sessionProperties_->LoggerNameOffset);
    wcscpy_s(loggerName, sessionName_.length() + 1, sessionName_.c_str());

    ControlTraceW(0, sessionName_.c_str(), sessionProperties_, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTraceW(&sessionHandle_, sessionName_.c_str(), sessionProperties_);
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            ControlTraceW(0, sessionName_.c_str(), sessionProperties_, EVENT_TRACE_CONTROL_STOP);
            status = StartTraceW(&sessionHandle_, sessionName_.c_str(), sessionProperties_);
        }
        if (status != ERROR_SUCCESS) {
            std::wcerr << L"[ETWMonitor] StartTraceW failed with status " << status << std::endl;
            FreeSessionProperties();
            return false;
        }
    }

    if (!EnableProcessProvider()) {
        std::wcerr << L"[ETWMonitor] EnableTraceEx2 failed." << std::endl;
        StopTrace(sessionHandle_, sessionName_.c_str(), sessionProperties_);
        sessionHandle_ = 0;
        FreeSessionProperties();
        return false;
    }

    EVENT_TRACE_LOGFILEW trace{};
    trace.LoggerName = const_cast<LPWSTR>(sessionName_.c_str());
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = EventRecordCallback;
    trace.Context = this;

    traceHandle_ = OpenTraceW(&trace);
    if (traceHandle_ == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"[ETWMonitor] OpenTraceW failed. LastError=" << GetLastError() << std::endl;
        StopTrace(sessionHandle_, sessionName_.c_str(), sessionProperties_);
        sessionHandle_ = 0;
        FreeSessionProperties();
        return false;
    }

    isRunning_.store(true, std::memory_order_release);
    processingThread_ = std::thread(&ETWMonitor::ProcessingThread, this);

    return true;
}

void ETWMonitor::Stop() {
    isRunning_.store(false, std::memory_order_release);

    if (traceHandle_ != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(traceHandle_);
        traceHandle_ = INVALID_PROCESSTRACE_HANDLE;
    }

    if (processingThread_.joinable()) {
        processingThread_.join();
    }

    if (sessionHandle_ != 0) {
        ULONG status = ControlTraceW(sessionHandle_, sessionName_.c_str(), sessionProperties_, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
            std::wcerr << L"[ETWMonitor] ControlTraceW stop failed. Status: " << status << std::endl;
        }
        sessionHandle_ = 0;
    }

    FreeSessionProperties();
}

bool ETWMonitor::EnableProcessProvider() {
    const ULONG64 processKeyword = EVENT_TRACE_FLAG_PROCESS;
    ULONG status = EnableTraceEx2(sessionHandle_,
                                  &kKernelProcessProviderGuid,
                                  EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                  TRACE_LEVEL_INFORMATION,
                                  processKeyword,
                                  0,
                                  0,
                                  nullptr);
    return status == ERROR_SUCCESS;
}

void ETWMonitor::ProcessingThread() {
    TRACEHANDLE handle = traceHandle_;
    if (handle != INVALID_PROCESSTRACE_HANDLE) {
        TRACEHANDLE handles[] = { handle };
        ULONG status = ProcessTrace(handles, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
            std::wcerr << L"[ETWMonitor] ProcessTrace exited with status " << status << std::endl;
        }
    }
    isRunning_.store(false, std::memory_order_release);
}

VOID WINAPI ETWMonitor::EventRecordCallback(PEVENT_RECORD eventRecord) {
    if (!eventRecord) {
        return;
    }
    ETWMonitor* monitor = reinterpret_cast<ETWMonitor*>(eventRecord->UserContext);
    if (monitor) {
        monitor->ProcessEventRecord(eventRecord);
    }
}

void ETWMonitor::ProcessEventRecord(PEVENT_RECORD eventRecord) {
    if (!IsEqualGUID(eventRecord->EventHeader.ProviderId, kKernelProcessProviderGuid)) {
        return;
    }

    USHORT eventId = eventRecord->EventHeader.EventDescriptor.Id;
    if (eventId == kProcessStartEventId) {
        HandleProcessStart(eventRecord);
    } else if (eventId == kProcessStopEventId) {
        HandleProcessStop(eventRecord);
    }
}

void ETWMonitor::HandleProcessStart(PEVENT_RECORD eventRecord) {
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    std::wstring imageName;
    if (!ExtractProcessEventInfo(eventRecord, processId, parentProcessId, imageName)) {
        return;
    }

    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (onProcessCreate_ && processId != 0) {
        onProcessCreate_(processId, imageName, parentProcessId);
    }
}

void ETWMonitor::HandleProcessStop(PEVENT_RECORD eventRecord) {
    DWORD processId = 0;
    if (eventRecord->UserData && eventRecord->UserDataLength >= sizeof(DWORD)) {
        memcpy(&processId, eventRecord->UserData, sizeof(DWORD));
    }

    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (onProcessTerminate_ && processId != 0) {
        onProcessTerminate_(processId, L"", 0);
    }
}

bool ETWMonitor::ExtractProcessEventInfo(PEVENT_RECORD eventRecord,
                                         DWORD& processId,
                                         DWORD& parentProcessId,
                                         std::wstring& imageName) {
    if (!eventRecord->UserData || eventRecord->UserDataLength == 0) {
        return false;
    }

    processId = static_cast<DWORD>(ExtractPropertyUInt64(eventRecord, L"ProcessID"));
    parentProcessId = static_cast<DWORD>(ExtractPropertyUInt64(eventRecord, L"ParentProcessID"));
    imageName = ExtractPropertyString(eventRecord, L"ImageName");

    if (processId == 0 && eventRecord->UserDataLength >= sizeof(DWORD) * 2) {
        memcpy(&processId, eventRecord->UserData, sizeof(DWORD));
        memcpy(&parentProcessId,
               reinterpret_cast<const BYTE*>(eventRecord->UserData) + sizeof(DWORD),
               sizeof(DWORD));

        if (eventRecord->UserDataLength > sizeof(DWORD) * 2) {
            const WCHAR* namePtr = reinterpret_cast<const WCHAR*>(
                reinterpret_cast<const BYTE*>(eventRecord->UserData) + sizeof(DWORD) * 2);
            imageName.assign(namePtr);
        }
    }

    return processId != 0;
}

ULONG64 ETWMonitor::ExtractPropertyUInt64(PEVENT_RECORD record, const wchar_t* propertyName) const {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG propertySize = 0;
    ULONG status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0) {
        return 0;
    }

    std::vector<BYTE> buffer(propertySize);
    status = TdhGetProperty(record, 0, nullptr, 1, &descriptor, propertySize, buffer.data());
    if (status != ERROR_SUCCESS) {
        return 0;
    }

    ULONG64 value = 0;
    memcpy(&value, buffer.data(), std::min<ULONG>(propertySize, sizeof(value)));
    return value;
}

std::wstring ETWMonitor::ExtractPropertyString(PEVENT_RECORD record, const wchar_t* propertyName) const {
    PROPERTY_DATA_DESCRIPTOR descriptor{};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = ULONG_MAX;

    ULONG propertySize = 0;
    ULONG status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0) {
        return L"";
    }

    size_t charCount = (propertySize / sizeof(WCHAR)) + 1;
    std::vector<WCHAR> buffer(charCount, 0);
    status = TdhGetProperty(record, 0, nullptr, 1, &descriptor,
                            propertySize, reinterpret_cast<PBYTE>(buffer.data()));
    if (status != ERROR_SUCCESS) {
        return L"";
    }

    buffer[charCount - 1] = L'\0';
    return std::wstring(buffer.data());
}

void ETWMonitor::FreeSessionProperties() {
    sessionProperties_ = nullptr;
    sessionPropertyBuffer_.clear();
}

} // namespace etw
