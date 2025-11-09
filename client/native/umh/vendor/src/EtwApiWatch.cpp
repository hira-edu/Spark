#include "../include/EtwApiWatch.h"

#include <tdh.h>
#include <initguid.h>

#pragma comment(lib, "tdh.lib")

namespace {
    bool ParseGuid(const std::wstring& s, GUID& g) {
        return CLSIDFromString(s.c_str(), &g) == S_OK;
    }
}

EtwApiWatch::EtwApiWatch() {}
EtwApiWatch::~EtwApiWatch() { Stop(); }

bool EtwApiWatch::Start(const std::wstring& sessionName,
                        const std::wstring& providerGuidStr,
                        const std::vector<USHORT>& eventIds,
                        EventCallback cb,
                        const std::wstring& payloadContains) {
    if (running_.load()) return true;
    if (!ParseGuid(providerGuidStr, provider_)) return false;
    sessionName_ = sessionName;
    eventIds_ = eventIds;
    callback_ = std::move(cb);
    payloadContains_ = payloadContains;

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (ULONG)((sessionName_.size()+2) * sizeof(WCHAR));
    propBuf_.assign(bufferSize, 0);
    props_ = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propBuf_.data());
    props_->Wnode.BufferSize = bufferSize;
    props_->Wnode.ClientContext = 1;
    props_->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props_->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props_->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    WCHAR* loggerName = reinterpret_cast<WCHAR*>(reinterpret_cast<BYTE*>(props_) + props_->LoggerNameOffset);
    wcscpy_s(loggerName, sessionName_.length()+1, sessionName_.c_str());

    ControlTraceW(0, sessionName_.c_str(), props_, EVENT_TRACE_CONTROL_STOP);
    ULONG st = StartTraceW(&sessionHandle_, sessionName_.c_str(), props_);
    if (st != ERROR_SUCCESS) {
        if (st == ERROR_ALREADY_EXISTS) {
            ControlTraceW(0, sessionName_.c_str(), props_, EVENT_TRACE_CONTROL_STOP);
            st = StartTraceW(&sessionHandle_, sessionName_.c_str(), props_);
        }
        if (st != ERROR_SUCCESS) return false;
    }

    ENABLE_TRACE_PARAMETERS params{}; params.Version = ENABLE_TRACE_PARAMETERS_VERSION;
    st = EnableTraceEx2(sessionHandle_, &provider_, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, &params);
    if (st != ERROR_SUCCESS) { Stop(); return false; }

    EVENT_TRACE_LOGFILEW log{}; log.LoggerName = const_cast<LPWSTR>(sessionName_.c_str()); log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD; log.EventRecordCallback = &EtwApiWatch::EventRecordStatic; log.Context = this;
    traceHandle_ = OpenTraceW(&log);
    if (traceHandle_ == INVALID_PROCESSTRACE_HANDLE) { Stop(); return false; }

    running_.store(true);
    thread_ = std::thread([&]() {
        ProcessTrace(&traceHandle_, 1, nullptr, nullptr);
    });
    return true;
}

void EtwApiWatch::Stop() {
    running_.store(false);
    if (traceHandle_ != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(traceHandle_); traceHandle_ = INVALID_PROCESSTRACE_HANDLE; }
    if (thread_.joinable()) thread_.join();
    if (sessionHandle_) { EnableTraceEx2(sessionHandle_, &provider_, EVENT_CONTROL_CODE_DISABLE_PROVIDER, TRACE_LEVEL_NONE, 0,0,0, nullptr); StopTraceW(sessionHandle_, sessionName_.c_str(), props_); sessionHandle_ = 0; }
    props_ = nullptr; propBuf_.clear();
}

VOID WINAPI EtwApiWatch::EventRecordStatic(PEVENT_RECORD rec) {
    if (!rec) return; EtwApiWatch* self = reinterpret_cast<EtwApiWatch*>(rec->UserContext);
    if (self) self->OnEvent(rec);
}

VOID EtwApiWatch::OnEvent(PEVENT_RECORD rec) {
    if (!callback_) return;
    USHORT id = rec->EventHeader.EventDescriptor.Id;
    if (!eventIds_.empty()) {
        bool match = false; for (auto eid : eventIds_) if (eid == id) { match = true; break; }
        if (!match) return;
    }
    if (!payloadContains_.empty() && rec->UserData && rec->UserDataLength >= sizeof(WCHAR)) {
        // naive UTF-16LE contains check
        const WCHAR* buf = reinterpret_cast<const WCHAR*>(rec->UserData);
        size_t wlen = rec->UserDataLength / sizeof(WCHAR);
        std::wstring payload(buf, buf + wlen);
        if (payload.find(payloadContains_) == std::wstring::npos) {
            return;
        }
    }
    DWORD pid = rec->EventHeader.ProcessId;
    callback_(pid, id);
}
