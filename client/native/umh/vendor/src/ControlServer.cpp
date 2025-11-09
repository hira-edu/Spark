#include "../include/ControlServer.h"
#include "../include/Policy.h"
#include "../include/PipeNames.h"

#include <Psapi.h>
#include <vector>
#include <sstream>
#include <cctype>
#include <sddl.h>

static std::wstring JsonEscapeW(const std::wstring& s) {
    std::wstring o; o.reserve(s.size()+8);
    for (wchar_t c : s) { if (c==L'\\') o+=L"\\\\"; else if (c==L'\"') o+=L"\\\""; else if (c==L'\n') o+=L"\\n"; else if (c==L'\r') o+=L"\\r"; else if (c==L'\t') o+=L"\\t"; else o+=c; }
    return o;
}

namespace {
    std::wstring BaseName(const std::wstring& p) {
        size_t pos = p.find_last_of(L"\\/");
        return pos==std::wstring::npos ? p : p.substr(pos+1);
    }
}

ControlServer::ControlServer() {}
ControlServer::~ControlServer() { Stop(); }

bool ControlServer::Start(HANDLE stopEvent,
                          const std::wstring& hookDllPath,
                          injection::InjectionEngine* engine) {
    if (running_.load()) return true;
    stopEvent_ = stopEvent;
    hookDllPath_ = hookDllPath;
    engine_ = engine;
    running_.store(true);
    thread_ = std::thread(&ControlServer::ServerThread, this);
    return true;
}

void ControlServer::Stop() {
    if (!running_.load()) return;
    running_.store(false);
    if (thread_.joinable()) thread_.join();
}

void ControlServer::ServerThread() {
    const wchar_t* pipeName = L"\\\\.\\pipe\\umh_control";
    // Build a strict security descriptor: SYSTEM and Builtin Admins full access
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = FALSE; sa.lpSecurityDescriptor = nullptr;
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &psd, nullptr)) {
        sa.lpSecurityDescriptor = psd;
    }
    while (running_.load()) {
        HANDLE pipe = CreateNamedPipeW(pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            4, 64*1024, 64*1024, 0, &sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(250);
            continue;
        }
        BOOL ok = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!ok) { CloseHandle(pipe); continue; }
        HandleClient(pipe);
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        if (stopEvent_ && WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0) break;
    }
    if (psd) LocalFree(psd);
}

static bool ReadAll(HANDLE h, std::string& out) {
    char buf[4096]; DWORD rd=0; out.clear();
    for (;;) {
        if (!ReadFile(h, buf, sizeof(buf), &rd, nullptr) || rd==0) break;
        out.append(buf, buf+rd);
        if (rd < sizeof(buf)) break;
    }
    return !out.empty();
}

void ControlServer::HandleClient(HANDLE pipe) {
    std::string req;
    ReadAll(pipe, req);
    auto audit = [&](const char* op){
        wchar_t dir[MAX_PATH] = {}; DWORD n = GetEnvironmentVariableW(L"ProgramData", dir, MAX_PATH);
        std::wstring base = (n&&n<MAX_PATH)?std::wstring(dir,dir+n):L"C:\\ProgramData";
        std::wstring path = base + L"\\UserModeHook\\audit.log";
        HANDLE f = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f!=INVALID_HANDLE_VALUE){
            SYSTEMTIME st; GetLocalTime(&st);
            char line[256]; int len = _snprintf_s(line, _TRUNCATE, "%04d-%02d-%02d %02d:%02d:%02d op=%s\r\n", st.wYear,st.wMonth,st.wDay, st.wHour,st.wMinute,st.wSecond, op);
            DWORD wr=0; WriteFile(f, line, (DWORD)strlen(line), &wr, nullptr); CloseHandle(f);
        }
    };
    auto findOp = [&](const char* key) -> bool { return req.find(std::string("\"op\":\"") + key + "\"") != std::string::npos; };

    auto findInt = [&](const char* key, DWORD& value) -> bool {
        size_t pos = req.find(std::string("\"") + key + "\"");
        if (pos == std::string::npos) return false;
        pos = req.find(':', pos); if (pos == std::string::npos) return false;
        while (pos < req.size() && (req[pos]==':' || req[pos]==' ')) ++pos;
        size_t end = pos; while (end < req.size() && isdigit((unsigned char)req[end])) ++end;
        if (end == pos) return false;
        value = (DWORD)std::stoul(req.substr(pos, end-pos));
        return true;
    };

    std::ostringstream json;
    json << "{";

    if (findOp("listProcesses")) {
        audit("listProcesses");
        DWORD pids[4096]; DWORD bytes=0; if (!EnumProcesses(pids, sizeof(pids), &bytes)) { json << "\"ok\":false,\"error\":\"EnumProcesses failed\"}"; goto send; }
        DWORD count = bytes/sizeof(DWORD);
        json << "\"ok\":true,\"data\":[";
        bool first = true;
        for (DWORD i=0;i<count;i++) {
            DWORD pid = pids[i]; if (pid<=4) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) continue;
            wchar_t path[MAX_PATH]={}; DWORD sz=MAX_PATH;
            std::wstring wpath;
            if (QueryFullProcessImageNameW(h, 0, path, &sz)) wpath.assign(path, path+sz);
            CloseHandle(h);
            wchar_t pipeName[128] = {}; pipes::FormatTelemetryPipe(pipeName, _countof(pipeName), pid);
            BOOL hasUmh = WaitNamedPipeW(pipeName, 20) ? TRUE : FALSE;
            if (!first) json << ","; first=false;
            std::wstring base = BaseName(wpath);
            std::wstring wjson = L"{\"pid\":" + std::to_wstring(pid) + L",\"exe\":\"" + JsonEscapeW(base) + L"\",\"umh\":" + (hasUmh?L"true":L"false") + L"}";
            int bytesW = WideCharToMultiByte(CP_UTF8, 0, wjson.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string u(bytesW-1, '\0'); WideCharToMultiByte(CP_UTF8, 0, wjson.c_str(), -1, u.data(), bytesW, nullptr, nullptr);
            json << u;
        }
        json << "]}";
        goto send;
    }

    if (findOp("inject")) {
        audit("inject");
        DWORD pid=0; if (!findInt("pid", pid)) { json << "\"ok\":false,\"error\":\"missing pid\"}"; goto send; }
        if (!engine_) { json << "\"ok\":false,\"error\":\"engine unavailable\"}"; goto send; }
        injection::InjectionOptions opt; opt.methodOrder = { injection::InjectionMethod::SectionMap, injection::InjectionMethod::Standard };
        auto res = engine_->Inject(pid, hookDllPath_, opt);
        std::wstring wmsg = res.detail;
        int bytesW = WideCharToMultiByte(CP_UTF8, 0, wmsg.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string msg(bytesW?bytesW-1:0, '\0'); if (bytesW) WideCharToMultiByte(CP_UTF8, 0, wmsg.c_str(), -1, msg.data(), bytesW, nullptr, nullptr);
        json << "\"ok\":" << (res.success?"true":"false") << ",\"data\":{\"method\":\"" << (res.success?"section-map":"fallback") << "\",\"detail\":\"" << msg << "\"}}";
        goto send;
    }

    if (findOp("telemetry")) {
        audit("telemetry");
        DWORD pid=0; if (!findInt("pid", pid)) { json << "\"ok\":false,\"error\":\"missing pid\"}"; goto send; }
        wchar_t name[128] = {}; pipes::FormatTelemetryPipe(name, _countof(name), pid);
        HANDLE h = CreateFileW(name, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { json << "\"ok\":false,\"error\":\"telemetry pipe unavailable\"}"; goto send; }
        const char* reqGet = "GET\n"; DWORD wr=0; WriteFile(h, reqGet, 4, &wr, nullptr);
        std::string buf; buf.resize(256*1024);
        DWORD rd=0; if (ReadFile(h, buf.data(), (DWORD)buf.size()-1, &rd, nullptr)) buf[rd] = '\0';
        CloseHandle(h);
        json << "\"ok\":true,\"data\":" << (rd?buf:"{}") << "}";
        goto send;
    }

    if (findOp("repair")) {
        audit("repair");
        DWORD pid=0; if (!findInt("pid", pid)) { json << "\"ok\":false,\"error\":\"missing pid\"}"; goto send; }
        wchar_t name[128] = {}; pipes::FormatTelemetryPipe(name, _countof(name), pid);
        HANDLE h = CreateFileW(name, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { json << "\"ok\":false,\"error\":\"telemetry pipe unavailable\"}"; goto send; }
        const char* cmd = "{\"op\":\"repair\"}\n"; DWORD wr=0; WriteFile(h, cmd, (DWORD)strlen(cmd), &wr, nullptr);
        CloseHandle(h);
        json << "\"ok\":true}";
        goto send;
    }

    if (findOp("setFlags")) {
        audit("setFlags");
        // Forward flags to any single UMH process (optional: iterate all)
        DWORD pid=0; findInt("pid", pid); // optional
        if (pid==0) {
            // find any UMH process
            DWORD pids[4096]; DWORD bytes=0; EnumProcesses(pids, sizeof(pids), &bytes); DWORD count=bytes/sizeof(DWORD);
            for (DWORD i=0;i<count;i++) {
                wchar_t pn[128] = {}; pipes::FormatTelemetryPipe(pn, _countof(pn), pids[i]);
                if (WaitNamedPipeW(pn, 5)) { pid = pids[i]; break; }
            }
        }
        if (pid==0) { json << "\"ok\":false,\"error\":\"no umh process found\"}"; goto send; }
        wchar_t name[128] = {}; pipes::FormatTelemetryPipe(name, _countof(name), pid);
        HANDLE h = CreateFileW(name, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { json << "\"ok\":false,\"error\":\"telemetry pipe unavailable\"}"; goto send; }
        // Extract flags object substring and forward
        size_t fp = req.find("\"flags\"");
        std::string minimal = "{\"op\":\"setFlags\",\"flags\":{}}\n";
        if (fp != std::string::npos) {
            size_t b1 = req.find('{', fp); size_t b2 = req.find('}', b1);
            if (b1!=std::string::npos && b2!=std::string::npos && b2>b1) {
                std::string flagsObj = req.substr(b1, b2-b1+1);
                minimal = std::string("{\"op\":\"setFlags\",\"flags\":") + flagsObj + "}\n";
            }
        }
        DWORD wr=0; WriteFile(h, minimal.data(), (DWORD)minimal.size(), &wr, nullptr);
        CloseHandle(h);
        json << "\"ok\":true}";
        goto send;
    }

    if (findOp("disable")) {
        audit("disable");
        DWORD pid=0; if (!findInt("pid", pid)) { json << "\"ok\":false,\"error\":\"missing pid\"}"; goto send; }
        wchar_t name[128] = {}; pipes::FormatTelemetryPipe(name, _countof(name), pid);
        HANDLE h = CreateFileW(name, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { json << "\"ok\":false,\"error\":\"telemetry pipe unavailable\"}"; goto send; }
        const char* cmd = "{\"op\":\"disable\"}\n"; DWORD wr=0; WriteFile(h, cmd, (DWORD)strlen(cmd), &wr, nullptr);
        CloseHandle(h);
        json << "\"ok\":true}";
        goto send;
    }

    if (findOp("getConfig")) {
        wchar_t buf[MAX_PATH] = {}; DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
        std::wstring base = (n && n<MAX_PATH) ? std::wstring(buf, buf+n) : L"C:\\ProgramData";
        std::wstring dir = base + L"\\UserModeHook"; std::wstring path = dir + L"\\config.json";
        HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) { json << "\"ok\":false,\"error\":\"config not found\"}"; goto send; }
        std::string data; data.resize(128*1024); DWORD rd=0; ReadFile(f, data.data(), (DWORD)data.size()-1, &rd, nullptr); CloseHandle(f); data[rd]='\0';
        json << "\"ok\":true,\"data\":\"";
        for (DWORD i=0;i<rd;i++){ char c=data[i]; if(c=='\\' || c=='\"') json<<'\\'; if(c=='\n') { json<<"\\n"; continue; } json<<c; }
        json << "\"}"; goto send;
    }

    if (findOp("setConfig")) {
        size_t p = req.find("\"content\"");
        if (p == std::string::npos) { json << "\"ok\":false,\"error\":\"missing content\"}"; goto send; }
        p = req.find(':', p);
        if (p == std::string::npos) { json << "\"ok\":false,\"error\":\"missing content\"}"; goto send; }
        p = req.find('"', p); size_t q = req.find('"', p+1); if (q==std::string::npos) { json << "\"ok\":false,\"error\":\"bad content\"}"; goto send; }
        std::string content = req.substr(p+1, q-(p+1));
        // unescape basic sequences
        std::string out; out.reserve(content.size());
        for (size_t i=0;i<content.size();++i){ char c=content[i]; if(c=='\\' && i+1<content.size()){ char n=content[++i]; if(n=='n'){ out+='\n'; } else { out+=n; } } else out+=c; }
        wchar_t buf[MAX_PATH] = {}; DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
        std::wstring base = (n && n<MAX_PATH) ? std::wstring(buf, buf+n) : L"C:\\ProgramData";
        std::wstring dir = base + L"\\UserModeHook"; CreateDirectoryW(dir.c_str(), nullptr);
        std::wstring path = dir + L"\\config.json";
        HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) { json << "\"ok\":false,\"error\":\"cannot write config\"}"; goto send; }
        DWORD wr=0; WriteFile(f, out.data(), (DWORD)out.size(), &wr, nullptr); CloseHandle(f);
        json << "\"ok\":true}"; goto send;
    }

    if (findOp("getPolicy")) {
        audit("getPolicy");
        UmhPolicy pol = policy::LoadPolicy();
        std::string js = policy::ExportPolicyJson(pol);
        json << "\"ok\":true,\"data\":" << js << "}"; goto send;
    }

    if (findOp("setPolicy")) {
        audit("setPolicy");
        // Expect full JSON in request; just persist the substring from first '{' after key
        size_t p = req.find("\"setPolicy\""); p = req.find('{', p); if (p==std::string::npos) { json << "\"ok\":false,\"error\":\"bad policy\"}"; goto send; }
        size_t e = req.find_last_of('}'); if (e==std::string::npos || e<p) { json << "\"ok\":false,\"error\":\"bad policy\"}"; goto send; }
        std::string polJson = req.substr(p, e-p+1);
        int w = MultiByteToWideChar(CP_UTF8,0,polJson.c_str(),(int)polJson.size(),nullptr,0);
        std::wstring wjson(w,L'\0'); MultiByteToWideChar(CP_UTF8,0,polJson.c_str(),(int)polJson.size(),wjson.data(),w);
        bool ok = policy::SavePolicy(wjson);
        json << "\"ok\":" << (ok?"true":"false") << "}"; goto send;
    }

    if (findOp("injectAll")) {
        audit("injectAll");
        DWORD pids[4096]; DWORD bytes=0; EnumProcesses(pids, sizeof(pids), &bytes); DWORD count=bytes/sizeof(DWORD);
        int success=0; if (engine_) {
            for (DWORD i=0;i<count;i++){ DWORD pid=pids[i]; if (pid<=4) continue; injection::InjectionOptions o; o.methodOrder={ injection::InjectionMethod::SectionMap, injection::InjectionMethod::Standard}; auto r=engine_->Inject(pid, hookDllPath_, o); if(r.success) success++; }
        }
        json << "\"ok\":true,\"data\":{\"success\":" << success << "}}"; goto send;
    }

    if (findOp("disableAll")) {
        audit("disableAll");
        DWORD pids[4096]; DWORD bytes=0; EnumProcesses(pids, sizeof(pids), &bytes); DWORD count=bytes/sizeof(DWORD); int success=0;
        for (DWORD i=0;i<count;i++){ wchar_t nm[128]={}; pipes::FormatTelemetryPipe(nm,_countof(nm), pids[i]); if(WaitNamedPipeW(nm,5)){ HANDLE h=CreateFileW(nm,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr); if(h!=INVALID_HANDLE_VALUE){ const char* cmd="{\"op\":\"disable\"}\n"; DWORD wr=0; WriteFile(h,cmd,(DWORD)strlen(cmd),&wr,nullptr); CloseHandle(h); success++; } }}
        json << "\"ok\":true,\"data\":{\"disabled\":" << success << "}}"; goto send;
    }

    json << "\"ok\":false,\"error\":\"unknown op\"}";

send:
    auto s = json.str(); DWORD wr=0; WriteFile(pipe, s.data(), (DWORD)s.size(), &wr, nullptr);
}


