#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <winreg.h>

#include "../include/PipeNames.h"

std::wstring ToWide(const std::string& s) { return std::wstring(s.begin(), s.end()); }

int PrintStatus() {
    const wchar_t* pipe = pipes::kServicePipeName;
    HANDLE h = CreateFileW(pipe, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to connect to service pipe." << std::endl;
        return 1;
    }
    const char* req = "STATUS\n"; DWORD wr=0; WriteFile(h, req, 7, &wr, nullptr);
    std::string buf; buf.resize(128*1024);
    DWORD rd=0; if (ReadFile(h, buf.data(), (DWORD)buf.size()-1, &rd, nullptr)) buf[rd] = '\0';
    CloseHandle(h);
    std::cout << buf << std::endl;
    return 0;
}

int PrintTelemetry(DWORD pid) {
    wchar_t name[128] = {};
    pipes::FormatTelemetryPipe(name, _countof(name), pid);
    HANDLE h = CreateFileW(name, GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[-] Failed to connect to telemetry pipe for PID " << pid << std::endl;
        return 1;
    }
    const char* req = "GET\n"; DWORD wr=0; WriteFile(h, req, 4, &wr, nullptr);
    std::string buf; buf.resize(128*1024);
    DWORD rd=0; if (ReadFile(h, buf.data(), (DWORD)buf.size()-1, &rd, nullptr)) buf[rd] = '\0';
    CloseHandle(h);
    std::cout << buf << std::endl;
    return 0;
}

int RegSetString(HKEY root, const wchar_t* key, const wchar_t* name, const std::wstring& value) {
    HKEY hKey; if (RegCreateKeyExW(root, key, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) return 1;
    int rc = RegSetValueExW(hKey, name, 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)((value.size()+1)*sizeof(wchar_t))) == ERROR_SUCCESS ? 0 : 1;
    RegCloseKey(hKey); return rc;
}

int ServiceControl(const std::string& action) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) { std::cerr << "[-] OpenSCManager failed" << std::endl; return 1; }
    SC_HANDLE svc = OpenServiceW(scm, L"AdvancedHookService", SERVICE_ALL_ACCESS);
    if (!svc) { std::cerr << "[-] OpenService failed" << std::endl; CloseServiceHandle(scm); return 1; }
    int rc = 0;
    if (action == "start") {
        if (!StartServiceW(svc, 0, nullptr)) rc = 1;
    } else if (action == "stop") {
        SERVICE_STATUS st{}; if (!ControlService(svc, SERVICE_CONTROL_STOP, &st)) rc = 1;
    } else if (action == "status") {
        SERVICE_STATUS_PROCESS ssp{}; DWORD bytes=0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes)) {
            std::cout << "state=" << ssp.dwCurrentState << " pid=" << ssp.dwProcessId << std::endl;
        } else rc = 1;
    }
    CloseServiceHandle(svc); CloseServiceHandle(scm); return rc;
}

int main(int argc, char* argv[]) {
    if (argc <= 1) {
        std::cout << "umh.exe usage:\n"
                  << "  status                    - aggregated service status JSON\n"
                  << "  telemetry <pid>           - HookDLL telemetry JSON for PID\n"
                  << "  service start|stop|status - control service\n"
                  << "  service set-dll <path>    - set HookDllPath for service\n"
                  << "  service set-agent <path> [args] - set AgentPath/AgentArgs and restart\n"
                  << "  flags-set name=value [...] - set HKCU\\Software\\UserModeHook\\Flags\n";
        return 0;
    }
    std::string cmd = argv[1];
    if (cmd == "status") return PrintStatus();
    if (cmd == "telemetry" && argc >= 3) return PrintTelemetry(static_cast<DWORD>(std::stoul(argv[2])));
    if (cmd == "service" && argc >= 3) {
        std::string act = argv[2];
        if (act == "start" || act == "stop" || act == "status") return ServiceControl(act);
        if (act == "set-dll" && argc >= 4) return RegSetString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\AdvancedHookService", L"HookDllPath", ToWide(argv[3]));
        if (act == "set-agent" && argc >= 4) {
            int rc = RegSetString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\AdvancedHookService", L"AgentPath", ToWide(argv[3]));
            std::wstring args = L""; for (int i = 4; i < argc; ++i) { if (i>4) args += L" "; args += ToWide(argv[i]); }
            if (!args.empty()) rc |= RegSetString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\AdvancedHookService", L"AgentArgs", args);
            rc |= ServiceControl("stop"); Sleep(2000); rc |= ServiceControl("start");
            return rc;
        }
        std::cerr << "Unknown service action" << std::endl; return 1;
    }
    if (cmd == "flags-set" && argc >= 3) {
        for (int i = 2; i < argc; ++i) {
            std::string kv = argv[i]; size_t eq = kv.find('='); if (eq == std::string::npos) continue;
            std::wstring name = ToWide(kv.substr(0, eq)); std::wstring val = ToWide(kv.substr(eq+1));
            RegSetString(HKEY_CURRENT_USER, L"Software\\UserModeHook\\Flags", name.c_str(), val);
        }
        return 0;
    }
    std::cerr << "Unknown command" << std::endl;
    return 1;
}



