#include <Windows.h>
#include <CommCtrl.h>
#include <string>
#include <vector>
#include <sstream>
#pragma comment(lib, "Comctl32.lib")

struct ProcItem { DWORD pid; std::wstring exe; bool umh; };

// Helpers
static int Utf8ToWide(const std::string& s, std::wstring& out) {
    int req = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (req <= 0) { out.clear(); return 0; }
    out.assign(req, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), req);
    return req;
}

static std::string RequestJson(const std::string& json) {
    HANDLE h = CreateFileW(L"\\\\.\\pipe\\umh_control", GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    DWORD wr=0; WriteFile(h, json.data(), (DWORD)json.size(), &wr, nullptr);
    std::string buf; buf.resize(512*1024); DWORD rd=0; ReadFile(h, buf.data(), (DWORD)buf.size()-1, &rd, nullptr); CloseHandle(h);
    buf[rd] = '\0'; return buf;
}

static std::vector<ProcItem> ParseProcessList(const std::string& json) {
    std::vector<ProcItem> out; size_t pos = json.find("\"data\":["); if (pos==std::string::npos) return out; pos += 8;
    while (true) {
        size_t p = json.find("{\"pid\":", pos); if (p==std::string::npos) break; p += 8;
        size_t end = json.find('}', p); if (end==std::string::npos) break; std::string obj = json.substr(p-8, end-(p-8)+1);
        ProcItem it{}; it.pid = 0; it.umh=false; it.exe=L"";
        size_t pp = obj.find("\"pid\":"); if (pp!=std::string::npos) it.pid = (DWORD)std::stoul(obj.substr(pp+7));
        pp = obj.find("\"exe\":\""); if (pp!=std::string::npos){ pp+=8; size_t q=obj.find('"', pp); std::string ex=obj.substr(pp, q-pp); it.exe = std::wstring(ex.begin(), ex.end()); }
        pp = obj.find("\"umh\":"); if (pp!=std::string::npos) it.umh = obj.substr(pp+7,4) == "true";
        out.push_back(it); pos = end+1;
    }
    return out;
}

static HWND g_list; static HWND g_hooks; static HWND g_btnRefresh, g_btnInject, g_btnTelemetry, g_btnRepair, g_btnDisable, g_btnGetCfg, g_btnSetCfg, g_editCfg, g_btnInjectAll, g_btnDisableAll, g_btnHooks, g_btnGetPolicy, g_btnSetPolicy, g_btnToggleSigned, g_btnApplyFlagsPid, g_btnApplyFlagsAll;

static void InitHooksListColumns(HWND lv) {
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    LVCOLUMNW c{}; c.mask=LVCF_TEXT|LVCF_WIDTH;
    c.pszText=L"Function"; c.cx=160; ListView_InsertColumn(lv,0,&c);
    c.pszText=L"Layer"; c.cx=90; ListView_InsertColumn(lv,1,&c);
    c.pszText=L"Installed"; c.cx=80; ListView_InsertColumn(lv,2,&c);
    c.pszText=L"Verified"; c.cx=80; ListView_InsertColumn(lv,3,&c);
    c.pszText=L"Failures"; c.cx=70; ListView_InsertColumn(lv,4,&c);
    c.pszText=L"VEH Hits"; c.cx=80; ListView_InsertColumn(lv,5,&c);
    c.pszText=L"VEH Rearm"; c.cx=90; ListView_InsertColumn(lv,6,&c);
    c.pszText=L"VEH Disabled"; c.cx=100; ListView_InsertColumn(lv,7,&c);
}

static void PopulateHooksFromTelemetry(HWND lv, const std::string& js) {
    ListView_DeleteAllItems(lv);
    size_t pos = 0;
    while (true) {
        size_t fpos = js.find("\"function\":\"", pos);
        if (fpos == std::string::npos) break;
        fpos += 12; size_t fend = js.find('"', fpos); if (fend==std::string::npos) break;
        std::string fn = js.substr(fpos, fend - fpos);
        // VEH block for this function context
        size_t veh = js.find("\"veh\":{", fend);
        int vehHits=0, vehRearm=0; bool vehDisabled=false;
        if (veh != std::string::npos) {
            size_t h = js.find("\"hits\":", veh); if (h!=std::string::npos) vehHits = atoi(js.c_str()+h+7);
            size_t r = js.find("\"rearm\":", veh); if (r!=std::string::npos) vehRearm = atoi(js.c_str()+r+9);
            size_t d = js.find("\"disabled\":", veh); if (d!=std::string::npos) vehDisabled = js.find("true", d) < js.find("}", d);
        }
        // Layers array
        size_t layers = js.find("\"layers\":[", fend);
        if (layers == std::string::npos) { pos = fend+1; continue; }
        size_t cursor = layers + 10;
        while (true) {
            size_t npos = js.find("\"name\":\"", cursor);
            if (npos == std::string::npos) break;
            npos += 9; size_t nend = js.find('"', npos); if (nend==std::string::npos) break;
            std::string lname = js.substr(npos, nend - npos);
            bool installed=false, verified=false; int failures=0;
            size_t inst = js.find("\"installed\":", nend); if (inst!=std::string::npos) installed = js.find("true", inst) < js.find("}", inst);
            size_t verf = js.find("\"verified\":", nend); if (verf!=std::string::npos) verified = js.find("true", verf) < js.find("}", verf);
            size_t fail = js.find("\"failures\":", nend); if (fail!=std::string::npos) failures = atoi(js.c_str()+fail+12);

            // Insert row
            LVITEMW it{}; it.mask = LVIF_TEXT; int row = ListView_GetItemCount(lv);
            std::wstring wfn; Utf8ToWide(fn, wfn); it.iItem = row; it.pszText = const_cast<LPWSTR>(wfn.c_str());
            ListView_InsertItem(lv, &it);
            std::wstring wl; Utf8ToWide(lname, wl);
            ListView_SetItemText(lv, row, 1, const_cast<LPWSTR>(wl.c_str()));
            ListView_SetItemText(lv, row, 2, const_cast<LPWSTR>((installed?L"Yes":L"No")));
            ListView_SetItemText(lv, row, 3, const_cast<LPWSTR>((verified?L"Yes":L"No")));
            wchar_t buf[32]; _snwprintf_s(buf,_TRUNCATE,L"%d", failures); ListView_SetItemText(lv, row, 4, buf);
            _snwprintf_s(buf,_TRUNCATE,L"%d", vehHits); ListView_SetItemText(lv, row, 5, buf);
            _snwprintf_s(buf,_TRUNCATE,L"%d", vehRearm); ListView_SetItemText(lv, row, 6, buf);
            ListView_SetItemText(lv, row, 7, const_cast<LPWSTR>((vehDisabled?L"Yes":L"No")));

            // advance to next layer object end
            size_t endObj = js.find("}", nend);
            if (endObj == std::string::npos) break;
            cursor = endObj + 1;
            if (cursor > js.size()) break;
            // stop if next token is ]
            if (js.find("]", endObj) < js.find("\"name\":\"", endObj)) break;
        }
        pos = fend + 1;
    }
}

static void RefreshList() {
    ListView_DeleteAllItems(g_list);
    auto resp = RequestJson("{\"op\":\"listProcesses\"}");
    auto items = ParseProcessList(resp);
    int idx=0;
    for (auto& e : items) {
        wchar_t pidbuf[32]; _itow_s(e.pid, pidbuf, 10);
        LVITEMW it{}; it.mask = LVIF_TEXT; it.iItem = idx; it.pszText = pidbuf; ListView_InsertItem(g_list, &it);
        ListView_SetItemText(g_list, idx, 1, const_cast<LPWSTR>(e.exe.c_str()));
        wchar_t st[8]; wcscpy_s(st, e.umh?L"yes":L"no"); ListView_SetItemText(g_list, idx, 2, st);
        idx++;
    }
}

static DWORD GetSelectedPid() {
    int sel = ListView_GetNextItem(g_list, -1, LVNI_SELECTED); if (sel<0) return 0;
    wchar_t buf[32]; ListView_GetItemText(g_list, sel, 0, buf, 32); return (DWORD)_wtoi(buf);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES }; InitCommonControlsEx(&icc);
        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD|WS_VISIBLE|LVS_REPORT, 10,10,560,240, h, (HMENU)101, nullptr, nullptr);
        ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT);
        LVCOLUMNW col{}; col.mask=LVCF_TEXT|LVCF_WIDTH; col.pszText=L"PID"; col.cx=80; ListView_InsertColumn(g_list,0,&col);
        col.pszText=L"Process"; col.cx=320; ListView_InsertColumn(g_list,1,&col);
        col.pszText=L"UMH"; col.cx=80; ListView_InsertColumn(g_list,2,&col);
        // Hooks list
        g_hooks = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_CHILD|WS_VISIBLE|LVS_REPORT, 10,260,560,140, h, (HMENU)200, nullptr, nullptr);
        InitHooksListColumns(g_hooks);
        g_btnRefresh = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD|WS_VISIBLE, 580,10,120,28,h,(HMENU)1,nullptr,nullptr);
        g_btnInject  = CreateWindowW(L"BUTTON", L"Inject",  WS_CHILD|WS_VISIBLE, 580,48,120,28,h,(HMENU)2,nullptr,nullptr);
        g_btnTelemetry=CreateWindowW(L"BUTTON", L"Telemetry",WS_CHILD|WS_VISIBLE, 580,86,120,28,h,(HMENU)3,nullptr,nullptr);
        g_btnRepair  = CreateWindowW(L"BUTTON", L"Repair",   WS_CHILD|WS_VISIBLE, 580,124,120,28,h,(HMENU)4,nullptr,nullptr);
        g_btnDisable = CreateWindowW(L"BUTTON", L"Disable",  WS_CHILD|WS_VISIBLE, 580,162,120,28,h,(HMENU)5,nullptr,nullptr);
        g_btnGetCfg  = CreateWindowW(L"BUTTON", L"Get Config",WS_CHILD|WS_VISIBLE, 580,200,120,28,h,(HMENU)6,nullptr,nullptr);
        g_btnSetCfg  = CreateWindowW(L"BUTTON", L"Set Config",WS_CHILD|WS_VISIBLE, 580,238,120,28,h,(HMENU)7,nullptr,nullptr);
        g_btnInjectAll = CreateWindowW(L"BUTTON", L"Inject All",WS_CHILD|WS_VISIBLE, 580,276,120,28,h,(HMENU)8,nullptr,nullptr);
        g_btnDisableAll= CreateWindowW(L"BUTTON", L"Disable All",WS_CHILD|WS_VISIBLE, 580,314,120,28,h,(HMENU)9,nullptr,nullptr);
        g_btnHooks    = CreateWindowW(L"BUTTON", L"Hooks",WS_CHILD|WS_VISIBLE, 580,352,120,28,h,(HMENU)10,nullptr,nullptr);
        g_btnGetPolicy= CreateWindowW(L"BUTTON", L"Get Policy",WS_CHILD|WS_VISIBLE, 580,390,120,28,h,(HMENU)11,nullptr,nullptr);
        g_btnSetPolicy= CreateWindowW(L"BUTTON", L"Set Policy",WS_CHILD|WS_VISIBLE, 580,428,120,28,h,(HMENU)12,nullptr,nullptr);
        g_btnToggleSigned = CreateWindowW(L"BUTTON", L"Toggle Signed",WS_CHILD|WS_VISIBLE, 580,466,120,28,h,(HMENU)13,nullptr,nullptr);
        g_btnApplyFlagsPid = CreateWindowW(L"BUTTON", L"Apply Flags (PID)",WS_CHILD|WS_VISIBLE, 580,504,120,28,h,(HMENU)14,nullptr,nullptr);
        g_btnApplyFlagsAll = CreateWindowW(L"BUTTON", L"Apply Flags (All)",WS_CHILD|WS_VISIBLE, 580,542,120,28,h,(HMENU)15,nullptr,nullptr);
        g_editCfg    = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|WS_VSCROLL,
                                       10,380,560,190, h, (HMENU)100, nullptr, nullptr);
        RefreshList();
        break; }
    case WM_COMMAND:
        if (LOWORD(w)==1) RefreshList();
        if (LOWORD(w)==2) { DWORD pid = GetSelectedPid(); if (pid){ std::ostringstream oss; oss<<"{\"op\":\"inject\",\"pid\":"<<pid<<"}"; RequestJson(oss.str()); RefreshList(); }}
        if (LOWORD(w)==3) { DWORD pid = GetSelectedPid(); if (pid){ std::ostringstream oss; oss<<"{\"op\":\"telemetry\",\"pid\":"<<pid<<"}"; auto js=RequestJson(oss.str()); MessageBoxA(h, js.c_str(), "Telemetry", MB_OK); }}
        if (LOWORD(w)==4) { DWORD pid = GetSelectedPid(); if (pid){ std::ostringstream oss; oss<<"{\"op\":\"repair\",\"pid\":"<<pid<<"}"; RequestJson(oss.str()); }}
        if (LOWORD(w)==5) { DWORD pid = GetSelectedPid(); if (pid){ std::ostringstream oss; oss<<"{\"op\":\"disable\",\"pid\":"<<pid<<"}"; RequestJson(oss.str()); RefreshList(); }}
        if (LOWORD(w)==6) { auto js = RequestJson("{\"op\":\"getConfig\"}"); MessageBoxA(h, js.c_str(), "Config", MB_OK); }
        if (LOWORD(w)==7) {
            int len = GetWindowTextLengthW(g_editCfg); std::wstring w; w.resize(len);
            GetWindowTextW(g_editCfg, w.data(), len+1);
            int req = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string utf8(req?req-1:0,'\0');
            if (req) WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,utf8.data(),req,nullptr,nullptr);
            std::string body = "{\"op\":\"setConfig\",\"content\":\""; for(char c: utf8){ if(c=='\\' || c=='\"') body.push_back('\\'); if(c=='\n'){ body += "\\n"; } else body.push_back(c);} body += "\"}";
            auto js = RequestJson(body); MessageBoxA(h, js.c_str(), "Set Config", MB_OK);
        }
        if (LOWORD(w)==8) { auto js = RequestJson("{\"op\":\"injectAll\"}"); MessageBoxA(h, js.c_str(), "Inject All", MB_OK); RefreshList(); }
        if (LOWORD(w)==9) { auto js = RequestJson("{\"op\":\"disableAll\"}"); MessageBoxA(h, js.c_str(), "Disable All", MB_OK); RefreshList(); }
        if (LOWORD(w)==10) { DWORD pid = GetSelectedPid(); if (pid){ std::ostringstream oss; oss<<"{\"op\":\"telemetry\",\"pid\":"<<pid<<"}"; auto js=RequestJson(oss.str()); PopulateHooksFromTelemetry(g_hooks, js); }}
        if (LOWORD(w)==11) { auto js = RequestJson("{\"op\":\"getPolicy\"}"); MessageBoxA(h, js.c_str(), "Policy", MB_OK); }
        if (LOWORD(w)==12) { int len = GetWindowTextLengthW(g_editCfg); std::wstring w; w.resize(len); GetWindowTextW(g_editCfg, w.data(), len+1); int req = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string utf8(req?req-1:0,'\0'); if(req) WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,utf8.data(),req,nullptr,nullptr); std::string body = "{\"op\":\"setPolicy\",\"content\":\""; for(char c: utf8){ if(c=='\\' || c=='\"') body.push_back('\\'); if(c=='\n'){ body += "\\n"; } else body.push_back(c);} body += "\"}"; auto js = RequestJson(body); MessageBoxA(h, js.c_str(), "Set Policy", MB_OK); }
        if (LOWORD(w)==13) { auto js = RequestJson("{\"op\":\"getPolicy\"}"); // crude toggle of requireSignedDll in payload
            // Not implementing full parse; show message directing to Set Policy for exact edits
            MessageBoxA(h, "Use Set Policy to toggle requireSignedDll (edit JSON)", "Toggle Signed", MB_OK);
        }
        if (LOWORD(w)==14) { DWORD pid = GetSelectedPid(); if (pid){ int len=GetWindowTextLengthW(g_editCfg); std::wstring w; w.resize(len); GetWindowTextW(g_editCfg,w.data(),len+1); // parse NAME=VALUE per line
                std::string flags="\"flags\":{"; int count=0; size_t i=0; while (i<w.size()){ size_t nl=w.find(L'\n',i); if(nl==std::wstring::npos) nl=w.size(); std::wstring line=w.substr(i,nl-i); i=nl+1; size_t eq=line.find(L'='); if(eq==std::wstring::npos) continue; std::wstring k=line.substr(0,eq); std::wstring v=line.substr(eq+1); int rk=WideCharToMultiByte(CP_UTF8,0,k.c_str(),-1,nullptr,0,nullptr,nullptr); std::string ku(rk?rk-1:0,'\0'); if(rk) WideCharToMultiByte(CP_UTF8,0,k.c_str(),-1,ku.data(),rk,nullptr,nullptr); int rv=WideCharToMultiByte(CP_UTF8,0,v.c_str(),-1,nullptr,0,nullptr,nullptr); std::string vu(rv?rv-1:0,'\0'); if(rv) WideCharToMultiByte(CP_UTF8,0,v.c_str(),-1,vu.data(),rv,nullptr,nullptr); if(count++) flags += ","; flags += "\""+ku+"\":\""+vu+"\""; }
                flags += "}"; std::ostringstream oss; oss<<"{\"op\":\"setFlags\",\"pid\":"<<pid<<","<<flags<<"}"; auto js=RequestJson(oss.str()); MessageBoxA(h, js.c_str(), "Apply Flags (PID)", MB_OK); }}
        if (LOWORD(w)==15) { // Apply flags to all UMH processes
            auto resp = RequestJson("{\"op\":\"listProcesses\"}"); auto items = ParseProcessList(resp); for (auto& e : items) if (e.umh) {
                int len=GetWindowTextLengthW(g_editCfg); std::wstring w; w.resize(len); GetWindowTextW(g_editCfg,w.data(),len+1); std::string flags="\"flags\":{"; int count=0; size_t i=0; while (i<w.size()){ size_t nl=w.find(L'\n',i); if(nl==std::wstring::npos) nl=w.size(); std::wstring line=w.substr(i,nl-i); i=nl+1; size_t eq=line.find(L'='); if(eq==std::wstring::npos) continue; std::wstring k=line.substr(0,eq); std::wstring v=line.substr(eq+1); int rk=WideCharToMultiByte(CP_UTF8,0,k.c_str(),-1,nullptr,0,nullptr,nullptr); std::string ku(rk?rk-1:0,'\0'); if(rk) WideCharToMultiByte(CP_UTF8,0,k.c_str(),-1,ku.data(),rk,nullptr,nullptr); int rv=WideCharToMultiByte(CP_UTF8,0,v.c_str(),-1,nullptr,0,nullptr,nullptr); std::string vu(rv?rv-1:0,'\0'); if(rv) WideCharToMultiByte(CP_UTF8,0,v.c_str(),-1,vu.data(),rv,nullptr,nullptr); if(count++) flags += ","; flags += "\""+ku+"\":\""+vu+"\""; } flags += "}"; std::ostringstream oss; oss<<"{\"op\":\"setFlags\",\"pid\":"<<e.pid<<","<<flags<<"}"; auto js=RequestJson(oss.str()); }
            MessageBoxA(h, "Applied flags to all UMH processes", "Apply Flags (All)", MB_OK);
        }
        break;
    case WM_SIZE: {
        RECT rc; GetClientRect(h,&rc);
        MoveWindow(g_list, 10,10, rc.right-10-140, 240, TRUE);
        MoveWindow(g_hooks, 10,260, rc.right-10-140, 140, TRUE);
        MoveWindow(g_btnRefresh, rc.right-120-10, 10, 120, 28, TRUE);
        MoveWindow(g_btnInject,  rc.right-120-10, 48, 120, 28, TRUE);
        MoveWindow(g_btnTelemetry,rc.right-120-10, 86, 120, 28, TRUE);
        MoveWindow(g_btnRepair,  rc.right-120-10, 124, 120, 28, TRUE);
        MoveWindow(g_btnDisable, rc.right-120-10, 162, 120, 28, TRUE);
        MoveWindow(g_btnGetCfg,  rc.right-120-10, 200, 120, 28, TRUE);
        MoveWindow(g_btnSetCfg,  rc.right-120-10, 238, 120, 28, TRUE);
        MoveWindow(g_btnInjectAll, rc.right-120-10, 276, 120, 28, TRUE);
        MoveWindow(g_btnDisableAll, rc.right-120-10, 314, 120, 28, TRUE);
        MoveWindow(g_btnHooks, rc.right-120-10, 352, 120, 28, TRUE);
        MoveWindow(g_btnGetPolicy, rc.right-120-10, 390, 120, 28, TRUE);
        MoveWindow(g_btnSetPolicy, rc.right-120-10, 428, 120, 28, TRUE);
        MoveWindow(g_btnToggleSigned, rc.right-120-10, 466, 120, 28, TRUE);
        MoveWindow(g_btnApplyFlagsPid, rc.right-120-10, 504, 120, 28, TRUE);
        MoveWindow(g_btnApplyFlagsAll, rc.right-120-10, 542, 120, 28, TRUE);
        MoveWindow(g_editCfg,    10, 380, rc.right-10-140, rc.bottom-10-380, TRUE);
        break; }
    case WM_DESTROY: PostQuitMessage(0); break;
    }
    return DefWindowProc(h,m,w,l);
}

int APIENTRY wWinMain(HINSTANCE hi, HINSTANCE, LPWSTR, int) {
    WNDCLASSW wc{}; wc.lpszClassName=L"UmhManager"; wc.hInstance=hi; wc.lpfnWndProc=WndProc; wc.hCursor=LoadCursor(nullptr,IDC_ARROW); RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(L"UmhManager", L"UserModeHook Manager", WS_OVERLAPPEDWINDOW|WS_VISIBLE, CW_USEDEFAULT,CW_USEDEFAULT,740,380, nullptr,nullptr,hi,nullptr);
    MSG msg; while (GetMessage(&msg,nullptr,0,0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}
