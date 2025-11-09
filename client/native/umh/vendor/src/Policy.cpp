#include "../include/Policy.h"

#include <Shlwapi.h>
#include <sddl.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "Shlwapi.lib")

namespace policy {

static std::wstring ProgramDataDir() {
    wchar_t buf[MAX_PATH] = {}; DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    return (n && n<MAX_PATH) ? std::wstring(buf, buf+n) : L"C:\\ProgramData";
}

static std::wstring PolicyPath() {
    std::wstring dir = ProgramDataDir() + L"\\UserModeHook";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\policy.json";
}

static std::wstring ReadAllW(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return L"";
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (s.size()>=2 && (unsigned char)s[0]==0xFF && (unsigned char)s[1]==0xFE) {
        return std::wstring((wchar_t*)s.data(), s.size()/sizeof(wchar_t));
    }
    int req = MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),nullptr,0);
    std::wstring w(req, L'\0'); MultiByteToWideChar(CP_UTF8,0,s.data(),(int)s.size(),w.data(),req);
    return w;
}

static void SplitPatterns(const std::wstring& csv, std::vector<std::wstring>& out) {
    size_t start=0; while (start < csv.size()) {
        size_t comma = csv.find(L',', start); if (comma==std::wstring::npos) comma = csv.size();
        std::wstring token = csv.substr(start, comma-start); if (!token.empty()) out.push_back(token);
        start = comma+1;
    }
}

UmhPolicy LoadPolicy() {
    UmhPolicy p; // defaults
    std::wstring path = PolicyPath();
    if (!PathFileExistsW(path.c_str())) return p;
    std::wstring text = ReadAllW(path);
    if (text.empty()) return p;
    auto findBool = [&](const wchar_t* key, bool& out) {
        size_t pos = text.find(key); if (pos==std::wstring::npos) return;
        pos = text.find(L":", pos); if (pos==std::wstring::npos) return;
        size_t ns = text.find_first_not_of(L" \t\r\n", pos+1);
        if (ns==std::wstring::npos) return; if (text.compare(ns, 4, L"true") == 0) out=true; else if (text.compare(ns,5,L"false")==0) out=false;
    };
    auto findInt = [&](const wchar_t* key, int& out) {
        size_t pos = text.find(key); if (pos==std::wstring::npos) return;
        pos = text.find(L":", pos); if (pos==std::wstring::npos) return;
        size_t ns = text.find_first_of(L"-0123456789", pos+1); if (ns==std::wstring::npos) return;
        out = _wtoi(text.c_str()+ns);
    };
    auto findArrayStr = [&](const wchar_t* key, std::vector<std::wstring>& out) {
        size_t pos = text.find(key); if (pos==std::wstring::npos) return;
        pos = text.find(L":", pos); if (pos==std::wstring::npos) return;
        size_t b = text.find(L"[", pos); size_t e = text.find(L"]", b); if (b==std::wstring::npos||e==std::wstring::npos||e<=b) return;
        std::wstring body = text.substr(b+1, e-b-1);
        size_t cur=0; while (cur<body.size()) {
            size_t q1 = body.find(L'"', cur); if (q1==std::wstring::npos) break; size_t q2 = body.find(L'"', q1+1); if (q2==std::wstring::npos) break;
            out.push_back(body.substr(q1+1, q2-q1-1)); cur = q2+1;
        }
    };
    findBool(L"requireSignedDll", p.requireSignedDll);
    findInt(L"maxRetries", p.maxRetries);
    findArrayStr(L"includePatterns", p.includePatterns);
    findArrayStr(L"excludePatterns", p.excludePatterns);
    // Watches (optional)
    size_t wpos = text.find(L"\"watches\"");
    if (wpos != std::wstring::npos) {
        size_t b = text.find(L"[", wpos); size_t e = text.find(L"]", b);
        if (b!=std::wstring::npos && e!=std::wstring::npos && e>b) {
            std::wstring body = text.substr(b+1, e-b-1);
            size_t cur=0;
            while (true) {
                size_t ob = body.find(L"{", cur); if (ob==std::wstring::npos) break; size_t oe = body.find(L"}", ob); if (oe==std::wstring::npos) break;
                std::wstring obj = body.substr(ob+1, oe-ob-1);
                UmhPolicy::Watch w;
                size_t pg = obj.find(L"\"providerGuid\""); if (pg!=std::wstring::npos){ size_t q1=obj.find(L'"', pg+15); size_t q2=obj.find(L'"', q1+1); if(q1!=std::wstring::npos&&q2!=std::wstring::npos) w.providerGuid=obj.substr(q1+1,q2-q1-1);}                
                size_t lb = obj.find(L"\"label\""); if (lb!=std::wstring::npos){ size_t q1=obj.find(L'"', lb+7); size_t q2=obj.find(L'"', q1+1); if(q1!=std::wstring::npos&&q2!=std::wstring::npos) w.label=obj.substr(q1+1,q2-q1-1);}                
                size_t ei = obj.find(L"\"eventIds\""); if (ei!=std::wstring::npos){ size_t sb=obj.find(L"[", ei); size_t se=obj.find(L"]", sb); if(sb!=std::wstring::npos&&se!=std::wstring::npos){ std::wstring arr=obj.substr(sb+1,se-sb-1); size_t p0=0; while(p0<arr.size()){ size_t p1=arr.find(L",",p0); if(p1==std::wstring::npos) p1=arr.size(); std::wstring tok=arr.substr(p0,p1-p0); int val=_wtoi(tok.c_str()); if(val>0 && val<=0xFFFF) w.eventIds.push_back((USHORT)val); p0=p1+1; } } }
                size_t ct = obj.find(L"\"contains\""); if (ct!=std::wstring::npos){ size_t q1=obj.find(L'"', ct+10); size_t q2=obj.find(L'"', q1+1); if(q1!=std::wstring::npos&&q2!=std::wstring::npos) w.contains=obj.substr(q1+1,q2-q1-1);}                
                p.watches.push_back(std::move(w));
                cur = oe+1;
            }
        }
    }
    return p;
}

bool SavePolicy(const std::wstring& json) {
    std::wstring path = PolicyPath();
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    // accept UTF-16 or UTF-8 input
    DWORD written=0;
    if (!json.empty() && json[0] == 0xFEFF) {
        WriteFile(f, json.data(), (DWORD)(json.size()*sizeof(wchar_t)), &written, nullptr);
    } else {
        int req = WideCharToMultiByte(CP_UTF8,0,json.c_str(),(int)json.size(),nullptr,0,nullptr,nullptr);
        std::string u(req,'\0'); WideCharToMultiByte(CP_UTF8,0,json.c_str(),(int)json.size(),u.data(),req,nullptr,nullptr);
        WriteFile(f, u.data(), (DWORD)u.size(), &written, nullptr);
    }
    CloseHandle(f); return true;
}

std::string ExportPolicyJson(const UmhPolicy& p) {
    std::ostringstream oss;
    oss << "{\"requireSignedDll\":" << (p.requireSignedDll?"true":"false")
        << ",\"maxRetries\":" << p.maxRetries
        << ",\"includePatterns\":[";
    for (size_t i=0;i<p.includePatterns.size();++i) { if (i) oss << ","; std::wstring w=p.includePatterns[i]; int r=WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string s(r?r-1:0,'\0'); if(r) WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,s.data(),r,nullptr,nullptr); oss<<"\""<<s<<"\""; }
    oss << "],\"excludePatterns\":[";
    for (size_t i=0;i<p.excludePatterns.size();++i) { if (i) oss << ","; std::wstring w=p.excludePatterns[i]; int r=WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr); std::string s(r?r-1:0,'\0'); if(r) WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,s.data(),r,nullptr,nullptr); oss<<"\""<<s<<"\""; }
    oss << "],\"watches\":[";
    for (size_t i=0;i<p.watches.size();++i) {
        if (i) oss << ",";
        auto &w = p.watches[i];
        int r=WideCharToMultiByte(CP_UTF8,0,w.providerGuid.c_str(),-1,nullptr,0,nullptr,nullptr); std::string guid(r?r-1:0,'\0'); if(r) WideCharToMultiByte(CP_UTF8,0,w.providerGuid.c_str(),-1,guid.data(),r,nullptr,nullptr);
        int r2=WideCharToMultiByte(CP_UTF8,0,w.label.c_str(),-1,nullptr,0,nullptr,nullptr); std::string lbl(r2?r2-1:0,'\0'); if(r2) WideCharToMultiByte(CP_UTF8,0,w.label.c_str(),-1,lbl.data(),r2,nullptr,nullptr);
        oss << "{\"providerGuid\":\""<<guid<<"\",\"label\":\""<<lbl<<"\",\"eventIds\":[";
        for (size_t j=0;j<w.eventIds.size();++j) { if (j) oss << ","; oss << (int)w.eventIds[j]; }
        oss << "]";
        if (!w.contains.empty()) { int rc=WideCharToMultiByte(CP_UTF8,0,w.contains.c_str(),-1,nullptr,0,nullptr,nullptr); std::string cs(rc?rc-1:0,'\0'); if(rc) WideCharToMultiByte(CP_UTF8,0,w.contains.c_str(),-1,cs.data(),rc,nullptr,nullptr); oss << ",\"contains\":\""<<cs<<"\""; }
        oss << "}";
    }
    oss << "]}";
    return oss.str();
}

} // namespace policy
