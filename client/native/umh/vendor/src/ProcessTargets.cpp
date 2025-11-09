#include "../include/ProcessTargets.h"

#include <Windows.h>
#include <Shlwapi.h>

#include <algorithm>
#include <cwctype>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")

namespace {

std::wstring Trim(const std::wstring& value) {
    size_t start = 0;
    while (start < value.size() && iswspace(value[start])) {
        ++start;
    }
    size_t end = value.size();
    while (end > start && iswspace(value[end - 1])) {
        --end;
    }
    return value.substr(start, end - start);
}

std::wstring NormalizeProcessName(const std::wstring& value) {
    std::wstring trimmed = Trim(value);
    if (trimmed.empty()) {
        return trimmed;
    }
    if (trimmed.size() >= 2 && trimmed.front() == L'"' && trimmed.back() == L'"') {
        trimmed = trimmed.substr(1, trimmed.size() - 2);
    }
    size_t slash = trimmed.find_last_of(L"\\/");
    std::wstring leaf = (slash == std::wstring::npos) ? trimmed : trimmed.substr(slash + 1);
    for (auto& ch : leaf) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    return Trim(leaf);
}

std::wstring ProgramDataDir() {
    wchar_t buf[MAX_PATH] = {};
    DWORD len = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    if (len && len < MAX_PATH) {
        return std::wstring(buf, buf + len);
    }
    return L"C:\\ProgramData";
}

std::wstring ModuleDir() {
    wchar_t path[MAX_PATH] = {};
    HMODULE mod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&ModuleDir),
                           &mod)) {
        if (GetModuleFileNameW(mod, path, MAX_PATH)) {
            PathRemoveFileSpecW(path);
            return path;
        }
    }
    return std::wstring();
}

std::wstring ReadEnvValue(const wchar_t* name) {
    wchar_t buf[4096] = {};
    DWORD len = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(_countof(buf)));
    if (!len || len >= _countof(buf)) {
        return std::wstring();
    }
    return std::wstring(buf, buf + len);
}

std::wstring ReadTextFile(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.good()) {
        return std::wstring();
    }
    std::string buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (buffer.empty()) {
        return std::wstring();
    }
    if (buffer.size() >= 2 && static_cast<unsigned char>(buffer[0]) == 0xFF &&
        static_cast<unsigned char>(buffer[1]) == 0xFE) {
        const wchar_t* wide = reinterpret_cast<const wchar_t*>(buffer.data());
        size_t chars = buffer.size() / sizeof(wchar_t);
        if (chars >= 1 && wide[0] == 0xFEFF) {
            return std::wstring(wide + 1, wide + chars);
        }
        return std::wstring(wide, wide + chars);
    }
    int required = MultiByteToWideChar(CP_UTF8, 0, buffer.c_str(), static_cast<int>(buffer.size()), nullptr, 0);
    if (required <= 0) {
        return std::wstring();
    }
    std::wstring out(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, buffer.c_str(), static_cast<int>(buffer.size()), out.data(), required);
    return out;
}

std::wstring ResolveTargetsPath() {
    std::wstring envPath = ReadEnvValue(L"UMH_TARGETS_PATH");
    if (!envPath.empty() && PathFileExistsW(envPath.c_str())) {
        return envPath;
    }
    std::wstring programDataPath = ProgramDataDir() + L"\\UserModeHook\\targets.txt";
    if (PathFileExistsW(programDataPath.c_str())) {
        return programDataPath;
    }
    std::wstring modulePath = ModuleDir();
    if (!modulePath.empty()) {
        std::wstring localPath = modulePath + L"\\configs\\targets.txt";
        if (PathFileExistsW(localPath.c_str())) {
            return localPath;
        }
    }
    return std::wstring();
}

std::vector<std::wstring> ParseTargets(const std::wstring& text) {
    std::vector<std::wstring> result;
    if (text.empty()) {
        return result;
    }
    std::wstring token;
    bool comment = false;
    auto flush = [&]() {
        if (token.empty()) {
            return;
        }
        std::wstring normalized = NormalizeProcessName(token);
        token.clear();
        if (normalized.empty()) {
            return;
        }
        result.push_back(normalized);
    };

    for (size_t i = 0; i < text.size(); ++i) {
        wchar_t ch = text[i];
        if (ch == L'\r') {
            continue;
        }
        if (comment) {
            if (ch == L'\n') {
                comment = false;
                flush();
            }
            continue;
        }
        if (ch == L'#') {
            comment = true;
            continue;
        }
        if (ch == L',' || ch == L';' || ch == L'\n') {
            flush();
            continue;
        }
        token.push_back(ch);
    }
    flush();

    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

std::vector<std::wstring> LoadTargets() {
    std::wstring envList = ReadEnvValue(L"UMH_TARGETS");
    if (!envList.empty()) {
        return ParseTargets(envList);
    }
    std::wstring path = ResolveTargetsPath();
    if (!path.empty()) {
        std::wstring text = ReadTextFile(path);
        if (!text.empty()) {
            return ParseTargets(text);
        }
    }
    return std::vector<std::wstring>();
}

std::once_flag g_once;
std::vector<std::wstring> g_targets;

}  // namespace

namespace umh {

const std::vector<std::wstring>& GetProcessTargets() {
    std::call_once(g_once, []() { g_targets = LoadTargets(); });
    return g_targets;
}

bool HasProcessTargetFilter() {
    return !GetProcessTargets().empty();
}

bool IsTargetProcess(const std::wstring& processPathOrName) {
    const auto& targets = GetProcessTargets();
    if (targets.empty()) {
        return true;
    }
    std::wstring normalized = NormalizeProcessName(processPathOrName);
    if (normalized.empty()) {
        return false;
    }
    return std::find(targets.begin(), targets.end(), normalized) != targets.end();
}

bool IsTargetProcessUtf8(const std::string& processPathOrName) {
    if (!HasProcessTargetFilter()) {
        return true;
    }
    if (processPathOrName.empty()) {
        return false;
    }
    int required = MultiByteToWideChar(CP_UTF8, 0, processPathOrName.c_str(), -1, nullptr, 0);
    if (required <= 1) {
        return false;
    }
    std::wstring wide(static_cast<size_t>(required - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, processPathOrName.c_str(), -1, wide.data(), required);
    return IsTargetProcess(wide);
}

}  // namespace umh
