// StrUtil.h - simple UTF-16 (wide) to UTF-8 narrow conversion
#pragma once
#include <string>
#include <Windows.h>

inline std::string Narrow(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), static_cast<int>(ws.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

