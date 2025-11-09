#pragma once
#include <string>

inline std::wstring EscapeJsonW(const std::wstring& s) {
    std::wstring o; o.reserve(s.size() + 8);
    for (wchar_t c : s) {
        switch (c) {
        case L'\\': o += L"\\\\"; break;
        case L'\"': o += L"\\\""; break;
        case L'\n': o += L"\\n"; break;
        case L'\r': o += L"\\r"; break;
        case L'\t': o += L"\\t"; break;
        default: o += c; break;
        }
    }
    return o;
}

