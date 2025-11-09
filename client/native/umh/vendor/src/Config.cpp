#include "../include/Config.h"

#include <Shlwapi.h>
#include <string>
#include <vector>
#include <fstream>

#pragma comment(lib, "Shlwapi.lib")

namespace umh {

namespace {

std::wstring ToLower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

bool IsTrueLiteral(const std::wstring& v) {
    auto s = ToLower(v);
    return s == L"1" || s == L"true" || s == L"yes" || s == L"on";
}

// Very small JSON-ish tokenizer for simple config files.
// Supports keys and values: strings (\"..\"), numbers, booleans, null.
// Only extracts flat pairs (section.key -> value) for sections we care about.
struct Token {
    enum Type { LBrace, RBrace, LBracket, RBracket, Colon, Comma, String, Number, True, False, Null, Identifier, End } type;
    std::wstring text;
};

struct Lexer {
    const wchar_t* p;
    explicit Lexer(const std::wstring& s) : p(s.c_str()) {}
    void SkipWs() { while (*p && iswspace(*p)) ++p; }
    Token Next() {
        SkipWs();
        if (!*p) return {Token::End, L""};
        wchar_t c = *p++;
        switch (c) {
        case L'{': return {Token::LBrace, L"{"};
        case L'}': return {Token::RBrace, L"}"};
        case L'[': return {Token::LBracket, L"["};
        case L']': return {Token::RBracket, L"]"};
        case L':': return {Token::Colon, L":"};
        case L',': return {Token::Comma, L","};
        case L'\"': {
            std::wstring out; out.reserve(16);
            for (;;) {
                if (!*p) break;
                wchar_t ch = *p++;
                if (ch == L'\\') { if (*p) { out.push_back(*p++); } continue; }
                if (ch == L'\"') break;
                out.push_back(ch);
            }
            return {Token::String, out};
        }
        default:
            // identifier/number/true/false/null
            {
                std::wstring out; out.push_back(c);
                while (*p && !iswspace(*p) && *p != L',' && *p != L'}' && *p != L']' && *p != L':') {
                    out.push_back(*p++);
                }
                std::wstring lower = ToLower(out);
                if (lower == L"true") return {Token::True, out};
                if (lower == L"false") return {Token::False, out};
                if (lower == L"null") return {Token::Null, out};
                // crude number check
                bool numeric = !out.empty() && (iswdigit(out[0]) || out[0] == L'-');
                if (numeric) return {Token::Number, out};
                return {Token::Identifier, out};
            }
        }
    }
};

struct PairsCollector {
    // section -> (key,value)
    std::vector<std::pair<std::wstring, std::pair<std::wstring, std::wstring>>> items;

    void Add(const std::wstring& section, const std::wstring& key, const std::wstring& value) {
        items.emplace_back(section, std::make_pair(key, value));
    }
};

// Parse a minimal object, collecting "key": value pairs into collector under a section name
void ParseObject(Lexer& lx, const std::wstring& section, PairsCollector& out);

std::wstring TokenToString(const Token& t) {
    switch (t.type) {
    case Token::String:
    case Token::Number:
    case Token::Identifier:
        return t.text;
    case Token::True: return L"true";
    case Token::False: return L"false";
    case Token::Null: return L"";
    default: return L"";
    }
}

void ParseValue(Lexer& lx, const std::wstring& section, const std::wstring& key, PairsCollector& out) {
    Token t = lx.Next();
    if (t.type == Token::LBrace) {
        ParseObject(lx, key.empty() ? section : key, out);
        return;
    }
    // For arrays, skip until closing bracket
    if (t.type == Token::LBracket) {
        int depth = 1; Token x;
        while (depth > 0 && (x = lx.Next()).type != Token::End) {
            if (x.type == Token::LBracket) depth++; else if (x.type == Token::RBracket) depth--;
        }
        return;
    }
    out.Add(section, key, TokenToString(t));
}

void ParseObject(Lexer& lx, const std::wstring& section, PairsCollector& out) {
    for (;;) {
        Token key = lx.Next();
        if (key.type == Token::RBrace || key.type == Token::End) break;
        if (key.type != Token::String && key.type != Token::Identifier) {
            // skip until next comma or end brace
            Token skip; do { skip = lx.Next(); } while (skip.type != Token::Comma && skip.type != Token::RBrace && skip.type != Token::End);
            if (skip.type == Token::RBrace) break; else continue;
        }
        Token colon = lx.Next(); if (colon.type != Token::Colon) continue;
        ParseValue(lx, section, key.text, out);
        // consume optional comma
        Token comma = lx.Next(); if (comma.type == Token::RBrace) break; else if (comma.type == Token::End) break; else if (comma.type != Token::Comma) { /* pushback not supported */ }
    }
}

std::wstring ReadFileW(const std::wstring& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return L"";
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (s.size() >= 2 && (unsigned char)s[0] == 0xFF && (unsigned char)s[1] == 0xFE) {
        // UTF-16LE: simple cast
        std::wstring w((wchar_t*)s.data(), s.size() / sizeof(wchar_t));
        return w;
    }
    // assume UTF-8
    int req = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(req, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), req);
    return w;
}

bool ApplyEnv(const std::wstring& key, const std::wstring& value) {
    // Only uppercase keys are applied to env
    bool upper = true;
    for (wchar_t c : key) { if (iswalpha(c) && towupper(c) != c) { upper = false; break; } }
    if (!upper) return false;
    if (value.empty()) return SetEnvironmentVariableW(key.c_str(), nullptr);
    return SetEnvironmentVariableW(key.c_str(), value.c_str());
}

std::wstring DefaultConfigPath() {
    wchar_t modPath[MAX_PATH] = {};
    HMODULE hMod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&DefaultConfigPath), &hMod)) {
        GetModuleFileNameW(hMod, modPath, MAX_PATH);
        PathRemoveFileSpecW(modPath);
        std::wstring base(modPath);
        std::wstring candidate = base + L"\\configs\\production.json";
        if (PathFileExistsW(candidate.c_str())) return candidate;
    }
    return L"";
}

std::wstring ProgramDataConfigPath() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring base = (n && n < MAX_PATH) ? std::wstring(buf, buf + n) : L"C:\\ProgramData";
    std::wstring path = base + L"\\UserModeHook\\config.json";
    if (PathFileExistsW(path.c_str())) return path;
    return L"";
}

}

std::wstring LoadAndApplyConfig() {
    // Resolve path
    wchar_t cfgPathBuf[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"UMH_CONFIG", cfgPathBuf, MAX_PATH);
    std::wstring path;
    if (n && n < MAX_PATH) { path.assign(cfgPathBuf, cfgPathBuf + n); }
    if (path.empty()) path = ProgramDataConfigPath();
    if (path.empty()) path = DefaultConfigPath();
    if (path.empty()) return L"";

    std::wstring text = ReadFileW(path);
    if (text.empty()) return L"";

    Lexer lx(text);
    Token t = lx.Next();
    if (t.type != Token::LBrace) return L"";

    PairsCollector pairs;
    ParseObject(lx, L"$root", pairs);

    // Apply: any pair where key is uppercase or section is one of [flags, agent, directx]
    for (const auto& it : pairs.items) {
        const auto& sect = it.first;
        const auto& key = it.second.first;
        auto val = it.second.second;
        if (sect == L"flags" || sect == L"agent" || sect == L"directx") {
            if (val == L"true") val = L"1"; else if (val == L"false") val = L"0";
            ApplyEnv(key, val);
        } else {
            // Also allow top-level uppercase keys
            bool upper = true; for (wchar_t c : key) { if (iswalpha(c) && towupper(c) != c) { upper = false; break; } }
            if (upper) {
                if (val == L"true") val = L"1"; else if (val == L"false") val = L"0";
                ApplyEnv(key, val);
            }
        }
    }
    return path;
}

} // namespace umh

