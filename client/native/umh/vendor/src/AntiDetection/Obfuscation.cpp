// Obfuscation.cpp - String encryption, API obfuscation, and code morphing
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "ntdll.lib")

// Compile-time string encryption
template<size_t N>
class ObfuscatedString {
private:
    char m_data[N];

public:
    constexpr ObfuscatedString(const char (&str)[N]) {
        for (size_t i = 0; i < N; ++i) {
            m_data[i] = str[i] ^ 0xAA; // Simple XOR encryption
        }
    }

    std::string decrypt() const {
        std::string result;
        for (size_t i = 0; i < N - 1; ++i) {
            result += m_data[i] ^ 0xAA;
        }
        return result;
    }
};

// Macro for easy use
#define OBFUSCATED(str) ObfuscatedString<sizeof(str)>(str).decrypt()

class Obfuscation {
private:
    std::mt19937 m_rng;
    std::vector<BYTE> m_trampolineCode;

public:
    Obfuscation() : m_rng(std::random_device{}()) {
        std::cout << "[Obfuscation] Engine initialized" << std::endl;
    }

    // Dynamic API resolution with obfuscated names
    template<typename T>
    T ResolveAPI(const std::string& dllName, const std::string& apiName) {
        // Obfuscate DLL name
        std::string obfDll = ObfuscateString(dllName);
        std::string obfApi = ObfuscateString(apiName);

        // Dynamically load and resolve
        HMODULE hModule = LoadLibraryA(DeobfuscateString(obfDll).c_str());
        if (!hModule) {
            // Try alternative loading methods
            hModule = GetModuleHandleA(DeobfuscateString(obfDll).c_str());
        }

        if (!hModule) {
            return nullptr;
        }

        // Resolve by hash instead of name
        DWORD apiHash = HashString(apiName);
        return (T)GetProcAddressByHash(hModule, apiHash);
    }

    // String obfuscation at runtime
    std::string ObfuscateString(const std::string& input) {
        std::string output;
        BYTE key = m_rng() & 0xFF;

        output.push_back(key); // Store key at beginning
        for (char c : input) {
            output.push_back(c ^ key);
            key = (key + 1) & 0xFF; // Rolling key
        }

        return output;
    }

    std::string DeobfuscateString(const std::string& input) {
        if (input.empty()) return "";

        std::string output;
        BYTE key = input[0];

        for (size_t i = 1; i < input.length(); ++i) {
            output.push_back(input[i] ^ key);
            key = (key + 1) & 0xFF;
        }

        return output;
    }

    // Hash-based API resolution
    DWORD HashString(const std::string& str) {
        DWORD hash = 0x811C9DC5; // FNV-1a offset basis

        for (char c : str) {
            hash ^= c;
            hash *= 0x01000193; // FNV-1a prime
        }

        return hash;
    }

    PVOID GetProcAddressByHash(HMODULE hModule, DWORD targetHash) {
        if (!hModule) return nullptr;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        PDWORD functions = (PDWORD)((PBYTE)hModule + exportDir->AddressOfFunctions);
        PDWORD names = (PDWORD)((PBYTE)hModule + exportDir->AddressOfNames);
        PWORD ordinals = (PWORD)((PBYTE)hModule + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* functionName = (char*)((PBYTE)hModule + names[i]);
            DWORD functionHash = HashString(functionName);

            if (functionHash == targetHash) {
                return (PBYTE)hModule + functions[ordinals[i]];
            }
        }

        return nullptr;
    }

    // Code morphing - generate polymorphic code
    std::vector<BYTE> GeneratePolymorphicCode(const std::vector<BYTE>& originalCode) {
        std::vector<BYTE> morphedCode;

        // Add random NOP sleds
        int nopCount = m_rng() % 10 + 1;
        for (int i = 0; i < nopCount; i++) {
            morphedCode.push_back(0x90); // NOP
        }

        // Process original code with modifications
        for (size_t i = 0; i < originalCode.size(); i++) {
            BYTE opcode = originalCode[i];

            // Replace certain patterns with equivalent instructions
            if (opcode == 0x50) { // PUSH RAX
                // Replace with SUB RSP, 8; MOV [RSP], RAX
                morphedCode.push_back(0x48); morphedCode.push_back(0x83);
                morphedCode.push_back(0xEC); morphedCode.push_back(0x08);
                morphedCode.push_back(0x48); morphedCode.push_back(0x89);
                morphedCode.push_back(0x04); morphedCode.push_back(0x24);
            }
            else if (opcode == 0x58) { // POP RAX
                // Replace with MOV RAX, [RSP]; ADD RSP, 8
                morphedCode.push_back(0x48); morphedCode.push_back(0x8B);
                morphedCode.push_back(0x04); morphedCode.push_back(0x24);
                morphedCode.push_back(0x48); morphedCode.push_back(0x83);
                morphedCode.push_back(0xC4); morphedCode.push_back(0x08);
            }
            else {
                morphedCode.push_back(opcode);
            }

            // Randomly insert junk instructions
            if ((m_rng() % 100) < 10) {
                InsertJunkCode(morphedCode);
            }
        }

        return morphedCode;
    }

    void InsertJunkCode(std::vector<BYTE>& code) {
        int junkType = m_rng() % 5;

        switch (junkType) {
        case 0: // XCHG RAX, RAX (NOP equivalent)
            code.push_back(0x48); code.push_back(0x90);
            break;
        case 1: // MOV RBX, RBX
            code.push_back(0x48); code.push_back(0x89);
            code.push_back(0xDB);
            break;
        case 2: // ADD RCX, 0
            code.push_back(0x48); code.push_back(0x83);
            code.push_back(0xC1); code.push_back(0x00);
            break;
        case 3: // JMP +2; NOP; NOP
            code.push_back(0xEB); code.push_back(0x02);
            code.push_back(0x90); code.push_back(0x90);
            break;
        case 4: // PUSH RBP; POP RBP
            code.push_back(0x55); code.push_back(0x5D);
            break;
        }
    }

    // Control flow obfuscation
    std::vector<BYTE> ObfuscateControlFlow(const std::vector<BYTE>& code) {
        std::vector<BYTE> obfuscated;

        // Add opaque predicates (always true/false conditions)
        obfuscated.push_back(0x48); obfuscated.push_back(0x31); // XOR RAX, RAX
        obfuscated.push_back(0xC0);
        obfuscated.push_back(0x48); obfuscated.push_back(0x85); // TEST RAX, RAX
        obfuscated.push_back(0xC0);
        obfuscated.push_back(0x74); obfuscated.push_back(0x02); // JZ +2 (always taken)
        obfuscated.push_back(0xEB); obfuscated.push_back(0x05); // JMP +5 (never taken)

        // Insert random dead code
        for (int i = 0; i < 5; i++) {
            obfuscated.push_back(0x90); // Dead NOPs
        }

        // Add the real code
        obfuscated.insert(obfuscated.end(), code.begin(), code.end());

        return obfuscated;
    }

    // API call obfuscation via trampolines
    PVOID CreateAPITrampoline(PVOID originalAPI) {
        // Allocate memory for trampoline
        PVOID trampoline = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline) return nullptr;

        PBYTE code = (PBYTE)trampoline;
        size_t idx = 0;

        // Add random prefix
        int prefixSize = m_rng() % 5 + 1;
        for (int i = 0; i < prefixSize; i++) {
            code[idx++] = 0x90; // NOP
        }

        // MOV RAX, originalAPI
        code[idx++] = 0x48; code[idx++] = 0xB8;
        *(PVOID*)&code[idx] = originalAPI;
        idx += sizeof(PVOID);

        // JMP RAX
        code[idx++] = 0xFF; code[idx++] = 0xE0;

        // Make executable
        DWORD oldProtect;
        VirtualProtect(trampoline, 64, PAGE_EXECUTE_READ, &oldProtect);

        return trampoline;
    }

    // Encrypt/decrypt memory regions
    void EncryptMemory(PVOID buffer, SIZE_T size, BYTE key) {
        PBYTE data = (PBYTE)buffer;
        for (SIZE_T i = 0; i < size; i++) {
            data[i] ^= key;
            key = (key + 1) & 0xFF;
        }
    }

    void DecryptMemory(PVOID buffer, SIZE_T size, BYTE key) {
        EncryptMemory(buffer, size, key); // XOR is reversible
    }

    // Generate random function names
    std::string GenerateRandomFunctionName() {
        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
        std::string result;

        int length = m_rng() % 10 + 5;
        for (int i = 0; i < length; i++) {
            result += charset[m_rng() % (sizeof(charset) - 1)];
        }

        return result;
    }

    // Indirect function calls via function pointer arrays
    template<typename Func>
    class IndirectCaller {
    private:
        std::vector<Func> m_functions;
        std::vector<int> m_indices;

    public:
        void AddFunction(Func func) {
            m_functions.push_back(func);
            m_indices.push_back(m_functions.size() - 1);
        }

        Func GetFunction(int index) {
            // Shuffle indices for obfuscation
            std::shuffle(m_indices.begin(), m_indices.end(), std::mt19937{std::random_device{}()});

            // Find the actual index
            for (size_t i = 0; i < m_indices.size(); i++) {
                if (m_indices[i] == index) {
                    return m_functions[i];
                }
            }

            return nullptr;
        }
    };

    // Stack string obfuscation
    class StackString {
    private:
        char m_buffer[256];

    public:
        StackString(const char* str) {
            size_t len = strlen(str);
            for (size_t i = 0; i < len; i++) {
                m_buffer[i] = str[i] ^ 0x55;
            }
            m_buffer[len] = 0;
        }

        const char* Get() {
            size_t len = strlen(m_buffer);
            for (size_t i = 0; i < len; i++) {
                m_buffer[i] ^= 0x55;
            }
            return m_buffer;
        }
    };
};

// Export functions
extern "C" {
    __declspec(dllexport) void* ObfuscateAPI(const char* dll, const char* api) {
        Obfuscation obf;
        return obf.ResolveAPI<void*>(dll, api);
    }

    __declspec(dllexport) void EncryptBuffer(void* buffer, size_t size) {
        Obfuscation obf;
        obf.EncryptMemory(buffer, size, 0x42);
    }

    __declspec(dllexport) void DecryptBuffer(void* buffer, size_t size) {
        Obfuscation obf;
        obf.DecryptMemory(buffer, size, 0x42);
    }
}