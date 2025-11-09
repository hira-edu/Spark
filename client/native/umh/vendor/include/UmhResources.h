#pragma once

#define IDR_UMH_HOOKDLL        101
#define IDR_UMH_UNIFIED_AGENT  102
#define IDR_UMH_INJECTOR       103
#define IDR_UMH_CLI            104
#define IDR_UMH_DRIVER         105

namespace umh::resources {

// Resource identifiers used by the embedded artifacts block.
constexpr int kResourceHookDll = IDR_UMH_HOOKDLL;
constexpr int kResourceUnifiedAgent = IDR_UMH_UNIFIED_AGENT;
constexpr int kResourceInjector = IDR_UMH_INJECTOR;
constexpr int kResourceCli = IDR_UMH_CLI;
constexpr int kResourceDriver = IDR_UMH_DRIVER;

// Filenames used when materialising embedded artifacts to disk.
inline constexpr wchar_t kArtifactsSubdir[] = L"embedded";
inline constexpr wchar_t kHookDllFileName[] = L"AdvancedHookDLL.dll";
inline constexpr wchar_t kUnifiedAgentFileName[] = L"UnifiedAgent.exe";
inline constexpr wchar_t kInjectorFileName[] = L"AdvancedInjector.exe";
inline constexpr wchar_t kCliFileName[] = L"umh-cli.exe";
inline constexpr wchar_t kDriverFileName[] = L"UMHDriver.sys";

}  // namespace umh::resources
