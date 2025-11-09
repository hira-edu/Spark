#pragma once
#include <Windows.h>
#include <string>

// Lightweight config loader that reads a JSON-like file and applies
// process-wide environment variables for flags used across the project.
//
// Precedence:
// 1) UMH_CONFIG env var (explicit path)
// 2) %ProgramData%\UserModeHook\config.json
// 3) <module_dir>\configs\production.json
//
// Only simple key/value pairs are supported in sections:
//   - flags: { NAME: bool|string|number }
//   - agent: { AGENT_* }
//   - directx: { MLHOOK_DISABLE_D3D9, MLHOOK_DISABLE_DXGI }
// Additional sections are ignored except for nested simple key: value pairs
// which will be applied as environment variables verbatim when keys are UPPERCASE.

namespace umh {

// Returns the resolved config path used, or empty if not found.
std::wstring LoadAndApplyConfig();

}

