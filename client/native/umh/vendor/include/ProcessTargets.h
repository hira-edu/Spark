#pragma once

#include <string>
#include <vector>

namespace umh {

// Returns the cached list of normalised process names sourced from configuration.
const std::vector<std::wstring>& GetProcessTargets();

// Indicates whether a restrictive allowlist is active.
bool HasProcessTargetFilter();

// Returns true when the supplied process path or filename matches the allowlist
// (or when the allowlist is empty).
bool IsTargetProcess(const std::wstring& processPathOrName);

// UTF-8 helper for callers that track narrow strings.
bool IsTargetProcessUtf8(const std::string& processPathOrName);

}  // namespace umh
