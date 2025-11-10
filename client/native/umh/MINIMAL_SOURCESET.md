# Minimal UMH Source Set (SetWindowDisplayAffinity + BlockInput)

This note enumerates the smallest slice of the vendored UserModeHook (UMH) tree
we need to ship the Phase‑0 enforcement goals: removing
`SetWindowDisplayAffinity` restrictions and preventing `BlockInput` from
disabling operator control.

## Core Translation Units

| Area | Files | Purpose |
| --- | --- | --- |
| Hook targets | `vendor/src/HookDLL.cpp` | Implements the actual User32 + NtUser detours for `SetWindowDisplayAffinity`, `NtUserSetWindowDisplayAffinity`, `BlockInput`, and `NtUserBlockInput`. Depends on MinHook-style helpers plus shared logging utilities. |
| Hook orchestration | `vendor/src/HookEngine.cpp`, `vendor/src/MultiLayerHook.cpp`, `vendor/src/MinHookWrapper.cpp`, `vendor/src/InjectionEngine.cpp`, `vendor/src/ManualMapInjector.cpp`, `vendor/src/SectionMapInjector.cpp` | Provide the layer-by-layer installation helpers (inline/IAT/EAT/VEH/syscall). Only the inline + VEH paths are strictly required for the SWDA/BlockInput hooks, but the other helpers are lightweight and needed to satisfy the shared interfaces. |
| Policy/runtime glue | `vendor/src/SystemWideMonitor.cpp`, `vendor/src/UnifiedAgent.cpp` | Owns the CLI-driven policy loop and telemetry fan-out. For our bridge we only need the helper routines that enumerate targets, log structured events, and keep SWDA/BlockInput bypasses alive; we can compile them as-is and stub out the CLI entrypoints. |
| Shared headers | `vendor/include/*.h`, `vendor/third_party/minhook/include/*.h` | Provide `HookTargetDescriptor`, `HookLayer`, telemetry structs, and the MinHook public API. |
| Third-party deps | `vendor/third_party/minhook/src/*.cpp` | MinHook’s core implementation used by `MinHookWrapper.cpp`. |

## Build Notes

1. The cgo package (`client/service/desktop/hookbridge`) now enforces `/std:c++17`,
   `/guard:cf`, and `/MT`. These flags satisfy the Windows service constraints and
   mirror UMH’s upstream project files.
2. When compiling this minimal set we only need to expose a narrow C ABI defined
   in `client/native/umh/include/spark_umh.h`. The bridge will wrap UMH’s
   higher-level C++ types and emit the simple `spark_umh_*` functions that Go
   already knows about.
3. To keep the single-executable promise we will compile the UMH sources directly
   into the agent via cgo rather than producing a sidecar DLL. The compiled code
   must avoid `#pragma comment(lib, ...)` directives that try to pull in dynamic
   CRTs; `/MT` takes care of this.
4. The initial bridge can focus on SetWindowDisplayAffinity + BlockInput only by
   defining build macros that disable the remaining detours inside
   `HookDLL.cpp`. Once that works we can expand the macro set to enable the rest
   of the UMH catalog incrementally.

## Next Steps

- Create `client/native/umh/src/bridge.cc` that includes the files above (or
  compiles them into a tiny static library) and implements the
  `spark_umh_{init,apply,release,shutdown}` entrypoints.
- Add a Windows-only CI task that runs `go test ./client/service/desktop/...`
  with `CGO_ENABLED=1` so we catch mismatched flags or missing sources whenever
  UMH is updated.
- Document any local edits we make to the vendored files (e.g., to disable CLI
  code paths) so future syncs are repeatable.
