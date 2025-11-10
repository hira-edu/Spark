# UserModeHook (UMH) Porting Plan

Consolidates the feasibility study, staged rollout plan, bridge design, and session/identity plumbing needed to fold the upstream UserModeHook engine into the Spark Windows agent without violating the single-executable, `svchost`-hosted constraints.

## Executive Summary

- UMH's MIT license, static CRT build, and small footprint (<1 MB compiled) make it safe to embed directly in the Spark agent with only notice requirements (see `client/native/umh/vendor/LICENSE.UserModeHook`).
- The current `hookbridge` package plus `spark_umh_*` cgo bindings already compile the vendored sources in-process; we only need to lock down testing, telemetry, and policy plumbing to treat it as production-ready.
- Session-aware enforcement hinges on `client/internal/winsession`, which now exports SID/session metadata so we can scope UMH policies per viewer instead of per-process.
- Rollout happens behind feature flags (`SPARK_EXPERIMENTAL_UMH`, server/device policies) with explicit rollback hooks so we can revert to the legacy SendInput path instantly if UMH destabilizes `svchost`.

## Feasibility Study

| Axis | Findings | Mitigations / Notes |
| ---- | -------- | ------------------- |
| Licensing & IP | UMH upstream is MIT. We vendor the exact headers/sources under `client/native/umh/vendor/*` and ship the upstream license verbatim. No copyleft or notice placement complications beyond retaining the license in `licenses/`. | Keep `vendor/LICENSE.UserModeHook` in release bundles and document under "Third-Party Notices." |
| Binary footprint | `du -sh client/native/umh/vendor` reports ~1.3 MB of source. The compiled `.obj` set produced by MSVC (C++17, `/O2 /MT`) is ~420 KB today when we include only SWDA/BlockInput detours; peak runtime RSS impact in staging stayed under 9 MB. | Guard optional subsystems (DX hooks, OpenXR, anti-detection) behind build macros so we only pay for features we need. |
| `svchost` compatibility | UMH injects inline/VECTORED detours inside the service host without spawning windows or requiring interactive tokens. All translation units are compiled with `/guard:cf`, `/DUNICODE`, and static CRT linking so there are no dynamic dependencies that would violate service isolation. | Ship health probes: watchdog telemetry already tracks `svchost` PID churn, and `sparkHookbridgeEmit` now emits `policy_state` updates so we can correlate hook activation with service stability. |
| Build/toolchain alignment | The bridge already builds via cgo when `GOOS=windows` and `CGO_ENABLED=1`. We drive MSVC on the Windows builder to satisfy `/std:c++17` and Control-Flow Guard. No additional toolchain (cmake, ninja) is required. | CI action item: add `go test ./client/service/desktop/...` on a Windows runner with CGO enabled to catch drift whenever UMH sources change. |
| Embedding strategy | `client/service/desktop/hookbridge/spark_umh_windows.cc` directly includes the vendored `.cpp` files and exports `spark_umh_{init,apply,release,shutdown}`. The bridge runs in the same process as the agent, so there are no DLLs to deploy and no shared-memory handles to keep track of. | Keep the single-executable invariant by forbidding `#pragma comment(lib, ...)` additions in future UMH syncs and ensuring config/policy is stored under `C:\ProgramData\Spark` rather than the original `%ProgramData%\UserModeHook`. |

## Staged Porting & Rollback Plan

| Phase | Scope | Flag / Exit Criteria | Rollback |
| ----- | ----- | -------------------- | -------- |
| Phase 0 - Enforcement MVP | Enable `SetWindowDisplayAffinity` and `BlockInput` bypass using the currently compiled hook set. Telemetry flows through `sparkHookbridgeEmit` so the server/UI can show whether enforcement is active. | Gate behind `SPARK_EXPERIMENTAL_UMH=1` (agent) + device policy bit so only opted-in tenants receive hooks. Exit when regression tests + soak (24h) show no watchdog restarts. | Flip the policy bit off. `hookbridge` downgrades to stub behavior and releases all native policies immediately. |
| Phase 1 - Session-aware enforcement | Start enforcing per-viewer policies (force input/capture) by wiring the policy manager to `winsession.Info` and storing active SIDs/session IDs in telemetry/audit logs. Extend CLI/console to show which viewer forced enforcement. | Requires `winsession` metadata flowing through `DESKTOP_CAPS` and server storage. Exit when the server can display session info and auditors can pull the state. | Disable the UMH feature flag; the legacy SendInput path continues to work because we only add metadata and per-session bookkeeping. |
| Phase 2 - Advanced UMH catalog | Incrementally turn on the remaining hook families (graphics detours, telemetry CLI, anti-analysis toggles) behind per-feature flags. Bundle TURN/relay aware policies as needed. | Each hook family rides its own feature flag and Playwright/CLI regression tests. Exit when metrics show parity with legacy SWDA bypass behavior. | Revert the specific feature flag; the base UMH runtime remains active for previously proven hooks. |

Rollback is always "flag off + optional agent restart." Because the hooks live in-process, no system reboot or uninstall is required.

## Hook Bridge Architecture

```text
client/service/desktop (policy manager)
        |
        v
hookbridge (Go) --> spark_umh_* (cgo, `spark_umh_windows.cc`)
        |                          |
        |                          v
        |               Vendored UMH runtime (HookDLL.cpp, HookEngine.cpp, ...)
        |
        +-- telemetry sink <-- sparkHookbridgeEmit(JSON, PID, SessionID)
```

- `hookbridge.Config` decides whether the native path is enabled (env var or device policy). When disabled we stay in pure-Go stub mode.
- `hookbridge.Policy` holds the PID/session metadata plumbed from `client/internal/winsession`. Policies are registered per remote desktop connection; the manager releases them automatically when sessions end or time out.
- All native calls happen synchronously on the desktop worker goroutine, but the bridge serializes state inside `client/native/umh/src/bridge.cc`, so multiple viewers do not race each other.
- Telemetry emerges from `sparkHookbridgeEmit` as JSON blobs (`policy_state`, `policy_native`, failure events). The sink registered in `desktop.go` fans these into server telemetry so support/SOC teams can confirm enforcement in real time.
- Shared memory/RPC separation: because UMH is compiled into the same executable we do not open new named pipes or mailslots (which would be blocked on some customer endpoints). The bridge surface behaves like an RPC boundary with stable request/response structs and a JSON telemetry channel without leaving the process boundary.

## Session & Identity Metadata Plumbing

1. `client/internal/winsession` now exposes `QueryProcess` / `QueryCurrentProcess`, returning `SessionID`, SID string, and `DOMAIN\User`.
2. `desktop.go` caches the agent's own session info at init and threads per-viewer session IDs through `hookbridge.Policy`.
3. Each `DESKTOP_CAPS` payload includes the agent SID/session info plus a `sessionPolicies.describe()` snapshot so the server/web UI can display who forced `ForceInput`/`ForceCapture`.
4. Server-side TODO (tracked separately): persist the SID/session tuple with every remote desktop session record so audit logs can answer "which Windows user context was being controlled?"
5. Telemetry stream: `sparkHookbridgeEmit` attaches the process PID + session ID, enabling watchdog/analytics jobs to detect split-brain situations (for example, UMH sees Session 1 while the server believes the agent is in Session 0).

### Guardrails

- The policy manager rate-limits `ForceInput` toggles and falls back to SendInput-only control if the native bridge returns `kErrNotInitialized` or `kErrInstallFailed`.
- UMH configuration lives under `C:\ProgramData\Spark\umh\policy.json` (created lazily by the bridge) so it inherits the same ACLs as the agent binary.
- SOC-friendly telemetry: every `policy_state` event is signed with the agent connection ID so the server can correlate enforcement with operator identity.

## Outstanding Follow-Ups

1. Add Windows CI coverage that runs `go test ./client/service/desktop/...` with `CGO_ENABLED=1` to catch UMH build/link regressions.
2. Expand `docs/ops/remote-desktop.md` with operational guidance for interpreting UMH telemetry (`policy_state`, failures).
3. Plumb the telemetry sink into the server audit log so SOC teams can see who enabled force capture/input and when.
4. Stage the Phase 0 flag rollout in canary tenants before enabling for general availability.
