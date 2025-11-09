# Remote Desktop Control – SSOT

Single source of truth for implementing “best of the best” remote desktop control in Spark. Keeps strategy, scope, and actionable backlog aligned as new requirements land.

---

## Vision & Principles

- Deliver enterprise-grade remote desktop comparable to top-tier RMM/RAT tooling: low latency, high fidelity, bi-directional control, secure by default.
- Maintain backwards compatibility via graceful fallbacks to the current diff/JPEG WebSocket path.
- Security, privacy, and auditability are first-class: every control action must be attributable and policy governed.
- Modularity: transport, encoding, input, and UX layers should evolve independently via feature flags.
- Operational constraint: the agent always runs inside `svchost` context, so implementations must respect service-host permissions, session isolation, and stealth requirements.
- Scope guardrail: **only Windows endpoints are in-scope for this phase**; Linux/macOS enablement is tracked separately and must not block or dilute Windows delivery.
- Deployment constraint: the Windows installer deposits a single, self-contained executable under `C:\ProgramData\Spark\Spark.exe` (exact path TBD) that hosts all remote-desktop functionality; no auxiliary binaries or scattered assets are permitted, and installation must be one-click (no additional dialogs, configs, or dependencies).

---

## Current State Snapshot

- **Streaming:** WebSocket-based diffed JPEG blocks (`client/service/desktop`, `server/handler/desktop`, `web/src/components/desktop/desktop.jsx`). 96px blocks, FPS capped at 24, single-monitor, no audio.
- **Input:** No mouse/keyboard injection; desktop sessions are view-only.
- **UX:** Simple modal canvas with FPS/bandwidth stats, manual refresh/fullscreen, no quality presets or monitor selection.
- **Security/Observability:** Session secrets, but no per-session auth tokens, RBAC, or audit logs. Limited telemetry (basic connect/disconnect logs).

---

## Master Plan (Phased)

1. **Foundation & Discovery**
   - Capture detailed diagrams of the existing pipeline, packet formats, queues, and failure modes.
   - Instrument baseline metrics (FPS, diff queue depth, encoder fallbacks) to benchmark improvements.

2. **Next-Gen Streaming Path**
   - Add WebRTC transport with hardware-accelerated encoders (NVENC/AMF/QuickSync) on Windows. Keep WebSocket diff path as fallback.
   - Implement adaptive bitrate & resolution management plus optional audio streaming.

3. **Full Input & Interaction Layer**
   - Introduce bidirectional mouse/keyboard/scroll/clipboard/file input channels with Windows-native injection first, leaving stubs for future OSes.
   - Support relative/absolute pointer modes, modifier tracking, secure clipboard toggles, session pause/blank screen.

4. **UX & Productivity Enhancements**
   - Multi-monitor enumeration + switching, quality presets, bandwidth/FPS HUD, reconnect/pause buttons, on-client toast notifications.
   - Clipboard/file redirection integrated with existing explorer, virtual cursor overlay, session recording/sharing.

5. **Security, Compliance, Observability**
   - Per-session signed tokens, RBAC enforcement, approval workflows, detailed audit logs, metrics dashboards, rate limiting.
   - Configurable policies (max concurrent sessions, idle timeout, privacy mode) and Prometheus/Grafana integration.

6. **Testing, Rollout, & Ops**
   - Add unit/integration/E2E coverage for packet formats, input pipelines, UI flows, and soak testing harnesses.
   - Ship feature flags for incremental rollout, author operational runbooks, and define blue/green deployment strategy.

---

## Comprehensive TODO Backlog

### Foundation & Discovery
- [x] Document current desktop session lifecycle (client/server/web) with sequence diagrams in `docs/remote-desktop.md`.
- [x] Expand telemetry in `server/handler/desktop/desktop.go` to log FPS, queue length, encoder errors.
- [x] Add client-side capture metrics (frame drops, diff sizes) reported back to server for aggregation.
- [ ] Produce Windows capture/encoder diagrams (Desktop Duplication vs GDI) covering multi-monitor surfaces, DPI scaling, HDR, and GPU requirements.
- [x] Define a versioned capability-negotiation schema (`DESKTOP_CAPS`) that advertises transports, codecs, input channels, and UX affordances during session init.
- [ ] Catalogue failure modes (encoder crash, dropped WS, lost frames) and document recovery/backpressure strategies in a troubleshooting appendix.
- [ ] Prove every new client component (capture, encoder, input) loads and runs inside the existing `svchost` service host, outlining required service manifests, privileges, and sandbox implications.
- [ ] Specify the single-executable packaging layout (embedded assets, codec binaries, WebRTC libs) and how it is staged under `ProgramData`, including update/rollback implications and antivirus exclusions.
- [ ] Document install/uninstall flow for the ProgramData deployment along with disk footprint budgets and how persistent caches/logs are rotated without leaving files elsewhere.
- [ ] Design the one-click installer UX (single elevation prompt, no wizard steps) that deploys to ProgramData, registers the `svchost` service, seeds config defaults, and verifies prerequisites offline.
- [ ] Define the scheduled task + watchdog architecture that bootstraps the agent post-install, auto-respawns it if svchost/session exits, and guarantees the remote desktop service is always present without requiring user login.
- [ ] Publish a network matrix outlining every outbound endpoint/protocol/port (signaling, TURN, telemetry), document that no inbound listeners exist, and provide customer-ready firewall language.
- [ ] Create a registry footprint manifest (`HKLM\Software\Spark\...`) listing every key/value touched by the agent plus rationale, default values, and cleanup expectations.
- [ ] Enumerate Windows privacy features that block capture/input (SetWindowDisplayAffinity, secure desktops, filter drivers) and document detection + operator messaging expectations.
- [ ] Complete a feasibility study for porting UserModeHook (UMH) components: licensing, binary size impact, `svchost` compatibility, build/toolchain alignment, and how to embed the hook DLL inside the single Spark executable.
- [ ] Define a porting plan that stages UMH features (SWDA bypass, BlockInput hooks, graphics detours, telemetry CLI) into Spark behind feature flags with rollback points and integration test coverage.
- [ ] Author a bridging layer that allows Spark’s `client/service/desktop` to request hook installation/removal via a stable RPC or shared memory channel, mirroring UMH’s SystemWideMonitor control plane.
- [ ] Import UMH’s session/identity metadata plumbing (ProcessIdToSessionId, SID capture, connection IDs) so the Spark agent can reason about console vs. RDP vs. VM sessions before applying enforcement.
- [ ] Vendor the core UMH native sources (hook engine, SWDA/BlockInput detours, DirectX hooks) under `client/native/umh`, ensuring every file retains MIT headers and fits inside the single-executable footprint.
- [ ] Produce and maintain `client/native/umh/include/spark_umh.h` so it faithfully maps UMH exports (policy toggles, monitor/repair routines) to a minimal C ABI consumed via cgo.
- [ ] Document the native build process (toolchain requirements, `/guard:cf`, `/MT`, static linkage) and bake it into the agent build so UMH gets compiled alongside Go sources without manual steps.

### Streaming & Transport
- [ ] Implement WebRTC signaling handler (`server/handler/desktop/webrtc.go`) using pion, bridging to existing event loop.
- [ ] Introduce encoder abstraction in client (DXGI+NVENC, AMD AMF, Intel QuickSync/Media Foundation) with dynamic capability detection.
- [ ] Build adaptive bitrate controller exchanging stats between browser and client; expose quality presets.
- [ ] Add optional **system audio** capture/stream path (WASAPI loopback on Windows first) with per-session consent prompts, bitrate controls, and policy flags to keep the signal inside the single EXE (no external binaries/codecs).
- [ ] Maintain WebSocket diff pipeline as fallback with improved diff heuristics and optional lossless mode for screenshots.
- [ ] Stand up STUN/TURN infrastructure plus relay/SFU mode for air-gapped or high-latency networks; bake configuration into device policy.
- [ ] Add FEC/RTX or tile retransmission support plus jitter buffering to smooth lossy WAN links.
- [ ] Support HDR/10-bit color surfaces, color-space negotiation (sRGB, Display P3), and gamma-correct scaling in both pipelines.
- [ ] Provide QUIC/HTTP3 data-channel fallback for restricted environments where WebRTC is blocked but UDP/QUIC is available.
- [ ] Implement per-session bandwidth ceilings/floors with policy-driven resource admission to prevent encoder starvation.
- [ ] Ensure WebRTC/native transports respect `svchost` hosting limits (no window handles, STA threading) and provide watchdog hooks when the service is recycled.
- [ ] Support HTTPS/TLS tunneling over TCP 443 with proxy-auth (NTLM/Kerberos) so agents can traverse outbound-only corporate firewalls without special ports.
- [ ] Offer an on-prem relay mode where devices connect to a customer-hosted collector that maintains the single sanctioned outbound link to Spark’s control plane.
- [ ] Provide offline/snapshot workflows (frame capture export, input playback scripts) for fully air-gapped networks where live sessions are impossible.
- [ ] Validate that WebRTC dependencies (codecs, TURN certificates) are embedded into the single exe or generated at runtime so no additional files outside `ProgramData` are required.
- [ ] Evaluate whether UMH’s manual-map injector or SectionMap loader can serve as the basis for Spark’s future in-memory encoder/capture DLL deployment, ensuring no additional binaries leak outside ProgramData.
- [ ] Design a **webcam capture/relay channel** (DirectShow/Media Foundation) that multiplexes into the new transport, enforces privacy lights/indicators, and keeps capture DLLs embedded in the ProgramData-extracted single executable.
- [ ] Ship policy toggles + RBAC hooks that govern when system audio/webcam streams may start, including redaction (mute/blank) flows and audit events for every activation.

### Input Injection Pipeline
- [x] Front-end: capture mouse + keyboard + clipboard events (push/pull UI) via the control toggle; package under the `DESKTOP_INPUT`/clipboard schema.
- [x] Server: route `DESKTOP_INPUT`, `DESKTOP_CLIPBOARD_PUSH`, and `DESKTOP_CLIPBOARD_PULL` packets with groundwork for rate limiting/auditing.
- [ ] Client: create `client/service/input` with full Windows-native injectors (SendInput, low-level hooks, HID emulation) and document extension points for future OSes.
- [x] Add basic pointer/clipboard rate limiting to guard against runaway UI spam ahead of full policy enforcement.
- [ ] Support multi-button, drag, double-click timing, modifier tracking, IME safety, and clipboard sync toggles.
- [ ] Ensure lifecycle hooks tie input to desktop sessions (init/kill/ping) for clean teardown.
- [ ] Negotiate pointer-lock/relative mode plus high-DPI cursor scale to keep 3D/CAD workflows usable.
- [ ] Handle secure hotkeys (Ctrl+Alt+Del, Win/Super, Ctrl+Shift+Esc) through privileged injectors with proper consent prompts.
- [ ] Layer clipboard virtualization with optional DLP/content filtering and read/write ACLs.
- [ ] Journal input events (hashed) for later audit/replay while respecting privacy retention policies.
- [ ] Detect when SetWindowDisplayAffinity or similar APIs blank the session and surface UX warnings plus optional policy-driven override/whitelist workflows.
- [ ] Provide fallbacks when local keyboard/mouse input is disabled (filter drivers, accessibility locks), including HID emulation paths with explicit authorization gates.
- [ ] Port UMH’s multi-layer hook stack for `SetWindowDisplayAffinity`, `NtUserSetWindowDisplayAffinity`, `BlockInput`, `NtUserBlockInput`, `AttachThreadInput`, DirectInput, and `SetWindowsHookEx*` into Spark to guarantee capture/input continuity.
- [ ] Expose policy flags (e.g., `FORCE_INPUT`, `FORCE_CAPTURE`) similar to UMH’s enforcement toggles so operators can escalate enforcement per session.
- [ ] Mirror UMH’s per-process targeting (allowlists, fingerprints) so Spark only injects hooks into desktop processes tied to an active remote session.
- [ ] Port UMH’s session-aware policy engine (rolling counters per PID/session, auto-enforce/relax logic) so keyboard/display remediation happens automatically with hysteresis instead of manual toggles.

### UX & Productivity
- [x] Multi-monitor enumeration API; UI selector to switch displays without session restart.
- [x] Quality presets surfaced in UI with `DESKTOP_SET_QUALITY`, adjusting JPEG quality/FPS dynamically.
- [ ] Canvas HUD upgrades: bandwidth graphs, FPS meter, quality presets, reconnect/pause buttons.
- [ ] Privacy controls: remote blank screen, local keyboard/mouse lock, client toast notification of control.
- [ ] Clipboard/file redirection via explorer integration plus quick clipboard sync channel.
- [ ] Virtual cursor overlay plus optional session recording/export/sharing controls.
- [ ] Introduce viewer/controller roles with baton-passing plus co-browsing mode for training or approvals.
- [ ] Surface inline chat/notes + session timeline so operators can coordinate without leaving the console.
- [ ] Provide recording library UI (tagging, retention, export) and per-session watermarks/callouts for compliance.
- [ ] Surface real-time banners when capture/input is degraded by OS privacy settings (SWDA, secure desktop) and offer operator guidance or links to policy docs.
- [ ] Integrate UMH-style CLI workflows (`swa watch/status/bypass`, `input status/release`) into the Spark console so operators can diagnose privacy blockers without shell access.
- [ ] Display session/identity context (session ID, user SID/name, connection source) alongside each remote desktop session, mirroring UMH’s telemetry summaries.

### Security & Observability
- [x] Surface live agent telemetry (FPS, bandwidth, queue depth) in the desktop modal HUD powered by `DESKTOP_METRICS`.
- [ ] Require per-session signed tokens with expiration and RBAC policy checks before session creation.
- [ ] Add approval workflow hooks (per-device or per-operator) for remote control requests.
- [ ] Write detailed audit logs (who, when, duration, clipboard usage) and expose metrics (FPS, latency, encoder type, input lag).
- [ ] Implement configurable caps (max concurrent sessions, idle timeout, bandwidth ceilings) and privacy guardrails.
- [ ] Embed visible/invisible watermarks plus optional privacy masks for sensitive screen regions.
- [ ] Stream structured audit + telemetry events into SIEM/OTLP exporters with correlation IDs for every action.
- [ ] Add anomaly detection heuristics (session frequency spikes, clipboard volume) with alerting hooks.
- [ ] Define retention/deletion policies for recordings, clipboard buffers, and metrics to satisfy compliance regimes.
- [ ] Harden `C:\ProgramData\Spark` ACLs (SYSTEM + trusted service only), add tamper detection for the single exe, and document steps for detecting corruption or unauthorized replacement.
- [ ] Emit watchdog heartbeat telemetry (scheduled task status, restart counts, svchost PID churn) and surface alerts when the always-on guarantee is violated.
- [ ] Provide signed Windows Firewall templates that only allow the Spark service SID to reach the documented outbound endpoints and keep inbound blocked by default.
- [ ] Add registry/firewall drift detection plus automated remediation (self-heal) with audit logs whenever a rule/key is re-applied.
- [ ] Telemetry must periodically report hashes/timestamps of firewall rules and registry hives so SOC teams can verify the device matches policy.
- [ ] Capture metrics/events when capture or input is blocked by SetWindowDisplayAffinity, secure attention sequences, or disabled keyboards so SOC/ops can distinguish intentional privacy blocks from defects.
- [ ] Port UMH’s hook telemetry schema (hit counts, repair attempts, failure reasons) and stream it into Spark’s metrics pipeline for health dashboards.
- [ ] Ensure watchdog heartbeat includes UMH-layer status (active hooks, enforcement flags) so alerts fire if the ported components fail inside `svchost`.
- [ ] Persist session/identity metadata in telemetry/audit logs so SOC teams can trace who triggered enforcement, aligning with UMH’s SessionIdentityProtection plan.

### Testing & Rollout
- [ ] Unit tests for packet framing, diff encoder, and input schemas.
- [ ] Integration harness that simulates device + browser to validate WebRTC and fallback signaling.
- [ ] E2E/UI tests (Playwright/Cypress) to ensure canvas interactions drive expected device-side input events.
- [ ] Soak/load tests for adaptive bitrate controller and encoder stability under long sessions.
- [ ] Feature-flag gates for new transport/input paths; document rollout + rollback steps in `docs/ops/remote-desktop.md`.
- [ ] Synthetic capture workload generator (scroll, video, static) for regression testing encoder/diff heuristics.
- [ ] GPU-matrix test suite covering Windows NVENC generations, AMD AMF, and Intel QuickSync to ensure parity across supported adapters.
- [ ] Chaos harness to inject packet loss, RTT spikes, TURN failover, and agent restarts to validate self-healing.
- [ ] Canary/blue-green deployment playbook with metrics-based promotion criteria and auto-rollback triggers.
- [ ] Add packaging regression tests that build the single exe, verify embedded asset tables, confirm only `ProgramData` writes happen at runtime, and exercise in-place upgrade/downgrade flows.
- [ ] Automate one-click installer smoke tests (fresh install, upgrade, uninstall) in CI to guarantee no extra prompts, missing dependencies, or leftover artifacts.
- [ ] Create watchdog resilience tests that kill svchost, scheduled tasks, or the process repeatedly to ensure the agent respawns within SLA and telemetry captures the events.
- [ ] Add regression tests that fail if the agent opens new outbound hosts/ports or writes registry keys outside the approved manifest.
- [ ] Package GPO/PowerShell sample scripts for firewall + registry enforcement and run automated import/export tests to ensure they remain valid across OS versions.
- [ ] Extend CI to simulate egress-blocked environments (proxy required, DNS interception, total outbound deny) and verify agents either tunnel via HTTPS/proxy or emit actionable diagnostics.
- [ ] Add integration tests that embed the UMH hook engine into a sandboxed Spark agent build, run the MultiLayerHookHarness scenarios, and validate auto-heal, SWDA bypass, and BlockInput enforcement.
- [ ] Mirror UMH’s WinDbg validation matrix inside Spark CI (CFG on/off, VEH toggles, syscall layers) to prevent regressions when we update the hook stack.
- [ ] Simulate multi-session environments (console + RDP + VM) in CI to ensure the ported session-aware policy chooses the correct targets and telemetry annotations.

### Performance & Operations
- [ ] Model server/device capacity (CPU, GPU, memory) and implement admission control plus backpressure signaling.
- [ ] Provide autoscaling + multi-region placement strategy for signaling, TURN, and relay components with data-residency guardrails.
- [ ] Produce operational runbooks (triage, log capture, incident response) and wire alerts into on-call tooling.
- [ ] Track per-feature cost (bandwidth, compute) to guide policy defaults and customer-facing SLAs.
- [ ] Add automated validation and soak scenarios that repeatedly start/stop the Spark service under `svchost`, ensuring remote desktop, input, and telemetry modules recover cleanly after each host recycle.
- [ ] Define artifact signing, distribution, and rollback procedures for the single exe along with checks that ProgramData deployments match manifest hashes.
- [ ] Publish guidance for ProgramData disk monitoring (quota alerts, log pruning) so the one-folder deployment stays within customer policy limits.
- [ ] Provide field playbooks for one-click installer distribution (RMM push, manual, GPO) and document fail-open actions if installation is interrupted mid-flight.
- [ ] Document and implement the Scheduled Task creation (system startup + periodic recovery) alongside a watchdog service that monitors the Spark process and re-launches it if absent.
- [ ] Deliver ready-to-import firewall/registry policy bundles (with rollback instructions) plus troubleshooting steps for environments where security tools revert those settings.
- [ ] Extend ops runbooks with procedures for investigating watchdog telemetry, validating firewall/registry state via scripted checks, and coordinating with SOC teams when drift is detected.
- [ ] Publish guidance for deploying customer-hosted relays (placement, capacity, TLS certs) and how to monitor their health when acting as the single allowed egress path.
- [ ] Document manual/offline support workflows (e.g., exporting diagnostics, screenshots) for sites that refuse to open any outbound traffic, including expected SLAs for deferred remote assistance.
- [ ] Create a UMH-to-Spark porting checklist (build flags, dependency pruning, signed binary ingestion, telemetry mapping) and keep it updated as we migrate features.
- [ ] Define rollback procedures if the ported hook stack destabilizes `svchost` (service restart, disable flag propagation, out-of-band uninstall script).
- [ ] Train support/on-call on the new CLI overlays (SWDA/input commands) including how to interpret telemetry and when to escalate to engineering.
- [ ] Add operational runbooks for session-aware enforcement (how to clear per-session policies, interpret session-specific telemetry, and coordinate with customer security teams when automation triggers).

### UserModeHook Feature Porting (Tracking)
- [ ] Inventory UMH components (hook DLL, UnifiedAgent, SystemWideMonitor, CLI, harnesses) and decide which pieces become source imports vs. rewritten modules.
- [ ] Stand up a separate branch/build flavor that statically links selected UMH code into the Spark agent for iterative testing before merging to mainline.
- [ ] Map UMH environment variables (`MLHOOK_*`, `HOOKDLL_FORCE_*`, `UMH_TARGETS`) to Spark configuration/feature-flag equivalents and document migration guidance.
- [ ] Port UMH telemetry parsers (JSONL logs, CLI exporters) into Spark’s Go backend so the web console can display the same insights without PowerShell.
- [ ] Ensure UMH’s manual-map/direct-syscall injection code adheres to Spark’s threat model (service permissions, AV/EDR posture) and document any deviations or mitigations.
- [ ] Port the Session & Identity Protection plan: ensure Spark captures session IDs/SIDs, stores enforcement state per session, and exposes CLI/API hooks to inspect and override that state.

---

**Next Actions**

1. Review/augment this SSOT with additional TODOs or constraints.
2. Prioritize Foundation + Streaming tasks for the first implementation sprint.
3. Assign owners per section and start tracking progress in project management tooling.

---

## Appendix – UMH Porting Blueprint (Single-EXE Alignment)

### Objectives
1. Embed UMH’s multi-layer hook engine (SetWindowDisplayAffinity, BlockInput, DirectX/DirectInput) inside the Spark `svchost` agent without extra binaries.
2. Preserve UMH’s automation loop (session-aware enforcement, telemetry, auto-heal) while adapting the control plane to Spark’s Go runtime.
3. Recreate UMH’s operator tooling (CLI verbs, telemetry schema) directly in Spark so portal-built agents expose the same diagnostics.
4. Honor Spark constraints: single EXE under `C:\ProgramData\Spark`, watchdog-enforced service, outbound-only networking.

### UMH Components to Vendor
| Component | Purpose in Spark | Notes |
| --- | --- | --- |
| `src/MultiLayerHook.*`, `src/HookEngine.*`, MinHook | Core inline/IAT/EAT/VEH/syscall detours + auto-heal | Build as static lib, expose C ABI |
| `src/GlobalHook.cpp`, `src/InputProtection.*` | SWDA + keyboard suppression bypass | Enforce `WDA_NONE`, `BlockInput(FALSE)` |
| `src/GraphicsHooks/*`, `docs/DirectXHooks.md` | D3D9/11/12, DXGI, Vulkan, Win32 Graphics Capture | Feed capture telemetry and policy |
| `SystemWideMonitor` policy logic | Session-aware enforcement per PID/session | Replace pipe-based control with Go bridge |
| Telemetry schema / CLI exporters | Logging & operator UX | Emit via Spark telemetry to server/UI |
| Harness/validation (`test/MultiLayerHookHarness.cpp`, `tools/RunWinDbgValidation.ps1`) | Regression coverage | Run in Spark Windows CI |

### Integration Strategy
1. **Build & Packaging**
   - Create CMake preset producing `libspark_umh.a` (x64, `/guard:cf`, `/MT`, no DLLs).
   - Add Go `hookbridge` package that links via cgo and exports `Init`, `ApplyPolicy`, `Shutdown`.
   - Embed any unavoidable helper binaries as PE resources, materialize under ProgramData temporarily, and clean up.
   - Update Windows build pipeline to invoke the UMH CMake step before `go build`.
2. **Control Plane**
   - Reimplement UMH `PolicyState` in Go (`pkg/policy/session`), keyed by PID + session.
   - Replace named pipes with direct cgo calls when Spark toggles enforcement.
   - Capture session ID (ProcessIdToSessionId) + user SID per target process; store alongside remote desktop session context.
   - Desktop session manager acquires/releases hooks per viewer session to avoid global injection.
3. **Telemetry & UX**
   - Mirror UMH JSON fields (`event`, `func`, `session`, `sid`, `policy`, counters) and send through Spark telemetry for UI banners.
   - Extend web console with enforcement indicators and one-click Force Input/Capture controls.
   - Persist telemetry in server DB for SOC triage; expose APIs mirroring UMH CLI workflows.
4. **Testing**
   - Vendor UMH’s `MultiLayerHookHarness` and run it during `go test` (Windows only).
   - Integrate `RunWinDbgValidation.ps1` into CI (CFG on/off, VEH toggles) before release.
   - Simulate console + RDP sessions in automated tests to confirm policy selects correct targets.

### Delivery Phases
| Phase | Deliverables |
| --- | --- |
| 0 – Feasibility | License review, file list, prototype static linking & cgo bridge. |
| 1 – Core Embed | Hook engine + SWDA/BlockInput detours embedded, telemetry reaching Go logs. |
| 2 – Session Policy | Port policy table/session metadata, auto-enforce with hysteresis, minimal UI alerts. |
| 3 – Graphics Hooks | Integrate DirectX/Vulkan capture detours & telemetry; align with streaming path. |
| 4 – Operator UX | Full console controls/CLI parity, audit logging. |
| 5 – Hardening & CI | WinDbg matrix, soak/stress, signed builds, operational runbooks. |

Each phase ships behind feature flags for staged tenant rollout.

### Risks & Mitigations
1. **`svchost` limits:** Validate manual-map + VEH layers within existing service descriptors; add kill switches if incompatible.
2. **Binary size:** Track EXE growth; trim unused UMH modules; enforce ProgramData disk budgets.
3. **EDR friction:** Document policy toggles to disable intrusive layers; coordinate with customer security for allowlists.
4. **Telemetry volume:** Rate-limit hook events or aggregate before forwarding to server.
5. **Maintenance:** Assign owners for vendored code, track upstream diffs, and enforce formatting/lint to avoid drift.

### Immediate Actions
1. Prototype Windows build that links the UMH static lib (even if hooks are inert) to validate toolchain.
2. Draft HookBridge cgo interface plus serialization for policy/telemetry.
3. Implement Go helpers to capture session ID + SID and tag desktop processes accordingly.
4. Wire UMH harness + WinDbg scripts into CI, publishing logs under `artifacts/umh`.
5. Socialize this appendix with stakeholders and assign owners per phase before enabling any feature flags.
- [ ] Identify and import the minimum UMH source set needed for SetWindowDisplayAffinity + BlockInput enforcement (e.g., GlobalHook.cpp, HookDLL.cpp, MultiLayerHook.cpp) and verify build parity under cgo.
- [ ] Replace the temporary `spark_umh_windows.c` stub with a C++ bridge that calls the real UMH hook engine, wiring Spark's policy flags (`forceInput`, `forceCapture`) into UMH policy toggles.
- [ ] Ensure the vendored UMH sources compile with `/std:c++17`, `/guard:cf`, `/MT`, and the existing service constraints, updating the Go cgo directives accordingly.
