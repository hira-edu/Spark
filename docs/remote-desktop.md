# Remote Desktop Pipeline

Single reference for how the current desktop streaming stack behaves across agent, server, and browser. This captures the as-is implementation before WebRTC/input work begins.

## Architecture Overview

- **Agent (`client/service/desktop`)** – Captures the active display (DXGI/GDI on Windows, screenshot lib elsewhere), diffs frames into 96px blocks, and pushes binary chunks over the control socket. A per-session metrics reporter samples FPS, queue depth, and encoder errors and emits `DESKTOP_METRICS`.
- **Server (`server/handler/desktop`)** – Terminates the browser WebSocket, relays binary diff packets from the agent, handles control actions (`PING`, `SHOT`, `KILL`), and now logs telemetry received via `DESKTOP_METRICS`.
- **Browser (`web/src/components/desktop/desktop.jsx`)** – Opens the WS tunnel, decrypts JSON control frames, reassembles diff chunks into a canvas, exposes manual refresh/fullscreen, and sends pings/shot requests.

```mermaid
flowchart LR
    Browser["Web UI\nReact Canvas"]
    Server["Spark Server\nDesktop Handler"]
    Agent["Spark Agent\nDesktop Service"]
    Browser <-->|WS (service 20)| Server
    Server <-->|Event Packets| Agent
    Agent -->|RAW diff chunks| Server
    Agent -->|DESKTOP_METRICS| Server
```

## Session Lifecycle

```mermaid
sequenceDiagram
    participant Operator
    participant Browser
    participant Server
    participant Agent
    Operator->>Browser: Open remote desktop modal
    Browser->>Server: GET /api/device/desktop (WS, secret, device)
    Server->>Browser: 101 + session keys
    Server->>Agent: DESKTOP_INIT {desktop: uuid}
    Agent->>Server: DESKTOP_INIT (code=0) or QUIT on failure
    Agent->>Agent: Start capture worker + session goroutines
    Agent-->>Server: Binary RAW_DATA frames (op=0/1/2)
    Server-->>Browser: Forward RAW chunks to canvas
    loop Every second
        Browser->>Server: DESKTOP_PING (keep-alive)
        Server->>Agent: DESKTOP_PING relay
    end
    Browser->>Server: DESKTOP_SHOT (full refresh)
    Server->>Agent: DESKTOP_SHOT relay
    Agent->>Server: DESKTOP_METRICS snapshot (5s cadence or on activity)
    Server->>Logs: DESKTOP_METRICS event (fps, queue, encoder errors)
    Agent->>Server: DESKTOP_QUIT when session closes
    Server->>Browser: QUIT + socket close
```

## Streaming Path & Packet Format

- **Capture loop** (`worker`) locks to one OS thread, uses DXGI Output Duplication when available (falls back to GDI/screenshot), caps FPS at 24, and keeps a shared `prevDesktop` buffer for diffing.
- **Diff encoding** – Each frame is split into up to `96x96` regions. A `diff` contains one or more blocks; each block is a 12-byte header (length, type, x/y, w/h) plus either raw BGRA or JPEG-compressed bytes (`image/jpeg` @ quality 70). Op codes:
  - `0x00` first chunk of a frame, `0x01` continuation chunks.
  - `0x02` resolution broadcast, `0x03` encrypted JSON control.
- **Transport** – Agent sends binary frames via `common.WSConn.SendData` (service 20). Server simply re-tags the payload and writes to the browser WebSocket (`desktop.srcConn.WriteBinary`). Browser stitches blocks directly into a `<canvas>` 2D context.
- **Back-pressure** – Each session keeps a channel buffer of 5 frame messages. When the buffer is full we drop the oldest entry (viewers skip frames rather than stall) and the metrics reporter increments `queueDrops`.

## Control, Telemetry, and Failure Handling

- **Control Plane** – Browser emits JSON commands (PING, SHOT, KILL) over op=0x03 frames. Server validates, then forwards to the agent over the existing event UUID. Agent responds with JSON (WARN/QUIT) or full-frame refreshes.
- **Metrics** – Every session now maintains per-interval counters (frames, bytes, diff blocks, queue depth, queue drops, encoder errors). Every 5s—or sooner if new data arrives—the agent sends `DESKTOP_METRICS` containing these raw counters plus the measurement interval and timestamp. Server consumes them and logs derived values (FPS, bandwidth, queue pressure, encoder error streaks) under the `DESKTOP_METRICS` event.
- **Operator HUD** – The server now forwards the derived telemetry back to the browser, and the React modal surfaces it (agent FPS/bandwidth/queue health) so operators can compare local rendering with device-side performance in real time.
- **Failure Modes** – Capture errors (DXGI timeouts, BitBlt failures) increment a shared counter. After 10 consecutive failures the agent calls `quitAllDesktop`, notifies every viewer with a `DESKTOP_QUIT`, and logs the error. Browser automatically warns users if the socket drops or upon explicit QUIT packets.

## Capability Negotiation

- **Schema** – At session creation the agent emits a versioned `DESKTOP_CAPS` packet describing transports (`ws-diff`), capture stack (primary backend, fallbacks, FPS/block settings, current resolution), encoder set (software JPEG @ quality 70), and input features (currently disabled). The payload also includes agent metadata (OS/arch/commit) and feature flags (`diff-jpeg:v1`, `metrics:v1`).
- **Server Handling** – `server/handler/desktop` logs and caches the latest capability payload per session, then forwards it to the browser via JSON so the UI can present operator-friendly summaries.
- **UI Surface** – `web/src/components/desktop/desktop.jsx` listens for `DESKTOP_CAPS`, updates the modal title with capture/encoder tags, and renders a compact banner showing capture backend, encoder pipeline, and active transport. This keeps operators aware of the exact transport path and encoder quality before we introduce WebRTC or hardware codecs.

This document should be kept up to date as we introduce WebRTC transport, input injection, audio, and expanded policy gates.

## Multi-Monitor Control

- **Enumeration API** – Agents expose `DESKTOP_MONITORS`, returning every active display (index, resolution, primary flag) and the currently selected display index. The server simply relays requests between browser and device, adding auditing metadata.
- **Selection Flow** – The browser issues `DESKTOP_SET_MONITOR` with the desired index. The agent reconfigures the capture worker in place (DXGI/GDI or screenshot fallback), resets diff buffers, rebroadcasts resolution packets, and acknowledges the change; no session restart is required.
- **UI** – A dropdown in the desktop modal header shows all displays and allows hot switching. Operators see the active display summarized in the capability HUD, alongside capture/encoder/transport metadata for quick validation.

## Quality Presets

- **Preset Catalog** – The agent exposes three presets (`High Fidelity`, `Balanced`, `Bandwidth Saver`) that tune JPEG quality and FPS caps. Presets are included in every `DESKTOP_CAPS` payload along with the currently selected value.
- **Runtime Switching** – When the browser emits `DESKTOP_SET_QUALITY`, the agent atomically updates capture settings, applies them to the shared worker loop (affecting diff encode quality and capture delay), and acknowledges with the refreshed preset metadata so the UI can reflect the active mode.
- **UI Integration** – A second dropdown in the modal banner lets operators flip between presets while watching the agent FPS/bandwidth HUD, making it easy to trade fidelity for responsiveness without restarting sessions or reinstalling the agent.

## Input Pipeline (Phase 0)

- **Browser Capture Layer** – When operators enable control, the canvas now captures mouse down/up/move/wheel events, normalizes coordinates to remote pixels, and sends them via `DESKTOP_INPUT` messages (throttled with `requestAnimationFrame` for moves).
- **Keyboard & Clipboard** – Key down/up events now travel through the same pipe, landing in the Windows agent where they’re injected via `keybd_event`. Operators can also push/pull clipboard text using new toolbar buttons; the agent writes/reads the OS clipboard via `github.com/atotto/clipboard`.
- **Server Relay** – The desktop handler forwards `DESKTOP_INPUT`, `DESKTOP_CLIPBOARD_PUSH`, and `DESKTOP_CLIPBOARD_PULL` packets straight to the agent alongside the existing session UUID plumbing, keeping observability hooks in place for future rate limiting/auditing.
- **Agent Hooks** – Pointer/keyboard packets are injected via the new `client/service/input` module (SendInput today, UMH later) with micro-throttling on high-frequency pointer move spam. Clipboard packets read/write text, enforce per-direction cooldowns, and send browser-friendly acknowledgements so the UI can keep operators in sync.

## UMH Porting Scaffold (WIP)

- **Hook bridge:** `client/service/desktop/hookbridge` provides a stub Go interface (`Init`, `ApplyPolicy`, `Shutdown`) that future cgo bindings will use to drive the vendored UserModeHook engine. The bridge currently gates itself via `SPARK_EXPERIMENTAL_UMH=1`, logs every policy request, and exposes a telemetry sink hook for the Go runtime.
- **Session metadata helper:** `client/internal/winsession` resolves `ProcessIdToSessionId`, SID, and user name so the agent can tag capability packets with session context and eventually drive session-aware enforcement.
- **Desktop service integration:** `client/service/desktop/desktop.go` now auto-initializes the hook bridge (once per process), attaches session/SID metadata to `DESKTOP_CAPS`, and sends a stub policy message per viewer connection. A Windows-only policy manager (`client/service/desktop/policy.go`) tracks these session policies and automatically unregisters them whenever sessions end (Kill, QUIT, health-check cleanup, or panic teardown), ensuring the future native bridge gets clean lifecycle events.
- **Native bridge scaffold:** `client/native/umh/include/spark_umh.h` plus the new cgo path in `client/service/desktop/hookbridge/hookbridge_native_windows.go` provide a landing zone for the real UMH engine. The interim implementation (`spark_umh_windows.c`) already disables `SetWindowDisplayAffinity` across all windows and clears `BlockInput` locks whenever a session requests enforcement, so we get immediate value while we port the full UMH hook stack.
