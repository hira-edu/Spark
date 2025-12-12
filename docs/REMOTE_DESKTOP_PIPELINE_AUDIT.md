# Remote Desktop Pipeline Audit

This living document is the **single source of truth** for the Rocket remote desktop capture → render pipeline. Rocket is the direct, fully-upgraded successor of Spark, so Spark is only referenced for historical context—parity efforts now target production-grade OSS stacks (Sunshine, RustDesk, Guacamole) instead of our legacy fork.

## Current Pipeline (Rocket)

| Stage | Responsibility | Key Paths | Notes / Best Practices |
|-------|----------------|-----------|------------------------|
| Browser Viewer | Establishes WS connection, renders frames on `<canvas>`, handles reconnection & stats | `web/src/components/features/desktop/hooks/useDesktopStream.js` | Uses magic header validation, pending-frame buffer, block versioning, latency/FPS stats, clipboard/file-drop limits, and reconnect backoff. Validate telemetry coverage (block stats, RTT split, share-token error paths) and ensure pending-frame buffer bounds align with device pacing. |
| Server Broker | Authenticates WS, validates origin, fans out device packets to browser, rate-limits control payloads | `server/handler/desktop/desktop.go` | Melody config extends Pong/Write timeouts (120s/30s), `ValidateWebSocketOrigin` enforces CSWSH rules, clipboard/cursor/file-drop payload caps exist. Need structured telemetry for frame relay failures, share-link policy checks, and instrumentation for per-session device heartbeat results. |
| Device Session Core | Tracks sessions, channels, adaptive quality, per-session cursor state | `client/service/desktop/desktop.go` | Maintains `framesDropped`, `framesDelivered`, `channelHighWater`, global adaptive quality manager fed by RTT + pending bytes. Ensure metrics are exported (currently tracked but unused) and that backpressure enforcement is traced so we can correlate with browser stats. |
| Capture Paths | DXGI/GDI (Windows), X11/XCB (Linux), CoreGraphics (macOS) capture loops | `client/service/desktop/desktop_windows.go`, `desktop_others.go`, etc. | DXGI path picks per-monitor DPI contexts and adaptive timeouts derived from FPS; falls back to GDI. Audit surface: multi-monitor bounds, dpi awareness, handle cleanup, GPU availability logging. |
| Codec / Packing | JPEG/RAW default, optional HW codecs (VP8/9/H.264) gated by build tags | `client/service/desktop/codec.go`, README codec section | `Codec` interface allows runtime switching, but stats/telemetry not wired back to server dashboards. Need deterministic codec selection per network hints and degrade gracefully when libvpx absent. |
| Input Injection | Translate WS control events to OS-specific APIs | `client/service/desktop/input_*.go`, server `maxDesktopInputBatch` | Windows path uses `SendInput`, DPI-aware pointer normalization, wheel delta conversions. Ensure share/view-only enforcement is respected before injecting events; consider rate-limiting or jitter smoothing. |
| WebRTC Fast Path | Optional WebRTC transport with VP8/VP9, SCTP data channel reuse | `client/service/desktop/webrtc.go` | Loads STUN/TURN via `SPARK_WEBRTC_*`, uses Pion interceptors for SRTP/NACK/TWCC, but default builds lack VPX encoder. Need environment parity between Rocket and Spark deployments plus TURN credential rotation guidance. |

## Spark Heritage (Historical Reference Only)

**Source located:** [XZB-1248/Spark](https://github.com/XZB-1248/Spark) on GitHub.

### Parity Check Complete (2024-12-07)

| Feature | Spark (Original) | Rocket (Fork) | Status |
|---------|------------------|---------------|--------|
| **WebRTC** | ❌ Not implemented | ✅ Full Pion v4 stack | **Major addition** |
| **Codec** | JPEG only (q=70) | JPEG + ProxyCodec (VP8/H.264 stubs) | Extended |
| **Block size** | 96x96 fixed | Configurable via adaptive quality | Improved |
| **FPS** | 24 fps fixed | Adaptive based on RTT | Improved |
| **Telemetry** | None | Prometheus + DESKTOP_METRICS | **Major addition** |
| **Session timeout** | 30s hardcoded | Configurable | Improved |
| **Input rate limiting** | None visible | Token bucket (200/s) | **Security addition** |
| **View-only mode** | Basic | Multi-layer defense | Enhanced |

**Spark desktop.go analysis:**
- JPEG encoding at quality 70
- 96x96 block-based differential frames
- Checkerboard scanning (alternating rows) for change detection
- Binary protocol: `Magic(5B)|OpCode(1B)|EventID(16B)|BodyLength(2B)|ImageType(2B)|X(2B)|Y(2B)|W(2B)|H(2B)|Data`
- XOR encryption with WebSocket secret keys
- 3-frame buffer with overflow dropping

**Conclusion:** Rocket has diverged significantly from Spark with WebRTC, telemetry, security hardening, and now pre-DWM capture plumbing. Rocket _is_ the upgraded Spark, so no further Spark-specific parity work is required; the remainder of this audit focuses on Sunshine/RustDesk/Guacamole feature gaps.

## Reference OSS Projects

* **RustDesk** – TCP transport with custom hole punching (not QUIC yet), rendezvous server for peer discovery, relay fallback. Highlights gap in Rocket's P2P capability.
* **Sunshine** – NVFBC/AMF/VAAPI zero-copy capture and HEVC/AV1 streaming. Emphasizes per-monitor QoS, capability negotiation, telemetry for encode latency.
* **Apache Guacamole / noVNC** – Mature RBAC, multi-protocol bridging, tile caching. Use as reference for recording/audit logging requirements.

---

## Parity Implementation Roadmap (Research Complete: 2024-12-07)

### Sunshine GPU Capture Architecture

**Source:** [LizardByte/Sunshine](https://github.com/LizardByte/Sunshine)

**Capture Dual-Path Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                     Sunshine Capture Flow                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │   VRAM Path      │    │   RAM Path       │                   │
│  │ (Zero-Copy)      │    │ (Fallback)       │                   │
│  └────────┬─────────┘    └────────┬─────────┘                   │
│           │                       │                              │
│           ▼                       ▼                              │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │ NVFBC (NVIDIA)   │    │ DXGI Duplication │                   │
│  │ Direct GPU read  │    │ CPU readback     │                   │
│  └────────┬─────────┘    └────────┬─────────┘                   │
│           │                       │                              │
│           ▼                       ▼                              │
│  ┌──────────────────────────────────────────┐                   │
│  │        Hardware Encoder Selection         │                   │
│  │  NVENC → AMF → VAAPI → QSV → Software    │                   │
│  └────────────────────┬─────────────────────┘                   │
│                       │                                          │
│                       ▼                                          │
│  ┌──────────────────────────────────────────┐                   │
│  │         FFmpeg hwframe APIs              │                   │
│  │  av_hwframe_get_buffer()                 │                   │
│  │  av_hwframe_transfer_data()              │                   │
│  └──────────────────────────────────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1 Progress — Backend Registry + Telemetry (2024-12-08)

| Component | Path | Notes |
|-----------|------|-------|
| Capture backend config | `client/service/desktop/capture_backend.go`, `control.go` | New `capture` field in `DESKTOP_CONFIG` (values: `auto`, `nvfbc`, `dxgi`, `gdi`, `pipewire`, `x11`). ACK payload now includes both requested (`capture_backend`) and active (`capture_backend_active`) names so operators / UI components can display the resolved backend. |
| Windows selection logic | `client/service/desktop/desktop_windows.go` | Mirrors Sunshine’s “best effort” order (NVFBC → DXGI → GDI). Structured telemetry records every fallback, increments `dxgiFallbackCount`, and probes for NVFBC by lazily loading `NvFBC64.dll`/`NvFBC.dll`. |
| CaptureFrame abstraction | `client/service/desktop/capture_frame.go`, `desktop.go` | Worker now receives a `CaptureFrame` (CPU image + optional GPU surface metadata). This is the zero-copy hook Sunshine uses to feed NVENC/VAAPI without additional refactors—future GPU encoders can use `frame.GPU.Resource` while JPEG/WebSocket path keeps `frame.Image`. |
| Cross-platform backend state | `desktop_*.go` | Non-Windows builds tag their backend (`screenshot`, `pipewire`, etc.) via `setActiveCaptureBackend`, so telemetry and `/metrics` endpoints report the exact capture path per platform. |

**Sunshine Parity Delta:** Sunshine exposes backend/encoder decisions via the UI; Rocket now matches that observability and provides the config entry point. What remains is wiring the NVFBC capture implementation, propagating GPU textures to hardware codecs, and adding the Linux PipeWire/VAAPI leg so QUIC/WebRTC paths can select optimal transports per endpoint capability.

**Key Patterns to Port:**

1. **Hierarchical Encoder Probing:**
   ```cpp
   // Sunshine probes in order: NVENC → AMF → VAAPI → QSV → Software
   // Each probe records success/failure reason for telemetry
   auto encoder = probe_nvenc();
   if (!encoder) encoder = probe_amf();
   if (!encoder) encoder = probe_vaapi();
   if (!encoder) encoder = probe_software();
   ```

2. **Zero-Copy Buffer Flow:**
   ```cpp
   // NVFBC path: GPU texture → encode without CPU copy
   AVFrame* hw_frame = av_frame_alloc();
   av_hwframe_get_buffer(hw_ctx, hw_frame, 0);
   // Encode directly from GPU memory
   avcodec_send_frame(encoder, hw_frame);
   ```

3. **HDR/MPO Support:**
   - Sunshine handles HDR10/HLG metadata passthrough
   - MPO (Multi-Plane Overlay) protected desktop capture via NVFBC
   - Requires driver-level permissions on Windows

**Implementation Plan for Rocket:**

| Phase | Task | Effort | Dependencies |
|-------|------|--------|--------------|
| 1 | Add `codec_hw_windows.go` with NVENC probe | 8h | CGO, FFmpeg libs |
| 2 | Add `codec_hw_linux.go` with VAAPI probe | 8h | CGO, libva |
| 3 | Integrate hwframe buffer pool | 4h | Phase 1-2 |
| 4 | Wire encoder selection to `DESKTOP_CONFIG` | 4h | Phase 3 |
| 5 | Add HDR metadata passthrough | 8h | Phase 4, browser support |

**Files to Create/Modify:**
- `client/service/desktop/codec_hw_windows.go` — NVENC/AMF probing
- `client/service/desktop/codec_hw_linux.go` — VAAPI/QSV probing
- `client/service/desktop/hwframe_pool.go` — Zero-copy buffer management
- `client/service/desktop/codec.go` — Integrate HW codecs into `SelectOptimalCodec()`

---

### RustDesk Transport Architecture

**Source:** [rustdesk/rustdesk](https://github.com/rustdesk/rustdesk)

**Important Correction:** RustDesk does NOT use QUIC for its main transport (as of December 2024). It uses TCP with custom hole punching.

**Connection Flow:**
```
┌─────────────────────────────────────────────────────────────────┐
│                   RustDesk Connection Model                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐     ┌────────────────┐     ┌──────────┐          │
│  │  Client  │────►│  Rendezvous    │◄────│  Host    │          │
│  │          │     │  Server        │     │  Device  │          │
│  └────┬─────┘     └───────┬────────┘     └────┬─────┘          │
│       │                   │                    │                 │
│       │  1. Register      │   1. Register      │                 │
│       │  ◄────────────────┤────────────────►   │                 │
│       │                   │                    │                 │
│       │  2. Request peer  │                    │                 │
│       │  ─────────────────►                    │                 │
│       │                   │  3. Notify host    │                 │
│       │                   │  ─────────────────►│                 │
│       │                   │                    │                 │
│       │  4. Exchange NAT info                  │                 │
│       │  ◄─────────────────────────────────────►                 │
│       │                                        │                 │
│       │  5. TCP Hole Punching                  │                 │
│       │  ◄─────────────────────────────────────►                 │
│       │     (or fallback to relay)             │                 │
│       │                                        │                 │
└───────┴────────────────────────────────────────┴─────────────────┘
```

**Key Patterns to Port:**

1. **Rendezvous Protocol:**
   - Central server for peer discovery (like STUN but for TCP)
   - Stores client NAT type and external IP:port
   - Facilitates peer exchange for hole punching

2. **TCP Hole Punching:**
   ```rust
   // Both peers simultaneously connect to each other's external IP:port
   // Works for cone NATs, fails for symmetric NATs
   async fn punch_hole(peer_addr: SocketAddr) -> Result<TcpStream> {
       let socket = TcpSocket::new_v4()?;
       socket.set_reuse_addr(true)?;
       socket.bind(local_addr)?;
       // Simultaneous connect attempts
       timeout(Duration::from_secs(5), socket.connect(peer_addr)).await
   }
   ```

3. **Relay Fallback:**
   - If hole punching fails (symmetric NAT), traffic routes through relay
   - Relay adds ~50-100ms latency vs direct
   - RustDesk charges for relay bandwidth (business model)

**Implementation Plan for Rocket:**

| Phase | Task | Effort | Dependencies |
|-------|------|--------|--------------|
| 1 | Design rendezvous protocol (gRPC or WS) | 4h | Protocol design |
| 2 | Implement rendezvous server | 16h | Phase 1 |
| 3 | Add TCP hole punching to client | 8h | Phase 2 |
| 4 | Add relay fallback mode | 8h | Existing WS transport |
| 5 | NAT type detection (STUN-based) | 4h | Phase 2 |
| 6 | Document transport selection logic | 4h | Phase 3-5 |

**Files to Create:**
- `server/handler/rendezvous/rendezvous.go` — Peer registration and exchange
- `client/transport/holepunch.go` — TCP hole punching logic
- `client/transport/selector.go` — Transport selection (direct vs relay vs WS)
- `docs/P2P_ARCHITECTURE.md` — Transport selection documentation

**Transport Selection Matrix:**

| NAT Type (Client) | NAT Type (Host) | Strategy | Expected Latency |
|-------------------|-----------------|----------|------------------|
| Cone | Cone | Direct (TCP punch) | <20ms |
| Cone | Symmetric | Relay | +50-100ms |
| Symmetric | Cone | Relay | +50-100ms |
| Symmetric | Symmetric | Relay | +50-100ms |

---

### Phase 1 Deliverable — Rendezvous MVP (2024-12-10)

**Goal:** Mirror RustDesk's peer-discovery service so Rocket devices can advertise both direct and relay endpoints without depending on the legacy desktop WebSocket broker. Phase 1 ships a scoped, in-memory service that client/relay engineers can build against while we design persistence and HA topology.

**API surface** (`/p2p/rendezvous/*`, mounted on the authenticated router group):

| Endpoint | Method | Purpose | Key validation |
|----------|--------|---------|----------------|
| `/register` | POST | Host publishes endpoints + metadata, receives opaque `token` | 1–4 endpoints allowed, each `protocol/host/port` required. Metadata (NAT hints, relay tier, adapter info) stored verbatim. |
| `/heartbeat` | POST | Refresh TTL for an existing peer | Validates `peer_id` + `token`, rejects expired peers. |
| `/request` | POST | Viewer/service fetches peer endpoints for hole punching | Returns peer ID, endpoints, metadata, and UTC last_seen. |
| `/register` | DELETE | Explicitly deregister a peer | Requires valid token and emits `RENDEZVOUS_DEREGISTER` telemetry. |

**Runtime characteristics:**
- `peerTTL = 2m`, cleanup ticker every 30s, matching RustDesk's expectation that clients heartbeat roughly once per minute.
- Crypto-secure 16-byte tokens (hex-encoded) prevent guessing; no shared secrets necessary.
- `maxEndpointsPerPeer = 4` bounds payload size while supporting direct+relay combos.
- Structured logging (`RENDEZVOUS_REGISTER`, `_DEREGISTER`) plus OTEL context provide forensic trails for peer lifecycle events.
- `RegisterRoutes()` now wired into `server/handler/handler.go` so only authenticated devices/admins can touch rendezvous APIs.

**Regression coverage:** `server/handler/rendezvous/rendezvous_test.go` exercises register/request/heartbeat HTTP flows via Gin's httptest harness and negative cases (empty endpoint list, missing peer IDs). These tests protect the MVP as we evolve persistence and ACL layers.

**Next steps:**
1. Persist the registry (Redis/Postgres) and introduce multi-node cleanup coordination (Phase 2).
2. Surface NAT-detection metadata + relay costs in responses and teach clients to select transports accordingly (Phases 3-5).
3. Extend `request` responses to surface relay auth material so viewers can fall back without going through the desktop WebSocket service.

### Phase 2 Deliverable — Mongo-backed Rendezvous Store (2024-12-11)

**Objective:** Keep rendezvous peers online across controller restarts and clustered deployments by persisting state to MongoDB while still supporting lightweight single-node installs.

**What shipped:**

| Area | Details | Paths |
|------|---------|-------|
| Pluggable store | Introduced `peerStore` abstraction with MongoDB + in-memory implementations selected lazily at runtime. | `server/handler/rendezvous/store.go` |
| Persistence | Peers are stored in `rendezvous_peers` with unique `peer_id`, TTL index on `last_seen`, and a cleanup ticker to cover TTL lag. Tokens + metadata survive controller restarts. | `mongoPeerStore.Upsert/Lookup/Delete` |
| API behavior | HTTP handlers now emit consistent errors (`peer not found`, `token mismatch`, `peer expired`) regardless of backend, and telemetry logs capture persistence failures. | `server/handler/rendezvous/rendezvous.go` |
| Tests | Reworked `rendezvous_test.go` to exercise the store abstraction, providing deterministic in-memory stores for handler tests while the real server uses MongoDB when available. | `server/handler/rendezvous/rendezvous_test.go` |

**Impact:** Rendezvous tokens no longer evaporate when controllers restart, and multi-controller clusters can share the same MongoDB-backed registry. This unblocks the next RustDesk parity phases (hole punching + relay fallbacks) because the discovery service is now highly available without adding new dependencies for operators who run without MongoDB.

---

### Guacamole/noVNC Parity (Reference Only)

**Key Features to Port:**

1. **Session Recording:**
   - Server-side frame capture to video file
   - Searchable timeline with keyframes
   - Compliance audit requirement for many enterprises

2. **RBAC Granularity:**
   - Separate permissions: view, keyboard, mouse, clipboard, file transfer
   - Time-based access windows
   - IP allowlisting per share

3. **Audit Logging:**
   - Every input event logged with timestamp
   - Clipboard content hashed (not stored in plain text)
   - File transfer manifest with checksums

**Note:** Guacamole parity is lower priority than Sunshine/RustDesk as current Rocket implementation already has basic view-only and rate limiting.

## TODO Checklist

- [x] **Document pipeline overview** — Capture end-to-end flow (this document) so audits have a shared source of truth.
- [x] **Instrument frame-drop/backpressure metrics** — Prometheus counters/gauges now track drops/delivery/high-water locally and a metrics reporter (`client/service/desktop/metrics_reporter.go`) emits `DESKTOP_METRICS` snapshots. The server stores snapshots and exposes `/api/device/desktop/metrics?desktop=<uuid>` for operators.
- [x] **Server telemetry & policy validation** — `server/handler/desktop/desktop.go` now emits OTEL events for every handshake outcome, aggregates counters for attempts/success/failures, heartbeats, and frame-relay drops, and logs view-only blocks via `blockControlAction`. The same handler enforces `allowControl` on clipboard/file-drop/audio/WebRTC operations and records each denial via `recordDesktopPolicyViolation()`.
- [x] **Spark parity check** — **Complete.** Source at [XZB-1248/Spark](https://github.com/XZB-1248/Spark). Rocket has diverged significantly: added WebRTC (Pion v4), Prometheus telemetry, adaptive quality, input rate limiting, and multi-layer view-only enforcement. No merge-back needed—Rocket supersedes Spark. See [Parity Check](#parity-check-complete-2024-12-07).
- [x] **Codec selection hardening** — `ProxyCodec` now records explicit fallback reasons, `DESKTOP_CONFIG_ACK` responses bubble those warnings back to the browser (`client/service/desktop/control.go`), and `GetCodecStats()`/`DESKTOP_STATS` carry `codec_fallback_reason` so Prometheus/Grafana can alert (“requested h264 → using jpeg (hardware encoder unavailable)”). The NetBird/Sunshine-style capability negotiation is therefore visible end-to-end, and operators immediately know when libvpx/NVENC is missing.
- [x] **Input-control enforcement** — **Defense-in-depth verified:** View-only enforcement at server (`share.go:792-871` for all control actions) AND client (`input.go:78-80`). **Payload limits:** `maxClipboardBytes=64KB`, `maxFileDropEntries=5`, `maxFileNameLength=255`, `maxDesktopInputBatch=32`, `maxCursorDataSize=~262KB`. **Rate limiting:** Token bucket at 200 events/sec with burst of 100 (`share.go:803`). **Code smell:** Duplicate constants in `desktop.go` and `share.go`—consider centralizing. **Regression coverage:** `server/handler/utility/limits_test.go` now exercises SDP/ICE/clipboard/file-name clamps, and `server/handler/desktop/desktop_test.go` hardens `normalizeCursor` against over-sized payloads.
- [x] **WebRTC/TURN best practices** — **Complete.** Core security in place: SRTP/DTLS via Pion interceptors, NACK/TWCC, `MaxBundle`, symmetric NAT auto-detection. **Documented:** TURN credential rotation (RFC 8656), sample `.env`, coturn integration guide with ephemeral credentials. See [coturn Integration Guide](#coturn-integration-guide) and [TURN Credential Rotation](#turn-credential-rotation-best-practices). **Known gaps (accepted risk):** No ICE candidate privacy filtering (mDNS/IP masking).
- [x] **Full regression test suite (Chromium + headless)** — **Complete.** Playwright now drives Rocket against the standalone mock desktop server launched via `go run test_client.go --mock-desktop --mock-standalone --mock-port 18081`. The mock exposes `/mock/*` HTTP controls (init, resolution, frame, events, disconnect) plus a compatible `/mock-desktop` WebSocket, so browser code exercises the exact binary protocol without a real agent. `web/e2e/fixtures/mockDevice.js` reroutes desktop/share sockets to the mock endpoint, records input telemetry, and provides helpers consumed by `web/e2e/desktop.spec.js` (connection, reconnect, input, share token, view-only, resolution-change, and edge-case tests). `.github/workflows/e2e.yml` boots the mock, server, and Playwright suite end-to-end on CI.
- [~] **Sunshine parity (GPU capture + zero-copy encode)** — **Phase 0 shipped (2024-12-09).** Capture defaults now come from the client config trailer (see `client/service/desktop/capture_config.go`), `enable_pre_dwm` gates shared-surface use, `fallback_order` is honored verbatim, and the shared-surface loader (`client/service/desktop/shared_surface_loader_windows.go`) + backend (`desktop_windows.go`) automatically prefer `sharedSurface → NVFBC → DXGI → GDI` with telemetry every time we fall through. Remaining phases:
  - Phase 1: `codec_hw_windows.go` with NVENC probe (~8h)
  - Phase 2: `codec_hw_linux.go` with VAAPI probe (~8h)
  - Phase 3: `hwframe_pool.go` for zero-copy buffer management (~4h)
  - Phase 4: Wire to `DESKTOP_CONFIG` codec selection (~4h)
  - Phase 5: HDR metadata passthrough (~8h, requires browser support)
  - **Total effort:** ~32h | **Dependencies:** CGO, FFmpeg libs, libva
  - [x] Capture backend registry + config plumbing (auto/NVFBC/DXGI/GDI) — *this change*
  - [x] Server + generator capture controls (`desktop.capture` config + `capture_*` overrides)
  - [x] DXGI zero-copy surfaces — DXGI duplication now copies the GPU texture alongside the CPU staging buffer and exposes it through `CaptureFrame.GPU`, so NVENC/AMF work can ingest native `ID3D11Texture2D` handles without additional shims.
  - [ ] NVFBC capture path (zero-copy from VRAM, HDR-safe)
  - [x] DXGI shared-surface export + GPU frame pool — completed via `hwframe_pool.go`, which broadcasts GPU-backed frames (with COM AddRef) to registered listeners so NVENC/AMF workers can ingest textures without re-copying.
  - [ ] Linux PipeWire/VAAPI backend for Wayland + libva detection
  - [ ] Hardware codecs: NVENC (Win/Linux), AMF (Win), VAAPI/QSV (Linux) wiring
  - [ ] Browser negotiation + HDR metadata passthrough + telemetry surface
  - **Remaining effort:** ~24h (excludes plumbing already completed) | **Dependencies:** CGO, FFmpeg/libva toolchain, GPU drivers
- [~] **RustDesk parity (transport & P2P security)** — **Research complete.** See [Parity Implementation Roadmap](#rustdesk-transport-architecture). **Correction:** RustDesk uses TCP hole punching (not QUIC). Key work:
  - [x] Phase 1: Design rendezvous protocol (gRPC or WS) (~4h) — *new `server/handler/rendezvous` package exposes `/p2p/rendezvous/{register,heartbeat,request}` so hosts can publish public/relay endpoints. In-memory registry (TTL=2m) issues opaque tokens and responds with endpoint sets for authorized requesters. See `server/handler/rendezvous/rendezvous.go` plus the Gin/httptest regression coverage in `rendezvous_test.go`, which now guards register/request/heartbeat flows and validation failures.*
  - [x] Phase 2: Implement rendezvous server HA/storage (~16h) — *peer metadata now persists to MongoDB (`rendezvous_peers` collection) with TTL indexes on `last_seen`, automatic cleanup tickers, and seamless fallback to the in-memory registry when MongoDB is disabled. Controllers can restart without losing rendezvous tokens.*
  - [x] Phase 3: TCP hole punching in client (~8h) — *implemented `client/transport/holepunch.go` with SO_REUSEADDR-based simultaneous TCP connect, bidirectional punching (connect + listen), and coordinated timing via rendezvous server. Punch coordination endpoints added: `/punch/initiate`, `/punch/exchange`, `/punch/relay`.*
  - [x] Phase 4: NAT type detection (~4h) — *implemented `client/transport/nat.go` using Pion STUN library. Detects Open/FullCone/RestrictedCone/PortRestricted/Symmetric NAT types by querying multiple STUN servers and comparing external ports.*
  - [x] Phase 5: Transport selector (~4h) — *implemented `client/transport/p2p.go` with automatic transport selection based on NAT compatibility. P2P transport has priority 5 (highest), falls back to WebSocket relay for Symmetric NAT.*
  - [x] Phase 6: P2P Architecture documentation (~4h) — *see `docs/P2P_ARCHITECTURE.md` for connection flow diagrams, NAT compatibility matrix, and usage examples.*
  - [ ] Phase 7: Relay fallback integration (~4h) — *connect P2P failures to existing WebSocket transport*
  - **Total effort:** ~44h (~36h complete) | **Dependencies:** Protocol design, existing WS transport
- [ ] **Guacamole/noVNC parity (RBAC, recording, auditing)** — See [Parity Implementation Roadmap](#guacamolenovnc-parity-reference-only). Lower priority—current Rocket has basic view-only and rate limiting. Key features:
  - Session recording with searchable timeline
  - Granular RBAC (view/keyboard/mouse/clipboard/file)
  - Audit logging with input timestamps, clipboard hashing
  - **Total effort:** ~60h | **Priority:** P3 (enterprise compliance)

- [x] **Browser telemetry enhancements** — **Complete.** Implemented all three recommended additions:
  1. **DESKTOP_BROWSER_STATS export** — Block stats (rendered/failed/skipped/stale + staleRate + latency + fps) now sent to server every 5 seconds via `sendControl({ act: 'DESKTOP_BROWSER_STATS', ... })`. Enables Prometheus/Grafana correlation with server-side metrics.
  2. **Network quality classification** — New `networkQuality` state exposed ("good"/"fair"/"poor"/"unknown") based on latency (<50ms good, <150ms fair) and stale rate (<5% good, <15% fair). Thresholds based on RustDesk/Sunshine patterns.
  3. **Differentiated share errors** — WebSocket close codes 4001-4004 now map to specific user-facing messages: auth failed, token expired, token revoked, rate limited. i18n keys added for localization.
- [x] **GPU info logging on DXGI init** — `client/service/desktop/desktop_windows.go` now emits a `DXGI adapter capabilities` telemetry event whenever `ScreenDXGI` builds a duplicator, including adapter description, vendor/device IDs, LUID, VRAM totals, and the output’s desktop rectangle so ops can correlate capture fallbacks with each device’s GPU inventory.

## Debug Plan — Production Readiness Gaps (2025-02-15)

1. **Close Sunshine GPU capture parity**
   - Implement NVFBC capture (`ScreenNVFBC`) with HDR-safe zero-copy output.
   - Add hardware codec backends (`codec_hw_windows.go`, `codec_hw_linux.go`) wired into `hwframe_pool` so NVENC/VAAPI ingest DXGI/NVFBC textures without copies.
   - Deliver Linux PipeWire/VAAPI capture and HDR metadata passthrough plus operator controls/telemetry.
2. **Finish RustDesk parity Phase 7 (relay integration)**
   - Route P2P failures through the existing transport manager so relay fallbacks reuse WebSocket/QUIC behaviors.
   - Extend punch endpoints (`/p2p/punch/*`) with relay hints and health telemetry; ensure symmetric NAT -> relay works under load tests.
3. **Guacamole/noVNC compliance parity**
   - Design and ship granular RBAC, desktop session recording, and audit logging (input traces, clipboard hashing, file manifests) with operator tooling/reporting.

### Regression Harness Reliability (2024-12-07)

* Added `web/e2e/utils/mockServer.js` so Playwright can boot, respawn, and tear down the standalone mock desktop server deterministically (PID tracking, health probes, binary vs `go run` fallback). The fixture now auto-restarts the mock server if a test detects `ECONNREFUSED`.
* Browser instrumentation: every `DESKTOP_SHOT` request updates `window.__rocketDesktopDebug` (shot counter + timestamp). Tests no longer rely on patching WebSocket internals to count shot requests, reducing flake.
* Full Playwright suite (`BASE_URL=http://127.0.0.1:18080 MOCK_DEVICE_PORT=18081 npx playwright test`) now runs in ~20s against the rebuilt server image (`main.bfeaa48.js`). Console logs confirm `requesting full frame after resolution update` fires for binary and JSON paths.

**Legend:** `[x]` complete, `[~]` partial/needs follow-up, `[ ]` not started

As TODOs close, update this document with summaries, code references, and follow-up tasks.

---

## Detailed Audit Findings (2024-12-07)

### Codec Selection Audit

**Architecture:** `client/service/desktop/codec.go`

| Codec | Type | Implementation | Hardware Detection |
|-------|------|----------------|-------------------|
| Raw | 0 | Direct RGBA copy | N/A |
| JPEG | 1 | `image/jpeg` stdlib | N/A |
| WebP | 2 | **Disabled** (requires CGO) → falls back to JPEG | N/A |
| AVIF | 3 | `ProxyCodec` → JPEG fallback | N/A |
| VP8 | 4 | `ProxyCodec` → JPEG fallback | CPU features (AVX/SSE4) |
| VP9 | 5 | `ProxyCodec` → JPEG fallback | CPU features (AVX/SSE4) |
| H.264 | 6 | `ProxyCodec` → JPEG fallback | `platformHardwareProbe()` |
| PNG | 7 | `image/png` stdlib (lossless) | N/A |

**Key functions:**
- `SelectOptimalCodec(config CodecConfig)` — lines 156-211
- `DetectHardwareCodecs()` — lines 535-559
- `GetCodecStats()` — lines 569-582

**Adaptive quality:** `JPEGCodec.EnableAdaptiveQuality(aqm)` connects to `AdaptiveQualityManager` for RTT-based quality adjustment.

### Codec Fallback Hardening (2024-12-08)

**Status:** ✅ Complete. The `ProxyCodec` wrapper now mirrors RustDesk’s proven playbook by surfacing both the requested codec and the encoder that is actually being used.

**Highlights:**

1. `ProxyCodec.Name()` / `Type()` now defer to the inner encoder so frame headers always match the bytes on the wire. Requested metadata is still tracked via `ProxyCodec.RequestedName()`/`RequestedType()`.
2. `ProxyCodec.HasFallback()` emits a single structured warning with the reason (`hardware unavailable` vs `codec not built`) whenever AVIF/VP8/VP9/H.264 fall back to JPEG.
3. `DESKTOP_CONFIG_ACK` responses expose `codec_requested` and `codec_fallback`, so browsers/admin tools can communicate “requested h264, actually streaming jpeg”.
4. `GetCodecStats()` now emits `requested_codec`, `requested_codec_type`, and `codec_fallback` for Prometheus scrapers.
5. Regression coverage: `client/service/desktop/codec_test.go` ensures AVIF/H.264 proxy codecs always report JPEG as the active encoder until native codecs ship.

**Result:** No more silent mismatches—the viewer, telemetry, and operators all receive consistent, accurate codec data, and warnings fire the moment a fallback is engaged.

### Shared-Surface Capture & Config (2024-12-09)

**Objective:** Mirror Sunshine's capture flexibility by letting ops pick the exact GPU capture path (shared surface vs. NVFBC vs. DXGI vs. GDI), persist those defaults in the signed client trailer, and auto-fallback while surfacing telemetry.

**What shipped:**

1. **Config plumbing:** `client/client.go` now calls `desktop.ApplyCaptureConfig()` so launcher-provided settings land before the worker starts. `capture_config.go` parses `mode`, `enable_pre_dwm`, `fallback_order`, and `adapter_luid`, updates the backend registry, and logs structured state to DESKTOP telemetry.
2. **Backend registry:** `capture_backend.go` gained the `sharedSurface` backend, configurable fallback order storage, and per-backend enablement (`enable_pre_dwm` toggles the shared-surface flag). `backendPreferenceOrder()` now honors explicit fallback lists and keeps auto order (`sharedSurface → NVFBC → DXGI → GDI`) when allowed.
3. **Shared-surface implementation:** `shared_surface_loader_windows.go` dynamically loads `spark_capture.dll`, binds the `SparkCapture_*` exports, and exposes a safe Go wrapper. `desktop_windows.go` added `ScreenSharedSurface`, so successful calls return `CaptureFrame` objects that participate in the normal diff pipeline while telemetry reports `backend=shared_surface`.
4. **Hardware frame bus:** `hwframe_pool.go` adds a broadcaster so any hardware encoder can `Register` for GPU-backed frames. The DXGI path now publishes every `CaptureFrame.GPU` (AddRef’d COM handle + stride/format metadata), giving the pending NVENC/AMF workers a zero-copy feed.
4. **Server/operator controls:** `config.json` exposes a new `desktop.capture` block (mode, enable_pre_dwm, fallback_order, adapter_luid), and the client generator (`/api/generate`, `/api/checkClient`) now accepts overrides via `capture_mode`, `capture_enable_pre_dwm`, `capture_fallback`, and `capture_adapter_luid`. Every generated trailer embeds these defaults so fleet-wide policies are centrally managed.

**Remaining work:** wire GPU frames into NVENC/AMF/VAAPI codecs (Phase 1+), add Linux shared-surface equivalent (PipeWire/Wayland), and package/distribute `spark_capture.dll` from the build pipeline alongside checksum validation.

### WebRTC/TURN Audit

**Security stack (Pion v4):**
```
MediaEngine → RegisterDefaultCodecs() (VP8/VP9)
     ↓
Interceptor Registry → SRTP, SRTCP, NACK, TWCC
     ↓
API → NewPeerConnection(cfg)
     ↓
DataChannel ("desktop-input") → SCTP over DTLS, ordered
```

**Environment variables:**
| Variable | Purpose | Default |
|----------|---------|---------|
| `SPARK_WEBRTC_ICE` | Full ICE override (url\|user\|pass) | — |
| `SPARK_WEBRTC_STUN` | Comma-separated STUN URLs | Google + Cloudflare |
| `SPARK_WEBRTC_TURN` | Comma-separated TURN URLs | `turn.example.com` (placeholder) |
| `SPARK_WEBRTC_TURN_USERNAME` | TURN username | — |
| `SPARK_WEBRTC_TURN_PASSWORD` | TURN password | — |
| `SPARK_WEBRTC_ICE_TRANSPORT_POLICY` | `all` or `relay` | `all` |
| `SPARK_WEBRTC_NAT_TYPE` | `symmetric`, `cone`, `auto` | `auto` |

**NAT handling:**
- `isSymmetricNATLikely()` counts TURN vs STUN servers
- If TURN > STUN or `NAT_TYPE=symmetric`, switches to relay-only policy
- `preferTURNServers()` reorders ICE server list

### TURN Credential Rotation Best Practices ✅ IMPLEMENTED (2024-12-07)

**Implementation:** RFC 8656 ephemeral credentials now supported via `server/handler/utility/turn_credentials.go`.

**Configuration (`config.json`):**
```json
{
  "webrtc": {
    "turn_servers": ["turn:turn.example.com:3478?transport=udp"],
    "stun_servers": ["stun:stun.l.google.com:19302"],
    "turn_secret": "your-coturn-static-auth-secret",
    "turn_credential_ttl": 3600
  }
}
```

**How it works:**
1. When `turn_secret` is configured, `iceServers()` and `guestICEConfig()` generate ephemeral credentials
2. Username format: `timestamp:userID` (e.g., `1733590800:share:abc12345`)
3. Password: `Base64(HMAC-SHA1(turn_secret, username))`
4. TTL defaults to 3600 seconds (1 hour), configurable via `turn_credential_ttl`

**Files created/modified:**
- `server/handler/utility/turn_credentials.go` — `GenerateTURNCredentials()`, `FormatTURNURIsWithCredentials()`
- `server/config/config.go` — Added `TurnSecret` and `TurnCredentialTTL` fields to `webrtc` struct
- `server/handler/webrtc/webrtc.go` — Updated `iceServers()` to generate ephemeral credentials
- `server/handler/share/share.go` — Updated `guestICEConfig()` to generate ephemeral credentials with share ID

**Coturn configuration (`/etc/turnserver.conf`):**
```
use-auth-secret
static-auth-secret=your-coturn-static-auth-secret
realm=rocket.example.com
```

**API response format (when turn_secret is configured):**
```json
{
  "ice": {
    "stun": ["stun:stun.l.google.com:19302"],
    "turn": [
      {
        "urls": "turn:turn.example.com:3478?transport=udp",
        "username": "1733594400:webrtc",
        "credential": "base64-hmac-password"
      }
    ],
    "turn_ttl": 3600
  }
}
```

**Backwards compatibility:** If `turn_secret` is not set, TURN URIs are returned without credentials (static auth mode).

### Input Control Enforcement Audit

**Multi-layer defense:**

```
Browser (guest.jsx)          Server (share.go)           Client (input.go)
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│ allowControlRef     │ ──► │ guest.viewOnly      │ ──► │ session.allowControl│
│ gates event queue   │     │ blocks at dispatch  │     │ blocks at SendInput │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘
```

**Payload limits (enforced at server):**
- `maxDesktopInputBatch = 32` events
- `maxClipboardBytes = 64KB`
- `maxFileDropEntries = 5`
- `maxFileNameLength = 255`
- `maxCursorWidth/Height = 256`
- `maxCursorDataSize = ~262KB` (base64 overhead)
- `maxSDPLength = 32KB`
- `maxCandidateLength = 4KB`

**Rate limiting:** Token bucket algorithm at `share.go:48-96`
- 200 tokens/second refill
- 100 token burst capacity
- Logged via `common.Warn(session, "SHARE_RATE_LIMIT", ...)` with structured fields

### Share Handler Structured Logging Migration ✅ COMPLETED (2024-12-07)

**Implementation:** All 27 `golog.Warnf/Infof/Errorf` calls migrated to `common.Info/Warn/Error(ctx, event, status, msg, fields)`.

**Benefits achieved:**
- Automatic trace ID propagation (OTel integration)
- Consistent JSON output for log aggregation
- IP/session context extraction from Gin/Melody handlers
- Removed unused `github.com/kataras/golog` import

**Event names implemented:**

| Category | Event Name | Description |
|----------|------------|-------------|
| Token validation | `SHARE_TOKEN_VALIDATE` | Token lookup, expiration, secret mismatch |
| Guest handshake | `SHARE_GUEST_HANDSHAKE` | WebSocket upgrade, origin validation |
| Guest WebSocket | `SHARE_GUEST_WS_CONNECT`, `SHARE_GUEST_DISCONNECT` | Session lifecycle |
| Share HTTP | `SHARE_GUEST_CONNECT` | Successful share link usage |
| Share CRUD | `SHARE_CREATE`, `SHARE_REVOKE`, `SHARE_GET`, `SHARE_LIST` | Admin operations |
| Rate limiting | `SHARE_RATE_LIMIT` | Input flood protection triggers |
| Cleanup | `SHARE_CLEANUP` | Expired share removal |
| Auto-revoke | `SHARE_AUTO_REVOKE` | Shares cleared on device disconnect |
| Access log | `SHARE_ACCESS_LOG`, `SHARE_GET_TOKEN`, `SHARE_GET_ACCESS_LOG` | Token/log operations |

**Example migration:**
```go
// Before:
golog.Warnf("InitGuestDesktop: token not found or expired, token=%s err=%v entry=%v",
    token[:8]+"...", err, entry != nil)

// After:
common.Warn(ctx, "SHARE_TOKEN_VALIDATE", "fail", "token not found or expired", map[string]any{
    "token_prefix": token[:8],
    "error":        err,
    "entry_exists": entry != nil,
})
```

### Payload Constant Centralization ✅ COMPLETED (2024-12-07)

**Problem:** Security-critical validation constants were duplicated across multiple handler packages.

**Resolution:** Created `server/handler/utility/limits.go` with all centralized constants and helper validation functions:

```go
// server/handler/utility/limits.go
package utility

const (
    MaxSDPLength         = 1 << 15  // 32 KiB
    MaxCandidateLength   = 4096     // 4 KiB
    MaxClipboardBytes    = 64 * 1024
    MaxFileDropEntries   = 5
    MaxFileNameLength    = 255
    MaxDesktopInputBatch = 32
    MaxCursorWidth       = 256
    MaxCursorHeight      = 256
    MaxCursorDataSize    = MaxCursorWidth * MaxCursorHeight * 4 * 4 / 3  // ~340KB base64
)

// Helper functions: ValidateSDPLength, ValidateCandidateLength,
// ValidateClipboardLength, TruncateClipboard, TruncateFileName
```

**Updated handlers:**
- `server/handler/webrtc/webrtc.go` — now uses `utility.MaxSDPLength`, `utility.MaxCandidateLength`
- `server/handler/webcam/webcam.go` — now uses `utility.MaxSDPLength`, `utility.MaxCandidateLength`
- `server/handler/audio/audio.go` — now uses `utility.MaxSDPLength`, `utility.MaxCandidateLength`
- `server/handler/share/share.go` — already migrated, uses all utility constants
- `server/handler/desktop/desktop.go` — added `desktopCounterSnapshot()` for metrics exposure

**Impact:** Single source of truth for security limits; changes propagate consistently.

---

## coturn Integration Guide

### Quick Start

```bash
# Install
apt update && apt install -y coturn

# Enable daemon
sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn
systemctl enable coturn
```

### Production Configuration (`/etc/turnserver.conf`)

```ini
# ─────────────── Network ───────────────
listening-port=3478
tls-listening-port=443
listening-ip=0.0.0.0
relay-ip=YOUR_PUBLIC_IP
external-ip=YOUR_PUBLIC_IP

# ─────────────── TLS ───────────────
cert=/etc/letsencrypt/live/turn.example.com/fullchain.pem
pkey=/etc/letsencrypt/live/turn.example.com/privkey.pem

# ─────────────── Auth (ephemeral) ───────────────
realm=turn.example.com
fingerprint
use-auth-secret
static-auth-secret=your-32-character-shared-secret

# ─────────────── Security ───────────────
total-quota=100
max-bps=0
no-multicast-peers
no-cli
no-loopback-peers

# ─────────────── Logging ───────────────
log-file=/var/log/turnserver.log
simple-log
```

### Firewall

```bash
ufw allow 3478/tcp     # TURN TCP
ufw allow 3478/udp     # TURN UDP
ufw allow 443/tcp      # TURNS (TLS)
ufw allow 49152:65535/udp  # Relay range
```

### Ephemeral Credential Script

```python
#!/usr/bin/env python3
import hashlib, hmac, base64, time

def turn_credentials(user: str, secret: str, ttl: int = 86400):
    expires = int(time.time()) + ttl
    username = f"{expires}:{user}"
    password = base64.b64encode(
        hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()
    return username, password

username, password = turn_credentials("rocket", "your-32-character-shared-secret")
print(f"{username}:{password}")
```

### Verification

```bash
# Test connectivity
turnutils_uclient -T -u rocket -w password turn.example.com

# Verify TLS
openssl s_client -connect turn.example.com:443

# Check logs
tail -f /var/log/turnserver.log
```


### Browser Terminal Flow Control (2024-12-09)

**Issue:** When the terminal panel streamed device stdout/stderr alongside desktop video, Rocket called `term.write()` on every chunk with no pacing. Under sustained output xterm.js' `WriteBuffer` exceeded its 50 MB guard rail and threw `Error: write data discarded, use flow control to avoid losing data`, flooding the browser console and destabilizing the session.

**Resolution:** `web/src/components/features/terminal/components/XTermWrapper.jsx` now enforces browser-side flow control:

- Introduced `WRITE_CHUNK_SIZE = 16 * 1024` so huge payloads are sliced into manageable UTF-16 segments before enqueueing.
- Added a FIFO queue + `flushWriteQueue()` loop that schedules only one chunk at a time and waits for xterm's write callback before dequeuing the next chunk. This mirrors the recommended pattern from Sunshine/noVNC and keeps `_pendingData` below xterm's safety watermark.
- Clearing/disposal flushes the queue and pending-byte counter to avoid leaks on reconnect.

All existing callers still invoke `terminalRef.write(...)`, but the wrapper now serializes the writes, preventing overflowing backlogs without dropping output.


### Browser-Side Telemetry Audit

**File:** `web/src/components/features/desktop/hooks/useDesktopStream.js` (910 lines)

**Existing telemetry:**

| Metric | Location | Scope | Export |
|--------|----------|-------|--------|
| Block stats (rendered/failed/skipped/stale) | `blockStatsRef` (line 60) | Session | Console log every 5s |
| Frame count & bytes | `statsRef` (line 61) | Per-second | Exposed as `fps`/`bandwidth` |
| Server vs device latency | `pingTimersRef` (line 77) | Per-ping | Device only exposed to UI |
| Connection duration | `connectionStartTimeRef` (line 82) | Session | Logged on close |
| Reconnect attempts | `reconnectAttemptRef` (line 80) | Session | Exposed to UI |

**Block versioning (industrial-grade):**
- `blockVersionRef` (line 69) prevents async race conditions
- Pattern: capture frame seq before decode, check against latest version after decode
- Same approach used by VNC/noVNC for tile rendering

**Telemetry gaps (2024-12-07):**

1. ~~**No server-side export**~~ — ✅ **FIXED:** Block stats now exported via `DESKTOP_BROWSER_STATS` every 5s (lines 813-826)
2. **No correlation IDs** — Console logs lack trace IDs for distributed tracing correlation (future: add OpenTelemetry browser SDK)
3. ~~**Share-token error opaque**~~ — ✅ **FIXED:** WebSocket close codes 4001-4004 now differentiated with specific messages (lines 741-766)
4. ~~**No network quality classification**~~ — ✅ **FIXED:** `networkQuality` state exposed ("good"/"fair"/"poor"/"unknown") based on latency + stale rate (lines 828-840)
5. **Codec mismatch invisible** — Browser cannot detect if receiving JPEG when expecting H.264 (future: parse block header image type)

**Recommended additions:**

1. **Export block stats to server:**
```javascript
// In ticker (line 781), alongside DESKTOP_PING:
if (stats.rendered > 0 || stats.stale > 0) {
  sendControl({
    act: "DESKTOP_BROWSER_STATS",
    data: {
      rendered: stats.rendered,
      failed: stats.failed,
      stale: stats.stale,
      staleRate: staleRate,
      latency: latency,
    }
  });
}
```

2. **Add network quality state:**
```javascript
const [networkQuality, setNetworkQuality] = useState("unknown");
// Update based on: latency < 50ms && staleRate < 5% = "good"
```

3. **Differentiate share errors:**
```javascript
// In onclose handler, parse error code from server response
// 4001 = auth, 4002 = expired, 4003 = revoked, 4004 = rate limited
```

---

## Regression Test Suite Requirements

### Existing Test Infrastructure

| File | Type | Purpose |
|------|------|---------|
| `test_e2e.go` | HTTP API | Tests device list, process list, file list, webcam, audio via REST |
| `test_client.go` | WebSocket | Simulates device connection with credential generation |
| `test_features.go` | Unit | Feature-level tests |
| `test_config.go` | Unit | Configuration parsing tests |

**Gap:** No browser-based E2E tests for remote desktop rendering.

### Proposed Chromium/Headless Test Harness

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                     CI Pipeline (GitHub Actions)                 │
├─────────────────────────────────────────────────────────────────┤
│ 1. Start MongoDB (docker)                                        │
│ 2. Start Rocket server (go run server/main.go)                   │
│ 3. Start mock TURN server (coturn in test mode)                  │
│ 4. Connect mock device client (test_client.go)                   │
│ 5. Run Playwright/Puppeteer test suite against desktop viewer    │
│ 6. Collect coverage + screenshots on failure                     │
└─────────────────────────────────────────────────────────────────┘
```

### Test Scenarios

**1. Connection Lifecycle**
```javascript
test("connects to device and receives frames", async ({ page }) => {
  await page.goto("/desktop?device=mock-device-id");
  await expect(page.locator(".connection-status")).toHaveText("Connected");
  await expect(page.locator("canvas")).toHaveAttribute("width", /[1-9]/);
});
```

**2. Reconnection on Network Failure**
```javascript
test("reconnects after WebSocket close", async ({ page }) => {
  await connectToDevice(page);
  await page.evaluate(() => wsRef.current.close(1006)); // Simulate disconnect
  await expect(page.locator(".reconnect-indicator")).toBeVisible();
  await expect(page.locator(".connection-status")).toHaveText("Connected", { timeout: 10000 });
});
```

**3. Input Event Delivery**
```javascript
test("sends normalized input events", async ({ page }) => {
  await connectToDevice(page);
  const canvas = page.locator("canvas");
  await canvas.click({ position: { x: 100, y: 200 } });
  // Verify mock device received DESKTOP_INPUT with correct coordinates
});
```

**4. Share Token Validation**
```javascript
test("rejects expired share token", async ({ page }) => {
  await page.goto("/share?token=expired-token&secret=invalid");
  await expect(page.locator(".error-message")).toContainText(/expired|invalid/i);
});
```

**5. View-Only Mode**
```javascript
test("blocks input in view-only mode", async ({ page }) => {
  await page.goto("/share?token=viewonly-token&secret=valid");
  const canvas = page.locator("canvas");
  await canvas.click({ position: { x: 100, y: 200 } });
  // Verify no DESKTOP_INPUT sent to device
});
```

**6. Resolution Change**
```javascript
test("handles resolution change mid-stream", async ({ page }) => {
  await connectToDevice(page);
  await triggerResolutionChange(mockDevice, 1920, 1080);
  await expect(page.locator("canvas")).toHaveAttribute("width", "1920");
  await expect(page.locator("canvas")).toHaveAttribute("height", "1080");
});
```

### Dependencies

```yaml
# .github/workflows/e2e.yml
jobs:
  e2e-test:
    runs-on: ubuntu-latest
    services:
      mongo:
        image: mongo:6
        ports: ["27017:27017"]
      coturn:
        image: coturn/coturn:latest
        ports: ["3478:3478/udp", "3478:3478/tcp"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.22" }
      - uses: actions/setup-node@v4
        with: { node-version: "20" }
      - name: Install Playwright
        run: npx playwright install --with-deps chromium
      - name: Build server
        run: go build -o rocket-server ./server
      - name: Start server
        run: ./rocket-server &
      - name: Build web
        run: cd web && npm ci && npm run build
      - name: Run mock device
        run: go run test_client.go --host localhost --port 8443 &
      - name: Run E2E tests
        run: cd web && npx playwright test
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: playwright-report
          path: web/playwright-report/
```

### Mock Device Requirements

Extend `test_client.go` to:
1. Accept `--mock-desktop` flag to simulate desktop frames
2. Send resolution updates on demand via stdin command
3. Echo input events to stdout for verification
4. Support multiple monitor simulation

### Implementation Files Needed

**1. `web/playwright.config.js`:**
```javascript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  expect: { timeout: 5000 },
  fullyParallel: false, // Sequential for WebSocket state
  retries: process.env.CI ? 2 : 0,
  reporter: 'html',
  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:18080',
    trace: 'on-first-retry',
    video: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run start',
    url: 'http://localhost:18080',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },
});
```

**2. `web/e2e/desktop.spec.js`:** (See test scenarios above)

**3. `web/e2e/fixtures/mockDevice.js`:**
```javascript
import { test as base } from '@playwright/test';
import { spawn } from 'child_process';

export const test = base.extend({
  mockDevice: async ({}, use) => {
    const proc = spawn('go', ['run', '../../test_client.go', '--mock-desktop']);
    await use({ proc, send: (cmd) => proc.stdin.write(cmd + '\n') });
    proc.kill();
  },
});
```

**4. `.github/workflows/e2e.yml`:** (See Dependencies section above)

**5. `web/package.json` additions:**
```json
{
  "scripts": {
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui"
  },
  "devDependencies": {
    "@playwright/test": "^1.40.0"
  }
}
```

---

### Implementation Status (2024-12-08)

- `go run test_client.go --mock-desktop --mock-standalone --mock-port 18081` now boots a standalone mock device server with:
  - WebSocket endpoint `/mock-desktop` that emits `DESKTOP_INIT`, binary resolution packets, JPEG frame blocks, and responds to `DESKTOP_PING/SHOT/CONFIG/INPUT`.
  - HTTP control plane `/mock/*` (`init`, `resolution`, `frame`, `auto`, `cursor`, `pong`, `disconnect`, `events`, `reset`, `health`) so tests can deterministically drive resolution changes, inject frames, and assert input telemetry.
  - Recorded input queue (`/mock/events`) to validate mouse/keyboard/clipboard handling without spelunking browser internals.
- `web/e2e/fixtures/mockDevice.js` reroutes browser WebSockets to the mock endpoint (both `/api/device/desktop` and `/api/share/desktop`), exposes helpers (`sendInit`, `sendResolution`, `sendTestFrame`, `simulateDisconnect`, `fetchInputEvents`, etc.), and waits for mock health/clients before running assertions.
- `web/e2e/desktop.spec.js` exercises all six SSOT scenarios plus protocol edge cases using the helpers (no more manual `MessageEvent` injection). Each test waits for the mock client, drives HTTP commands, and inspects mock telemetry.
- `web/e2e/global-setup.js` spawns the standalone mock server, exports `MOCK_DEVICE_PORT/HTTP/WS` to Playwright, and polls `/mock/health` before the suite starts. `global-teardown.js` still handles PID cleanup.

## Capture Path Audit

### Windows Capture (`desktop_windows.go`)

**Architecture:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    Screen.Init(displayIndex, rect)               │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐     FAIL      ┌──────────────┐                │
│  │  ScreenDXGI  │ ───────────►  │  ScreenGDI   │                │
│  │  (D3D11/DXGI)│               │  (BitBlt)    │                │
│  └──────────────┘               └──────────────┘                │
│         │                              │                         │
│         ▼                              ▼                         │
│  OutputDuplication.GetImage()    BitBlt + GetDIBits()           │
│  (GPU zero-copy)                 (CPU copy via GDI)             │
└─────────────────────────────────────────────────────────────────┘
```

**Telemetry (lines 79-104):**
- ✅ DXGI init success/failure logged with display index
- ✅ GDI fallback trigger logged with error reason
- ✅ GDI init failure logged
- ✅ Capture latency measurement per frame (atomic counters: `captureCount`, `captureErrors`, `captureLatency`) — Added 2024-12-07
- ✅ `CaptureStats()` function exposes telemetry for dashboards — Added 2024-12-07
- ✅ `dxgiFallbackCount` tracks DXGI→GDI fallback occurrences — Added 2024-12-07
- ❌ No GPU device info logged (vendor, driver version)

**DPI handling (lines 116-122):**
- Uses `DpiAwarenessContextPerMonitorAwareV2`
- Fails gracefully with error if context unavailable

**Adaptive timeout (lines 30-44):**
```go
func dxgiCaptureTimeoutMillis() int {
    fps := clampFPSValue(configFPS.Load())
    frameDuration := time.Second / time.Duration(fps)
    timeout := frameDuration / 2  // Half frame period
    // Clamp to [5ms, 100ms]
}
```

**Resource cleanup (lines 149-162, 229-247):**
- DXGI: Releases `ddup`, `device`, `deviceCtx` in order
- GDI: Releases `hdc`, `memoryDevice`, `bitmap`, `hmem`
- ✅ Panic-safe deferred cleanup added to `Screen.Init()`, `ScreenDXGI.Init()`, `ScreenGDI.Init()` — Fixed 2024-12-07

### Non-Windows Capture (`desktop_others.go`)

**Implementation (114 lines with telemetry):**
```go
func (s *Screen) Capture() (*image.RGBA, error) {
    start := time.Now()
    img, err := screenshot.CaptureRect(s.rect)
    latency := time.Since(start)
    captureLatency.Store(latency.Nanoseconds())
    captureCount.Add(1)
    // ... error tracking
    return img, err
}
```

**Status (Updated 2024-12-07):**
- ✅ Full telemetry parity with Windows (atomic counters, `CaptureStats()`)
- ✅ Per-frame latency tracking
- ✅ Error counting with periodic log sampling (every 100 errors)
- ✅ Init-time test capture with validation
- ❌ No fallback mechanism (uses kbinani/screenshot for all platforms)
- ❌ No X11/XCB vs Wayland selection logic
- ❌ No CoreGraphics-specific handling for macOS

### Recommended Improvements

1. **~~Add capture latency metric~~** ✅ IMPLEMENTED (2024-12-07)
   - Windows: `captureLatency` atomic in `desktop_windows.go`
   - Non-Windows: `captureLatency` atomic in `desktop_others.go`
   - Both expose `CaptureStats()` function

2. **Add GPU info on Windows DXGI init:** (P3 - Low Priority)
```go
// After D3D11Device creation, log adapter info
adapter := s.device.GetAdapter()
desc := adapter.GetDesc()
telemetry.LogStructured("INFO", "DXGI GPU info", map[string]interface{}{
    "vendor": desc.VendorId,
    "device": desc.Description,
})
```

3. **~~Add telemetry to non-Windows~~** ✅ IMPLEMENTED (2024-12-07)
   - Full telemetry parity: `captureCount`, `captureErrors`, `captureLatency`
   - Init-time test capture validation
   - Periodic error log sampling (every 100 errors)

4. **~~Wrap cleanup in defer for panic safety~~** ✅ IMPLEMENTED (2024-12-07)
   - `Screen.Init()`: Panic-safe with deferred cleanup
   - `ScreenDXGI.Init()`: Named return with panic recovery
   - `ScreenGDI.Init()`: Named return with panic recovery

---

## Executive Summary (2024-12-07)

### Audit Scope

This audit covered the complete remote desktop capture → render pipeline:

| Component | Files Analyzed | Lines of Code |
|-----------|----------------|---------------|
| Browser viewer | `useDesktopStream.js` | ~910 |
| Server broker | `desktop.go`, `share.go` | ~2000 |
| Device session | `desktop.go`, `codec.go` | ~1500 |
| Capture paths | `desktop_windows.go`, `desktop_others.go` | ~300 |
| WebRTC transport | `webrtc.go`, `webrtc_vpx*.go` | ~700 |
| Telemetry | `telemetry.go`, `metrics_reporter.go` | ~400 |

### Findings by Severity

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 0 | — |
| 🟠 High | 2 | Documented |
| 🟡 Medium | 5 | Documented |
| 🟢 Low | 8 | Documented |

**High-severity findings:**
1. **Codec mismatch transparency** — ~~`ProxyCodec.Name()` reports "h264" while encoding JPEG~~ ✅ Fixed
2. ~~**Static TURN credentials** — No ephemeral credential rotation mechanism~~ ✅ Fixed (2024-12-07)

**Medium-severity findings:**
1. ~~Payload constants duplicated across 5 handler files~~ ✅ Fixed (2024-12-07) → `utility/limits.go`
2. ~~Share handler uses `golog` instead of structured `common.Warn`~~ ✅ Fixed (31 structured calls)
3. ~~Non-Windows capture path has zero telemetry~~ ✅ Fixed (2024-12-07) → `desktop_others.go`
4. ~~Browser block stats not exported to server~~ ✅ Fixed (2024-12-07)
5. ~~No E2E test coverage for desktop rendering~~ ✅ Fixed (2024-12-07)

### Deliverables

1. **SSOT Document** — This file (~1000 lines, comprehensive pipeline documentation)
2. **TODO Checklist** — 12 items total: 9 complete, 3 pending (parity items with research complete)
3. **Implementation Guides:**
   - TURN credential rotation with coturn
   - Share handler logging migration inventory
   - Payload constant centralization plan
   - Regression test suite architecture
   - **NEW:** Sunshine GPU capture implementation roadmap
   - **NEW:** RustDesk P2P transport implementation roadmap

### Recommended Prioritization

| Priority | Action | Effort | Impact | Status |
|----------|--------|--------|--------|--------|
| ~~P0~~ | ~~Add codec fallback warning~~ | 1h | Prevents silent decode failures | ✅ Done |
| ~~P0~~ | ~~Centralize payload constants~~ | 2h | Single source of truth for security limits | ✅ Done (2024-12-07) |
| ~~P1~~ | ~~Implement TURN ephemeral credentials~~ | 4h | Credential rotation for production | ✅ Done (2024-12-07) |
| ~~P1~~ | ~~Migrate share.go to structured logging~~ | 4h | Distributed tracing consistency | ✅ Done (verified 2024-12-07) |
| ~~P2~~ | ~~Add capture telemetry to non-Windows~~ | 2h | Observability parity | ✅ Done (2024-12-07) |
| ~~P2~~ | ~~Add capture latency to Windows DXGI/GDI~~ | 2h | Per-frame observability | ✅ Done (2024-12-07) |
| ~~P2~~ | ~~Add panic-safe cleanup to Windows capture~~ | 1h | Resource leak prevention | ✅ Done (2024-12-07) |
| ~~P2~~ | ~~Export browser stats to server~~ | 2h | End-to-end visibility | ✅ Done (2024-12-07) |
| ~~P3~~ | ~~Set up Playwright E2E suite~~ | 8h | Regression prevention | ✅ Done (2024-12-07) |
| ~~P3~~ | ~~Add GPU info logging on DXGI init~~ | 2h | Hardware diagnostics | ✅ Done (DXGI telemetry logging shipped) |
| P4 | Sunshine parity (GPU capture) | 32h | Zero-copy encode, HDR support | 🔬 Research done |
| P4 | RustDesk parity (P2P transport) | 44h | Direct connections, lower latency | 🔬 Research done |
| P5 | Guacamole parity (RBAC/recording) | 60h | Enterprise compliance | 📋 Scoped |

### Error Handling Hardening (Phase 2) ✅ COMPLETED (2024-12-07)

**Comprehensive error handling audit performed with 14 issues identified and fixed:**

| Category | Issues Fixed | Files Modified |
|----------|-------------|----------------|
| Panic Recovery | 3 | `desktop.go` (client), `desktop.go` (server), `share.go` |
| Silent Failures | 7 | `relay.go`, `share.go`, `bridge.go` |
| Resource Leaks | 1 | `share.go` |
| Missing Propagation | 3 | `relay.go`, `share.go` |

**Key fixes implemented:**

1. **Panic recovery with auto-restart:**
   - `safeHealthCheck()` wraps `healthCheck()` with defer/recover and auto-restart
   - `safeCleanupExpiredShares()` wraps cleanup with defer/recover and auto-restart
   - Server heartbeat goroutine now has defer/recover

2. **IPC error handling:**
   - `relay.go:sendHelloLocked()` now logs and marks connection degraded on failure
   - `relay.go:sendStateLocked()` now logs state update failures

3. **Database error handling:**
   - `share.go:ensureDesktop()` now checks `UpdateDesktop()` error and returns empty on failure

4. **JSON unmarshal logging:**
   - `bridge.go` handlers (`handleKill`, `handlePing`, `handleInput`, `handleConfig`, `handleShot`) now log unmarshal failures with payload size

5. **Resource cleanup:**
   - `cleanupExpiredShares()` now has `defer ticker.Stop()` to prevent ticker leak

**Pattern established for future goroutines:**
```go
go func() {
    defer func() {
        if r := recover(); r != nil {
            telemetry.LogStructured("ERROR", "goroutine panic", map[string]interface{}{
                "panic": r,
            })
            time.Sleep(backoff)
            go safeRestart() // Auto-restart if appropriate
        }
    }()
    actualWork()
}()
```

### Next Steps

1. ~~Review and approve this audit document~~ ✅
2. ~~Create tickets for P0/P1 items~~ ✅ All complete
3. ~~Schedule Spark parity check~~ ✅ Complete (Rocket supersedes Spark)
4. ~~Integrate E2E tests into CI pipeline~~ ✅ GitHub Actions workflow created
5. **Begin Sunshine parity Phase 1** — `codec_hw_windows.go` with NVENC probe (requires CGO setup)
6. **Begin RustDesk parity Phase 1** — Design rendezvous protocol (gRPC vs WebSocket)

---

*Document generated: 2024-12-07*
*Last updated: 2025-02-15 (DXGI adapter telemetry logging)*
*Audit version: 1.3*
*Total sections: 19*
