# Automated Testing Plan (E2E + Perf)

This document describes how to run and extend Rocket/Spark's automated testing across the **server**, **agent (client)**, and **web UI**, with emphasis on the remote-desktop pipeline (capture → encode → transport → decode → render → input feedback).

## Goals

- Catch regressions in the desktop pipeline end-to-end (including reconnection, backpressure, and input feedback).
- Validate fallbacks: WebRTC ↔ tiles/canvas, codec fallback, reconnect/backoff, view-only enforcement.
- Produce objective signals: latency/jitter, FPS, frame drops, buffering/backpressure, bitrate.
- Keep CI deterministic; gate hardware-dependent tests (DXGI/GPU/HW codecs) behind env flags.

## Current Automated Coverage

### Go tests

- Run: `go test ./...`
- Includes server + client unit/integration tests and Windows-only desktop capture tests (gated/conditional).

### Browser E2E (Playwright)

- Run: `cd web; npx playwright test`
- Test types:
  - **Browser-only desktop** via `/mock-desktop` and a standalone mock desktop server.
  - **Full-stack desktop** via Rocket server + an in-repo mock agent (device WS), driven by `web/e2e/desktop.fullstack.spec.js`.
- Harness behavior:
  - Rocket server is started by Playwright (`web/playwright.config.js`) using `../config.e2e.json`.
  - Global setup starts:
    - Standalone mock desktop server (for browser-only tests).
    - Mock agent connected to Rocket server (for full-stack tests).
  - For Windows stability, the harness builds reusable binaries under `web/.playwright/bin/` (see `web/e2e/utils/mockServer.js` and `web/e2e/utils/mockAgent.js`).

### CI

- GitHub Actions workflow: `.github/workflows/tests.yml`
  - Runs `go test ./...`
  - Runs Playwright E2E (Chromium) on Ubuntu

## Recommended Local Commands

- Go: `go test ./...`
- Full regression (Windows): `powershell -ExecutionPolicy Bypass -File scripts/test.e2e.ps1`
- E2E only: `cd web; npx playwright test`

## Hardware / Performance Suite (Windows)

The hardware perf suite is an **opt-in** E2E benchmark intended to answer: “Is the remote desktop stream smooth and low-latency under real usage?” It runs a real server + real client + a visual “perf marker” window, then uses Playwright to measure what the viewer actually renders.

### Run

- Command (builds + runs everything): `powershell -ExecutionPolicy Bypass -File scripts/perf.desktop.ps1`
- Recommended env (headed, longer run, explicit thresholds):
  - `$env:PERF_HEADED='1'`
  - `$env:PERF_DURATION_SEC='300'` (5 minutes)
  - `$env:PERF_TRANSPORT='webrtc'` (or `'tiles'` to test the WS tile pipeline)
  - `$env:PERF_MIN_FPS='30'`
  - `$env:PERF_MAX_P95_MS='120'`
  - `$env:PERF_MAX_P99_MS='200'`
  - `$env:PERF_MAX_STALL_MS='500'`

### What it does

- Builds: `built/server_perf.exe`, `built/client_perf.<runId>.exe`, `built/perfmarker.exe`
- Starts:
  - Rocket server on `http://localhost:18080` (using `config.e2e.json`)
  - A real client/agent connected to that server
  - `perfmarker.exe`: a tiny top-left window that renders a high-contrast bit-grid encoding a timestamp, updating at a fixed FPS
- Runs Playwright using `web/playwright.perf.config.js` and `web/e2e/desktop.perf.hardware.spec.js`, which samples rendered pixels and computes:
  - Approx FPS (distinct marker updates per second)
  - End-to-end latency (now − marker timestamp) with p50/p95/p99
  - Stall detection (max time since the marker last changed)

### Logs and artifacts

- Orchestrator logs: `logs/perf_server.<runId>.out.log`, `logs/perf_client.<runId>.out.log`, `logs/perf_marker.<runId>.out.log`
- Playwright artifacts: `web/playwright-report-perf/` and `web/test-results/`
- Client runtime log (useful for capture backend): `%TEMP%\\rocket_client.log`

### Notes / limitations

- This suite is hardware- and session-dependent (Windows desktop session, GPU drivers, capture backend, encode/decode availability). Keep it opt-in and run it on a self-hosted Windows runner for CI.
- “Commercial smooth” is not a single boolean; it becomes reliable once you define and enforce explicit thresholds (FPS/latency/jitter/stalls) for your target hardware and network profile.

## Docker-assisted Testing (Optional)

Docker is useful for reproducible, disposable dependencies (TURN servers, signaling relays, network impairment, etc.). For example, you can add a `docker-compose.yml` with a `coturn` container to exercise WebRTC TURN fallback and NAT traversal without installing those services on the host.

## Codex / Automation Notes (Dependency Downloads)

Automation can download/install what it needs (when network access is allowed), including:

- Go toolchain (via `go` + `go.mod` toolchain/module download)
- Node dependencies (`npm ci` / `npm install`)
- Playwright browsers (`npx playwright install chromium`)
- Optional Docker images/services (e.g., coturn for TURN/WebRTC testing) if you add containerized test dependencies

For reproducibility, prefer pinned versions (`go.mod`, `package-lock.json`) and CI caching (Go build cache, npm cache, Playwright browsers).

## What Still Needs Hardware / "Live" Validation

Some aspects cannot be fully validated on a headless/CI runner without the right OS/hardware/session:

- Real desktop capture (DXGI/GDI) correctness (no black frames) on the target GPU/driver.
- Hardware encode/decode availability and performance (H.264/H.265/AV1 depending on your stack).
- End-to-end display correctness on real monitors (HDR/VRR/multi-monitor edge cases).

Plan: keep deterministic mock-based suites always-on, and add **self-hosted Windows hardware suites** gated by env (example: `ROCKET_HARDWARE_PERF=1`).

## Codex Prompt Template (for this repo)

Use this prompt when you want Codex to set up and run the full automated suite (authorized testing only):

1. `cd C:\\Users\\Workstation\\Documents\\GitHub\\Spark`
2. Install missing dependencies (Go/Node/Playwright) if needed.
3. Run `scripts/test.e2e.ps1` and iterate until green.
4. Run `scripts/perf.desktop.ps1` in headed mode for a longer duration and fail on explicit perf thresholds.
5. For any failures: collect Playwright traces/videos and `logs/perf_*` outputs, fix root causes, and add/adjust tests to prevent regressions.
