# WebRTC End-to-End Upgrade Plan

Tracks everything needed to evolve Spark's remote-desktop transport from the current WebSocket diff mirroring + beta data channel into a fully fledged WebRTC media pipeline.

## 1. Current State (June 2025)

| Layer | Implementation | Notes |
| --- | --- | --- |
| Agent | `client/service/desktop/webrtc` spins up pion peers when `SPARK_EXPERIMENTAL_WEBRTC=1`. Every diff/resolution packet is mirrored over the `spark-diff` data channel via `broadcastWebRTCFrame`. A Media Foundation video pipeline exists but is not yet wired to transports. | No RTP tracks, no TURN awareness beyond env vars, and no adaptive bitrate controller. |
| Server | `server/handler/desktop/desktop.go` blindly forwards `DESKTOP_WEBRTC_SIGNAL` messages between browser and agent. The new `server/handler/desktop/webrtc.go` file only contains validators. | No session bookkeeping (offers collide, no retries), no TURN credential injection, no metrics. |
| Browser | Modal stands up an `RTCPeerConnection` when the agent advertises `transports` containing `webrtc`. It consumes the `spark-diff` data channel, toggles WebRTC via a switch, and falls back to WebSocket diff if the connection fails. | No playback of true media tracks; audio support is absent; ICE settings must come from the capability payload or `window.SPARK_WEBRTC_*`. |

## 2. Gaps to Close

1. **Server-Side Signalling Controller**
   - Track WebRTC state per desktop UUID (offer seen, answer pending, last ICE candidate, retries, timestamps).
   - Validate browser-origin offers against `DESKTOP_CAPS.transports`/`webrtc` hints before forwarding to the agent.
   - Queue agent ICE candidates when the browser connection is not ready; flush them once the browser acknowledges the answer.
   - Emit structured telemetry (`DESKTOP_WEBRTC_STATE`) so ops can see signalling failures.
   - ✅ Every `DESKTOP_WEBRTC_STATE` packet is now logged via `common.Info`, giving SOC teams the same stage timeline the browser sees.

2. **Agent Media Tracks**
   - Wire `videoPipeline` into the capture loop so we push actual H.264 samples to `pion.TrackLocalStaticSample` (one per viewer) instead of only mirroring diffs.
   - Build track management in `Manager`: create video tracks on offer, attach them to the peer connection, stream samples fan-out, and renegotiate on resolution changes.
   - Integrate Media Foundation encoder capability detection (`mf-h264`) and expose bitrate/fps knobs via `DESKTOP_CAPS.encoders`.
   - Provide policy toggles/env vars for enabling data-channel mirroring vs. pure media path.

3. **Browser Media Playback**
   - Attach `ontrack` handlers to render H.264 video (and later audio) instead of relying solely on the canvas.
   - Offer operator control to switch between `Canvas (WS diff)` and `WebRTC Video` until feature parity is confirmed.
   - Surface bitrate/FPS stats and gracefully downgrade to diff when RTP stalls.

4. **Audio + Input Channels (Future)**
   - Capture WASAPI audio and stream it over a dedicated RTP track when policy allows.
   - Evaluate moving input/clipboard to WebRTC data channels for lower latency once control-plane auditing is ready.

5. **TURN / Credential Management**
   - Move from static env vars to policy-driven TURN credentials minted by the server (short-lived, per session).
   - Extend `DESKTOP_CAPS.webrtc` with `token`, `ttl`, and `relayHint` fields so browsers can bootstrap without reading globals.
   - ✅ Server now issues per-session TURN credentials (when `server/config.json` contains a `webrtc` block) and injects `iceServers`/`token` metadata into `DESKTOP_CAPS`. The Windows agent still hydrates its pion stack from `SPARK_WEBRTC_*` env vars until we build the symmetric pull.

## 3. Implementation Milestones

1. **M1 – Server Controller + Telemetry**
   - Add `controller` struct in `server/handler/desktop/webrtc.go` with CRUD helpers, TTL cleanup, and logging hooks.
   - Update `handleBrowserWebRTCSignal` / `handleAgentWebRTCSignal` to route through the controller, enforce ordering, and return actionable errors to browsers.
   - Emit `DESKTOP_WEBRTC_STATE` packets to browsers for UI HUDs (connecting, answer, ice, failed).
   - Emit `DESKTOP_TRANSPORT_FALLBACK` when negotiation errors occur so browsers immediately disable WebRTC and resume the diff path.

2. **M2 – Agent Track Plumbing**
   - Introduce `TrackManager` in `client/service/desktop/webrtc` that creates per-session `TrackLocalStaticSample` objects, subscribes to the global `videoPipeline`, and sends media samples per viewer.
   - Add capture integration: when `videoStreamingEnabled()` is true, `handleDesktop` should submit frames to `videoPipeline.submit` after diff encoding.
   - Gate behind `SPARK_EXPERIMENTAL_WEBRTC_MEDIA=1` until stabilised.

3. **M3 – Browser Playback & Controls**
   - Render the first available `ontrack` video stream in a `<video>` element (currently hidden behind the WebRTC toggle), with an explicit fallback button to switch back to canvas.
   - Display bitrate/FPS stats sourced from `getStats()` and agent metrics.

4. **M4 – TURN / Dynamic ICE**
   - Teach the server to mint per-session TURN creds (using WebRTC config service or a static secret) and embed them inside `DESKTOP_CAPS.webrtc`.
   - Rotate credentials when the session renews and expire them on `DESKTOP_KILL`.

5. **M5 – Audio + Data-Channel Input (Future)**
   - Once video parity is achieved, replicate the pipeline for audio capture and eventually migrate input/clipboard onto reliable data channels to maximise symmetry.

## 4. Open Questions / Decisions Needed

- **Bitrate Policy:** Do we expose bitrate presets via device policy or link it to the existing quality presets?
- **Track Fan-Out:** Should each browser session get its own track (current plan) or can we multicast? (pion TrackLocal supports multiple readers but needs session-aware keyframe handling.)
- **Recording & Compliance:** When we add RTP tracks, how do we identify them in audit logs versus the existing diff stream?
- **Fallback Trigger:** What metrics should trigger automatic fallback to diff (RTT, packet loss, decoder errors)?

## 5. Next Steps

1. ✅ The server-side controller (M1) now validates offers, tracks state, and buffers ICE candidates—keep burn-in logging on while we watch telemetry.
2. ✅ Per-session TURN credential minting (+ browser HUD tokens) is live behind `server/config.json.webrtc`. Next follow-up is teaching the agent to request the same credentials so we can drop long-lived secrets entirely.
3. Hook the `videoPipeline` into the desktop worker to start producing H.264 samples, even if we initially log them instead of streaming (M2 scaffolding).
4. Extend the browser UI to prefer capability-provided ICE/TURN settings (already partially done), then wire the `<video>` element to real tracks once available.
5. Console HUD now surfaces the minted TURN TTL + relay hint so operators can verify whether sessions are on TURN or direct paths.

### Config Snippet

```json
{
  "webrtc": {
    "enabled": true,
    "credentialTTL": "10m",
    "relayHint": "turn",
    "servers": [
      {
        "urls": [
          "turns:turn1.example.com:5349?transport=tcp",
          "turn:turn1.example.com:3478"
        ],
        "credentialSecret": "coturn-static-secret",
        "credentialType": "password"
      }
    ]
  }
}
```

When this block is present the server mints short-lived usernames (`<expiry-unix>:<desktop-id>`) and HMAC-SHA1 passwords per remote-desktop session, injects them into `DESKTOP_CAPS.webrtc.iceServers`, and attaches a `token` payload that exposes `issuedAt`, `expiresAt`, and `ttlSeconds` to the console HUD.
