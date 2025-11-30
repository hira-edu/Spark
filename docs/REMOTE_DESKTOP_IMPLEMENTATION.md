# Full-Featured Remote Desktop Implementation Plan

This document outlines the implementation plan for adding full remote desktop control (mouse + keyboard) to Spark. Phase 1 uses the existing WebSocket stream plus Windows-native SendInput; Phase 2 adds WebRTC (media + data channel) with graceful fallback to the WS JPEG path.

## Current State

### What Exists
- **Screen Capture**: `client/service/desktop/desktop.go` - JPEG streaming with delta compression
- **Web Viewer**: `web/src/components/desktop/desktop.jsx` - Canvas-based display
- **WebSocket Transport**: Binary frame protocol over existing WS connection

### What's Missing
- WebRTC media + data channel (offer/answer/candidates, TURN/STUN, VP8/VP9 track, DESKTOP_INPUT over data channel)
- Cross-platform input injection (Linux/macOS)

---

## Implementation Phases

### Phase 1: Input Control (Priority: HIGH)

Status: Implemented for Windows via Win32 `SendInput`; non-Windows uses RobotGo when built with CGO and falls back to an explicit unsupported error otherwise. Inputs travel over the existing WS `0x14/0x03` channel.

- Device: `client/service/desktop/input.go` parses/bounds batches (32 max), rate-limits per second, and injects via `client/service/desktop/input_windows.go` (SendInput) on Windows or `client/service/desktop/input_nonwindows_cgo.go` (RobotGo) on macOS/Linux CGO builds. Non-Windows without CGO uses the stub in `input_nonwindows_stub.go`.
- Server: `server/handler/desktop/desktop.go` clamps incoming batches to 32, rejects malformed payloads, and tags with desktop UUID.
- Web: `web/src/components/features/desktop` (DesktopViewer + hooks) batches mouse move/button/wheel and key up/down every 16 ms (32-cap buffer), supports pointer lock, and cleans up listeners on unmount; `allowControl` gates view-only share sessions by skipping input capture.

**Guardrails:** Prefer absolute coordinates when pointer lock is off, fall back to relative deltas when pointer lock is on, and always bound coordinates to the current display size. If a desktop session id is missing or stale, return `DESKTOP_INPUT` with a non-zero code and do not try to inject input.

**File**: `web/src/components/desktop/desktop.jsx`

Add input event handlers (mouse move, click, scroll, keyboard) that send events to the server:

```jsx
// Input batching - collect events and send every 16ms (60fps)
let inputBuffer = [];
let flushTimer = null;

function startInputFlush() {
    flushTimer = setInterval(() => {
        if (conn && inputBuffer.length > 0) {
            sendData({
                act: 'DESKTOP_INPUT',
                data: { events: inputBuffer }
            });
            inputBuffer = [];
        }
    }, 16);
}

// Mouse move handler
canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    inputBuffer.push({
        type: 'move',
        x: Math.round((e.clientX - rect.left) / rect.width * canvas.width),
        y: Math.round((e.clientY - rect.top) / rect.height * canvas.height)
    });
});

// Mouse button handlers
canvas.addEventListener('mousedown', (e) => {
    const buttons = ['left', 'middle', 'right'];
    inputBuffer.push({
        type: 'button',
        button: buttons[e.button] || 'left',
        down: true
    });
});

canvas.addEventListener('mouseup', (e) => {
    const buttons = ['left', 'middle', 'right'];
    inputBuffer.push({
        type: 'button',
        button: buttons[e.button] || 'left',
        down: false
    });
});

// Scroll handler
canvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    inputBuffer.push({
        type: 'scroll',
        deltaX: e.deltaX,
        deltaY: e.deltaY
    });
}, { passive: false });

// Keyboard handlers (need to capture on window when canvas is focused)
window.addEventListener('keydown', (e) => {
    if (!canvasFocused) return;
    e.preventDefault();
    inputBuffer.push({
        type: 'key',
        key: e.key,
        keyCode: e.keyCode,
        down: true
    });
});

window.addEventListener('keyup', (e) => {
    if (!canvasFocused) return;
    e.preventDefault();
    inputBuffer.push({
        type: 'key',
        key: e.key,
        keyCode: e.keyCode,
        down: false
    });
});
```

---

### Phase 2: WebRTC Streaming (Priority: MEDIUM)

Replace WebSocket JPEG streaming with WebRTC for lower latency and move DESKTOP_INPUT to the WebRTC data channel, with automatic fallback to the WS JPEG path.

**Guardrails:** Keep the existing binary header (magic + op + len) on signaling JSON to avoid breaking older clients; gate WebRTC behind a feature flag; do not send input over WebRTC until the data channel is open; drop buffered inputs after 200 ms instead of blocking render.

**Observability/flags TODO:** Add connection metrics/logging and a first-class disable toggle; WebRTC is default-on today with only the `SPARK_WEBRTC_ENABLED` opt-out env.

#### 2.1 Signaling Contract
- Add server/device acts for `DESKTOP_WEBRTC_OFFER`, `DESKTOP_WEBRTC_ANSWER`, and `DESKTOP_WEBRTC_CANDIDATE`, wrapped in the existing WS service header (`0x14` + JSON op `0x03`) and tagged with the desktop UUID.
- Payloads: `{ sdp, type }` for offer/answer; `{ candidate, sdpMid, sdpMLineIndex }` for ICE; include `role` and `retry` fields for observability; validate sizes/rates and return error codes.

#### 2.2 Server (Go, Pion)
- Add Pion WebRTC dependency and env-driven ICE servers (STUN/TURN), plus a flag to disable WebRTC.
- WebRTC session manager keyed by desktop UUID: create PeerConnection, video track (VP8/VP9), and reliable data channel `input`; hook ICE state/logging and cleanup.
- SDP/ICE handlers bound to the desktop WS session: forward offers/answers/candidates to/from browser; reply with errors via JSON op.
- Data channel: forward `DESKTOP_INPUT` payloads to the device handler; enforce batch cap and per-second rate; close on protocol violations.
- Media: produce a VP8 (or VP9) `TrackLocal` from the desktop capture; mirror FPS/quality settings and reset on disconnect.

#### 2.3 Device (client service)
- Feature-flag WebRTC; build peer with ICE servers; create video track; encode capture frames to VP8/VP9 (mediadevices/vpx or libvpx) at configured FPS/bitrate.
- Create data channel “input”; onmessage → existing input injector; enforce batch limit and throttle.
- Handle renegotiation/ICE restart; cleanup on close; fall back to WS JPEG if disabled or negotiation fails.

#### 2.4 Web Frontend (`web/src/components/desktop/desktop.jsx`)
- Add a WebRTC controller: create RTCPeerConnection with ICE servers, negotiate offer/answer/candidates over existing WS, render the video track to `<video>` or canvas.
- Create reliable data channel for input; batch DESKTOP_INPUT every 16 ms with a bounded buffer; if channel not open within 200 ms, drop buffered inputs and/or fall back to WS.
- Reconnect/backoff logic; UI toggle to disable WebRTC (force WS); surface states/errors; keep pointer-lock and input enable/disable.

#### 2.5 Observability & Flags
- Flags (default on): `SPARK_WEBRTC_ENABLED` (set to `0`/`false` to disable), `SPARK_WEBRTC_ICE`, `SPARK_WEBRTC_STUN`, `SPARK_WEBRTC_TURN`, `SPARK_WEBRTC_MAX_BITRATE`, `SPARK_WEBRTC_MAX_FPS`.
- Metrics/logs: peer/ICE states, bitrate/FPS, data-channel errors, fallback reason.

#### 2.6 VP8/VP9 Encoding
- Convert RGBA capture to I420 and encode to VP8 (preferred) or VP9; tune bitrate/FPS from env; drop/pace frames on backpressure.
- Suggested encoder (Go): `github.com/pion/mediadevices/pkg/codec/vpx`

```go
import (
    "github.com/pion/mediadevices/pkg/codec/vpx"
    "github.com/pion/mediadevices/pkg/codec/vpx/encoder"
)

func newVP8Encoder(bitrate, fps int) (*vpx.Encoder, error) {
    return vpx.NewVP8Encoder(
        encoder.WithBitrate(bitrate),
        encoder.WithFrameRate(fps),
    )
}
```

#### 2.7 Testing & Validation
- Unit/integration: signaling handlers, data-channel input parsing, encoder outputs valid RTP.
- Manual: negotiate WebRTC, verify video + input, simulate TURN-only networks, and confirm WS fallback path works when WebRTC fails/disabled.

---

### Phase 3: Platform-Specific Optimizations (Priority: LOW)

#### 3.1 Windows: Use Windows API for Better Performance

```go
// +build windows

package desktop

import (
    "syscall"
    "unsafe"
)

var (
    user32           = syscall.NewLazyDLL("user32.dll")
    sendInput        = user32.NewProc("SendInput")
    setcursorpos     = user32.NewProc("SetCursorPos")
)

// Native Windows input for better performance
func nativeMouseMove(x, y int) {
    setcursorpos.Call(uintptr(x), uintptr(y))
}
```

#### 3.2 Linux: X11/Wayland Support

```go
// +build linux

package desktop

// For Wayland, may need to use libei or portal APIs
// For X11, robotgo works well
```

#### 3.3 macOS: Accessibility Permissions

```go
// +build darwin

package desktop

// Note: macOS requires accessibility permissions for input simulation
// User must grant permission in System Preferences > Security & Privacy > Accessibility
```

---

## File Structure After Implementation

```
client/
├── service/
│   └── desktop/
│       ├── desktop.go          # Screen capture (existing)
│       ├── desktop_windows.go  # Windows-specific capture
│       ├── desktop_others.go   # Linux/macOS capture
│       ├── input.go            # Input parsing/dispatch
│       ├── input_windows.go    # Windows SendInput path
│       ├── webrtc.go           # NEW: WebRTC streaming (Phase 2)
│       └── screen.go           # Screen abstraction (existing)

server/
├── handler/
│   └── desktop/
│       └── desktop.go          # WebSocket relay (existing)

web/
└── src/
    └── components/
        └── desktop/
            ├── desktop.jsx     # Remote desktop UI
            └── desktop.css     # Styles
```

---

## Build Requirements

The current Windows-only input path relies on Win32 `SendInput` and does not require RobotGo or additional CGO toolchains.

### Cross-Compilation

Update `scripts/build.client.sh`:

```bash
# Windows (requires mingw-w64)
GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build ...

# Linux
GOOS=linux GOARCH=amd64 go build ...
```

---

## TODO Checklist

### Phase 1: Input Control
- [x] Define and parse DESKTOP_INPUT payloads in `client/service/desktop/input.go`, clamping coordinates to display bounds, normalizing scroll, and dropping unknown events with a 32-event cap.
- [x] Implement Windows input injection via Win32 SendInput in `client/service/desktop/input_windows.go`; use RobotGo on macOS/Linux CGO builds (`client/service/desktop/input_nonwindows_cgo.go`) and return a clear unsupported error when CGO is off.
- [x] Wire DESKTOP_INPUT through `client/core/handler.go` and the server desktop bridge so payloads keep the existing WS headers (`0x14` + JSON `0x03`) and attach the desktop UUID.
- [x] Web UI: capture mouse move/button/wheel and key down/up with pointer-lock support, batch every 16 ms with a bounded buffer, scale coords to the remote resolution, and clean up listeners on unmount (`web/src/components/desktop/desktop.jsx`).
- [x] Surface an explicit enable/disable toggle in the UI and relay device-side input errors back to the modal.
- [ ] Smoke test on Windows (move/click/scroll/modifier+char keys); document macOS/Linux as unsupported until a cross-platform injector is added.

### Phase 2: WebRTC (Optional)
- [x] Add Pion WebRTC dependency (v4) and VP8/VP9 encoder (mediadevices/vpx or equivalent) with env-driven STUN/TURN.
- [x] Create client WebRTC session/encoder to mirror JPEG cadence, reuse DESKTOP_INPUT over a data channel, and expose lifecycle hooks (offer/answer/ICE/state).
- [x] Add signaling endpoints in the server (offer/answer + ICE) with auth checks and configurable TURN list; bridge acts `DESKTOP_WEBRTC_OFFER/ANSWER/CANDIDATE` with size validation.
- [x] Web frontend: negotiate WebRTC, render the video track, and send batched DESKTOP_INPUT over the data channel with reconnect handling and a disable toggle.
- [ ] Add observability (connection state logs/metrics) and a first-class flag to disable WebRTC entirely (currently default-on with opt-out env only).
- [x] Secure share/guest desktop: tie share tokens to desktop sessions and enforce them on a guest-only WS endpoint (`/api/share/desktop`) that wraps the same WebRTC+WS desktop stream with view-only input gating; TTL + single-use options, access logging, revoke on device disconnect, and TURN-only ICE filtering for guests.

### Phase 3: Optimizations
- [x] Windows SendInput fast path with DPI awareness + wake (SetThreadDpiAwarenessContext + SetThreadExecutionState); further screensaver/idle tuning still possible.
- [ ] Hardware-assisted encoding (NVENC/VAAPI/VideoToolbox) and adaptive quality/FPS based on bandwidth or dropped frames.
- [ ] Multi-monitor selection with bounds offsets and cursor overlay.
- [ ] Idle/keepalive cadence tweaks so capture drops to low-power mode when idle; add rate/permission guards and basic telemetry on drops/frame cadence.

---

## Security Considerations

1. **Input Validation**: Sanitize all input events before processing
2. **Rate Limiting**: Limit input events to prevent abuse
3. **Permission Checks**: Verify user has remote control permission
4. **Encryption**: All input events should be encrypted (existing XOR/AES)

---

## References

- [Pointer Lock API](https://developer.mozilla.org/en-US/docs/Web/API/Pointer_Lock_API) and [Wheel event](https://developer.mozilla.org/en-US/docs/Web/API/WheelEvent) normalization
- [Pion WebRTC](https://github.com/pion/webrtc) and [datachannels guide](https://github.com/pion/webrtc/wiki/Examples#data-channels)
- [Pion mediadevices VP8 codec](https://pkg.go.dev/github.com/pion/mediadevices/pkg/codec/vpx) and [TrackLocal](https://pkg.go.dev/github.com/pion/webrtc/v3#TrackLocal)
- [WebRTC ICE/STUN/TURN primer](https://webrtc.org/getting-started/overview) and [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445)
- [Spark original repository](https://github.com/XZB-1248/Spark) for baseline desktop pipeline
