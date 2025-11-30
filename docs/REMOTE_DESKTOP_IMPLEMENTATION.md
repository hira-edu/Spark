# Full-Featured Remote Desktop Implementation Plan

This document outlines the implementation plan for adding full remote desktop control (mouse + keyboard) to Spark using RobotGo and Pion WebRTC.

## Current State

### What Exists
- **Screen Capture**: `client/service/desktop/desktop.go` - JPEG streaming with delta compression
- **Web Viewer**: `web/src/components/desktop/desktop.jsx` - Canvas-based display
- **WebSocket Transport**: Binary frame protocol over existing WS connection

### What's Missing
- Mouse input handling (move, click, scroll)
- Keyboard input handling (key press/release)
- Optional: WebRTC for lower latency streaming

---

## Implementation Phases

### Phase 1: Input Control with RobotGo (Priority: HIGH)

Add mouse and keyboard control using the RobotGo library.

**Guardrails:** Prefer absolute coordinates when pointer lock is off, fall back to relative deltas when pointer lock is on, and always bound coordinates to the current display size. If a desktop session id is missing or stale, return `DESKTOP_INPUT` with a non-zero code and do not try to inject input.

#### 1.1 Add RobotGo Dependency

```bash
go get github.com/go-vgo/robotgo
```

**File**: `go.mod`
```go
require (
    github.com/go-vgo/robotgo v0.100.10
)
```

#### 1.2 Create Input Handler Service

**New File**: `client/service/desktop/input.go`

```go
package desktop

import (
    "Spark/modules"
    "github.com/go-vgo/robotgo"
)

// InputEvent represents a mouse/keyboard event from the web client
type InputEvent struct {
    Type    string `json:"type"`    // "move", "button", "scroll", "key"

    // Mouse move
    X       int    `json:"x,omitempty"`
    Y       int    `json:"y,omitempty"`
    DeltaX  int    `json:"deltaX,omitempty"`
    DeltaY  int    `json:"deltaY,omitempty"`

    // Mouse button
    Button  string `json:"button,omitempty"` // "left", "right", "middle"
    Down    bool   `json:"down,omitempty"`

    // Keyboard
    Key     string `json:"key,omitempty"`
    KeyCode int    `json:"keyCode,omitempty"`
}

// HandleInput processes input events from the web client
func HandleInput(pack modules.Packet) error {
    var events []InputEvent
    if val, ok := pack.GetData("events", reflect.Slice); ok {
        // Parse events array
        events = parseInputEvents(val)
    }

    for _, event := range events {
        switch event.Type {
        case "move":
            handleMouseMove(event)
        case "button":
            handleMouseButton(event)
        case "scroll":
            handleMouseScroll(event)
        case "key":
            handleKeyboard(event)
        }
    }
    return nil
}

func handleMouseMove(e InputEvent) {
    if e.DeltaX != 0 || e.DeltaY != 0 {
        // Relative movement (pointer lock mode)
        x, y := robotgo.Location()
        robotgo.Move(x+e.DeltaX, y+e.DeltaY)
    } else {
        // Absolute position
        robotgo.Move(e.X, e.Y)
    }
}

func handleMouseButton(e InputEvent) {
    button := e.Button
    if button == "" {
        button = "left"
    }

    if e.Down {
        robotgo.MouseDown(button)
    } else {
        robotgo.MouseUp(button)
    }
}

func handleMouseScroll(e InputEvent) {
    // Scroll direction and amount
    if e.DeltaY != 0 {
        direction := "down"
        if e.DeltaY < 0 {
            direction = "up"
        }
        robotgo.ScrollDir(abs(e.DeltaY)/100+1, direction)
    }
    if e.DeltaX != 0 {
        direction := "right"
        if e.DeltaX < 0 {
            direction = "left"
        }
        robotgo.ScrollDir(abs(e.DeltaX)/100+1, direction)
    }
}

func handleKeyboard(e InputEvent) {
    key := mapKeyCode(e.KeyCode, e.Key)
    if key == "" {
        return
    }

    if e.Down {
        robotgo.KeyDown(key)
    } else {
        robotgo.KeyUp(key)
    }
}

// mapKeyCode converts JavaScript keyCodes to RobotGo key names
func mapKeyCode(keyCode int, key string) string {
    // Special keys mapping
    specialKeys := map[int]string{
        8:   "backspace",
        9:   "tab",
        13:  "enter",
        16:  "shift",
        17:  "ctrl",
        18:  "alt",
        19:  "pause",
        20:  "capslock",
        27:  "escape",
        32:  "space",
        33:  "pageup",
        34:  "pagedown",
        35:  "end",
        36:  "home",
        37:  "left",
        38:  "up",
        39:  "right",
        40:  "down",
        45:  "insert",
        46:  "delete",
        91:  "cmd",    // Windows key / Command
        112: "f1",
        113: "f2",
        114: "f3",
        115: "f4",
        116: "f5",
        117: "f6",
        118: "f7",
        119: "f8",
        120: "f9",
        121: "f10",
        122: "f11",
        123: "f12",
    }

    if mapped, ok := specialKeys[keyCode]; ok {
        return mapped
    }

    // For regular characters, use the key string (lowercase)
    if len(key) == 1 {
        return strings.ToLower(key)
    }

    return ""
}

func abs(x int) int {
    if x < 0 {
        return -x
    }
    return x
}
```

#### 1.3 Register Input Handler

**File**: `client/core/handler.go` (add to existing)

```go
import "Spark/client/service/desktop"

// In the packet handler switch statement, add:
case "DESKTOP_INPUT":
    err = desktop.HandleInput(pack)
```

#### 1.4 Update Web Frontend for Input

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

Replace WebSocket JPEG streaming with WebRTC for lower latency.

**Guardrails:** Keep the existing binary header (magic + op + len) on the signaling JSON to avoid breaking older clients while rolling out. Do not send input over WebRTC until the data channel is open and negotiated; buffer and drop after 200 ms rather than blocking the render loop.

#### 2.1 Add Pion WebRTC Dependency

```bash
go get github.com/pion/webrtc/v3
```

#### 2.2 Create WebRTC Service

**New File**: `client/service/desktop/webrtc.go`

```go
package desktop

import (
    "github.com/pion/webrtc/v3"
    "github.com/pion/webrtc/v3/pkg/media"
)

type WebRTCDesktop struct {
    peerConnection *webrtc.PeerConnection
    videoTrack     *webrtc.TrackLocalStaticSample
    dataChannel    *webrtc.DataChannel
}

func NewWebRTCDesktop() (*WebRTCDesktop, error) {
    config := webrtc.Configuration{
        ICEServers: []webrtc.ICEServer{
            {URLs: []string{"stun:stun.l.google.com:19302"}},
        },
    }

    pc, err := webrtc.NewPeerConnection(config)
    if err != nil {
        return nil, err
    }

    // Create video track for screen sharing
    videoTrack, err := webrtc.NewTrackLocalStaticSample(
        webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
        "video", "screen",
    )
    if err != nil {
        return nil, err
    }

    _, err = pc.AddTrack(videoTrack)
    if err != nil {
        return nil, err
    }

    // Create data channel for input events
    dc, err := pc.CreateDataChannel("input", nil)
    if err != nil {
        return nil, err
    }

    return &WebRTCDesktop{
        peerConnection: pc,
        videoTrack:     videoTrack,
        dataChannel:    dc,
    }, nil
}

func (w *WebRTCDesktop) SendFrame(frame []byte, duration time.Duration) error {
    return w.videoTrack.WriteSample(media.Sample{
        Data:     frame,
        Duration: duration,
    })
}
```

#### 2.3 VP8/VP9 Encoding

For WebRTC, frames need to be encoded as VP8/VP9 instead of JPEG:

```go
import "github.com/pion/mediadevices/pkg/codec/vpx"

func encodeFrameVP8(img *image.RGBA) ([]byte, error) {
    encoder, err := vpx.NewVP8Encoder()
    if err != nil {
        return nil, err
    }
    defer encoder.Close()

    return encoder.Encode(img)
}
```

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
│       ├── input.go            # NEW: Input handling with RobotGo
│       ├── input_windows.go    # NEW: Windows native input (optional)
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

### RobotGo Dependencies

**Windows:**
```bash
# MinGW-w64 for CGO
choco install mingw
```

**Linux:**
```bash
# X11 development libraries
sudo apt-get install libx11-dev libxtst-dev libxinerama-dev
```

**macOS:**
```bash
# Xcode command line tools
xcode-select --install
```

### Cross-Compilation

Update `scripts/build.client.sh`:

```bash
# Enable CGO for RobotGo
export CGO_ENABLED=1

# Windows (requires mingw-w64)
GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build ...

# Linux
GOOS=linux GOARCH=amd64 go build ...
```

---

## TODO Checklist

### Phase 1: Input Control
- [ ] Define DESKTOP_INPUT payload: array of `{type, x, y, deltaX, deltaY, button, down, key, keyCode}` with a hard cap (e.g., 32 events) and keep the service/op headers (`0x14` + JSON `0x03`) unchanged.
- [ ] Add RobotGo to `go.mod` (note CGO_ENABLED=1 in build docs) and author a key map from JS keyCode/key → RobotGo names (modifiers/function keys included).
- [ ] Build `client/service/desktop/input.go`: parse/validate batches, clamp coordinates to display bounds, normalize scroll, drop unknown types, and short-circuit when sessions are missing or control is disabled.
- [ ] Platform handling: implement Windows injection via RobotGo; return `${i18n|DESKTOP.UNSUPPORTED_PLATFORM}` on non-Windows with a clear error surface; guard scroll granularity to prevent runaway deltas.
- [ ] Wire `DESKTOP_INPUT` through `client/core/handler.go` with lightweight rate limiting (discard when >60Hz sustained) and callbacks on error.
- [ ] Server bridge: accept `DESKTOP_INPUT` frames on the desktop websocket, attach the desktop UUID, validate payload size, and close or warn on malformed/oversized batches.
- [ ] Web UI: add input enable/disable toggle + pointer-lock option, batch every 16 ms with a bounded buffer, scale coords using the remote resolution, and capture mouse move/button/wheel plus key down/up; clean up listeners on unmount.
- [ ] Smoke test on Windows (move/click/scroll/modifier+char keys), note macOS Accessibility prompt requirement, and document Linux support status; add a short payload example to this doc once stabilized.

### Phase 2: WebRTC (Optional)
- [ ] Add Pion WebRTC dependency and VP8/VP9 encoder (mediadevices/vpx or equivalent) with env-driven STUN/TURN.
- [ ] Create `client/service/desktop/webrtc.go` to mirror JPEG cadence, reuse DESKTOP_INPUT over a data channel, and expose lifecycle hooks (offer/answer/ICE/state).
- [ ] Add signaling endpoints in the server (offer/answer + ICE) with auth checks and a configurable TURN list.
- [ ] Web frontend: negotiate WebRTC, render the video track, and send batched DESKTOP_INPUT over the data channel with reconnect handling and a disable toggle.
- [ ] Add observability (connection state logs/metrics) and a flag to disable WebRTC entirely.

### Phase 3: Optimizations
- [ ] Windows native SendInput fast path (cursor + keyboard) with DPI awareness and screensaver wake.
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

- [RobotGo documentation](https://github.com/go-vgo/robotgo) and [key/mouse API](https://github.com/go-vgo/robotgo#keyboard)
- [Pointer Lock API](https://developer.mozilla.org/en-US/docs/Web/API/Pointer_Lock_API) and [Wheel event](https://developer.mozilla.org/en-US/docs/Web/API/WheelEvent) normalization
- [Pion WebRTC](https://github.com/pion/webrtc) and [datachannels guide](https://github.com/pion/webrtc/wiki/Examples#data-channels)
- [Pion mediadevices VP8 codec](https://pkg.go.dev/github.com/pion/mediadevices/pkg/codec/vpx) and [TrackLocal](https://pkg.go.dev/github.com/pion/webrtc/v3#TrackLocal)
- [WebRTC ICE/STUN/TURN primer](https://webrtc.org/getting-started/overview) and [RFC 8445](https://datatracker.ietf.org/doc/html/rfc8445)
- [Spark original repository](https://github.com/XZB-1248/Spark) for baseline desktop pipeline
