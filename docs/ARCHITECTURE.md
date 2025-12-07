# System Architecture

Technical overview of Rocket's architecture, components, and protocols.

## Table of Contents

- [High-Level Architecture](#high-level-architecture)
- [Component Overview](#component-overview)
- [Communication Protocols](#communication-protocols)
- [Data Flow](#data-flow)
- [Key Features](#key-features)
- [Security Model](#security-model)
- [Scalability](#scalability)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                        │
└─────────────────────────────────────────────────────────────────────────────┘
        │                                    │                    │
        ▼                                    ▼                    ▼
┌──────────────────┐                ┌──────────────────┐  ┌──────────────────┐
│   Web Browser    │                │   Guest Access   │  │  Client Binary   │
│   (Admin Panel)  │                │   (Share Links)  │  │  (Target Device) │
│                  │                │                  │  │                  │
│  React + Ant UI  │                │  Limited Viewer  │  │  Go Application  │
└────────┬─────────┘                └────────┬─────────┘  └────────┬─────────┘
         │                                   │                     │
         │ HTTPS/WSS                         │ HTTPS/WSS           │ WSS
         │                                   │                     │
         ▼                                   ▼                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CADDY REVERSE PROXY                                 │
│                     (TLS Termination, WebSocket Upgrade)                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ HTTP
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ROCKET SERVER                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   REST API      │  │   WebSocket     │  │   Static Files  │             │
│  │   Handlers      │  │   Handlers      │  │   (Embedded)    │             │
│  └────────┬────────┘  └────────┬────────┘  └─────────────────┘             │
│           │                    │                                            │
│           ▼                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────────┐           │
│  │                    Core Services                             │           │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │           │
│  │  │  Device   │  │  Desktop  │  │  Terminal │  │   Share   │ │           │
│  │  │  Manager  │  │  Streamer │  │  Handler  │  │  Handler  │ │           │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘ │           │
│  └─────────────────────────────────────────────────────────────┘           │
│           │                                                                 │
│           ▼                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐           │
│  │                    Storage Layer                             │           │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐                │           │
│  │  │  MongoDB  │  │  In-Memory│  │   File    │                │           │
│  │  │  (Optional)│  │   State   │  │  Storage  │                │           │
│  │  └───────────┘  └───────────┘  └───────────┘                │           │
│  └─────────────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Overview

### Frontend (Web UI)

| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | React 18 | Component-based UI |
| UI Library | Ant Design 5 | Pre-built components |
| State Management | React Context | Global state |
| Networking | Axios + WebSocket | API calls + realtime |
| Terminal | xterm.js | Terminal emulation |
| Desktop | Canvas + WebRTC | Screen rendering |

**Key Features:**
- Device list with real-time status
- Remote desktop viewer with input control
- Terminal emulator with full PTY support
- File explorer with upload/download
- Share link management

### Server

| Module | Path | Purpose |
|--------|------|---------|
| Main | `server/main.go` | Entry point, routing |
| Config | `server/config/` | Configuration loading |
| Handlers | `server/handler/` | Request handlers |
| Common | `server/common/` | Shared utilities |
| Storage | `server/storage/` | MongoDB integration |
| Cluster | `server/cluster/` | Multi-controller |

**Handler Modules:**

| Handler | Endpoint Pattern | Purpose |
|---------|------------------|---------|
| `device` | `/api/device/*` | Device management |
| `desktop` | `/api/device/desktop` | Remote desktop |
| `terminal` | `/api/device/terminal` | Terminal sessions |
| `share` | `/api/share/*` | Share links |
| `generate` | `/api/client/*` | Client generation |
| `auth` | `/api/auth/*` | Authentication |

### Client

| Module | Path | Purpose |
|--------|------|---------|
| Main | `client/client.go` | Entry point |
| Config | `client/config/` | Trailer reading |
| Core | `client/core/` | Connection, handlers |
| Lifecycle | `client/lifecycle/` | Service installation |
| Services | `client/service/` | Feature modules |

**Service Modules:**

| Service | Path | Purpose |
|---------|------|---------|
| Desktop | `client/service/desktop/` | Screen capture, input |
| Terminal | `client/service/terminal/` | PTY management |
| File | `client/service/file/` | File operations |
| Process | `client/service/process/` | Process management |

---

## Communication Protocols

### Binary Protocol

All WebSocket messages use a binary protocol with this header:

```
┌─────────────────────────────────────────────────────────────┐
│  Magic (4 bytes)  │ Service │  Op   │    Event UUID (16)   │
│  [34, 22, 19, 17] │ (1 byte)│(1 byte)│     (optional)       │
├───────────────────┴─────────┴───────┴──────────────────────┤
│                     Payload (variable)                       │
└─────────────────────────────────────────────────────────────┘
```

**Service IDs:**

| ID | Service | Purpose |
|----|---------|---------|
| 20 | Control | JSON commands |
| 21 | Data | Binary data streams |

**Operation Codes (Desktop):**

| Op | Name | Purpose |
|----|------|---------|
| 0x00 | FrameFull | Full frame data |
| 0x01 | FrameDelta | Delta frame |
| 0x02 | FrameKey | Keyframe |
| 0x03 | Control | Control commands |

**Operation Codes (Terminal):**

| Op | Name | Purpose |
|----|------|---------|
| 0x00 | Stream | Raw terminal I/O |
| 0x01 | JSON | Control commands |

### Message Flow

#### Device Connection

```
Client                    Server
   │                         │
   │──────── WSS Connect ────▶│
   │                         │
   │◀─────── Auth Challenge ──│
   │                         │
   │──────── Auth Response ──▶│
   │                         │
   │◀───── Session Token ─────│
   │                         │
   │══════ Bidirectional ═════│
   │         Messages         │
```

#### Remote Desktop

```
Browser                  Server                   Client
   │                        │                        │
   │── Open Desktop WS ────▶│                        │
   │                        │─── DESKTOP_INIT ──────▶│
   │                        │                        │
   │                        │◀── DESKTOP_READY ──────│
   │                        │                        │
   │◀─── Frame Stream ──────│◀── Frame Data ────────│
   │                        │                        │
   │─── Mouse/Keyboard ────▶│─── Input Events ─────▶│
   │                        │                        │
```

#### Terminal Session

```
Browser                  Server                   Client
   │                        │                        │
   │── Open Terminal WS ───▶│                        │
   │                        │─── TERMINAL_INIT ────▶│
   │                        │                        │
   │                        │◀── TERMINAL_READY ────│
   │                        │                        │
   │─── Keyboard Input ────▶│─── PTY Input ────────▶│
   │                        │                        │
   │◀─── Terminal Output ───│◀── PTY Output ────────│
   │                        │                        │
```

---

## Data Flow

### Desktop Streaming

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLIENT (Target)                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │   Screen    │───▶│   Encoder   │───▶│  WebSocket  │──────────────┤
│  │   Capture   │    │  (JPEG/VP8) │    │   Client    │              │
│  └─────────────┘    └─────────────┘    └─────────────┘              │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐                                 │
│  │   Input     │◀───│  WebSocket  │◀─────────────────────────────────┤
│  │  Injection  │    │   Client    │                                 │
│  └─────────────┘    └─────────────┘                                 │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ WSS
┌──────────────────────────────────────────────────────────────────────┐
│                            SERVER                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │   Device    │───▶│   Desktop   │───▶│  Browser    │              │
│  │   Handler   │    │   Handler   │    │   Handler   │              │
│  └─────────────┘    └─────────────┘    └─────────────┘              │
└──────────────────────────────────────────────────────────────────────┘
                                │
                                ▼ WSS
┌──────────────────────────────────────────────────────────────────────┐
│                           BROWSER                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
│  │  WebSocket  │───▶│   Decoder   │───▶│   Canvas    │              │
│  │   Client    │    │             │    │  Renderer   │              │
│  └─────────────┘    └─────────────┘    └─────────────┘              │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐                                 │
│  │   Mouse/    │───▶│  WebSocket  │─────────────────────────────────▶│
│  │  Keyboard   │    │   Client    │                                 │
│  └─────────────┘    └─────────────┘                                 │
└──────────────────────────────────────────────────────────────────────┘
```

### Terminal Flow

```
Client (ConPTY/PTY)          Server              Browser (xterm.js)
       │                        │                        │
       │◀─── Create PTY ────────│◀─── Open Terminal ─────│
       │                        │                        │
       │                        │                        │
       ├─── PTY Output ────────▶├─── Raw Data ──────────▶│
       │    (binary)            │    (binary)            │
       │                        │                        │
       │◀─── PTY Input ─────────│◀─── Key Events ────────│
       │    (binary)            │    (binary)            │
       │                        │                        │
```

---

## Key Features

### Remote Desktop

- **Capture Methods:**
  - Windows: DXGI (Direct3D 11)
  - Linux: X11/XCB
  - macOS: CoreGraphics

- **Encoding:**
  - JPEG (default, no dependencies)
  - Hardware codecs (optional): VP8, VP9, H.264

- **Input Injection:**
  - Windows: SendInput API
  - Linux: XTest extension
  - macOS: CGEventPost

### Terminal (ConPTY Fix)

Windows terminal uses ConPTY with direct Windows API calls:

```go
// Direct Windows pipe I/O (not os.File wrapper)
type handleIO struct {
    handle windows.Handle
}

func (h *handleIO) Read(p []byte) (int, error) {
    var numRead uint32
    err := windows.ReadFile(h.handle, p, &numRead, nil)
    return int(numRead), err
}
```

This fixes the issue where `os.NewFile()` wrapper caused terminal output to block.

### Share Links

Time-limited guest access to devices:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Share Link Flow                               │
│                                                                      │
│  Admin creates share ─▶ Token generated ─▶ Stored in MongoDB        │
│                                                                      │
│  Guest visits URL ─▶ Token validated ─▶ WebSocket connected         │
│                                                                      │
│  Options:                                                            │
│  - View Only / Full Control                                          │
│  - Single Use                                                        │
│  - TURN Only (for strict firewalls)                                  │
│  - Expiration (1-24 hours)                                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Security Model

### Authentication

1. **Admin Authentication:**
   - Username/password in config
   - Session tokens stored in cookies
   - Optional MongoDB-backed sessions

2. **Device Authentication:**
   - Unique UUID generated per client
   - Encryption key embedded in trailer
   - Salt-based key derivation

3. **Share Link Authentication:**
   - Token + secret for validation
   - Origin header verification
   - Optional single-use tokens

### Encryption

| Layer | Method | Purpose |
|-------|--------|---------|
| Transport | TLS 1.3 | Network encryption |
| Config | AES-CTR | Trailer encryption |
| Session | Server salt | Key derivation |

### Origin Validation

WebSocket connections validate Origin header for share links:

```go
// Accept requests from configured public_url
allowedOrigins := []string{
    servercfg.Config.Cluster.PublicURL,
    // ... additional origins
}
```

---

## Scalability

### Single Controller

Handles typical deployments:
- 100+ concurrent devices
- Multiple simultaneous desktop sessions
- In-memory state, optional MongoDB

### Multi-Controller Cluster

For high availability and scale:

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Controller1 │  │ Controller2 │  │ Controller3 │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
               ┌─────────────────┐
               │     MongoDB     │
               │  (Shared State) │
               │                 │
               │  - Devices      │
               │  - Sessions     │
               │  - Share Links  │
               │  - Leases       │
               └─────────────────┘
```

**Features:**
- Leader election via leases
- Session handoff between controllers
- Change streams for real-time sync
- Automatic stale cleanup

---

## Related Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment
- [CONFIGURATION.md](./CONFIGURATION.md) - Configuration reference
- [BUILD.md](./BUILD.md) - Building from source
- [CLIENT_GENERATION.md](./CLIENT_GENERATION.md) - Client binaries
