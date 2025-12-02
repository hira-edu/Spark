# Rocket Server Broker Architecture

## Overview

The Rocket server acts as a **WebSocket broker** that mediates bidirectional communication between:
- **Clients (Devices)**: Desktop agents that stream screen, handle input, manage sessions
- **Browsers (Users)**: Web interfaces that view streams, send input, control devices

The server **does not** process video frames or decrypt sensitive data - it acts as a **transparent relay** with validation and routing logic.

---

## Core Architecture: WebSocket Terminator

### Connection Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Connection Establishment                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. WebSocket Handshake                                             │
│     ├─ Validate Origin (CORS policy)                               │
│     ├─ Check authentication headers                                │
│     └─ Establish encrypted connection (TLS)                        │
│                                                                       │
│  2. Device Registration (DEVICE_UP)                                 │
│     ├─ Validate device secret (shared key)                         │
│     ├─ Generate unique session UUID                                │
│     ├─ Register in device registry: deviceID → session UUID        │
│     ├─ Kick existing session (if duplicate deviceID)               │
│     └─ Set LastPack timestamp                                      │
│                                                                       │
│  3. Browser Connection                                              │
│     ├─ Authenticate user (session/JWT)                             │
│     ├─ Validate device access permissions                          │
│     ├─ Lookup device session UUID in registry                      │
│     └─ Establish forwarding path: browser ↔ device                │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Breakdown

### 1. Device Registry

**Location**: `server/common/devices.go`
**Purpose**: Maps device IDs to active WebSocket sessions

```go
type DeviceRegistry struct {
    devices *cmap.CMap[string, *modules.Device] // UUID → Device metadata
}

// Key operations:
- Set(uuid, device)      // Register device
- Get(uuid)              // Lookup device
- Has(uuid)              // Check if online
- Remove(uuid)           // Unregister on disconnect
- IterCb(func)           // Iterate all devices
```

**Enforcement**:
- **One connection per device**: New connection kicks old session with same deviceID
- **Atomic operations**: Thread-safe concurrent access via cmap
- **Automatic cleanup**: Health check goroutine removes stale entries

**Data Stored**:
```go
type Device struct {
    ID       string  // Unique device identifier
    Hostname string  // Device name
    WAN      string  // Public IP address
    CPU      float64 // CPU usage %
    RAM      float64 // RAM usage %
    Net      float64 // Network usage bytes/sec
    Disk     float64 // Disk usage %
    Uptime   int64   // System uptime seconds
}
```

---

### 2. Origin Validation

**Location**: `server/main.go` (WebSocket upgrade handler)

```go
// CORS and origin validation (production security)
allowedOrigins := []string{
    "https://yourdomain.com",
    "https://app.yourdomain.com",
}

// Check Origin header
origin := req.Header.Get("Origin")
if !isAllowedOrigin(origin, allowedOrigins) {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

**Best Practices (2025)**:
- ✅ Whitelist allowed origins (no wildcards in production)
- ✅ Check `Origin` and `Referer` headers
- ✅ Validate `Sec-WebSocket-Key` for proper WebSocket handshake
- ✅ Enforce TLS (wss://) in production
- ✅ Rate limit connection attempts per IP

---

### 3. Secret Validation

**Location**: `server/handler/utility/utility.go:OnDevicePackWithUUID()`

**Device Authentication Flow**:
```
Device → Server: DEVICE_UP packet
    {
        "act": "DEVICE_UP",
        "data": {
            "id": "device-uuid",
            "hostname": "user-pc",
            "secret": "shared-secret-key",
            ...
        }
    }

Server validates:
1. Secret matches expected value (from config/database)
2. Device not blacklisted
3. Rate limit not exceeded

If valid:
- Register device in registry
- Return success (Code: 0)

If invalid:
- Close connection (Code: 1)
- Log security event
```

**Secret Storage**:
- Embedded in client binary during build (see `/root/Rocket/built/` workflow)
- Server reads from config or environment variable
- Future: Per-device secrets in database

---

### 4. Binary Frame Forwarding (Desktop Streaming)

**Location**: `server/handler/desktop/desktop.go`

**Path**: Device → Server → Browser (zero-copy relay)

```go
// Desktop binary frame format:
// [12 bytes header][N bytes JPEG/WebP/VP8 data]
//
// Header:
// [0-3]:   Block X coordinate (uint32)
// [4-7]:   Block Y coordinate (uint32)
// [8-11]:  Data length (uint32)
// [12+]:   Compressed image data

// Server does NOT decode frames - forwards directly to browser
func HandleDesktopData(binaryData []byte, deviceUUID string) {
    // Validate size (prevent DoS)
    if len(binaryData) > MaxFrameSize {
        return errors.New("frame too large")
    }

    // Forward to all connected browsers watching this device
    forwardToBrowsers(deviceUUID, binaryData)
}
```

**Optimizations**:
- **Zero-copy forwarding**: No frame decoding/re-encoding
- **Backpressure handling**: Drop frames if browser can't keep up
- **MTU awareness**: Fragments large frames automatically (see `mtu_fragmentation.go`)

---

### 5. JSON Decryption & Forwarding

**Location**: `server/main.go:onBinaryMessage()`

**Path**: Device → Server (decrypt) → Browser (JSON)

```go
// Encrypted JSON packets (control messages)
// Device encrypts with stream cipher (XOR with shared secret)

func onBinaryMessage(session *melody.Session, data []byte) {
    // Attempt to decrypt
    decrypted := utility.SimpleDecrypt(data, session)
    if decrypted == nil {
        return // Not encrypted or invalid
    }

    // Parse JSON
    var pack modules.Packet
    if err := json.Unmarshal(decrypted, &pack); err != nil {
        return // Invalid JSON
    }

    // Route to handler based on pack.Act
    common.CallEvent(pack, session)
}
```

**Encrypted Packet Types**:
- `TERMINAL_OUTPUT`: Shell command results
- `FILE_LIST`: Directory listings
- `DESKTOP_INIT`: Desktop session metadata
- `WEBCAM_INIT`: Camera capabilities

**Unencrypted Packet Types** (already secure over TLS):
- `DEVICE_UP`: Initial registration
- `DEVICE_UPDATE`: Status updates
- Binary frames (already compressed, no sensitive data)

---

### 6. Input/Control Routing (Browser → Device)

**Location**: `server/handler/desktop/input.go`

**Path**: Browser → Server (validate) → Device

```go
// Browser sends input events
POST /api/desktop/input
{
    "uuid": "browser-session-uuid",
    "device": "device-id",
    "events": [
        {"type": "mousemove", "x": 100, "y": 200},
        {"type": "mousedown", "button": 0},
        {"type": "keydown", "key": "a"}
    ]
}

// Server validation:
func HandleDesktopInput(ctx *gin.Context, form InputForm) {
    // 1. Validate session
    connUUID := CheckForm(ctx, form)

    // 2. Enforce batch size limit
    if len(form.Events) > InputBatchLimit {
        form.Events = form.Events[:InputBatchLimit]
    }

    // 3. Validate event types (prevent injection)
    for _, event := range form.Events {
        if !isValidInputEvent(event) {
            return error
        }
    }

    // 4. Forward to device
    SendPackByUUID(modules.Packet{
        Act: "DESKTOP_INPUT",
        Data: form.Events,
    }, connUUID)
}
```

**Security Measures**:
- ✅ Batch size limit (prevent DoS): Max 100 events per request
- ✅ Event type whitelist: Only allowed input events
- ✅ Rate limiting: Max requests per second per session
- ✅ Input sanitization: Validate coordinates, key codes

---

### 7. WebRTC Signaling Routing

**Location**: `server/handler/desktop/webrtc.go`

**Path**: Bidirectional signaling relay

```
Browser                Server                  Device
   │                      │                       │
   │──SDP Offer────────▶  │                       │
   │   (JSON)             │──Validate SDP───────▶ │
   │                      │   (size, format)      │
   │                      │                       │
   │                      │  ◀──SDP Answer────────│
   │  ◀───────────────────│                       │
   │                      │                       │
   │──ICE Candidate────▶  │                       │
   │   (JSON)             │──Validate ICE───────▶ │
   │                      │   (size, format)      │
   │                      │                       │
```

**Validation** (`webrtc_signaling.go`):
```go
const (
    maxSDPLength       = 1 << 15 // 32 KiB
    maxCandidateLength = 4096
)

func HandleWebRTCOffer(pack modules.Packet) {
    // Validate SDP size
    sdp := pack.GetData("sdp")
    if len(sdp) > maxSDPLength {
        return error
    }

    // Validate SDP format (basic check)
    if !isValidSDP(sdp) {
        return error
    }

    // Forward to device
    forwardToDevice(pack)
}

func isValidSDP(sdp string) bool {
    // Must contain version and media lines
    return strings.Contains(sdp, "v=") &&
           strings.Contains(sdp, "m=")
}

func isValidICECandidate(candidate string) bool {
    // Empty = end-of-candidates (valid)
    if candidate == "" {
        return true
    }

    // Must contain type info
    return strings.Contains(candidate, " ") &&
           (strings.HasPrefix(candidate, "candidate:") ||
            strings.Contains(candidate, "typ "))
}
```

**WebRTC Handlers**:
- `DESKTOP_WEBRTC_OFFER`: Browser initiates WebRTC connection
- `DESKTOP_WEBRTC_ANSWER`: Device responds with answer
- `DESKTOP_WEBRTC_ICE`: Bidirectional ICE candidate exchange

**Server Role**:
- ✅ Validates packet sizes (prevent DoS)
- ✅ Validates format (basic sanity checks)
- ✅ Routes between browser and device
- ❌ Does NOT process SDP/ICE (transparent relay)
- ❌ Does NOT participate in media path (P2P after negotiation)

---

### 8. Size Limits & Validation

**Global Limits** (defined in various handlers):

```go
// WebSocket message limits
const (
    MaxMessageSize = 10 * 1024 * 1024  // 10 MB (Melody default)
    MaxFrameSize   = 5 * 1024 * 1024   // 5 MB per desktop frame
)

// Input validation
const (
    InputBatchLimit     = 100          // Max events per batch
    MaxInputPayload     = 1 << 16      // 64 KB per input packet
)

// WebRTC validation
const (
    maxSDPLength        = 1 << 15      // 32 KiB SDP
    maxCandidateLength  = 4096         // 4 KB ICE candidate
)

// Terminal validation
const (
    MaxTerminalCols     = 500          // Max terminal width
    MaxTerminalRows     = 200          // Max terminal height
    MaxTerminalOutput   = 1 << 20      // 1 MB output buffer
)
```

**Validation Strategy**:
1. **Check size first**: Reject oversized packets immediately
2. **Validate format**: Basic structure checks (not full parsing)
3. **Sanitize content**: Remove/escape dangerous characters
4. **Enforce limits**: Cap batch sizes, truncate if needed
5. **Log violations**: Track potential attacks

---

### 9. Shares & Guest Access

**Location**: `server/handler/share/`

**Architecture**:
```
Regular Access:
Browser ──[user session]──▶ Server ──▶ Device
          (full permissions)

Guest Access (Share):
Browser ──[share token]──▶ Server ──▶ Device
          (scoped permissions)

Share Token Format:
{
    "token": "random-uuid",
    "deviceID": "target-device",
    "permissions": ["view", "control"],
    "expiresAt": "2025-01-01T00:00:00Z",
    "maxConnections": 5,
    "secret": "scoped-secret"
}
```

**Share Workflow**:
```go
// 1. User creates share
POST /api/share/create
{
    "device": "device-id",
    "permissions": ["view", "control"],
    "expiry": "24h"
}

Response:
{
    "token": "abc123...",
    "url": "https://app.domain.com/share/abc123"
}

// 2. Guest accesses share
GET /share/abc123
    ├─ Validate token (exists, not expired)
    ├─ Check max connections not exceeded
    ├─ Grant scoped access to device
    └─ Same flow as regular access, but:
        ├─ Limited permissions (read-only, etc.)
        ├─ Separate secret for encryption
        └─ Usage tracking for auditing
```

**Scoped Permissions**:
```go
type SharePermissions struct {
    View     bool  // Can view desktop stream
    Control  bool  // Can send input events
    Terminal bool  // Can access terminal
    Files    bool  // Can browse/download files
    Webcam   bool  // Can view webcam
    Audio    bool  // Can hear audio
}

// Enforced at handler level
func HandleDesktopInput(ctx *gin.Context) {
    share := getShareFromContext(ctx)
    if share != nil && !share.Permissions.Control {
        return error("permission denied")
    }
    // ... normal input handling
}
```

**Share Security**:
- ✅ Random token generation (UUID v4)
- ✅ Time-based expiry
- ✅ Max concurrent connections
- ✅ Permission scoping
- ✅ Separate encryption secret
- ✅ Audit logging
- ✅ Revocation support

---

## Data Flow Examples

### Desktop Streaming (Binary)

```
Client Device                    Server                     Browser
     │                              │                            │
     │──1. Capture screen───────────│                            │
     │   (1920x1080 → JPEG 50KB)    │                            │
     │                              │                            │
     │──2. Send binary frame───────▶│                            │
     │   [12 byte header][50KB]     │                            │
     │                              │                            │
     │                              │──3. Forward directly────▶  │
     │                              │   (zero-copy)              │
     │                              │                            │
     │                              │──4. Check backpressure──   │
     │                              │   (browser queue depth)    │
     │                              │                            │
     │                              │◀──5. Browser renders────── │
     │                              │   (decode JPEG, display)   │
     │                              │                            │
     │◀─6. DESKTOP_INPUT────────────│◀──6. User clicks──────────│
     │   {"type": "mousedown"}      │                            │
```

### WebRTC Negotiation

```
Browser                Server               Device
   │                      │                    │
   │──1. Click "Connect"──│                    │
   │                      │                    │
   │──2. POST /api/       │                    │
   │   desktop/webrtc/    │                    │
   │   offer              │                    │
   │   {sdp: "v=0..."}    │                    │
   │                      │                    │
   │                      │──3. Validate SDP──▶│
   │                      │   Forward packet   │
   │                      │                    │
   │                      │◀──4. Create answer─│
   │                      │   {sdp: "v=0..."}  │
   │                      │                    │
   │◀─5. Return answer────│                    │
   │   {sdp: "v=0..."}    │                    │
   │                      │                    │
   │──6. Exchange ICE─────│◀──▶ Exchange ICE───│
   │   candidates         │      candidates    │
   │                      │                    │
   │────────────7. Direct P2P media path──────▶│
   │            (server no longer in path)     │
```

### Health Check & Cleanup

```
Server Health Goroutine (every 20s)
   │
   ├─▶ Iterate all sessions
   │   ├─ Check LastPack timestamp
   │   │  ├─ < 10s: Active, skip
   │   │  ├─ 10-300s: Idle, send PING
   │   │  └─ > 300s: Dead, close connection
   │   │
   │   ├─ Send PING (record PingTime)
   │   │  └─▶ Device responds with PONG
   │   │      └─▶ Calculate RTT = now - PingTime
   │   │          └─▶ Store RTT for adaptive quality
   │   │
   │   └─ Close dead connections
   │      └─▶ Remove from device registry
   │          └─▶ Notify connected browsers
```

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Network (TLS/WSS)                                   │
│ - TLS 1.3 encryption                                         │
│ - Certificate validation                                     │
│ - Forward secrecy                                            │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Connection (Origin/CORS)                           │
│ - Origin whitelist validation                               │
│ - CSRF token checks                                          │
│ - Rate limiting per IP                                       │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Authentication (Secret/Session)                    │
│ - Device secret validation                                  │
│ - User session verification                                 │
│ - JWT/token validation                                       │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Authorization (Permissions)                        │
│ - Device ownership checks                                   │
│ - Share permission scoping                                  │
│ - Action-level access control                               │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Validation (Input/Size)                            │
│ - Packet size limits                                        │
│ - Input event validation                                    │
│ - SDP/ICE format checks                                      │
│ - Batch size enforcement                                     │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│ Layer 6: Encryption (E2E for JSON)                          │
│ - Stream cipher (XOR) for control packets                   │
│ - Scoped secrets for shares                                 │
│ - Key rotation support                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## Performance Optimizations

### 1. Zero-Copy Binary Relay
- Desktop frames forwarded without parsing/re-encoding
- Server acts as dumb pipe for video data
- Minimal CPU usage on server

### 2. Concurrent Session Handling
- Each WebSocket connection runs in own goroutine
- Lock-free device registry (cmap)
- Atomic lastPack updates

### 3. Backpressure Management
- Tracks pending bytes per session
- Drops frames if browser can't keep up
- Prevents server memory exhaustion

### 4. MTU-Aware Fragmentation
- Large frames chunked to 256 KB
- Respects WebSocket MaxMessageSize
- Avoids TCP head-of-line blocking

### 5. Health Check Optimization
- Only pings idle connections
- Active connections skip checks
- Batched cleanup (queue before close)

---

## Monitoring & Observability

### Metrics Tracked

```go
// Connection metrics
- total_connections (gauge)
- active_sessions (gauge)
- idle_sessions (gauge)
- connection_errors_total (counter)

// Performance metrics
- rtt_milliseconds (histogram)
- frame_size_bytes (histogram)
- frames_forwarded_total (counter)
- frames_dropped_total (counter)

// Health check metrics
- health_check_cycles_total (counter)
- stale_connections_closed_total (counter)
- ping_timeouts_total (counter)

// Security metrics
- authentication_failures_total (counter)
- oversized_packets_dropped_total (counter)
- invalid_input_events_total (counter)
```

### Logging Structure

```json
{
    "level": "INFO|WARN|ERROR",
    "event": "EVENT_TYPE",
    "status": "success|fail|timeout",
    "msg": "human-readable message",
    "sessionUUID": "abc123...",
    "data": {
        "key": "value"
    }
}
```

---

## Scalability Considerations

### Current Architecture (Single Server)
- **Capacity**: ~10,000 concurrent connections per server
- **Bottleneck**: Network bandwidth (not CPU)
- **Scaling**: Vertical (more cores/bandwidth)

### Future: Horizontal Scaling
```
Browser ──▶ Load Balancer ──┬──▶ Server 1 ──▶ Redis
                            ├──▶ Server 2 ──▶ (shared state)
                            └──▶ Server 3 ──▶ Device Registry
```

**Required Changes**:
- Move device registry to Redis (centralized)
- Sticky sessions or session affinity
- Pub/sub for inter-server routing
- Distributed health checks

---

## Configuration

### Environment Variables

```bash
# Server binding
SERVER_HOST=0.0.0.0
SERVER_PORT=18080

# TLS (production)
TLS_ENABLED=true
TLS_CERT=/path/to/cert.pem
TLS_KEY=/path/to/key.pem

# Limits
MAX_FRAME_SIZE=5242880        # 5 MB
MAX_INPUT_BATCH=100           # events
WS_MAX_MESSAGE_SIZE=10485760  # 10 MB

# Health check
PING_INTERVAL=20              # seconds
IDLE_TIMEOUT=300              # seconds

# Security
ALLOWED_ORIGINS=https://app.domain.com,https://admin.domain.com
DEVICE_SECRET=your-secret-key

# Monitoring
LOG_LEVEL=INFO
METRICS_ENABLED=true
METRICS_PORT=9090
```

---

## Summary

The Rocket server is a **high-performance WebSocket broker** that:

✅ **Validates** origins, devices, and secrets
✅ **Registers** devices in thread-safe registry
✅ **Forwards** binary frames with zero-copy efficiency
✅ **Decrypts** JSON control packets for routing
✅ **Routes** input/WebRTC signaling bidirectionally
✅ **Enforces** size limits and input validation
✅ **Supports** tokenized share endpoints with scoped permissions
✅ **Monitors** connection health with PING/PONG
✅ **Measures** RTT for adaptive quality
✅ **Cleans up** idle sessions automatically

**Design Philosophy**: Simple, fast, secure relay—complexity belongs in clients, not the broker.
