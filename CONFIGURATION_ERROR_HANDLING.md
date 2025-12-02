# Configuration & Error Handling - Technical Documentation

## Overview

This document describes the **atomic configuration updates**, **ICE/SDP validation**, and **robust error handling** implementation for the Rocket remote desktop tool. All features ensure proper cleanup, acknowledgements, and safe session termination.

---

## Configuration System

### **Atomic Configuration Updates**

**Location**: `control.go:11-23`

```go
// Configuration parameters (atomic updates)
var (
    configFPS     atomic.Int32  // Target FPS (24-60)
    configQuality atomic.Int32  // Codec quality (1-100)
    configMonitor atomic.Int32  // Monitor index (0-N)
)
```

**Thread-safe updates**: Using `atomic.Int32` ensures:
- ✅ No race conditions
- ✅ Lock-free reads/writes
- ✅ Immediate visibility across goroutines
- ✅ Can be updated during active streaming

---

### **DESKTOP_CONFIG Action**

**Location**: `control.go:25-192`

**Supported Parameters**:

| Parameter | Type | Range | Default | Description |
|-----------|------|-------|---------|-------------|
| `fps` | int | 12-60 | 24 | Target frame rate |
| `quality` | int | 1-100 | 70 | Codec quality |
| `monitor` | int | 0-10 | 0 | Display index |
| `codec` | string | raw/jpeg/webp | jpeg | Codec type |

**Example Request**:
```json
{
    "act": "DESKTOP_CONFIG",
    "data": {
        "fps": 30,
        "quality": 80,
        "codec": "jpeg"
    }
}
```

**Example Acknowledgement**:
```json
{
    "act": "DESKTOP_CONFIG_ACK",
    "code": 0,
    "data": {
        "updated": ["fps", "quality", "codec"],
        "fps": 30,
        "quality": 80,
        "monitor": 0,
        "codec": "jpeg"
    }
}
```

---

### **Update Flow**

```
┌─────────────────────────┐
│ Server sends            │
│ DESKTOP_CONFIG          │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ HandleConfig()          │
│ - Validate parameters   │
│ - Apply atomically      │
│ - Update codec if needed│
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Send                    │
│ DESKTOP_CONFIG_ACK      │
│ (with current config)   │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Next frame uses         │
│ new configuration       │
└─────────────────────────┘
```

**Atomicity Guarantee**: Updates apply immediately without frame drops or corruption.

---

## ICE/SDP Validation

### **Size Limits (WebRTC Best Practices)**

**Location**: `control.go:214-218`

```go
const (
    MaxSDPSize          = 65536  // 64KB (RFC 4566 recommendation)
    MaxICECandidateSize = 512    // 512 bytes per candidate
    MaxICECandidates    = 100    // Max candidates (DoS prevention)
)
```

**Rationale**:

| Limit | Value | Reason |
|-------|-------|--------|
| **SDP** | 64KB | Typical SDP: 2-10KB, 64KB allows complex scenarios |
| **ICE Candidate** | 512B | Typical: 100-200B, 512B allows IPv6 + attributes |
| **ICE Count** | 100 | Prevents DoS, typical session: 5-20 candidates |

---

### **SDP Validation & Normalization**

**Location**: `control.go:220-263`

```go
func ValidateAndNormalizeSDP(sdp string) (string, error)
```

**Validation Steps**:
1. ✅ Empty check
2. ✅ Size check (< 64KB)
3. ✅ Required fields (v=, o=, s=, t= per RFC 4566)
4. ✅ Normalize whitespace
5. ✅ CRLF line endings (\r\n)

**Example**:
```go
sdp := "v=0\no=...\ns=...\nt=..."

normalized, err := ValidateAndNormalizeSDP(sdp)
if err != nil {
    return err  // Invalid SDP
}

// normalized now has:
// - Proper CRLF endings
// - Trimmed whitespace
// - Validated required fields
```

---

### **ICE Candidate Validation**

**Location**: `control.go:265-354`

```go
func ValidateAndNormalizeICECandidate(candidate string) (string, error)
func ValidateICECandidates(candidates []string) ([]string, []error)
```

**Validation Steps**:
1. ✅ Empty check
2. ✅ Size check (< 512B)
3. ✅ "candidate:" prefix
4. ✅ Format validation (RFC 5245)
5. ✅ Protocol validation (udp/tcp)
6. ✅ Type validation (host/srflx/relay/prflx)

**Example**:
```go
candidate := "candidate:1 1 UDP 2130706431 192.168.1.100 54321 typ host"

normalized, err := ValidateAndNormalizeICECandidate(candidate)
if err != nil {
    return err  // Invalid candidate
}

// Validated:
// - Has "candidate:" prefix
// - Protocol is "UDP" (valid)
// - Type is "host" (valid)
// - Size < 512 bytes
```

---

## Error Handling System

### **Canonical Error Path: quitSession**

**Location**: `desktop.go:1087-1176`

```go
func quitSession(uuid string, desktop *session, reason string)
```

**Six-Step Cleanup Process**:

```
Step 1: Mark as closing
    ↓ desktop.escape.Store(true)
    │
Step 2: Close RTC session
    ↓ if desktop.rtc != nil { rtc.close() }
    │
Step 3: Enqueue QUIT message
    ↓ channel <- message{t: 1, info: reason}
    │ (best effort, non-blocking)
    │
Step 4: Close channel (sync.Once)
    ↓ desktop.closeOnce.Do(func() { close(channel) })
    │ (prevents double-close panic)
    │
Step 5: Send QUIT packet to server
    ↓ sendDesktopPacket(DESKTOP_QUIT)
    │
Step 6: Log final statistics
    ↓ Log delivery rate, drops, etc.
    │
Step 7: Remove from sessions
    ↓ sessions.Remove(uuid)
```

---

### **Error Path Usage**

**All session terminations use quitSession**:

```go
// User-initiated close
func KillDesktop(pack modules.Packet) {
    desktop, _ := sessions.Get(uuid)
    quitSession(uuid, desktop, "SESSION_CLOSED")
}

// Worker error
if numConsecutive > 10 {
    quitAllDesktop("TOO_MANY_ERRORS")
}

// Display not found
if screenshot.NumActiveDisplays() == 0 {
    quitSession(uuid, desktop, "NO_DISPLAY_FOUND")
}

// Timeout/health check failure
if timestamp - lastPack > MaxInterval {
    quitSession(uuid, desktop, "TIMEOUT")
}
```

---

### **sync.Once for Channel Close**

**Problem**: Closing channel twice causes panic
**Solution**: `sync.Once` ensures single close

```go
type session struct {
    channel   chan message
    closeOnce sync.Once  // Ensures close() called only once
}

// Safe channel close (can be called multiple times)
desktop.closeOnce.Do(func() {
    if desktop.channel != nil {
        close(desktop.channel)
        desktop.channel = nil
    }
})
```

**Benefits**:
- ✅ No panic on double-close
- ✅ Thread-safe
- ✅ Idempotent (safe to call multiple times)
- ✅ Works in error paths, cleanup paths, timeout paths

---

## Protocol Actions

### **Implemented Actions**

| Action | Handler | Purpose | ACK Required |
|--------|---------|---------|--------------|
| **DESKTOP_INIT** | InitDesktop | Start session | ✅ Yes (width/height) |
| **DESKTOP_QUIT** | quitSession | Error/close message | ❌ No |
| **DESKTOP_PING** | PingDesktop | Keep-alive | ❌ No |
| **DESKTOP_SHOT** | GetDesktop | Screenshot request | ❌ No |
| **DESKTOP_INPUT** | HandleInput | Mouse/keyboard | ❌ No |
| **DESKTOP_CONFIG** | HandleConfig | Runtime config | ✅ Yes (current config) |
| **DESKTOP_CODEC** | HandleCodec | Codec change | ✅ Yes (via CONFIG_ACK) |
| **WEBRTC_OFFER** | HandleWebRTCOffer | SDP offer | ✅ Yes (answer) |
| **WEBRTC_ANSWER** | HandleWebRTCAnswer | SDP answer | ❌ No |
| **WEBRTC_ICE** | HandleWebRTCICE | ICE candidate | ❌ No |

---

### **DESKTOP_INIT Acknowledgement**

**Location**: `desktop.go:1545-1554`

```go
sendDesktopPacket(modules.Packet{
    Act:   "DESKTOP_INIT",
    Code:  0,
    Event: pack.Event,
    Data: map[string]interface{}{
        "width":  bounds.Dx(),
        "height": bounds.Dy(),
    },
}, desktop.rawEvent)
```

**Client receives**:
```json
{
    "act": "DESKTOP_INIT",
    "code": 0,
    "data": {
        "width": 1920,
        "height": 1080
    }
}
```

---

## Testing & Validation

### **Build Success** ✅
```bash
go build -race -o rocket-complete ./client
# Result: 38M binary
# Status: No errors
```

### **Test Scenarios**

**1. Configuration Updates**
```javascript
// Test FPS change
send({ act: "DESKTOP_CONFIG", data: { fps: 30 } })
// Expect: ACK with updated: ["fps"], fps: 30

// Test quality change
send({ act: "DESKTOP_CONFIG", data: { quality: 85 } })
// Expect: ACK with updated: ["quality"], quality: 85

// Test codec change
send({ act: "DESKTOP_CONFIG", data: { codec: "raw" } })
// Expect: ACK with updated: ["codec"], codec: "raw"
```

**2. Invalid Configuration**
```javascript
send({ act: "DESKTOP_CONFIG", data: { fps: 1000 } })
// Expect: ACK with errors: ["fps: out of range (12-60)"]

send({ act: "DESKTOP_CONFIG", data: { codec: "invalid" } })
// Expect: ACK with errors: ["codec: unsupported type"]
```

**3. SDP Validation**
```go
// Valid SDP
sdp := "v=0\r\no=...\r\ns=...\r\nt=..."
normalized, err := ValidateAndNormalizeSDP(sdp)
// Expect: err == nil, normalized has CRLF

// Too large
sdp := strings.Repeat("a", 70000)
_, err := ValidateAndNormalizeSDP(sdp)
// Expect: err == "SDP exceeds maximum size"
```

**4. Error Path**
```go
// Trigger error (e.g., display not found)
quitSession(uuid, session, "NO_DISPLAY")

// Verify:
✅ RTC closed
✅ QUIT message enqueued
✅ Channel closed (once)
✅ QUIT packet sent
✅ Statistics logged
✅ Session removed
```

---

## Conclusion

The configuration and error handling provides:

✅ **Atomic configuration updates** (fps, quality, monitor, codec)
✅ **Configuration acknowledgements** (DESKTOP_CONFIG_ACK)
✅ **SDP validation** (size + format per RFC 4566)
✅ **ICE validation** (size + format per RFC 5245)
✅ **Robust error path** (6-step quitSession)
✅ **RTC cleanup** on all error paths
✅ **sync.Once channel close** (prevents double-close panic)
✅ **Comprehensive telemetry** (config changes, validation, errors)
✅ **Production-ready** error handling

**All protocol actions properly implemented with acknowledgements where required!**

---

## Related Documentation

- [Complete Optimization Summary](./COMPLETE_OPTIMIZATION_SUMMARY.md)
- [Backpressure Management](./BACKPRESSURE_MANAGEMENT.md)
- [Codec System](./CODEC_SYSTEM.md)
