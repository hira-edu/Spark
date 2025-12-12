# P2P Architecture Guide

## Overview

Rocket implements P2P (peer-to-peer) connectivity based on patterns from [RustDesk](https://github.com/rustdesk/rustdesk) and [Pion](https://github.com/pion/webrtc). This enables direct connections between clients, reducing latency and server load compared to relay-based communication.

## Configuration

Generated clients now read a dedicated `p2p` block from the config trailer. Controllers can define global defaults in `config.json` (see `config.example.json`) so every built client inherits sane rendezvous values:

```json
"p2p": {
  "enable": true,
  "rendezvous_url": "https://controller.example.com/api",
  "target": "peer-id-or-env-override",
  "stun_servers": [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302"
  ]
}
```

During generation you can override the enable flag, target, or rendezvous URL via the API/UI form fields (`p2p_enable`, `p2p_target`, `p2p_rendezvous_url`). The CLI helper `gen_config.go` exposes equivalent `-p2p-*` flags. Devices may still supply `SPARK_P2P_TARGET` at runtime to override the baked target without rebuilding.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              P2P Connection Flow                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────┐                  ┌──────────────┐                ┌─────────┐  │
│   │ Client A│                  │  Rendezvous  │                │ Client B│  │
│   │(Viewer) │                  │    Server    │                │ (Host)  │  │
│   └────┬────┘                  └──────┬───────┘                └────┬────┘  │
│        │                              │                              │       │
│        │ 1. NAT Detection (STUN)      │                              │       │
│        │◄──────────────────►          │                              │       │
│        │                              │                              │       │
│        │ 2. Register Endpoints        │ 2. Register Endpoints        │       │
│        │────────────────────►         │◄────────────────────────────│       │
│        │                              │                              │       │
│        │ 3. Punch Initiate            │                              │       │
│        │────────────────────►         │                              │       │
│        │                              │                              │       │
│        │◄──────────────────────────── │ 4. Peer Endpoints + StartTime│       │
│        │                              │ ───────────────────────────► │       │
│        │                              │                              │       │
│        │ ◄═══════════════════════════════════════════════════════► │       │
│        │              5. Simultaneous TCP Connect (Hole Punch)       │       │
│        │                                                             │       │
│        │ ◄═══════════════════════════════════════════════════════► │       │
│        │                      6. Direct P2P Channel                  │       │
│        │                                                             │       │
│   ┌────┴────┐                                                  ┌────┴────┐  │
│   │NAT/     │                                                  │NAT/     │  │
│   │Firewall │                                                  │Firewall │  │
│   └─────────┘                                                  └─────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### 1. NAT Detector (`client/transport/nat.go`)

Detects the NAT type using STUN (Session Traversal Utilities for NAT) protocol to determine if hole punching will work.

Rocket now runs the RFC 5780 filtering tests (CHANGE-REQUEST) against STUN servers that expose the `OTHER-ADDRESS` attribute so we can distinguish Full Cone, Restricted, and Port-Restricted behavior rather than collapsing everything into a generic "cone" bucket. When the STUN server honors the change requests we:

1. Request the server to reply from a different IP/port to detect Full Cone NATs.
2. Request a port-only change to discriminate between Restricted and Port-Restricted filtering.
3. Fall back to Restricted Cone when the server does not support these extensions.

**NAT Types:**

| Type | Description | Hole Punch? |
|------|-------------|-------------|
| Open | No NAT, public IP | Yes |
| Full Cone | 1:1 mapping, any external host can send | Yes |
| Restricted Cone | 1:1 mapping, only contacted hosts can send | Yes |
| Port Restricted | 1:1 mapping, only contacted host:port can send | Yes |
| Symmetric | Different mapping per destination | **No** |

**Usage:**

```go
detector := transport.NewNATDetector(nil) // Uses default STUN servers
natInfo, err := detector.Detect(ctx)

if natInfo.Type.CanHolePunch() {
    // Proceed with P2P
} else {
    // Fall back to relay
}
```

**Default STUN Servers:**
- stun.l.google.com:19302
- stun1.l.google.com:19302
- stun.cloudflare.com:3478
- stun.stunprotocol.org:3478

### 2. Hole Puncher (`client/transport/holepunch.go`)

Implements TCP hole punching using simultaneous connect with `SO_REUSEADDR`.

**How it works:**

1. Both peers bind to a local port with `SO_REUSEADDR`
2. Both peers simultaneously send TCP SYN packets to each other's external IP:port
3. The first SYN "punches" a hole by creating an outbound NAT mapping
4. The peer's incoming SYN uses the same hole (NAT sees it as part of the session)
5. TCP handshake completes through the "punched" hole

**Configuration:**

```go
config := &transport.HolePunchConfig{
    LocalPort:     0,               // Auto-assign
    PunchAttempts: 5,               // Parallel connect attempts
    PunchTimeout:  3 * time.Second, // Per-attempt timeout
    RetryDelay:    500 * time.Millisecond,
    MaxRetries:    3,
}
puncher := transport.NewHolePuncher(config)
```

**Punch Methods:**

| Method | Description |
|--------|-------------|
| `Punch()` | Basic hole punch |
| `PunchAsync()` | Non-blocking hole punch |
| `PunchBidirectional()` | Connect + Listen simultaneously |
| `CoordinatedPunch()` | Waits for agreed start time |

### 3. Rendezvous Server (`server/handler/rendezvous/`)

Facilitates peer discovery and punch coordination.

**Endpoints:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/p2p/rendezvous/register` | POST | Register peer endpoints |
| `/p2p/rendezvous/heartbeat` | POST | Keep registration alive |
| `/p2p/rendezvous/request` | POST | Get peer's endpoints |
| `/p2p/rendezvous/register` | DELETE | Deregister peer |
| `/p2p/punch/initiate` | POST | Start punch session |
| `/p2p/punch/exchange` | POST | Report punch result |
| `/p2p/punch/relay` | GET | Get relay servers |

**Registration Payload:**

```json
{
  "peer_id": "device-uuid",
  "endpoints": [
    {"protocol": "tcp", "host": "1.2.3.4", "port": 54321},
    {"protocol": "tcp-local", "host": "192.168.1.100", "port": 12345}
  ],
  "metadata": {
    "nat_type": "RestrictedCone",
    "latency": 45
  }
}
```

**Punch Initiation Response:**

```json
{
  "session_id": "abc123",
  "start_time": "2024-12-08T10:00:00.500Z",
  "target_endpoints": [...],
  "target_nat_type": "FullCone",
  "can_punch": true,
  "recommend_relay": false
}
```

### 4. Transport Selector (`client/transport/p2p.go`)

Automatically selects the best transport based on NAT analysis.

The core dialer (`client/core/transport_connect.go`) now invokes the selector before building the fallback chain so that when the selector determines the NAT can hole punch, the app attempts a coordinated P2P connection before trying WebSocket/relay transports.

**Selection Logic:**

```go
selector := transport.NewTransportSelector(config)
result, _ := selector.SelectWithDetails(ctx)

switch {
case result.NATInfo.Type.CanHolePunch():
    // Use P2P transport (priority 5)
default:
    // Use WebSocket relay (priority 10)
}
```

## Connection Flow

### Phase 1: Discovery

1. **NAT Detection**: Client queries STUN servers to determine external IP:port and NAT type
2. **Registration**: Client registers with rendezvous server, providing endpoints and NAT metadata
3. **Heartbeat**: Client maintains registration with periodic heartbeats (every ~60s)

### Phase 2: Punch Coordination

1. **Initiate**: Viewer calls `/punch/initiate` with target peer ID
2. **Validation**: Server checks both peers' NAT types for compatibility
3. **Timing**: Server returns synchronized `start_time` (500ms in future) and target endpoints
4. **Exchange**: Both peers report punch results via `/punch/exchange`

The client-side transport now wires these endpoints end-to-end: `client/transport/p2p.go` calls `/p2p/punch/initiate` immediately after fetching the peer record, waits for the rendezvous-provided `start_time`, and uses `HolePuncher.CoordinatedPunch` to ensure both peers fire simultaneously. After the attempt, the transport reports the result through `/p2p/punch/exchange` (success/failure plus attempt metadata) so the rendezvous service can drive relay recommendations and telemetry.

### Phase 3: Connection

```
Both peers at synchronized start_time:

Client A                           Client B
   │                                   │
   │── TCP SYN ──────────────────────► │ (blocked by B's NAT)
   │                                   │
   │ ◄─────────────────────── TCP SYN ─│ (blocked by A's NAT)
   │                                   │
   │ (A's NAT now expects B's IP)      │ (B's NAT now expects A's IP)
   │                                   │
   │── TCP SYN ──────────────────────► │ (passes through B's NAT!)
   │                                   │
   │ ◄─────────────────────── TCP SYN ─│ (passes through A's NAT!)
   │                                   │
   │═══════════════════════════════════│ TCP Connection Established!
```

## NAT Compatibility Matrix

| Client NAT | Host NAT | Strategy | Latency |
|------------|----------|----------|---------|
| Cone | Cone | Direct (TCP punch) | <20ms |
| Cone | Symmetric | Relay | +50-100ms |
| Symmetric | Cone | Relay | +50-100ms |
| Symmetric | Symmetric | Relay | +50-100ms |
| Open | Any | Direct | <10ms |

## Storage Backend

The rendezvous server supports two storage backends:

### In-Memory (Default)
- Suitable for single-node deployments
- Peers lost on server restart
- Zero external dependencies

### MongoDB
- For production/HA deployments
- Peers survive server restarts
- Automatic TTL-based cleanup via MongoDB indexes
- Collection: `rendezvous_peers`

**Environment Variables:**
```bash
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=rocket
```

## Testing

### Unit Tests

```bash
# NAT detection and hole punching tests
go test ./client/transport/... -v

# Rendezvous handler tests
go test ./server/handler/rendezvous/... -v
```

### Integration Tests (requires network)

```bash
# Full integration tests including STUN queries
go test ./client/transport/... -v -run Integration
```

## Security Considerations

1. **Token-based Authentication**: All rendezvous operations require a token received at registration
2. **TTL Expiry**: Registrations expire after 2 minutes without heartbeat
3. **Punch Session Expiry**: Punch sessions expire after 30 seconds
4. **Rate Limiting**: Consider adding rate limits for registration endpoints
5. **Token Entropy**: 16-byte crypto-random tokens (128-bit security)

## Future Improvements

1. **UDP Hole Punching**: Add UDP support for lower latency (Phase 4)
2. **ICE Integration**: Full ICE agent for TURN fallback
3. **DTLS Encryption**: Secure the P2P channel
4. **Multi-hop Relay**: Relay through nearby peers for better latency
5. **NAT-PMP/UPnP**: Automatic port forwarding when available

## References

- [RFC 5389 - STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 5245 - ICE](https://tools.ietf.org/html/rfc5245)
- [RustDesk Source](https://github.com/rustdesk/rustdesk)
- [Pion WebRTC](https://github.com/pion/webrtc)
- [NAT Traversal Techniques](https://tailscale.com/blog/how-nat-traversal-works)
