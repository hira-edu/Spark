# Rocket Transport Fallback System

## Overview
Industrial-grade C2 transport system with automatic fallback for firewall bypass and network resilience in pentesting engagements.

## Architecture

### Transport Priority Order
1. **WebSocket (WS)** - Priority 10 (fastest, lowest latency)
2. **WebSocket Secure (WSS)** - Priority 15 (encrypted WebSocket)
3. **QUIC** - Priority 20 (UDP-based, HTTP/3, harder to block)
4. **Long Polling (HTTP/HTTPS)** - Priority 30 (HTTP fallback)
5. **DNS Tunneling** - Priority 40 (last resort, works even with strict firewalls)

The system automatically tries each transport in order until one succeeds.

## Features

### 1. Protocol Mimicry
Makes C2 traffic appear as legitimate web browsing:
- **Realistic User-Agents**: Rotates through Chrome, Firefox, Safari
- **Browser Headers**: Accept-Language, Accept-Encoding, etc.
- **TLS Fingerprinting**: Mimics modern browser TLS handshakes
- **HTTP/2 Support**: Uses h2 protocol when available

### 2. Transport-Specific Features

#### WebSocket (WS/WSS)
- Real-time bidirectional communication
- TLS 1.2/1.3 support with cipher suite mimicry
- Automatic upgrade from HTTP to WebSocket
- Secret-based authentication

#### QUIC Protocol
- UDP-based (harder to detect/block than TCP)
- Built-in encryption (TLS 1.3 required)
- HTTP/3 ALPN negotiation
- Multiplexed streams for better performance
- Datagrams for low-latency data

#### Long Polling (HTTP/HTTPS)
- HTTP POST/GET fallback
- Works through most corporate proxies
- Session-based with per-session secret
- Authenticated via UUID/Key check (same as WebSocket handshake)

#### DNS Tunneling
- Base32-encoded data in DNS queries
- TXT record responses
- Chunked transmission for large payloads
- Configurable DNS server
- Works even in highly restrictive networks
- Nonce + HMAC on every query to prevent hijack/replay

## Implementation Files

### Client-Side

#### Core Transport Files
- `/root/Rocket/client/transport/transport.go` - Transport abstraction and manager
- `/root/Rocket/client/transport/websocket.go` - WebSocket (WS/WSS) implementation
- `/root/Rocket/client/transport/quic.go` - QUIC protocol implementation
- `/root/Rocket/client/transport/longpoll.go` - HTTP long polling implementation
- `/root/Rocket/client/transport/dns.go` - DNS tunneling implementation
- `/root/Rocket/client/transport/adapters.go` - Transport adapters for non-WebSocket transports

#### Integration Files
- `/root/Rocket/client/core/transport_connect.go` - Transport manager integration
- `/root/Rocket/client/core/core.go` - Modified to use transport fallback
- `/root/Rocket/client/common/common.go` - Extended to support transport adapters
- `/root/Rocket/client/common/transport_adapter.go` - Transport adapter interface
- `/root/Rocket/client/config/config.go` - Added transport configuration fields

## Configuration

### Client Config Fields (config.go)

```go
EnableTransportFallback bool   // Enable automatic transport fallback
EnableQUIC              bool   // Enable QUIC protocol
EnableLongPoll          bool   // Enable HTTP long polling
EnableDNS               bool   // Enable DNS tunneling
QUICPort                int    // QUIC port (default: 443)
DNSDomain               string // DNS domain for tunneling
DNSServer               string // DNS server (default: "8.8.8.8:53")
EnableMimicry           bool   // Enable protocol mimicry
InsecureSkipVerify      bool   // Skip TLS verification (off by default)
```

### Example Configuration

```json
{
  "secure": true,
  "host": "gapict.com",
  "port": 8443,
  "path": "",
  "uuid": "client-uuid-here",
  "key": "client-key-here",
  "enable_transport_fallback": true,
  "enable_longpoll": true,
  "enable_quic": true,
  "quic_port": 443,
  "enable_dns": true,
  "dns_domain": "c2.example.com",
  "dns_server": "8.8.8.8:53",
  "enable_mimicry": true,
  "insecure_skip_verify": false
}
```

## Usage

### Enable Transport Fallback
Set `EnableTransportFallback: true` in client configuration.

The client will automatically:
1. Try WebSocket first (fastest)
2. Fall back to WSS if WS fails
3. Try QUIC if WebSocket blocked
4. Use Long Polling if QUIC unavailable
5. Resort to DNS tunneling as last option

### Disable Fallback (Legacy Mode)
Set `EnableTransportFallback: false` to use WebSocket only (original behavior).

## Server-Side Implementation

- **Long Polling**: `/api/longpoll/{handshake,poll,send}` with per-session secrets and UUID/Key validation (same AES check as WebSocket).
- **QUIC**: UDP listener (configurable), TLS 1.3, per-session derived secret, UUID/Key validation, registry integration for server→client sends.
- **DNS**: TXT-based tunneling with base32 payloads, nonce+HMAC on every poll/send, chunk reassembly, and rate limiting; UUID/Key validated at handshake.

## Testing Strategy

### Unit Tests
1. Test each transport independently
2. Test fallback mechanism
3. Test protocol mimicry headers
4. Test encryption/decryption

### Integration Tests
1. WebSocket connection and message exchange
2. QUIC connection with stream handling
3. Long polling handshake and polling
4. DNS tunneling query/response

### Firewall Simulation Tests
1. Block WebSocket → verify WSS fallback
2. Block all TCP → verify QUIC works
3. Block UDP → verify Long Polling works
4. Block all except DNS → verify DNS tunneling works

## Deployment Notes

### For Pentesting Engagements

1. **Enable All Transports**: Set all fallback options to true
2. **Configure DNS Domain**: Set up DNS server for tunneling
3. **Enable Mimicry**: Makes traffic blend in with normal browsing
4. **Test Before Engagement**: Verify all transports work in test environment

### Production Recommendations

- Use WSS as primary (encrypted, standard)
- Enable QUIC for performance
- Configure Long Polling for proxy environments
- Reserve DNS tunneling for highly restrictive networks

## Security Considerations

### Encryption
- All transports use encryption (TLS/QUIC native encryption)
- Secret-based session authentication
- Per-message encryption with AES

### Stealth
- Protocol mimicry makes traffic appear legitimate
- User-Agent rotation prevents fingerprinting
- HTTP/2 and QUIC mimic modern web apps
- DNS tunneling blends with normal DNS traffic

### Detection Evasion
- No hardcoded patterns in traffic
- Randomized backoff timing
- Jitter in reconnection attempts
- Browser-like TLS fingerprints

## Dependencies

### New Dependencies Added
- `github.com/quic-go/quic-go@v0.57.1` - QUIC protocol support

### Existing Dependencies Used
- `github.com/gorilla/websocket` - WebSocket
- Standard library `net` - DNS operations
- Standard library `crypto/tls` - TLS configuration

## Next Steps

1. ✅ Client-side transport implementation
2. ✅ Transport manager and fallback logic
3. ✅ Protocol mimicry
4. ✅ Configuration integration
5. ⏳ **Server-side transport handlers** (IN PROGRESS)
6. ⏳ Testing and validation
7. ⏳ Documentation and examples

## Performance Characteristics

| Transport | Latency | Throughput | Stealth | Bypass Capability |
|-----------|---------|------------|---------|-------------------|
| WS        | Lowest  | Highest    | Medium  | Low               |
| WSS       | Low     | High       | High    | Medium            |
| QUIC      | Low     | High       | High    | High              |
| Long Poll | Medium  | Medium     | High    | High              |
| DNS       | Highest | Lowest     | Medium  | Highest           |

## Troubleshooting

### Connection Issues
- Check server supports desired transport
- Verify firewall rules allow traffic
- Check DNS server responds to queries
- Validate QUIC port is open (UDP)

### Fallback Not Working
- Ensure `EnableTransportFallback: true`
- Check circuit breaker state
- Review telemetry logs for errors
- Verify all transports configured

## Contact
For questions or issues, refer to Rocket documentation or create an issue in the repository.
