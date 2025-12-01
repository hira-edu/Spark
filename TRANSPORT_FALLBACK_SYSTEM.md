# Spark Transport Fallback System

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
- Automatic chunking for large messages
- Session-based with secret authentication

#### DNS Tunneling
- Base32-encoded data in DNS queries
- TXT record responses
- Chunked transmission for large payloads
- Configurable DNS server
- Works even in highly restrictive networks

## Implementation Files

### Client-Side

#### Core Transport Files
- `/root/Spark/client/transport/transport.go` - Transport abstraction and manager
- `/root/Spark/client/transport/websocket.go` - WebSocket (WS/WSS) implementation
- `/root/Spark/client/transport/quic.go` - QUIC protocol implementation
- `/root/Spark/client/transport/longpoll.go` - HTTP long polling implementation
- `/root/Spark/client/transport/dns.go` - DNS tunneling implementation
- `/root/Spark/client/transport/adapters.go` - Transport adapters for non-WebSocket transports

#### Integration Files
- `/root/Spark/client/core/transport_connect.go` - Transport manager integration
- `/root/Spark/client/core/core.go` - Modified to use transport fallback
- `/root/Spark/client/common/common.go` - Extended to support transport adapters
- `/root/Spark/client/common/transport_adapter.go` - Transport adapter interface
- `/root/Spark/client/config/config.go` - Added transport configuration fields

## Configuration

### Client Config Fields (config.go)

```go
EnableTransportFallback bool   // Enable automatic transport fallback
EnableQUIC              bool   // Enable QUIC protocol
QUICPort                int    // QUIC port (default: 443)
DNSTunnelDomain         string // DNS domain for tunneling
DNSServer               string // DNS server (default: "8.8.8.8:53")
EnableMimicry           bool   // Enable protocol mimicry
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
  "enable_quic": true,
  "quic_port": 443,
  "dns_tunnel_domain": "c2.example.com",
  "dns_server": "8.8.8.8:53",
  "enable_mimicry": true
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

## Server-Side Implementation (TODO)

### Required Server Changes

1. **Long Polling Endpoints** (`/api/longpoll/`)
   - `/api/longpoll/handshake` - Initial handshake
   - `/api/longpoll/poll` - Poll for messages
   - `/api/longpoll/send` - Send messages

2. **QUIC Listener**
   - Listen on UDP port (default: 443)
   - Handle QUIC connections
   - Implement stream-based message handling

3. **DNS Server**
   - DNS server to handle TXT queries
   - Parse base32-encoded requests
   - Return TXT records with responses
   - Implement DNS query routing

### Server Implementation Files Needed
- `/root/Spark/server/handler/longpoll/longpoll.go`
- `/root/Spark/server/handler/quic/quic.go`
- `/root/Spark/server/handler/dns/dns.go`
- `/root/Spark/server/main.go` - Add QUIC and DNS listeners

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
For questions or issues, refer to Spark documentation or create an issue in the repository.
