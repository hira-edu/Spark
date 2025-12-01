# Spark Server Transport Deployment Guide

## Overview
Complete server-side implementation for multi-transport C2 communication with automatic fallback.

## Implemented Server Components

### 1. Long Polling Handler (`server/handler/longpoll/`)
- **Endpoints:**
  - `POST /api/longpoll/handshake` - Client authentication and secret exchange
  - `GET /api/longpoll/poll` - Long-running request for message polling
  - `POST /api/longpoll/send` - Client message submission

- **Features:**
  - Session management with automatic cleanup
  - Message queuing (1000 messages per session)
  - 30-second poll timeout with batching
  - Secret-based authentication
  - Encrypted communication

### 2. QUIC Server (`server/handler/quic/`)
- **Port:** UDP 443 (configurable)
- **Features:**
  - TLS 1.3 required (inherits from HTTP/HTTPS config)
  - Bidirectional stream communication
  - Session management
  - Keep-alive (30 seconds)
  - Max idle timeout (5 minutes)
  - Automatic cleanup of dead connections

### 3. DNS Tunneling Server (`server/handler/dns/`)
- **Port:** UDP 53 (configurable)
- **Features:**
  - TXT record-based communication
  - Base32 encoding for DNS safety
  - Chunk reassembly for large messages
  - Session management
  - Automatic session expiration

## Configuration

### Server Config File (`config.json`)

```json
{
  "listen": ":8443",
  "salt": "your-secret-salt-here",
  "auth": {
    "admin": "your-password"
  },
  "tls": {
    "enable": true,
    "cert": "./certs/server.crt",
    "key": "./certs/server.key"
  },
  "transport": {
    "long_polling": {
      "enable": true
    },
    "quic": {
      "enable": true,
      "listen": ":443"
    },
    "dns": {
      "enable": true,
      "listen": ":53",
      "domain": "c2.example.com"
    }
  }
}
```

### Configuration Options

#### Long Polling
```json
"long_polling": {
  "enable": true  // Enable HTTP long polling fallback
}
```

#### QUIC
```json
"quic": {
  "enable": true,      // Enable QUIC transport
  "listen": ":443"     // UDP listen address
}
```
**Note:** Requires TLS to be enabled. Uses same TLS config as HTTPS.

#### DNS Tunneling
```json
"dns": {
  "enable": true,             // Enable DNS tunneling
  "listen": ":53",            // UDP DNS port
  "domain": "c2.example.com"  // Your DNS domain
}
```

## Deployment Steps

### 1. Prerequisites

- TLS certificates (required for QUIC)
- Domain name (required for DNS tunneling)
- Open firewall ports:
  - TCP 8443 (or your HTTPS port)
  - UDP 443 (QUIC)
  - UDP 53 (DNS)

### 2. Generate TLS Certificates

#### Self-Signed (Testing)
```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=yourdomain.com"
```

#### Let's Encrypt (Production)
```json
"tls": {
  "autocert": {
    "enable": true,
    "domains": ["yourdomain.com"],
    "email": "admin@yourdomain.com",
    "cache_dir": "./certs"
  }
}
```

### 3. DNS Setup (for DNS Tunneling)

Add NS records for your C2 subdomain:
```
c2.example.com.  IN  NS  ns1.example.com.
ns1.example.com. IN  A   <your-server-ip>
```

### 4. Firewall Configuration

```bash
# Allow HTTPS
sudo ufw allow 8443/tcp

# Allow QUIC
sudo ufw allow 443/udp

# Allow DNS (requires root or CAP_NET_BIND_SERVICE)
sudo ufw allow 53/udp
```

### 5. Start Server

```bash
# Build server
cd /root/Spark
./scripts/build.server.sh

# Run with all transports enabled
sudo ./spark-server -config config.json
```

**Note:** DNS server on port 53 requires root privileges or `CAP_NET_BIND_SERVICE` capability.

## Monitoring & Logs

### Log Events

The server logs transport-specific events:

**Long Polling:**
- `LONGPOLL_ENABLED` - Long polling initialized
- `LONGPOLL_SESSION_CREATED` - New session created
- `LONGPOLL_SESSION_EXPIRED` - Session timed out
- `LONGPOLL_HANDSHAKE_SUCCESS` - Client authenticated
- `LONGPOLL_PACKET_RECEIVED` - Message received

**QUIC:**
- `QUIC_ENABLED` - QUIC server started
- `QUIC_CONNECTION_ACCEPTED` - New QUIC connection
- `QUIC_SESSION_ESTABLISHED` - Handshake complete
- `QUIC_PACKET_RECEIVED` - Message received
- `QUIC_SESSION_CLOSED` - Connection closed

**DNS:**
- `DNS_ENABLED` - DNS server started
- `DNS_SESSION_CREATED` - New DNS session
- `DNS_PACKET_RECEIVED` - Message received via DNS
- `DNS_SESSION_REMOVED` - Session cleaned up

### Monitoring Commands

```bash
# View real-time logs
tail -f logs/spark.log | grep -E "LONGPOLL|QUIC|DNS"

# Count active sessions by transport
grep "SESSION_CREATED" logs/spark.log | wc -l

# Monitor QUIC connections
sudo netstat -anu | grep :443

# Monitor DNS queries
sudo tcpdump -i any udp port 53 -n
```

## Security Considerations

### Transport Security

1. **Long Polling**
   - Secret-based authentication
   - TLS encryption (when HTTPS enabled)
   - Session timeout (5 minutes)
   - Message queue limits

2. **QUIC**
   - TLS 1.3 mandatory
   - Encrypted by default
   - Certificate validation
   - Keep-alive detection

3. **DNS**
   - Data encrypted with session secret
   - Base32 encoding
   - Session expiration
   - Query rate limiting (recommended)

### Best Practices

1. **Always enable TLS** for production deployments
2. **Use strong salts** (24 characters)
3. **Rotate credentials** regularly
4. **Monitor logs** for suspicious activity
5. **Rate limit** DNS queries to prevent DoS
6. **Firewall** unused transports

## Troubleshooting

### QUIC Not Starting
- **Issue:** "QUIC_DISABLED: TLS must be enabled"
- **Solution:** Enable TLS in config.json

### DNS Server Port 53 Permission Denied
- **Issue:** Cannot bind to port 53
- **Solutions:**
  ```bash
  # Option 1: Run as root
  sudo ./spark-server

  # Option 2: Grant capability
  sudo setcap 'cap_net_bind_service=+ep' ./spark-server

  # Option 3: Use alternate port
  "dns": { "listen": ":5353" }
  ```

### Long Polling Sessions Expiring Too Fast
- **Issue:** Clients disconnecting frequently
- **Solution:** Increase session timeout in `longpoll.go`:
  ```go
  defaultSessionTimeout = 10 * time.Minute
  ```

### High Memory Usage
- **Issue:** Too many queued messages
- **Solution:** Reduce queue size in handlers:
  ```go
  maxQueueSize = 500  // Default: 1000
  ```

## Performance Tuning

### Long Polling
```go
// In longpoll.go
defaultPollTimeout = 60 * time.Second  // Longer polls
maxQueueSize = 2000                    // More queued messages
```

### QUIC
```go
// In quic.go
maxConcurrentStreams = 200  // More concurrent connections
keepAlivePeriod = 15 * time.Second  // Faster keep-alive
```

### DNS
```go
// In dns.go
sessionTimeout = 10 * time.Minute  // Longer sessions
maxChunks = 200                    // Larger messages
```

## Testing

### Test Long Polling
```bash
# Handshake
curl -X POST https://yourserver:8443/api/longpoll/handshake \
  -H "UUID: test-uuid" \
  -H "Key: test-key" \
  -k

# Poll
curl -X GET https://yourserver:8443/api/longpoll/poll \
  -H "UUID: test-uuid" \
  -H "Secret: <secret-from-handshake>" \
  -k
```

### Test QUIC
- Requires QUIC client
- Client transport layer will automatically connect

### Test DNS
```bash
# Query handshake
dig @yourserver handshake.test-uuid.c2.example.com TXT

# Monitor DNS traffic
sudo tcpdump -i any udp port 53 -vv
```

## Production Checklist

- [ ] TLS certificates installed
- [ ] Firewall rules configured
- [ ] DNS records configured (if using DNS tunneling)
- [ ] Log rotation enabled
- [ ] Monitoring alerts configured
- [ ] Backup strategy in place
- [ ] Rate limiting configured
- [ ] Strong authentication credentials
- [ ] Session timeouts configured
- [ ] Resource limits set

## Next Steps

1. **Client Configuration:** Configure clients to enable transport fallback
2. **Testing:** Test all transports in target environment
3. **Monitoring:** Set up alerting for transport failures
4. **Optimization:** Tune parameters based on usage patterns

## Support

For issues or questions:
1. Check logs for error messages
2. Review configuration syntax
3. Test firewall rules
4. Verify TLS certificates
5. Check DNS resolution

## License

This software is for authorized penetration testing and security research only.
