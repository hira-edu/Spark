# Configuration Reference

Complete reference for Rocket server configuration (`config.json`).

## Table of Contents

- [Minimal Configuration](#minimal-configuration)
- [Full Configuration](#full-configuration)
- [Configuration Sections](#configuration-sections)
  - [Core Settings](#core-settings)
  - [Authentication](#authentication)
  - [Logging](#logging)
  - [TLS/HTTPS](#tlshttps)
  - [MongoDB](#mongodb)
  - [Cluster Mode](#cluster-mode)
  - [WebRTC](#webrtc)
  - [Transport Fallbacks](#transport-fallbacks)
- [Environment Variables](#environment-variables)
- [Command Line Flags](#command-line-flags)

---

## Minimal Configuration

The simplest working configuration:

```json
{
  "listen": ":8443",
  "salt": "your-secret-salt"
}
```

---

## Full Configuration

Complete configuration with all options:

```json
{
  "listen": "127.0.0.1:18080",
  "salt": "your-secret-salt-max24",
  "auth": {
    "admin": "secure-password",
    "user2": "$sha256$hashed-password"
  },
  "log": {
    "level": "info",
    "path": "./logs",
    "days": 7
  },
  "tls": {
    "enable": true,
    "cert": "/path/to/cert.pem",
    "key": "/path/to/key.pem",
    "autocert": {
      "enable": false,
      "domains": ["example.com", "www.example.com"],
      "email": "admin@example.com",
      "cache_dir": "./certs"
    }
  },
  "mongodb": {
    "enable": true,
    "uri": "mongodb://localhost:27017",
    "database": "rocket"
  },
  "cluster": {
    "enable": true,
    "public_url": "https://example.com:8443",
    "controller_id": "",
    "controller_id_file": "./controller_id",
    "lease_ttl_seconds": 120,
    "session_lease_seconds": 180,
    "stale_after_seconds": 90,
    "cleanup_interval_seconds": 30,
    "use_change_streams": true,
    "prefer_proxy": true,
    "proxy_timeout_seconds": 10
  },
  "webrtc": {
    "turn_servers": [
      "turn:turn.example.com:3478?transport=udp"
    ],
    "stun_servers": [
      "stun:stun.l.google.com:19302",
      "stun:stun.cloudflare.com:3478"
    ]
  },
  "transport": {
    "long_polling": {
      "enable": true
    },
    "quic": {
      "enable": false,
      "listen": ":443"
    },
    "dns": {
      "enable": false,
      "listen": ":53",
      "domain": "c2.example.com"
    }
  }
}
```

---

## Configuration Sections

### Core Settings

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `listen` | string | **Yes** | - | Listen address in `IP:Port` format |
| `salt` | string | **Yes** | - | Encryption salt (max 24 chars). Changing requires client regeneration |

**Examples:**
```json
// Direct internet exposure
"listen": ":8443"

// Behind reverse proxy (recommended)
"listen": "127.0.0.1:18080"

// Specific interface
"listen": "192.168.1.10:8443"
```

---

### Authentication

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `auth` | object | No | - | Username:password pairs |

**Password Formats:**

1. **Plain text** (not recommended):
   ```json
   "auth": {
     "admin": "mypassword"
   }
   ```

2. **Hashed** (recommended):
   ```json
   "auth": {
     "admin": "$sha256$5e884898da28047d..."
   }
   ```

**Supported hash algorithms:**
- `$sha256$` - SHA-256 hash
- `$sha512$` - SHA-512 hash
- `$bcrypt$` - bcrypt hash

**Generate hashed password:**
```bash
echo -n "mypassword" | sha256sum | cut -d' ' -f1
# Output: 5e884898da28047d...
# Use as: "$sha256$5e884898da28047d..."
```

---

### Logging

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `log.level` | string | No | `info` | Log level |
| `log.path` | string | No | `./logs` | Log directory |
| `log.days` | int | No | `7` | Log retention days |

**Log Levels:**
- `disable` - No logging
- `fatal` - Fatal errors only
- `error` - Errors
- `warn` - Warnings and above
- `info` - Informational (recommended)
- `debug` - Debug messages (verbose)

---

### TLS/HTTPS

#### Manual Certificates

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tls.enable` | bool | No | `false` | Enable TLS |
| `tls.cert` | string | Cond | - | Path to certificate file |
| `tls.key` | string | Cond | - | Path to private key file |

```json
"tls": {
  "enable": true,
  "cert": "/etc/letsencrypt/live/example.com/fullchain.pem",
  "key": "/etc/letsencrypt/live/example.com/privkey.pem"
}
```

#### Automatic Certificates (Let's Encrypt)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `tls.autocert.enable` | bool | No | `false` | Enable ACME |
| `tls.autocert.domains` | []string | Cond | - | Domain names |
| `tls.autocert.email` | string | Cond | - | Admin email |
| `tls.autocert.cache_dir` | string | No | `./certs` | Certificate cache |

```json
"tls": {
  "autocert": {
    "enable": true,
    "domains": ["example.com", "www.example.com"],
    "email": "admin@example.com",
    "cache_dir": "./certs"
  }
}
```

**Note:** When behind Caddy (recommended), set `tls.enable: false` and let Caddy handle TLS.

---

### MongoDB

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `mongodb.enable` | bool | No | `false` | Enable MongoDB |
| `mongodb.uri` | string | Cond | - | MongoDB connection URI |
| `mongodb.database` | string | Cond | `rocket` | Database name |

```json
"mongodb": {
  "enable": true,
  "uri": "mongodb://localhost:27017",
  "database": "rocket"
}
```

**Why enable MongoDB?**
- Share links (time-limited guest access)
- Session persistence across restarts
- Multi-controller clustering
- Device history and metadata

**With authentication:**
```json
"mongodb": {
  "enable": true,
  "uri": "mongodb://user:password@localhost:27017/rocket?authSource=admin",
  "database": "rocket"
}
```

---

### Cluster Mode

For multi-controller deployments with shared state.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cluster.enable` | bool | No | `false` | Enable clustering |
| `cluster.public_url` | string | **Yes*** | - | External URL clients use |
| `cluster.controller_id` | string | No | Auto | Unique controller ID |
| `cluster.controller_id_file` | string | No | - | File to persist controller ID |
| `cluster.lease_ttl_seconds` | int | No | `120` | Controller lease TTL |
| `cluster.session_lease_seconds` | int | No | `180` | Session lease TTL |
| `cluster.stale_after_seconds` | int | No | `90` | Mark stale after |
| `cluster.cleanup_interval_seconds` | int | No | `30` | Cleanup frequency |
| `cluster.use_change_streams` | bool | No | `true` | Use MongoDB change streams |
| `cluster.prefer_proxy` | bool | No | `false` | Prefer proxying to redirect |
| `cluster.proxy_timeout_seconds` | int | No | `10` | Proxy request timeout |

```json
"cluster": {
  "enable": true,
  "public_url": "https://example.com:8443",
  "controller_id_file": "./controller_id",
  "lease_ttl_seconds": 120,
  "use_change_streams": true
}
```

**CRITICAL:** `public_url` must match exactly what clients use to connect (including port if non-standard).

---

### WebRTC

For remote desktop streaming peer-to-peer connections.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `webrtc.stun_servers` | []string | No | Google STUN | STUN servers for NAT traversal |
| `webrtc.turn_servers` | []string | No | - | TURN relay servers |

```json
"webrtc": {
  "stun_servers": [
    "stun:stun.l.google.com:19302",
    "stun:stun.cloudflare.com:3478"
  ],
  "turn_servers": [
    "turn:turn.example.com:3478?transport=udp"
  ]
}
```

**TURN Server Format:**
```
turn:HOST:PORT?transport=udp
turn:HOST:PORT?transport=tcp
turns:HOST:PORT (TLS)
```

Clients can also use environment variables:
- `SPARK_WEBRTC_STUN` - Comma-separated STUN URLs
- `SPARK_WEBRTC_TURN` - Comma-separated TURN URLs
- `SPARK_WEBRTC_TURN_USERNAME` - TURN username
- `SPARK_WEBRTC_TURN_PASSWORD` - TURN password

---

### Transport Fallbacks

Alternative transports when WebSocket is blocked.

#### Long Polling

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `transport.long_polling.enable` | bool | No | `false` | Enable long polling |

```json
"transport": {
  "long_polling": {
    "enable": true
  }
}
```

#### QUIC

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `transport.quic.enable` | bool | No | `false` | Enable QUIC |
| `transport.quic.listen` | string | Cond | `:443` | QUIC listen address |

```json
"transport": {
  "quic": {
    "enable": true,
    "listen": ":443"
  }
}
```

#### DNS Tunneling

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `transport.dns.enable` | bool | No | `false` | Enable DNS tunneling |
| `transport.dns.listen` | string | Cond | `:53` | DNS listen address |
| `transport.dns.domain` | string | Cond | - | Base domain for DNS queries |

```json
"transport": {
  "dns": {
    "enable": true,
    "listen": ":53",
    "domain": "c2.example.com"
  }
}
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint |
| `SPARK_TRACE_SAMPLE_RATIO` | Trace sampling ratio (0.0-1.0) |
| `OTEL_EXPORTER_OTLP_HEADERS` | OTLP headers |
| `OTEL_EXPORTER_OTLP_INSECURE` | Allow insecure OTLP connection |

---

## Command Line Flags

The server accepts these command-line flags:

| Flag | Description |
|------|-------------|
| `-config <path>` | Path to config file (default: `./config.json`) |
| `-listen <addr>` | Override listen address |
| `-tls` | Enable TLS |
| `-tls-cert <path>` | TLS certificate path |
| `-tls-key <path>` | TLS key path |
| `-tls-autocert` | Enable Let's Encrypt |
| `-tls-domains <list>` | Comma-separated domains |
| `-tls-email <email>` | ACME email |
| `-tls-cache <path>` | Certificate cache directory |

**Example:**
```bash
./rocket-server -config /etc/rocket/config.json -listen :8443
```

---

## Related Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Deployment guide
- [CLIENT_GENERATION.md](./CLIENT_GENERATION.md) - Client generation
- [BUILD.md](./BUILD.md) - Building from source
