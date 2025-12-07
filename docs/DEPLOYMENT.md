# Rocket Deployment Guide

This guide covers the complete deployment of Rocket in a production environment, including reverse proxy setup, TLS configuration, MongoDB, and systemd service management.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Server Deployment](#server-deployment)
- [Caddy Reverse Proxy](#caddy-reverse-proxy)
- [MongoDB Setup](#mongodb-setup)
- [Systemd Service](#systemd-service)
- [TLS/SSL Configuration](#tlsssl-configuration)
- [Firewall Configuration](#firewall-configuration)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Caddy Reverse Proxy                          │
│                    (Port 8443 - HTTPS)                          │
│         TLS Termination + WebSocket Handling                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Rocket Server                                │
│                (127.0.0.1:18080 - HTTP)                         │
│     WebSocket handlers + REST API + Static files                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       MongoDB                                   │
│                  (localhost:27017)                              │
│     Sessions, Devices, Share Links, Auth                        │
└─────────────────────────────────────────────────────────────────┘
```

**Key Design Decisions:**

1. **Caddy as TLS Terminator**: Handles HTTPS, Let's Encrypt certificates, and WebSocket upgrades
2. **Internal HTTP**: Server listens on localhost only, no direct internet exposure
3. **MongoDB for State**: Enables multi-controller clusters and persistent sessions

---

## Prerequisites

- Ubuntu 22.04+ or Debian 12+ (recommended)
- Go 1.21+ (for building from source)
- Node.js 18+ and npm (for frontend builds)
- MongoDB 6.0+ (optional but recommended)
- Caddy 2.x (for reverse proxy)
- Domain name with DNS configured

### Install Dependencies

```bash
# Update system
apt update && apt upgrade -y

# Install build tools
apt install -y git build-essential curl wget

# Install Go (if building from source)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Install MongoDB
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg
echo "deb [signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" > /etc/apt/sources.list.d/mongodb-org-7.0.list
apt update && apt install -y mongodb-org
systemctl enable mongod && systemctl start mongod

# Install Caddy
apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt update && apt install caddy
```

---

## Server Deployment

### 1. Clone and Build

```bash
cd /root
git clone https://github.com/your-repo/Rocket.git
cd Rocket

# Build frontend
cd web
npm install
NODE_ENV=production npm run build-prod
cd ..

# Generate statik embed (IMPORTANT: use -ns web for namespace)
go install github.com/rakyll/statik@latest
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f

# Build server
go build -o rocket-server ./server

# Build client binaries (for trailer embedding)
./scripts/build.client.sh
```

### 2. Configuration File

Create `/root/Rocket/config.json`:

```json
{
  "listen": "127.0.0.1:18080",
  "salt": "your-secret-salt-max24",
  "auth": {
    "admin": "your-secure-password"
  },
  "log": {
    "level": "info",
    "path": "./logs",
    "days": 7
  },
  "tls": {
    "enable": false
  },
  "mongodb": {
    "enable": true,
    "uri": "mongodb://localhost:27017",
    "database": "rocket"
  },
  "cluster": {
    "enable": true,
    "public_url": "https://your-domain.com:8443",
    "controller_id_file": "./controller_id",
    "lease_ttl_seconds": 120,
    "session_lease_seconds": 180,
    "stale_after_seconds": 90,
    "cleanup_interval_seconds": 30,
    "use_change_streams": true
  }
}
```

**Key Configuration Notes:**

| Setting | Description |
|---------|-------------|
| `listen` | Use `127.0.0.1:PORT` when behind reverse proxy |
| `salt` | Max 24 characters, changing requires client regeneration |
| `tls.enable` | Set `false` when Caddy handles TLS |
| `cluster.public_url` | Must match external URL clients connect to |
| `mongodb.enable` | Required for share links, sessions, clustering |

---

## Caddy Reverse Proxy

### Caddyfile Configuration

Create `/etc/caddy/Caddyfile`:

```caddyfile
{
    email admin@your-domain.com
    auto_https disable_redirects
}

https://your-domain.com:8443, https://www.your-domain.com:8443 {
    # TLS with Let's Encrypt or manual certificates
    tls /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/letsencrypt/live/your-domain.com/privkey.pem

    # Logging
    log {
        output file /var/log/caddy/access.log
        format json
    }

    # Compression
    encode gzip zstd

    # WebSocket matcher - CRITICAL for remote desktop, terminal, device connections
    @websocket {
        header Connection *Upgrade*
        header Upgrade websocket
    }

    # Handle WebSocket requests (desktop, terminal, device connections)
    reverse_proxy @websocket http://127.0.0.1:18080 {
        header_up Host {http.reverse_proxy.upstream.hostport}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    # Handle all other HTTP requests
    reverse_proxy http://127.0.0.1:18080 {
        header_up Host {http.reverse_proxy.upstream.hostport}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### Critical WebSocket Endpoints

Caddy must properly proxy these WebSocket paths:

| Endpoint | Purpose |
|----------|---------|
| `/api/device/desktop` | Remote desktop streaming |
| `/api/device/terminal` | Terminal sessions |
| `/api/device/conn` | Device connection |
| `/api/share/desktop` | Guest share desktop access |
| `/api/share/webcam` | Guest share webcam access |
| `/api/share/audio` | Guest share audio access |

### Enable and Start Caddy

```bash
# Validate configuration
caddy validate --config /etc/caddy/Caddyfile

# Reload Caddy
systemctl reload caddy

# Check status
systemctl status caddy
```

---

## MongoDB Setup

### Initialize Database

MongoDB will auto-create collections on first use. Verify connection:

```bash
mongosh --eval "db.adminCommand('ping')"
```

### Collections Used

| Collection | Purpose |
|------------|---------|
| `devices` | Connected device registry |
| `sessions` | Active terminal/desktop sessions |
| `shares` | Share link tokens and metadata |
| `users` | User authentication (if using MongoDB auth) |

### Recommended Indexes

```javascript
// Connect to MongoDB
mongosh rocket

// Create indexes for performance
db.sessions.createIndex({ "device": 1 })
db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })
db.shares.createIndex({ "token": 1 }, { unique: true })
db.shares.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })
db.devices.createIndex({ "last_seen": 1 })
```

---

## Systemd Service

### Create Service File

Create `/etc/systemd/system/rocket-server.service`:

```ini
[Unit]
Description=Rocket C2 Server
After=network.target mongodb.service
Wants=mongodb.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/Rocket
ExecStart=/root/Rocket/rocket-server -config /root/Rocket/config.json
Restart=always
RestartSec=5
StandardOutput=append:/root/Rocket/logs/server.log
StandardError=append:/root/Rocket/logs/server.log

# Resource limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### Enable and Manage Service

```bash
# Reload systemd
systemctl daemon-reload

# Enable on boot
systemctl enable rocket-server

# Start service
systemctl start rocket-server

# Check status
systemctl status rocket-server

# View logs
journalctl -u rocket-server -f

# Restart after changes
systemctl restart rocket-server
```

---

## TLS/SSL Configuration

### Option 1: Certbot (Recommended)

```bash
# Install certbot
apt install -y certbot

# Get certificate (standalone mode)
certbot certonly --standalone -d your-domain.com -d www.your-domain.com

# Certificate files location:
# /etc/letsencrypt/live/your-domain.com/fullchain.pem
# /etc/letsencrypt/live/your-domain.com/privkey.pem

# Auto-renewal cron (certbot adds this automatically)
certbot renew --dry-run
```

### Option 2: Self-Signed (Development Only)

```bash
mkdir -p /root/Rocket/certs
cd /root/Rocket/certs

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=your-domain.com"
```

---

## Firewall Configuration

### UFW (Ubuntu)

```bash
# Allow SSH
ufw allow 22/tcp

# Allow HTTPS (Caddy)
ufw allow 8443/tcp

# Allow HTTP (for ACME challenges if using Let's Encrypt)
ufw allow 80/tcp

# Enable firewall
ufw enable

# Check status
ufw status
```

### iptables

```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTPS
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow HTTP (for ACME)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT

# Save rules
iptables-save > /etc/iptables.rules
```

---

## Troubleshooting

### Server Won't Start

```bash
# Check for lock file
ls -la /tmp/rocket-server.lock
rm -f /tmp/rocket-server.lock  # If stale

# Check port conflicts
ss -tlnp | grep 18080

# View detailed logs
./rocket-server -config ./config.json 2>&1 | head -50
```

### WebSocket Connections Fail

```bash
# Test WebSocket upgrade
curl -v -X GET https://your-domain.com:8443/api/device/conn \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: test" \
  -H "Sec-WebSocket-Version: 13"

# Check Caddy logs
tail -f /var/log/caddy/access.log
```

### MongoDB Connection Issues

```bash
# Check MongoDB status
systemctl status mongod

# Test connection
mongosh --eval "db.adminCommand('ping')"

# Check Rocket server logs for MongoDB errors
grep -i mongo /root/Rocket/logs/server.log
```

### Static Assets Not Loading

```bash
# Verify statik was generated with correct namespace
grep "RegisterWithNamespace" /root/Rocket/server/embed/web/statik.go
# Should show: fs.RegisterWithNamespace("web", data)

# Rebuild if needed
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f
go build -o rocket-server ./server
systemctl restart rocket-server
```

---

## Quick Rebuild Commands

```bash
# Full rebuild and restart
cd /root/Rocket
cd web && NODE_ENV=production npm run build-prod && cd ..
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f
go build -o rocket-server ./server
systemctl restart rocket-server
```

---

## Next Steps

- [CLIENT_GENERATION.md](./CLIENT_GENERATION.md) - How client binaries are built and configured
- [CONFIGURATION.md](./CONFIGURATION.md) - Complete configuration reference
- [BUILD.md](./BUILD.md) - Building from source
