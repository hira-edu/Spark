# Client Generation Guide

This document explains how Rocket generates client binaries with embedded configuration using the trailer embedding system.

## Table of Contents

- [Overview](#overview)
- [Binary Naming Convention](#binary-naming-convention)
- [Trailer Embedding System](#trailer-embedding-system)
- [Building Client Templates](#building-client-templates)
- [Server-Side Generation](#server-side-generation)
- [Transport Fallback Options](#transport-fallback-options)
- [Troubleshooting](#troubleshooting)

---

## Overview

Rocket uses a **trailer embedding** approach to inject configuration into pre-built client binaries at download time. This is similar to how modern C2 frameworks like Sliver handle client configuration.

**Key Benefits:**
- Template binaries remain unchanged (can be code-signed)
- Configuration is appended, not patched
- Works identically across Windows, Linux, and macOS
- Each downloaded client gets unique credentials

**Flow:**
```
[Template Binary] + [Trailer Config] → [Configured Client]
     (built/)         (generated)        (downloaded)
```

---

## Binary Naming Convention

### CRITICAL: Server Expectation

The server looks for template binaries at:
```
./built/{OS}_{ARCH}
```

**Without `.exe` extension, even for Windows binaries!**

This is because the server appends the trailer during download, and the final filename is determined separately.

### Required Binary Names

| OS | Architecture | Expected Path |
|----|--------------|---------------|
| Windows | x86 (32-bit) | `./built/windows_386` |
| Windows | x64 (64-bit) | `./built/windows_amd64` |
| Windows | ARM64 | `./built/windows_arm64` |
| Linux | x86 (32-bit) | `./built/linux_i386` |
| Linux | x64 (64-bit) | `./built/linux_amd64` |
| Linux | ARM (32-bit) | `./built/linux_arm` |
| Linux | ARM64 | `./built/linux_arm64` |
| macOS | x64 | `./built/darwin_amd64` |
| macOS | ARM64 (M1/M2) | `./built/darwin_arm64` |

### Build Script Copies

The build script (`scripts/build.client.sh`) handles this:

```bash
# Build Windows with .exe extension
go build -o ./built/windows_amd64.exe ./client

# Copy to extensionless name for server
cp -f ./built/windows_amd64.exe ./built/windows_amd64
```

---

## Trailer Embedding System

### Binary Structure

When a client is generated, the server:

1. Reads the clean template binary from `./built/`
2. Generates a unique configuration
3. Encrypts the config with AES-CTR
4. Appends the trailer footer

```
┌─────────────────────────────────────────┐
│       Original Clean Binary              │
│   (from ./built/windows_amd64)           │
├─────────────────────────────────────────┤
│     Config Payload (384 bytes)           │
│  ┌───────────────────────────────────┐  │
│  │ Length (2 bytes, big-endian)     │  │
│  │ AES Key (16 bytes, random)       │  │
│  │ Encrypted JSON Config            │  │
│  │ Random Padding                    │  │
│  └───────────────────────────────────┘  │
├─────────────────────────────────────────┤
│     Trailer Footer (20 bytes)            │
│  ┌───────────────────────────────────┐  │
│  │ Magic: "SPARKCFG" (8 bytes)      │  │
│  │ Version: 1 (2 bytes)              │  │
│  │ Reserved: 0 (2 bytes)             │  │
│  │ Length: 384 (4 bytes)             │  │
│  │ CRC32: checksum (4 bytes)         │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Configuration Content

The encrypted JSON config contains:

```json
{
  "secure": true,
  "host": "your-domain.com",
  "port": 8443,
  "path": "/",
  "uuid": "unique-client-identifier",
  "key": "encryption-key-for-comms",
  "enable_quic": false,
  "quic_port": 8443,
  "enable_longpoll": true,
  "enable_dns": false,
  "dns_domain": "",
  "dns_server": "",
  "enable_mimicry": false
}
```

### Client-Side Reading

At startup, the client:

1. Opens itself and seeks to end - 20 bytes
2. Reads the trailer footer
3. Validates magic ("SPARKCFG") and CRC32
4. Reads and decrypts the config payload
5. Connects to the embedded server address

---

## Building Client Templates

### Prerequisites

Cross-compilation requires appropriate toolchains:

```bash
# Ubuntu/Debian - Install cross-compilers
apt install -y \
  gcc-mingw-w64-x86-64 \
  gcc-mingw-w64-i686 \
  gcc-aarch64-linux-gnu \
  gcc-arm-linux-gnueabihf
```

### Full Build Script

```bash
#!/bin/bash
export GO111MODULE=auto
export COMMIT=$(git rev-parse HEAD)
export CGO_ENABLED=1

mkdir -p ./built

# ============= Linux Builds =============

# Linux AMD64 (primary, with CGO)
GOOS=linux GOARCH=amd64 CC=gcc CXX=g++ \
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/linux_amd64 ./client

# Linux i386 (no CGO due to multilib conflicts)
CGO_ENABLED=0 GOOS=linux GOARCH=386 \
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/linux_i386 ./client

# Linux ARM64
GOOS=linux GOARCH=arm64 CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ \
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/linux_arm64 ./client

# Linux ARM (32-bit)
GOOS=linux GOARCH=arm CC=arm-linux-gnueabihf-gcc CXX=arm-linux-gnueabihf-g++ \
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/linux_arm ./client

# ============= Windows Builds =============

# Windows AMD64
GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/windows_amd64.exe ./client

# Windows 386
GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc CXX=i686-w64-mingw32-g++ \
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/windows_386.exe ./client

# Windows ARM64 (no CGO - special cross-compiler needed)
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 \
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/windows_arm64.exe ./client

# ============= CRITICAL: Copy to extensionless names =============
cp -f ./built/windows_386.exe ./built/windows_386
cp -f ./built/windows_amd64.exe ./built/windows_amd64
cp -f ./built/windows_arm64.exe ./built/windows_arm64

echo "Build complete. Files in ./built/:"
ls -lh ./built/
```

### Build Flags Explained

| Flag | Purpose |
|------|---------|
| `-s` | Strip symbol table |
| `-w` | Strip DWARF debug info |
| `-H=windowsgui` | Windows: hide console window |
| `-X '...Commit=$COMMIT'` | Embed git commit hash |

---

## Server-Side Generation

### API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/client/check` | Validate parameters (dry run) |
| POST | `/api/client/generate` | Generate and download client |

### Generation Request

```json
{
  "os": "windows",
  "arch": "amd64",
  "host": "your-domain.com",
  "port": 8443,
  "path": "/",
  "secure": "true",
  "enable_quic": "false",
  "enable_longpoll": "true",
  "enable_dns": "false"
}
```

### Generation Process

1. **Validate** - Check template exists at `./built/{os}_{arch}`
2. **Generate Credentials** - Create unique UUID and encryption key
3. **Build Config** - Create JSON with connection details
4. **Encrypt** - AES-CTR encrypt with random key
5. **Create Trailer** - Build 384-byte payload + 20-byte footer
6. **Stream Response** - Send binary + trailer as download

---

## Transport Fallback Options

Clients support multiple transport layers for resilience:

### WebSocket (Primary)

Default transport over HTTP/HTTPS.

```json
{
  "secure": true,
  "host": "your-domain.com",
  "port": 8443
}
```

### QUIC (Experimental)

UDP-based transport for faster connections.

```json
{
  "enable_quic": true,
  "quic_port": 443
}
```

### Long Polling (Fallback)

HTTP polling when WebSocket is blocked.

```json
{
  "enable_longpoll": true
}
```

### DNS Tunneling (Advanced)

Exfiltrate data via DNS queries.

```json
{
  "enable_dns": true,
  "dns_domain": "c2.example.com",
  "dns_server": "8.8.8.8:53"
}
```

---

## Troubleshooting

### "No Prebuilt Found" Error

**Cause:** Server can't find template binary

**Solution:**
```bash
# Check built directory
ls -la ./built/

# Ensure extensionless copies exist for Windows
cp -f ./built/windows_amd64.exe ./built/windows_amd64
cp -f ./built/windows_386.exe ./built/windows_386
cp -f ./built/windows_arm64.exe ./built/windows_arm64
```

### "Config Too Large" Error

**Cause:** Configuration exceeds 384-byte buffer

**Solution:** Shorten host/domain names or disable unused transport options

### Client Doesn't Connect

**Check:**
1. Is `secure: true` set when using HTTPS?
2. Is `port` correct (matches external port, not internal)?
3. Is `public_url` in server config correct?
4. Can the client reach the server? (firewall, DNS)

### Verify Trailer Was Embedded

```bash
# Check for SPARKCFG magic at end of binary
tail -c 20 client_binary | xxd

# Should show: 53 50 41 52 4b 43 46 47 (SPARKCFG)
```

---

## Related Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Server deployment guide
- [CONFIGURATION.md](./CONFIGURATION.md) - Configuration reference
- [BUILD.md](./BUILD.md) - Complete build instructions
