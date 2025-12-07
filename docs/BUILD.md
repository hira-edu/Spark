# Build Guide

Complete guide for building Rocket from source, including frontend, server, and client binaries.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Build](#quick-build)
- [Frontend Build](#frontend-build)
- [Static Asset Embedding](#static-asset-embedding)
- [Server Build](#server-build)
- [Client Build](#client-build)
- [Cross-Compilation](#cross-compilation)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

```bash
# Go 1.21+
go version  # go1.21.x or higher

# Node.js 18+ and npm
node --version  # v18.x or higher
npm --version

# Git
git --version
```

### Install on Ubuntu/Debian

```bash
# Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Build tools (for CGO)
sudo apt install -y build-essential

# Cross-compilers (optional, for multi-platform builds)
sudo apt install -y \
  gcc-mingw-w64-x86-64 \
  gcc-mingw-w64-i686 \
  gcc-aarch64-linux-gnu \
  gcc-arm-linux-gnueabihf
```

### Install Go Tools

```bash
# Statik (for embedding static files)
go install github.com/rakyll/statik@latest

# Verify
~/go/bin/statik -version
```

---

## Quick Build

Complete build in one script:

```bash
#!/bin/bash
set -e

cd /path/to/Rocket

# 1. Frontend
cd web
npm install
NODE_ENV=production npm run build-prod
cd ..

# 2. Embed static assets
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f

# 3. Server
go build -o rocket-server ./server

# 4. Clients (optional)
./scripts/build.client.sh

echo "Build complete!"
ls -lh rocket-server
ls -lh built/
```

---

## Frontend Build

The frontend is a React application using Ant Design.

### Development Build

```bash
cd web
npm install
npm run dev
```

### Production Build

```bash
cd web
npm install
NODE_ENV=production npm run build-prod
```

**Output:** `web/dist/` directory containing:
- `index.html`
- `main.[hash].js`
- `[chunk].[hash].js`
- Gzipped versions (`.gz`)

### Build Configuration

Key files:
- `web/package.json` - Dependencies and scripts
- `web/webpack.config.js` - Webpack configuration
- `web/src/index.jsx` - Application entry point

---

## Static Asset Embedding

The server embeds frontend assets using [statik](https://github.com/rakyll/statik).

### CRITICAL: Correct Namespace

```bash
# MUST use -ns web for the namespace
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f
```

**Flags explained:**
| Flag | Purpose |
|------|---------|
| `-src` | Source directory (webpack output) |
| `-dest` | Destination for generated Go code |
| `-p web` | Package name (`web`) |
| `-ns web` | Namespace (must match server's `fs.NewWithNamespace("web")`) |
| `-f` | Force overwrite existing |

### Verify Embedding

```bash
# Check namespace registration
grep "RegisterWithNamespace" server/embed/web/statik.go
# Should output: fs.RegisterWithNamespace("web", data)

# Check file size (should be ~14MB)
ls -lh server/embed/web/statik.go
```

### Common Error: "no zip data registered"

**Cause:** Statik generated without `-ns web` flag

**Fix:**
```bash
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f
go build -o rocket-server ./server
```

---

## Server Build

### Basic Build

```bash
go build -o rocket-server ./server
```

### Production Build (with optimizations)

```bash
export COMMIT=$(git rev-parse HEAD)

go build \
  -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" \
  -tags=jsoniter \
  -o rocket-server \
  ./server
```

**Flags explained:**
| Flag | Purpose |
|------|---------|
| `-s` | Strip symbol table |
| `-w` | Strip DWARF debug info |
| `-X '...Commit=$COMMIT'` | Embed git commit hash |
| `-tags=jsoniter` | Use faster JSON library |

### Output Size

- Debug build: ~45MB
- Production build: ~40MB

---

## Client Build

### Single Platform

```bash
export COMMIT=$(git rev-parse HEAD)
export CGO_ENABLED=1

# Linux AMD64
GOOS=linux GOARCH=amd64 \
  go build -ldflags "-s -w -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/linux_amd64 ./client

# Windows AMD64
GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
  go build -ldflags "-s -w -H=windowsgui -X 'Rocket/client/config.Commit=$COMMIT'" \
  -o ./built/windows_amd64.exe ./client

# Copy for trailer embedding (server expects no extension)
cp ./built/windows_amd64.exe ./built/windows_amd64
```

### All Platforms

Use the build script:

```bash
./scripts/build.client.sh
```

This creates binaries for:
- Linux: amd64, i386, arm, arm64
- Windows: amd64, 386, arm64
- macOS: amd64, arm64 (requires macOS for CGO)

---

## Cross-Compilation

### Windows from Linux

```bash
# Install MinGW
sudo apt install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-i686

# Build Windows AMD64
export GOOS=windows
export GOARCH=amd64
export CGO_ENABLED=1
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++

go build -ldflags "-s -w -H=windowsgui" -o client.exe ./client
```

### Linux ARM from AMD64

```bash
# Install cross-compiler
sudo apt install -y gcc-aarch64-linux-gnu

# Build Linux ARM64
export GOOS=linux
export GOARCH=arm64
export CGO_ENABLED=1
export CC=aarch64-linux-gnu-gcc
export CXX=aarch64-linux-gnu-g++

go build -ldflags "-s -w" -o client_arm64 ./client
```

### Platforms Without CGO

Some builds must disable CGO (no cross-compiler available):

```bash
export CGO_ENABLED=0
export GOOS=windows
export GOARCH=arm64

go build -ldflags "-s -w -H=windowsgui" -o client_arm64.exe ./client
```

**Note:** Some features may be limited without CGO.

---

## Development Workflow

### Watch Mode (Frontend)

```bash
cd web
npm run dev  # Starts webpack dev server with hot reload
```

### Rebuild After Changes

```bash
# Frontend changes
cd web && npm run build-prod && cd ..
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f

# Server changes
go build -o rocket-server ./server

# Restart
systemctl restart rocket-server
```

### One-Liner Rebuild

```bash
cd /root/Rocket && \
  (cd web && NODE_ENV=production npm run build-prod) && \
  ~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f && \
  go build -o rocket-server ./server && \
  systemctl restart rocket-server
```

---

## Troubleshooting

### "statik/fs: no zip data registered"

**Cause:** Namespace mismatch in statik generation

**Fix:**
```bash
# Regenerate with correct namespace
~/go/bin/statik -src=./web/dist -dest=./server/embed -p web -ns web -f
go build -o rocket-server ./server
```

### "package Rocket/... is not in GOROOT"

**Cause:** Wrong working directory or module issues

**Fix:**
```bash
cd /path/to/Rocket
go mod tidy
go build ./server
```

### CGO Errors with Cross-Compilation

**Cause:** Missing or wrong cross-compiler

**Fix:**
```bash
# Check installed compilers
which x86_64-w64-mingw32-gcc
which aarch64-linux-gnu-gcc

# Install if missing
sudo apt install -y gcc-mingw-w64-x86-64 gcc-aarch64-linux-gnu

# Or disable CGO (limited features)
CGO_ENABLED=0 go build ./client
```

### Frontend Build Fails

**Common issues:**

1. **Node version too old:**
   ```bash
   node --version  # Need 18+
   ```

2. **npm cache issues:**
   ```bash
   rm -rf node_modules package-lock.json
   npm install
   ```

3. **Memory issues:**
   ```bash
   export NODE_OPTIONS="--max-old-space-size=4096"
   npm run build-prod
   ```

### Binary Size Too Large

**Optimize:**
```bash
# Strip debug info
go build -ldflags "-s -w" ./server

# Use UPX compression (optional)
upx --best rocket-server
```

---

## Build Artifacts

### Server
| File | Description |
|------|-------------|
| `rocket-server` | Linux AMD64 server binary |
| `server/embed/web/statik.go` | Embedded frontend assets |

### Clients
| File | Description |
|------|-------------|
| `built/linux_amd64` | Linux 64-bit client |
| `built/linux_i386` | Linux 32-bit client |
| `built/linux_arm64` | Linux ARM64 client |
| `built/windows_amd64` | Windows 64-bit (no extension for server) |
| `built/windows_amd64.exe` | Windows 64-bit (with extension) |
| `built/windows_386` | Windows 32-bit |
| `built/windows_arm64` | Windows ARM64 |

---

## Related Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Deployment guide
- [CLIENT_GENERATION.md](./CLIENT_GENERATION.md) - Client configuration
- [CONFIGURATION.md](./CONFIGURATION.md) - Server configuration
