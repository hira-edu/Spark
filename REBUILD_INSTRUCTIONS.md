# Rocket C2 Framework - Rebuild Instructions

## Critical Issue
The bash execution environment is currently non-functional, preventing automated script execution. You must run these commands manually.

## Project Status
- **Location**: `/root/Rocket`
- **Frontend dist exists**: Yes (`/root/Rocket/web/dist/`)
- **Statik embeddings exist**: Yes (`/root/Rocket/server/embed/web/statik.go` - 13.1MB)
- **Compiled binary exists**: Yes (`/root/Rocket/rocket-server`)

## BrowserRouter Configuration
The server already supports clean URLs with BrowserRouter. The implementation is in `/root/Rocket/server/main.go` lines 96-117:

```go
app.NoRoute(func(ctx *gin.Context) {
    path := ctx.Request.URL.Path
    // Let API/WebSocket return 404 as usual
    if strings.HasPrefix(path, "/api") || path == "/ws" {
        ctx.Status(http.StatusNotFound)
        return
    }

    // Serve static file if it exists, otherwise fall back to SPA index.html
    if serveGzip(ctx, webFS) || checkCache(ctx, webFS) {
        return
    }

    f, err := webFS.Open("/index.html")
    if err != nil {
        http.FileServer(webFS).ServeHTTP(ctx.Writer, ctx.Request)
        return
    }
    defer f.Close()
    ctx.Header("Content-Type", "text/html; charset=utf-8")
    io.Copy(ctx.Writer, f)
})
```

This NoRoute handler:
1. Returns 404 for API/WebSocket routes
2. Serves static files with gzip and caching support
3. Falls back to `index.html` for all other routes (SPA routing)

## Manual Rebuild Steps

### Option 1: Use the Automated Script
Run the pre-created script:
```bash
chmod +x /root/Rocket/rebuild.sh
/root/Rocket/rebuild.sh
```

### Option 2: Manual Step-by-Step

#### Step 1: Build Frontend
```bash
cd /root/Rocket/web
NODE_ENV=production npx webpack --mode production
```

**Expected output**: Webpack should create/update files in `/root/Rocket/web/dist/`

**Verify**:
```bash
ls -lh /root/Rocket/web/dist/index.html
```

#### Step 2: Regenerate Statik Embeddings
```bash
cd /root/Rocket
~/go/bin/statik -src=./web/dist -dest=./server/embed -f -ns=web -p=web
```

**Expected output**: Creates `/root/Rocket/server/embed/web/statik.go` (large file ~13MB)

**Verify**:
```bash
ls -lh /root/Rocket/server/embed/web/statik.go
```

#### Step 3: Build Go Server
```bash
cd /root/Rocket
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "dev")
echo "Building with commit: $COMMIT"
CGO_ENABLED=0 go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./rocket-server Rocket/server
```

**Expected output**: Compiled binary at `/root/Rocket/rocket-server`

**Verify**:
```bash
ls -lh /root/Rocket/rocket-server
./rocket-server --help  # Test if binary works
```

#### Step 4: Stop Current Server
```bash
# Check current process
ps aux | grep rocket-server | grep -v grep

# Stop gracefully
pkill -f rocket-server

# Wait and verify
sleep 2
ps aux | grep rocket-server | grep -v grep

# If still running, force kill
pkill -9 -f rocket-server
```

#### Step 5: Start New Server
```bash
cd /root/Rocket
nohup ./rocket-server > /tmp/rocket-server.log 2>&1 &
echo $!  # This is your server PID
```

#### Step 6: Verify Server Status
```bash
# Wait a few seconds for startup
sleep 3

# Check if process is running
ps aux | grep rocket-server | grep -v grep

# Check recent logs
tail -50 /tmp/rocket-server.log

# Test if server responds
curl -I http://localhost:7896  # Adjust port as needed
```

## Configuration Files

### Go Module
- **File**: `/root/Rocket/go.mod`
- **Module**: `Rocket`
- **Go Version**: 1.24.0

### Frontend Package
- **File**: `/root/Rocket/web/package.json`
- **Build Script**: `npm run build-prod` (or use webpack directly)

### Server Configuration
Check `/root/Rocket/config.json` or similar for:
- Listen address/port
- TLS settings
- MongoDB settings (if used)
- Transport settings (QUIC, DNS, long-polling)

## Troubleshooting

### Frontend Build Fails
- Check if Node.js and npm are installed: `node --version && npm --version`
- Check if dependencies are installed: `cd /root/Rocket/web && npm install`
- Check webpack config: `/root/Rocket/web/webpack.config.js`

### Statik Generation Fails
- Check if statik is installed: `~/go/bin/statik --help`
- If not installed: `go install github.com/rakyll/statik@latest`
- Verify dist directory exists: `ls -la /root/Rocket/web/dist/`

### Server Build Fails
- Check Go version: `go version`
- Run with verbose output: `go build -v ...`
- Check for missing dependencies: `go mod download`
- Verify module path: `go list -m`

### Server Won't Start
- Check logs: `tail -100 /tmp/rocket-server.log`
- Check port conflicts: `netstat -tlnp | grep :7896` (or your configured port)
- Check config file permissions and syntax
- Check if MongoDB is required and running (if configured)

### Server Starts but Routes Don't Work
- Check if statik embeddings are up to date
- Verify NoRoute handler in main.go
- Check browser console for 404 errors
- Verify frontend was built with correct settings

## Clean URLs with BrowserRouter

The server configuration already supports React Router's BrowserRouter with clean URLs:

1. **API routes** (`/api/*`): Return proper 404 if not found
2. **WebSocket** (`/ws`): Handled separately
3. **Static files**: Served with gzip compression and caching (ETag)
4. **SPA routes**: All other routes fall back to `index.html`

This means URLs like these will work:
- `http://yourserver.com/` → index.html
- `http://yourserver.com/dashboard` → index.html (React Router handles routing)
- `http://yourserver.com/devices/123` → index.html (React Router handles routing)
- `http://yourserver.com/main.js` → static file from dist
- `http://yourserver.com/api/devices` → API route (not SPA)

## Additional Notes

### Build Flags Explanation
- `CGO_ENABLED=0`: Static binary, no C dependencies
- `-s -w`: Strip debug info and symbol table (smaller binary)
- `-X 'Rocket/server/config.Commit=$COMMIT'`: Inject git commit into binary
- `-tags=jsoniter`: Use jsoniter for faster JSON parsing
- `-o ./rocket-server`: Output binary name

### Statik Flags Explanation
- `-src=./web/dist`: Source directory with frontend files
- `-dest=./server/embed`: Destination for generated Go file
- `-f`: Force overwrite existing file
- `-ns=web`: Namespace for the embedded filesystem
- `-p=web`: Package name

## Files Created

1. `/root/Rocket/rebuild.sh` - Automated rebuild script
2. `/root/Rocket/REBUILD_INSTRUCTIONS.md` - This instruction file

## Support

If you encounter issues:
1. Check all logs carefully
2. Verify all paths are correct
3. Ensure all dependencies are installed
4. Check file permissions
5. Verify config file syntax

The codebase appears to be a C2 (Command & Control) framework for remote system administration. The server is already configured to support modern SPA routing with clean URLs.
