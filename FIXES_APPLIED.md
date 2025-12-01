# Rocket Server Fixes Applied - December 1, 2025

## Issues Resolved

### 1. ✅ Client Auto-Update Loop (FIXED)
**Problem**: Client was restarting every 30-40 seconds due to version mismatch
- Client commit: `66b87eeb5efd0380afba4b77352f06417c5b7c6a`
- Server commit: `"dev"` (not set properly)

**Solution**:
- Rebuilt server binary with proper commit hash
- Rebuilt Windows client (amd64) with matching commit hash
- Both now use commit: `66b87eeb5efd0380afba4b77352f06417c5b7c6a`

**Files**:
- `/root/Rocket/rocket-server` - Server binary with commit hash
- `/root/Rocket/built/windows_amd64` - Windows client with matching commit

**Verification**:
```
needsUpdate: false
msg: "already latest"
```

---

### 2. ✅ Server Stability - HTTP 502 Errors (FIXED)
**Problem**: Clients getting 502 Bad Gateway because rocket-server wasn't running or was crashing

**Solution**: Created systemd service for automatic startup and restart
- Service file: `/etc/systemd/system/rocket-server.service`
- Enabled on boot
- Auto-restart on crash (5 second delay)
- Logs to: `/root/Rocket/logs/server.log`

**Commands**:
```bash
sudo systemctl status rocket-server
sudo systemctl restart rocket-server
sudo journalctl -u rocket-server -f
```

---

### 3. ✅ React 18 + Ant Design 5 Upgrade (COMPLETED)
**Branch**: `upgrade-react18-antd5`

**Dependencies Upgraded**:
- antd: 4.24.16 → 5.29.1
- @ant-design/icons: 4.8.3 → 5.6.1
- @ant-design/pro-form: 1.74.7 → 2.32.0
- @ant-design/pro-layout: 6.38.22 → 7.22.7
- @ant-design/pro-table: 2.80.8 → 3.21.0

**Changes**:
- Updated CSS imports to `antd/dist/reset.css`
- Webpack esbuild target: es2015 → es2018
- Moved `.old.jsx` backup files to `.old-backups/`
- Rebuilt web assets and embedded with statik

**Status**: Build successful, all tests passing

---

## ⚠️ Known Issue: Desktop Capture Not Working

### Problem
Desktop connections succeed but immediately close:
1. DESKTOP_CONN → success
2. DESKTOP_INIT → success
3. DESKTOP_CLOSE → immediate (connection drops)
4. DESKTOP_HANDSHAKE → success (after close)

### Root Cause Analysis
The Windows client service is running in **Session 0** (non-interactive Windows service context) where desktop/screen capture is not possible.

**Expected Behavior**:
- Service detects active user Session 1 ✅ (logs show: "found active session 1")
- Service should launch UI helper process in Session 1 with `--ui-only` flag
- UI helper process performs desktop capture from user session
- Service proxies data between server and UI helper

**Actual Behavior**:
- Session 1 detected correctly ✅
- **UI helper process NOT launching** ❌ (no "launching UI" or "UI launched" logs)
- Desktop capture fails because Session 0 has no desktop access

### Client Architecture
The client code HAS the correct architecture:
- File: `client/lifecycle/service_windows.go`
- Lines 359-567: `launchUIInSession()` function
- Launch command: `exePath + " --ui-only"`

### What's Missing
The UI launch is failing silently. Possible causes:
1. Token/permission issues when calling `WTSQueryUserToken`
2. `CreateProcessAsUser` failing
3. UI process crashes immediately after launch
4. Job object assignment failing

### Enhanced Logging Added (December 1, 2025 17:09 UTC)

**New Windows client binary built with comprehensive debugging**:
- **SHA256**: `2fd6ada5b55768357f5b467475f59cdbc2c109dba0fff979b33d6c93ce13e111`
- **Size**: 20MB
- **Build time**: 2025-12-01 17:09 UTC

**Logging enhancements in `/root/Rocket/client/lifecycle/service_windows.go`**:
1. `reconcileSession()` (lines 309-366):
   - Logs when new session state is created
   - Logs desired/actual state checks
   - Logs when states match (no action needed)
   - Logs when UI launch is triggered
   - Logs unexpected state combinations

2. `setSessionDesiredState()` (lines 368-392):
   - Logs when updating existing session state (shows old→new desired state)
   - Logs when creating new session state

3. `handleSessionChangeEvent()` (lines 216-246):
   - Logs when user active events occur (LOGON, UNLOCK, etc.)
   - Logs when user inactive events occur (LOGOFF, LOCK, etc.)

4. `reconcileAllSessions()` (lines 276-322):
   - Logs when no active sessions found
   - Logs when active session is detected
   - Logs when marking session as active (shows state transition)
   - Logs when creating new active session state

**Logging enhancements in `/root/Rocket/client/service/desktop/desktop_windows.go`**:
1. `Screen.Init()` (lines 52-83):
   - Logs successful DXGI initialization with display and rect
   - Logs DXGI failure with error details
   - Logs GDI fallback attempt
   - Logs GDI failure if both methods fail
   - Logs successful GDI initialization

### Expected Log Output

With the new logging, the Windows client logs should now show:

**Every 10 seconds (from reconciliation loop)**:
```
[INFO] reconcileAllSessions: found active session session_id=1
[INFO] reconcileAllSessions: marking session active session_id=1 old_desired=active new_desired=active actual=stopped
[INFO] reconcileSession: checking state session_id=1 desired=active actual=stopped
[INFO] reconcileSession: will launch UI session_id=1 desired=active actual=stopped
[INFO] launching UI session_id=1 attempt=1
```

**When desktop capture initializes**:
```
[INFO] Desktop capture initialized with DXGI display=0 rect=...
```
OR
```
[WARN] DXGI initialization failed, falling back to GDI error=... display=0
[INFO] Desktop capture initialized with GDI display=0 rect=...
```

### Next Steps to Debug
1. **Deploy new Windows client** to target machine:
   - Binary: `/root/Rocket/built/windows_amd64`
   - SHA256: `2fd6ada5b55768357f5b467475f59cdbc2c109dba0fff979b33d6c93ce13e111`

2. **Get full Windows client logs** from target machine:
   - Location: `C:\ProgramData\Microsoft\Update\client.log`
   - Look for new log entries showing:
     - "reconcileSession: checking state"
     - "reconcileSession: will launch UI"
     - "launching UI"
     - "Desktop capture initialized"
     - Any error messages with details

3. **Diagnose based on logs**:
   - If "reconcileSession: states match" appears → desired=actual, need to check why
   - If "launching UI" appears but process fails → token/permission issue
   - If "Desktop capture initialized" doesn't appear → capture initialization failing
   - If DXGI and GDI both fail → Session 0 context confirmed

---

## System Status

### Services Running:
- ✅ rocket-server (port 18080) - systemd managed
- ✅ caddy (port 8443) - reverse proxy with TLS
- ✅ mongodb (port 27017) - database

### Client Status:
- ✅ Connected and stable
- ✅ No auto-update loop
- ✅ Session 1 detected
- ❌ Desktop capture not working (UI process not launching)

### Server Commit:
```
66b87eeb5efd0380afba4b77352f06417c5b7c6a
```

### Build Commands Used:
```bash
# Server
COMMIT=66b87eeb5efd0380afba4b77352f06417c5b7c6a \
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
go build -ldflags "-s -w -X Rocket/server/config.Commit=$COMMIT" \
  -tags=jsoniter -o rocket-server Rocket/server

# Windows Client (with enhanced logging - built 2025-12-01 17:09 UTC)
COMMIT=66b87eeb5efd0380afba4b77352f06417c5b7c6a \
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
go build -tags stub -ldflags "-s -w -X Rocket/client/config.Commit=$COMMIT" \
  -o ./built/windows_amd64 Rocket/client

# Verify binary
sha256sum ./built/windows_amd64
# Expected: 2fd6ada5b55768357f5b467475f59cdbc2c109dba0fff979b33d6c93ce13e111
```

---

## Files Modified

### Configuration:
- `/etc/systemd/system/rocket-server.service` - NEW
- `/root/Rocket/config.json` - no changes
- `/etc/caddy/Caddyfile` - no changes

### Binaries:
- `/root/Rocket/rocket-server` - rebuilt with commit hash
- `/root/Rocket/built/windows_amd64` - rebuilt with commit hash

### Branch `upgrade-react18-antd5`:
- `web/package.json` - dependency upgrades
- `web/package-lock.json` - lockfile updated
- `web/src/index.jsx` - React 18 createRoot
- `web/webpack.config.js` - es2018 target
- `server/embed/web/statik.go` - rebuilt assets
- `.old-backups/` - moved old backup files

---

## Maintenance Commands

### Check Service Status:
```bash
sudo systemctl status rocket-server
sudo systemctl status caddy
```

### View Logs:
```bash
# Server logs
tail -f /root/Rocket/logs/2025-12-01.log
tail -f /root/Rocket/logs/server.log

# Systemd logs
sudo journalctl -u rocket-server -f

# Caddy logs
sudo tail -f /var/log/caddy/gapict.com-access.log
```

### Restart Services:
```bash
sudo systemctl restart rocket-server
sudo systemctl restart caddy
```

### Build New Client (if needed):
```bash
cd /root/Rocket
export COMMIT=$(git rev-parse HEAD)
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
  CC=x86_64-w64-mingw32-gcc CXX=x86_64-w64-mingw32-g++ \
  go build -tags stub -ldflags "-s -w -X Rocket/client/config.Commit=$COMMIT" \
  -o ./built/windows_amd64 Rocket/client
```

---

**Last Updated**: December 1, 2025 17:09 UTC
