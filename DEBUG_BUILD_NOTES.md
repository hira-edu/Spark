# Debug Build - Enhanced Logging

**Build Date**: December 1, 2025 17:09 UTC
**Binary**: `/root/Rocket/built/windows_amd64`
**SHA256**: `2fd6ada5b55768357f5b467475f59cdbc2c109dba0fff979b33d6c93ce13e111`
**Size**: 20MB

## What Was Added

This debug build adds comprehensive logging to track down why the UI helper process isn't launching in Session 1.

### Session Management Logging

**File**: `client/lifecycle/service_windows.go`

Added detailed logging at every step of the session reconciliation process:

1. **reconcileAllSessions()** - Shows which session is detected as active
2. **setSessionDesiredState()** - Shows when session desired state changes
3. **reconcileSession()** - Shows state comparison and launch decisions
4. **handleSessionChangeEvent()** - Shows Windows session events (LOGON, UNLOCK, etc.)

### Desktop Capture Logging

**File**: `client/service/desktop/desktop_windows.go`

Added logging to show desktop capture initialization:

1. DXGI initialization success/failure
2. GDI fallback attempt
3. Any errors during screen capture setup

## What to Look For in Logs

After deploying this binary to the Windows machine, check `C:\ProgramData\Microsoft\Update\client.log` for:

### Expected Good Flow:
```
[INFO] reconcileAllSessions: found active session session_id=1
[INFO] reconcileAllSessions: marking session active session_id=1 ...
[INFO] reconcileSession: checking state session_id=1 desired=active actual=stopped
[INFO] reconcileSession: will launch UI session_id=1
[INFO] launching UI session_id=1 attempt=1
[INFO] UI launched successfully session_id=1 pid=XXXX
[INFO] Desktop capture initialized with DXGI display=0
```

### If UI Launch Fails:
Look for error logs showing:
- `no user token after retries` - Token acquisition failing
- `process creation failed` - CreateProcessAsUser failing
- `job assignment failed` - Job object issue

### If States Don't Trigger Launch:
```
[INFO] reconcileSession: states match, no action needed state=stopped
```
This means both desired and actual are "stopped" - session management isn't working correctly

### If Desktop Capture Fails:
```
[WARN] DXGI initialization failed, falling back to GDI error=...
[ERROR] GDI initialization also failed error=...
```
This confirms Session 0 cannot access desktop

## Deployment

1. **Stop current service** on Windows machine:
   ```cmd
   sc stop UpdateService
   ```

2. **Replace binary**:
   - Download new binary from `/root/Rocket/built/windows_amd64`
   - Replace `C:\ProgramData\Microsoft\Update\UpdateService.exe`

3. **Start service**:
   ```cmd
   sc start UpdateService
   ```

4. **Collect logs** after 1-2 minutes:
   ```cmd
   type C:\ProgramData\Microsoft\Update\client.log
   ```

## Code Changes Summary

### session management (service_windows.go)
- Lines 109-366: Added 7 new log statements tracking state transitions
- Lines 368-392: Added 2 log statements in setSessionDesiredState
- Lines 216-246: Added 2 log statements in event handler
- Lines 276-322: Added 4 log statements in reconcileAllSessions

### Desktop capture (desktop_windows.go)
- Lines 52-83: Added 4 log statements tracking DXGI/GDI initialization
- Import added: `Rocket/client/telemetry` for LogStructured function

All logging uses the existing telemetry.LogStructured() function with proper log levels (INFO, WARN, ERROR).

---

**Next Step**: Deploy this binary and collect the enhanced logs to identify the root cause.
