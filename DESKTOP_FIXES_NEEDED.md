# Desktop Service: Comprehensive Fix Plan

## Critical Issues Found

### Race Conditions (8 critical)
1. **worker start race** - Multiple goroutines could start workers simultaneously
2. **prevDesktop race** - Concurrent read/write without synchronization
3. **working flag race** - Check-then-act pattern without lock
4. **lastPack race** - Written without lock in PingDesktop, read without lock in healthCheck
5. **displayBounds race** - Global variable accessed without synchronization
6. **quitAllDesktop races** - Multiple fields accessed without proper locking
7. **GetDesktop prevDesktop race** - Lock released before using copied reference
8. **Double-close potential** - Channel could be closed from multiple places

### Memory Safety Issues (2 critical)
1. **Unsafe pointer arithmetic** - No bounds checking in isDiff()
2. **Channel close race** - Multiple goroutines could interact with closed channel

### Logic Bugs (4 critical)
1. **Missing resolution message** - User modification removed critical initialization step
2. **Worker doesn't restart** - Once all sessions close, new sessions won't have a worker
3. **Frame drop logic incorrect** - Uses wrong capacity check
4. **healthCheck unsynchronized** - Reads lastPack without lock

### Resource Leaks (3 issues)
1. **healthCheck goroutine** - Runs forever with no shutdown mechanism
2. **Unnecessary manual GC** - Not following Go best practices
3. **Delayed cleanup** - 7-second timeout before goroutine exits

## Fix Strategy

### Phase 1: Critical Race Conditions
- Add atomic operations for `working` flag
- Protect `prevDesktop` with proper locking
- Fix `lastPack` synchronization
- Make `displayBounds` local to each session

### Phase 2: Worker Management
- Implement proper worker lifecycle with context cancellation
- Add worker restart logic when new sessions arrive
- Use sync.WaitGroup for graceful shutdown

### Phase 3: Memory Safety
- Add bounds checking in isDiff()
- Implement safe channel close with sync.Once
- Add channel state tracking

### Phase 4: Best Practices
- Replace manual locks with sync.RWMutex where appropriate
- Use atomic operations for flags
- Implement proper shutdown mechanism
- Remove unnecessary manual GC calls

## Implementation Priority

**Must Fix Immediately:**
1. Resolution message restoration (breaks functionality)
2. prevDesktop race (causes crashes)
3. worker start race (causes resource leaks)
4. unsafe pointer race (causes segfaults)

**Should Fix Soon:**
5. lastPack synchronization
6. displayBounds race
7. Worker restart logic
8. Channel close safety

**Nice to Have:**
9. healthCheck shutdown
10. Frame drop logic improvement
11. Cleanup timeout reduction
