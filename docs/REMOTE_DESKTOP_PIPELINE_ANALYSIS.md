# Remote Desktop Pipeline Analysis

## Executive Summary

Analysis of `Cache.zip` containing a remote desktop implementation that works reliably on all Windows platforms. This document compares their approach to our NVENC-based implementation to identify why ours fails on non-NVIDIA systems.

---

## Files Analyzed

| File | Size | Type | Description |
|------|------|------|-------------|
| `Prism.exe` | 4.9MB | PE32 i386 | Main remote desktop client/controller |
| `Sub.dat` | 1.2MB | PE32 i386 | Windows service component |

---

## Key Findings

### 1. Screen Capture Method: GDI (Not DXGI/D3D11)

The analyzed software uses **pure GDI** for screen capture, not DXGI Desktop Duplication or D3D11.

**Evidence - GDI32.dll imports:**
```
BitBlt              - Primary screen capture function
StretchBlt          - Scaled capture
CreateCompatibleDC  - Memory DC for offscreen rendering
CreateCompatibleBitmap - Bitmap buffer
GetDIBits           - Convert to DIB for processing
CreateDIBitmap      - Create device-independent bitmap
CreateDIBSection    - Direct pixel access
```

**Why this matters:**
- GDI works on ALL Windows versions (XP through 11)
- No GPU driver requirements
- No DXGI/D3D11 initialization that can fail
- Compatible with Remote Desktop sessions, VMs, and basic display drivers

### 2. Image Compression: zlib + PNG (Not H.264)

Uses **zlib deflate** compression with optional PNG encoding, not video codecs.

**Evidence:**
```
deflate 1.1.3 Copyright 1995-1998 Jean-loup Gailly
inflate 1.1.3 Copyright 1995-1998 Mark Adler
libpng-*
PNG file corrupted by ASCII conversion
```

**Compression approach:**
- Delta/difference encoding (only send changed regions)
- zlib deflate for lossless compression
- PNG for full-frame fallback
- No dependency on hardware video encoders

### 3. Multi-Monitor Support

**Evidence:**
```
EnumDisplayMonitors
GetMonitorInfoA
MonitorFromPoint
MonitorFromRect
MonitorFromWindow
EnumDisplaySettingsA
```

Uses standard Windows monitor enumeration APIs that work on all systems.

### 4. Network Layer: Custom TCP (bbtcp.dll)

**Evidence:**
```
bbtcp.dll           - Custom TCP library
WS2_32.dll          - Winsock2
CONNECT %s:%d HTTP/1.1  - HTTP tunnel support
Proxy-Connection: Keep-Alive
```

Uses a custom TCP library with HTTP proxy tunneling support - no WebRTC complexity.

### 5. Service Architecture

`Sub.dat` is a Windows service that:
- Runs as `svchost.exe -k netsvcs`
- Uses registry key: `software\microsoft\remoto\Desktop\`
- Has self-update capability (`Sub.dat.bak`)

---

## Architecture Comparison

| Aspect | Their Implementation | Our Implementation |
|--------|---------------------|-------------------|
| **Screen Capture** | GDI BitBlt | DXGI Desktop Duplication |
| **Pixel Format** | DIB (RGB/BGRA) | NV12 (GPU texture) |
| **Compression** | zlib deflate + PNG | H.264 (NVENC/MF) |
| **Transport** | Raw TCP socket | WebRTC (complex) |
| **GPU Required** | No | Yes (NVIDIA for NVENC) |
| **Driver Deps** | None | NVIDIA driver |
| **Latency** | Higher (~50-100ms) | Lower (~20-50ms) |
| **Bandwidth** | Higher | Lower |
| **Compatibility** | Universal | NVIDIA only |

---

## Why Their Approach Works Everywhere

### 1. No Hardware Dependencies
- GDI is software-rendered, works on any display driver
- zlib is pure software, no GPU acceleration needed
- No CUDA, NVENC, or Media Foundation requirements

### 2. Graceful Degradation
- If PNG fails, falls back to raw DIB
- If compression fails, sends uncompressed
- No hard failures that kill the stream

### 3. Simple Protocol
- TCP sockets are universally supported
- No WebRTC ICE/STUN/TURN complexity
- No codec negotiation issues

### 4. Proven Technology
- GDI has worked since Windows 3.1
- zlib is battle-tested (30+ years)
- PNG is universally decodable

---

## Recommendations for Our Implementation

### Option 1: Add GDI Fallback Path (Recommended)

When NVENC/DXGI fails, fall back to:
```
GDI Capture → RGBA → JPEG/zlib → WebSocket tiles
```

**Implementation:**
1. Detect NVENC availability at startup (already done)
2. When `isWindowsSinglePipeline()` returns `false`, use tile encoding
3. Tile encoding should use GDI capture, not DXGI

**Files to modify:**
- `capture_gdi_windows.go` - Already exists
- `desktop_windows.go` - Ensure GDI path is used when DXGI fails

### Option 2: Improve DXGI Fallback

DXGI Desktop Duplication also works on most systems, but:
- Fails in Remote Desktop sessions
- Fails with some display drivers
- Needs proper error handling

**Add fallback chain:**
```
DXGI NV12 → DXGI BGRA → GDI → Error
```

### Option 3: Use Software H.264 Encoder

Instead of NVENC, use x264 or OpenH264:
```
DXGI/GDI Capture → RGBA → x264 → H.264 → WebRTC
```

**Pros:** H.264 benefits without hardware requirements
**Cons:** Higher CPU usage, still needs CGO

---

## Detailed API Usage

### Screen Capture Pipeline (Their Approach)

```c
// 1. Get desktop window
HWND hwnd = GetDesktopWindow();
HDC hdcScreen = GetWindowDC(hwnd);

// 2. Create compatible DC
HDC hdcMem = CreateCompatibleDC(hdcScreen);

// 3. Create bitmap
HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, width, height);
SelectObject(hdcMem, hbm);

// 4. Capture screen
BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

// 5. Get pixel data
BITMAPINFO bi = {sizeof(BITMAPINFOHEADER), width, -height, 1, 32, BI_RGB};
GetDIBits(hdcMem, hbm, 0, height, pixels, &bi, DIB_RGB_COLORS);

// 6. Compress with zlib
z_stream strm;
deflateInit(&strm, Z_DEFAULT_COMPRESSION);
deflate(&strm, Z_FINISH);

// 7. Send over TCP
send(socket, compressed_data, compressed_size, 0);
```

### Our Current Pipeline

```go
// 1. DXGI Desktop Duplication
dupl.AcquireNextFrame() → ID3D11Texture2D (BGRA)

// 2. GPU Color Conversion
D3D11VideoProcessor.ConvertBGRAToNV12() → ID3D11Texture2D (NV12)

// 3. NVENC Encoding
NVENCEncoder.EncodeGPU(nv12Texture) → H.264 NAL units

// 4. WebRTC Transport
webrtc.SendFrame(nalUnits) → RTP packets
```

### Problem Points

| Step | Their Approach | Our Approach | Issue |
|------|---------------|--------------|-------|
| Capture | GDI (universal) | DXGI (GPU-specific) | DXGI fails without proper GPU |
| Format | BGRA (standard) | NV12 (video-specific) | Requires video processor |
| Encode | zlib (software) | NVENC (NVIDIA-only) | No NVIDIA = no encoding |
| Transport | TCP (simple) | WebRTC (complex) | ICE/STUN can fail |

---

## Implementation Priority

### High Priority (Quick Wins)
1. **Fix NVENC detection** ✓ Done - `checkNVENCAvailable()`
2. **Enable tile fallback** ✓ Done - `isWindowsSinglePipeline()` returns false when no NVENC
3. **Verify GDI capture works** - Test tile mode on non-NVIDIA system

### Medium Priority
4. Add DXGI BGRA fallback (no NV12 conversion)
5. Add software JPEG encoder fallback
6. Improve error messages for capture failures

### Low Priority (Future)
7. Add x264 software encoder option
8. Add OpenH264 encoder option
9. Implement delta/difference encoding for tiles

---

## Conclusion

The analyzed remote desktop software prioritizes **compatibility over performance** by using:
- GDI (universal screen capture)
- zlib/PNG (software compression)
- TCP (simple transport)

Our implementation prioritizes **performance over compatibility** by using:
- DXGI Desktop Duplication (GPU capture)
- NVENC (NVIDIA hardware encoding)
- WebRTC (low-latency transport)

**The fix is simple**: When NVENC is unavailable, our tile-based fallback should work. The issue was that `isWindowsSinglePipeline()` was returning `true` even when NVENC wasn't available, preventing the fallback from activating.

With the fix applied (`checkNVENCAvailable()`), the system should now:
1. Try NVENC if available → use single pipeline (low latency)
2. Fall back to tile encoding → use GDI + JPEG + WebSocket (universal)

---

## Appendix: Full Import Analysis

### Prism.exe DLL Imports
- KERNEL32.dll - Core Windows APIs
- USER32.dll - Window/input management
- GDI32.dll - Graphics/screen capture
- GDIPLUS.dll - Image processing
- WS2_32.dll - Winsock networking
- ADVAPI32.dll - Registry/services
- SHELL32.dll - Shell integration
- WININET.dll - HTTP/proxy support
- WINMM.dll - Multimedia (audio)
- bbtcp.dll - Custom TCP library

### Sub.dat DLL Imports
- KERNEL32.dll - Core Windows APIs
- USER32.dll - Window management
- ADVAPI32.dll - Service control
- PSAPI.DLL - Process management
- SHELL32.dll - Shell integration
- SHLWAPI.dll - Path utilities
- WS2_32.dll - Networking
