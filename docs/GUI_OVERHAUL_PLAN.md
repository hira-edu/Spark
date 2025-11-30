# Spark GUI Overhaul - Remote Features Implementation

A focused implementation plan for redesigning Desktop Viewer, Terminal, and File Explorer components with modern UX patterns.

---

## Overview

This document focuses exclusively on **Phase 3: Remote Features** - the core functionality that users interact with most frequently.

### Scope
1. **Desktop Viewer** - Remote desktop viewing and control
2. **Terminal** - Remote shell/command line access
3. **File Explorer** - Remote file management

### Design Goals
- Modern, clean interface inspired by VS Code, GitHub, and enterprise RMM tools
- Dark mode first with light mode support
- Keyboard-first navigation
- Real-time feedback and status indicators
- Responsive design for different screen sizes

---

## 1. Desktop Viewer Redesign

### 1.1 Architecture Overview

Replace modal-based viewer with a full panel/page component.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TOOLBAR                                                                 │
│ ┌─────────┐ ┌─────────────────┐ ┌─────────┐ ┌─────────┐ ┌────────────┐ │
│ │🖥 Device│ │ 🟢 Connected 23ms│ │FPS: 30  │ │BW: 2.1MB│ │1920x1080   │ │
│ └─────────┘ └─────────────────┘ └─────────┘ └─────────┘ └────────────┘ │
│                                                                         │
│ ┌──────────────────────────────────────────────────────────────────┐   │
│ │                                                                  │   │
│ │                                                                  │   │
│ │                     REMOTE DESKTOP CANVAS                        │   │
│ │                                                                  │   │
│ │                                                                  │   │
│ │                                                                  │   │
│ └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│ ┌─────────────────────────────────────────────────────────────────────┐│
│ │ Quality: ████████░░ 70%  │ FPS: [30▼] │ 🖱 ON │ ⌨ ON │ 📷 │ 📋 │ ⛶ ││
│ └─────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Structure

```
components/features/desktop/
├── DesktopViewer.tsx           # Main container component
├── DesktopViewer.css           # Styles
├── components/
│   ├── Toolbar/
│   │   ├── Toolbar.tsx         # Top toolbar
│   │   ├── DeviceIndicator.tsx # Device name + OS icon
│   │   ├── ConnectionStatus.tsx # Status + latency
│   │   └── StatsDisplay.tsx    # FPS, bandwidth, resolution
│   ├── Canvas/
│   │   ├── DesktopCanvas.tsx   # Canvas wrapper with input handling
│   │   ├── InputOverlay.tsx    # Pointer lock indicator
│   │   └── CursorOverlay.tsx   # Remote cursor display
│   ├── Controls/
│   │   ├── ControlBar.tsx      # Bottom control bar
│   │   ├── QualitySlider.tsx   # Quality adjustment
│   │   ├── FPSSelector.tsx     # FPS dropdown
│   │   ├── InputToggle.tsx     # Mouse/keyboard toggles
│   │   └── ActionButtons.tsx   # Screenshot, clipboard, fullscreen
│   └── MonitorSelector/
│       ├── MonitorSelector.tsx # Multi-monitor picker
│       └── MonitorPreview.tsx  # Monitor thumbnail
├── hooks/
│   ├── useDesktopStream.ts     # WebSocket stream management
│   ├── useInputCapture.ts      # Mouse/keyboard input handling
│   ├── useCanvasRenderer.ts    # Canvas drawing logic
│   └── useFullscreen.ts        # Fullscreen API wrapper
└── types.ts                    # TypeScript interfaces
```

### 1.3 Desktop Viewer Component

```tsx
// components/features/desktop/DesktopViewer.tsx
import React, { useState, useRef, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Toolbar } from './components/Toolbar/Toolbar';
import { DesktopCanvas } from './components/Canvas/DesktopCanvas';
import { ControlBar } from './components/Controls/ControlBar';
import { MonitorSelector } from './components/MonitorSelector/MonitorSelector';
import { useDesktopStream } from './hooks/useDesktopStream';
import { useInputCapture } from './hooks/useInputCapture';
import { useFullscreen } from './hooks/useFullscreen';
import './DesktopViewer.css';

interface DesktopViewerProps {
  device: Device;
  onClose: () => void;
}

export const DesktopViewer: React.FC<DesktopViewerProps> = ({ device, onClose }) => {
  // State
  const [quality, setQuality] = useState(70);
  const [targetFps, setTargetFps] = useState(30);
  const [mouseEnabled, setMouseEnabled] = useState(true);
  const [keyboardEnabled, setKeyboardEnabled] = useState(true);
  const [selectedMonitor, setSelectedMonitor] = useState(0);
  const [showMonitorSelector, setShowMonitorSelector] = useState(false);

  // Refs
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Custom hooks
  const {
    status,
    latency,
    currentFps,
    bandwidth,
    resolution,
    monitors,
    connect,
    disconnect,
    sendConfig,
  } = useDesktopStream(device, canvasRef);

  const {
    pointerLocked,
    requestPointerLock,
    exitPointerLock,
  } = useInputCapture(canvasRef, {
    enabled: status === 'connected',
    mouseEnabled,
    keyboardEnabled,
    onInput: (events) => sendInput(events),
  });

  const {
    isFullscreen,
    toggleFullscreen,
  } = useFullscreen(containerRef);

  // Effects
  useEffect(() => {
    connect();
    return () => disconnect();
  }, [device.id]);

  useEffect(() => {
    sendConfig({ quality, fps: targetFps, display: selectedMonitor });
  }, [quality, targetFps, selectedMonitor]);

  // Handlers
  const handleScreenshot = useCallback(() => {
    if (!canvasRef.current) return;
    const link = document.createElement('a');
    link.download = `screenshot_${device.hostname}_${Date.now()}.png`;
    link.href = canvasRef.current.toDataURL('image/png');
    link.click();
  }, [device.hostname]);

  const handleClipboardSync = useCallback(async () => {
    // Implementation for clipboard sync
  }, []);

  const handleMonitorChange = useCallback((index: number) => {
    setSelectedMonitor(index);
    setShowMonitorSelector(false);
  }, []);

  return (
    <div
      ref={containerRef}
      className={`desktop-viewer ${isFullscreen ? 'fullscreen' : ''}`}
    >
      {/* Top Toolbar */}
      <Toolbar
        device={device}
        status={status}
        latency={latency}
        currentFps={currentFps}
        bandwidth={bandwidth}
        resolution={resolution}
        onClose={onClose}
      />

      {/* Canvas Container */}
      <div className="desktop-canvas-container">
        <DesktopCanvas
          ref={canvasRef}
          pointerLocked={pointerLocked}
          onCanvasClick={requestPointerLock}
        />

        {/* Pointer Lock Indicator */}
        <AnimatePresence>
          {pointerLocked && (
            <motion.div
              className="pointer-lock-indicator"
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
            >
              Press ESC to release cursor
            </motion.div>
          )}
        </AnimatePresence>

        {/* Connection Overlay */}
        {status !== 'connected' && (
          <div className="connection-overlay">
            {status === 'connecting' && (
              <>
                <div className="spinner" />
                <span>Connecting to {device.hostname}...</span>
              </>
            )}
            {status === 'disconnected' && (
              <>
                <span>Disconnected</span>
                <button onClick={connect}>Reconnect</button>
              </>
            )}
            {status === 'error' && (
              <>
                <span>Connection failed</span>
                <button onClick={connect}>Retry</button>
              </>
            )}
          </div>
        )}
      </div>

      {/* Bottom Control Bar */}
      <ControlBar
        quality={quality}
        onQualityChange={setQuality}
        targetFps={targetFps}
        onFpsChange={setTargetFps}
        mouseEnabled={mouseEnabled}
        onMouseToggle={() => setMouseEnabled(!mouseEnabled)}
        keyboardEnabled={keyboardEnabled}
        onKeyboardToggle={() => setKeyboardEnabled(!keyboardEnabled)}
        onScreenshot={handleScreenshot}
        onClipboardSync={handleClipboardSync}
        isFullscreen={isFullscreen}
        onFullscreenToggle={toggleFullscreen}
        monitors={monitors}
        selectedMonitor={selectedMonitor}
        onMonitorSelect={handleMonitorChange}
      />
    </div>
  );
};
```

### 1.4 Desktop Stream Hook

```tsx
// components/features/desktop/hooks/useDesktopStream.ts
import { useState, useEffect, useRef, useCallback } from 'react';
import { encrypt, decrypt, genRandHex, hex2ua, ua2hex } from '@/utils/crypto';

interface StreamState {
  status: 'disconnected' | 'connecting' | 'connected' | 'error';
  latency: number;
  currentFps: number;
  bandwidth: number;
  resolution: { width: number; height: number };
  monitors: Monitor[];
}

export const useDesktopStream = (
  device: Device,
  canvasRef: React.RefObject<HTMLCanvasElement>
) => {
  const [state, setState] = useState<StreamState>({
    status: 'disconnected',
    latency: 0,
    currentFps: 0,
    bandwidth: 0,
    resolution: { width: 0, height: 0 },
    monitors: [],
  });

  const wsRef = useRef<WebSocket | null>(null);
  const secretRef = useRef<Uint8Array>(hex2ua(genRandHex(32)));
  const statsRef = useRef({ frames: 0, bytes: 0 });

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setState(s => ({ ...s, status: 'connecting' }));

    const secret = ua2hex(secretRef.current);
    const url = `${getBaseURL(true)}api/device/desktop?device=${device.id}&secret=${secret}`;

    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
      setState(s => ({ ...s, status: 'connected' }));
    };

    ws.onmessage = (event) => {
      handleMessage(event.data);
    };

    ws.onclose = () => {
      setState(s => ({ ...s, status: 'disconnected' }));
    };

    ws.onerror = () => {
      setState(s => ({ ...s, status: 'error' }));
    };

    wsRef.current = ws;

    // Stats ticker
    const ticker = setInterval(() => {
      setState(s => ({
        ...s,
        currentFps: statsRef.current.frames,
        bandwidth: statsRef.current.bytes,
      }));
      statsRef.current = { frames: 0, bytes: 0 };
    }, 1000);

    return () => {
      clearInterval(ticker);
      ws.close();
    };
  }, [device.id]);

  const disconnect = useCallback(() => {
    wsRef.current?.close();
    wsRef.current = null;
  }, []);

  const sendConfig = useCallback((config: DesktopConfig) => {
    sendData({ act: 'DESKTOP_CONFIG', data: config });
  }, []);

  const sendInput = useCallback((events: InputEvent[]) => {
    sendData({ act: 'DESKTOP_INPUT', data: { events } });
  }, []);

  const sendData = useCallback((data: any) => {
    if (wsRef.current?.readyState !== WebSocket.OPEN) return;

    const body = encrypt(JSON.stringify(data), secretRef.current);
    const buffer = new Uint8Array(body.length + 8);
    buffer.set([34, 22, 19, 17, 20, 3], 0);
    buffer.set([body.length >> 8, body.length & 0xff], 6);
    buffer.set(body, 8);
    wsRef.current.send(buffer);
  }, []);

  const handleMessage = useCallback((data: ArrayBuffer) => {
    // Parse and render frames to canvas
    // Update stats
    statsRef.current.frames++;
    statsRef.current.bytes += data.byteLength;

    // Render logic...
  }, []);

  return {
    ...state,
    connect,
    disconnect,
    sendConfig,
    sendInput,
  };
};
```

### 1.5 Input Capture Hook

```tsx
// components/features/desktop/hooks/useInputCapture.ts
import { useState, useEffect, useCallback, useRef } from 'react';

interface InputOptions {
  enabled: boolean;
  mouseEnabled: boolean;
  keyboardEnabled: boolean;
  onInput: (events: InputEvent[]) => void;
}

export const useInputCapture = (
  canvasRef: React.RefObject<HTMLCanvasElement>,
  options: InputOptions
) => {
  const [pointerLocked, setPointerLocked] = useState(false);
  const inputBufferRef = useRef<InputEvent[]>([]);
  const flushTimerRef = useRef<number>();

  // Start input flush interval (16ms = 60fps)
  useEffect(() => {
    if (!options.enabled) return;

    flushTimerRef.current = window.setInterval(() => {
      if (inputBufferRef.current.length > 0) {
        options.onInput(inputBufferRef.current);
        inputBufferRef.current = [];
      }
    }, 16);

    return () => {
      if (flushTimerRef.current) {
        clearInterval(flushTimerRef.current);
      }
    };
  }, [options.enabled, options.onInput]);

  // Mouse move handler
  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!options.mouseEnabled) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    if (document.pointerLockElement === canvas) {
      // Relative movement (pointer locked)
      inputBufferRef.current.push({
        type: 'move',
        deltaX: e.movementX,
        deltaY: e.movementY,
      });
    } else {
      // Absolute position
      const rect = canvas.getBoundingClientRect();
      inputBufferRef.current.push({
        type: 'move',
        x: Math.round((e.clientX - rect.left) / rect.width * canvas.width),
        y: Math.round((e.clientY - rect.top) / rect.height * canvas.height),
      });
    }
  }, [options.mouseEnabled]);

  // Mouse button handlers
  const handleMouseDown = useCallback((e: MouseEvent) => {
    if (!options.mouseEnabled) return;

    const buttons = ['left', 'middle', 'right'];
    inputBufferRef.current.push({
      type: 'button',
      button: buttons[e.button] || 'left',
      down: true,
    });
  }, [options.mouseEnabled]);

  const handleMouseUp = useCallback((e: MouseEvent) => {
    if (!options.mouseEnabled) return;

    const buttons = ['left', 'middle', 'right'];
    inputBufferRef.current.push({
      type: 'button',
      button: buttons[e.button] || 'left',
      down: false,
    });
  }, [options.mouseEnabled]);

  // Scroll handler
  const handleWheel = useCallback((e: WheelEvent) => {
    if (!options.mouseEnabled) return;
    e.preventDefault();

    inputBufferRef.current.push({
      type: 'scroll',
      deltaX: e.deltaX,
      deltaY: e.deltaY,
    });
  }, [options.mouseEnabled]);

  // Keyboard handlers
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (!options.keyboardEnabled) return;
    if (!pointerLocked) return;

    e.preventDefault();
    inputBufferRef.current.push({
      type: 'key',
      key: e.key,
      keyCode: e.keyCode,
      down: true,
    });
  }, [options.keyboardEnabled, pointerLocked]);

  const handleKeyUp = useCallback((e: KeyboardEvent) => {
    if (!options.keyboardEnabled) return;
    if (!pointerLocked) return;

    e.preventDefault();
    inputBufferRef.current.push({
      type: 'key',
      key: e.key,
      keyCode: e.keyCode,
      down: false,
    });
  }, [options.keyboardEnabled, pointerLocked]);

  // Pointer lock handlers
  const requestPointerLock = useCallback(() => {
    canvasRef.current?.requestPointerLock();
  }, []);

  const exitPointerLock = useCallback(() => {
    document.exitPointerLock();
  }, []);

  // Setup event listeners
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !options.enabled) return;

    // Pointer lock change listener
    const handlePointerLockChange = () => {
      setPointerLocked(document.pointerLockElement === canvas);
    };

    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mousedown', handleMouseDown);
    canvas.addEventListener('mouseup', handleMouseUp);
    canvas.addEventListener('wheel', handleWheel, { passive: false });
    canvas.addEventListener('contextmenu', (e) => e.preventDefault());
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('keyup', handleKeyUp);
    document.addEventListener('pointerlockchange', handlePointerLockChange);

    return () => {
      canvas.removeEventListener('mousemove', handleMouseMove);
      canvas.removeEventListener('mousedown', handleMouseDown);
      canvas.removeEventListener('mouseup', handleMouseUp);
      canvas.removeEventListener('wheel', handleWheel);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('keyup', handleKeyUp);
      document.removeEventListener('pointerlockchange', handlePointerLockChange);
    };
  }, [options.enabled, handleMouseMove, handleMouseDown, handleMouseUp, handleWheel, handleKeyDown, handleKeyUp]);

  return {
    pointerLocked,
    requestPointerLock,
    exitPointerLock,
  };
};
```

### 1.6 Desktop Viewer Styles

```css
/* components/features/desktop/DesktopViewer.css */

.desktop-viewer {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

.desktop-viewer.fullscreen {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  z-index: 9999;
  border-radius: 0;
}

/* Toolbar */
.desktop-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 16px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-primary);
  gap: 16px;
}

.toolbar-section {
  display: flex;
  align-items: center;
  gap: 12px;
}

.stat-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--text-secondary);
}

.stat-value {
  font-family: 'JetBrains Mono', monospace;
  color: var(--text-primary);
}

/* Canvas Container */
.desktop-canvas-container {
  flex: 1;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #000;
  overflow: hidden;
}

.desktop-canvas {
  max-width: 100%;
  max-height: 100%;
  cursor: crosshair;
}

.desktop-canvas.pointer-locked {
  cursor: none;
}

/* Pointer Lock Indicator */
.pointer-lock-indicator {
  position: absolute;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  padding: 8px 16px;
  background: rgba(0, 0, 0, 0.8);
  color: var(--text-primary);
  border-radius: var(--radius-md);
  font-size: 12px;
  pointer-events: none;
}

/* Connection Overlay */
.connection-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  background: rgba(0, 0, 0, 0.9);
  color: var(--text-primary);
}

.spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-primary);
  border-top-color: var(--accent-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

/* Control Bar */
.desktop-control-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 16px;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-primary);
  gap: 16px;
}

.control-group {
  display: flex;
  align-items: center;
  gap: 8px;
}

.quality-slider {
  display: flex;
  align-items: center;
  gap: 8px;
}

.quality-slider input[type="range"] {
  width: 100px;
}

.control-button {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  background: transparent;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.control-button:hover {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.control-button.active {
  background: var(--accent-primary);
  border-color: var(--accent-primary);
  color: white;
}

.control-button.danger:hover {
  background: var(--status-offline);
  border-color: var(--status-offline);
}

/* Monitor Selector */
.monitor-selector {
  position: absolute;
  bottom: 60px;
  right: 16px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  padding: 8px;
  display: flex;
  gap: 8px;
}

.monitor-option {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  padding: 8px;
  border: 2px solid transparent;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.15s ease;
}

.monitor-option:hover {
  background: var(--bg-tertiary);
}

.monitor-option.selected {
  border-color: var(--accent-primary);
}

.monitor-preview {
  width: 80px;
  height: 45px;
  background: var(--bg-primary);
  border-radius: var(--radius-sm);
}

.monitor-label {
  font-size: 11px;
  color: var(--text-secondary);
}
```

---

## 2. Terminal Redesign

### 2.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TABS                                                                    │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  [+]                │
│ │ 🔵 Session 1 │ │ 🟢 Session 2 │ │ 🔴 Session 3 │                     │
│ └──────────────┘ └──────────────┘ └──────────────┘                     │
├─────────────────────────────────────────────────────────────────────────┤
│ HEADER                                                                  │
│ 🐚 PowerShell  │  C:\Users\Admin  │  🟢 Connected  │  ⏱ 00:05:23  │ ⚙ │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│                                                                         │
│                        XTERM TERMINAL                                   │
│                                                                         │
│                                                                         │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ FOOTER                                                                  │
│ Quick: [ls] [pwd] [clear] [top]          │  [📤 Upload] [📥 Download]  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Structure

```
components/features/terminal/
├── TerminalPanel.tsx           # Main container
├── TerminalPanel.css           # Styles
├── components/
│   ├── TabBar/
│   │   ├── TabBar.tsx          # Session tabs
│   │   ├── Tab.tsx             # Individual tab
│   │   └── AddTabButton.tsx    # New session button
│   ├── Header/
│   │   ├── Header.tsx          # Terminal header
│   │   ├── ShellIndicator.tsx  # Shell type icon
│   │   ├── PathDisplay.tsx     # Current directory
│   │   ├── ConnectionStatus.tsx
│   │   └── SessionTimer.tsx    # Session duration
│   ├── Terminal/
│   │   ├── XTermWrapper.tsx    # XTerm.js wrapper
│   │   └── TerminalThemes.ts   # Color schemes
│   └── Footer/
│       ├── Footer.tsx          # Quick commands + file transfer
│       ├── QuickCommands.tsx   # Shortcut buttons
│       └── FileTransfer.tsx    # Upload/download buttons
├── hooks/
│   ├── useTerminalSession.ts   # Session management
│   ├── useTerminalSocket.ts    # WebSocket connection
│   └── useZmodem.ts            # File transfer
└── types.ts
```

### 2.3 Terminal Panel Component

```tsx
// components/features/terminal/TerminalPanel.tsx
import React, { useState, useCallback, useRef } from 'react';
import { TabBar } from './components/TabBar/TabBar';
import { Header } from './components/Header/Header';
import { XTermWrapper } from './components/Terminal/XTermWrapper';
import { Footer } from './components/Footer/Footer';
import { useTerminalSession } from './hooks/useTerminalSession';
import './TerminalPanel.css';

interface TerminalPanelProps {
  device: Device;
  onClose: () => void;
}

interface Session {
  id: string;
  status: 'connecting' | 'connected' | 'disconnected';
  shell: string;
  cwd: string;
  startTime: number;
}

export const TerminalPanel: React.FC<TerminalPanelProps> = ({ device, onClose }) => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light' | 'retro'>('dark');

  const {
    createSession,
    closeSession,
    sendCommand,
    sendInput,
  } = useTerminalSession(device);

  // Create initial session on mount
  useEffect(() => {
    handleNewSession();
  }, []);

  const handleNewSession = useCallback(async () => {
    const session = await createSession();
    setSessions(prev => [...prev, session]);
    setActiveSessionId(session.id);
  }, [createSession]);

  const handleCloseSession = useCallback((sessionId: string) => {
    closeSession(sessionId);
    setSessions(prev => prev.filter(s => s.id !== sessionId));

    // Switch to another session if closing active one
    if (activeSessionId === sessionId) {
      const remaining = sessions.filter(s => s.id !== sessionId);
      setActiveSessionId(remaining[0]?.id || null);
    }
  }, [activeSessionId, sessions, closeSession]);

  const handleQuickCommand = useCallback((cmd: string) => {
    if (activeSessionId) {
      sendCommand(activeSessionId, cmd);
    }
  }, [activeSessionId, sendCommand]);

  const activeSession = sessions.find(s => s.id === activeSessionId);

  return (
    <div className="terminal-panel">
      {/* Tab Bar */}
      <TabBar
        sessions={sessions}
        activeId={activeSessionId}
        onSelect={setActiveSessionId}
        onClose={handleCloseSession}
        onNew={handleNewSession}
      />

      {/* Header */}
      {activeSession && (
        <Header
          shell={activeSession.shell}
          cwd={activeSession.cwd}
          status={activeSession.status}
          startTime={activeSession.startTime}
          theme={theme}
          onThemeChange={setTheme}
        />
      )}

      {/* Terminal */}
      <div className="terminal-content">
        {sessions.map(session => (
          <div
            key={session.id}
            className={`terminal-instance ${session.id === activeSessionId ? 'active' : ''}`}
          >
            <XTermWrapper
              sessionId={session.id}
              theme={theme}
              onInput={(data) => sendInput(session.id, data)}
            />
          </div>
        ))}

        {sessions.length === 0 && (
          <div className="terminal-empty">
            <span>No active sessions</span>
            <button onClick={handleNewSession}>Create Session</button>
          </div>
        )}
      </div>

      {/* Footer */}
      <Footer
        os={device.os}
        onQuickCommand={handleQuickCommand}
        sessionId={activeSessionId}
      />
    </div>
  );
};
```

### 2.4 XTerm Wrapper

```tsx
// components/features/terminal/components/Terminal/XTermWrapper.tsx
import React, { useEffect, useRef, useImperativeHandle, forwardRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import { WebglAddon } from 'xterm-addon-webgl';
import { terminalThemes } from './TerminalThemes';
import 'xterm/css/xterm.css';

interface XTermWrapperProps {
  sessionId: string;
  theme: 'dark' | 'light' | 'retro';
  onInput: (data: string) => void;
  onResize?: (cols: number, rows: number) => void;
}

export const XTermWrapper = forwardRef<Terminal, XTermWrapperProps>(
  ({ sessionId, theme, onInput, onResize }, ref) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const terminalRef = useRef<Terminal | null>(null);
    const fitAddonRef = useRef<FitAddon | null>(null);

    useImperativeHandle(ref, () => terminalRef.current!, []);

    useEffect(() => {
      if (!containerRef.current) return;

      const terminal = new Terminal({
        cursorBlink: true,
        cursorStyle: 'block',
        fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
        fontSize: 14,
        lineHeight: 1.2,
        letterSpacing: 0,
        allowTransparency: true,
        theme: terminalThemes[theme],
      });

      const fitAddon = new FitAddon();
      const webLinksAddon = new WebLinksAddon();

      terminal.loadAddon(fitAddon);
      terminal.loadAddon(webLinksAddon);

      // Try WebGL addon for better performance
      try {
        const webglAddon = new WebglAddon();
        terminal.loadAddon(webglAddon);
      } catch (e) {
        console.warn('WebGL addon not supported, using canvas renderer');
      }

      terminal.open(containerRef.current);
      fitAddon.fit();

      // Handle input
      terminal.onData(onInput);

      // Handle resize
      const resizeObserver = new ResizeObserver(() => {
        fitAddon.fit();
        onResize?.(terminal.cols, terminal.rows);
      });
      resizeObserver.observe(containerRef.current);

      terminalRef.current = terminal;
      fitAddonRef.current = fitAddon;

      return () => {
        resizeObserver.disconnect();
        terminal.dispose();
      };
    }, [sessionId]);

    // Update theme
    useEffect(() => {
      if (terminalRef.current) {
        terminalRef.current.options.theme = terminalThemes[theme];
      }
    }, [theme]);

    return <div ref={containerRef} className="xterm-container" />;
  }
);
```

### 2.5 Terminal Themes

```typescript
// components/features/terminal/components/Terminal/TerminalThemes.ts
import { ITheme } from 'xterm';

export const terminalThemes: Record<string, ITheme> = {
  dark: {
    background: '#0d1117',
    foreground: '#c9d1d9',
    cursor: '#58a6ff',
    cursorAccent: '#0d1117',
    selectionBackground: 'rgba(88, 166, 255, 0.3)',
    selectionForeground: '#ffffff',
    black: '#484f58',
    red: '#ff7b72',
    green: '#3fb950',
    yellow: '#d29922',
    blue: '#58a6ff',
    magenta: '#bc8cff',
    cyan: '#39c5cf',
    white: '#b1bac4',
    brightBlack: '#6e7681',
    brightRed: '#ffa198',
    brightGreen: '#56d364',
    brightYellow: '#e3b341',
    brightBlue: '#79c0ff',
    brightMagenta: '#d2a8ff',
    brightCyan: '#56d4dd',
    brightWhite: '#f0f6fc',
  },

  light: {
    background: '#ffffff',
    foreground: '#24292f',
    cursor: '#0969da',
    cursorAccent: '#ffffff',
    selectionBackground: 'rgba(9, 105, 218, 0.3)',
    black: '#24292f',
    red: '#cf222e',
    green: '#1a7f37',
    yellow: '#9a6700',
    blue: '#0969da',
    magenta: '#8250df',
    cyan: '#1b7c83',
    white: '#6e7781',
    brightBlack: '#57606a',
    brightRed: '#a40e26',
    brightGreen: '#2da44e',
    brightYellow: '#bf8700',
    brightBlue: '#218bff',
    brightMagenta: '#a475f9',
    brightCyan: '#3192aa',
    brightWhite: '#8c959f',
  },

  retro: {
    background: '#0a0a0a',
    foreground: '#00ff00',
    cursor: '#00ff00',
    cursorAccent: '#0a0a0a',
    selectionBackground: 'rgba(0, 255, 0, 0.3)',
    black: '#0a0a0a',
    red: '#ff0000',
    green: '#00ff00',
    yellow: '#ffff00',
    blue: '#0000ff',
    magenta: '#ff00ff',
    cyan: '#00ffff',
    white: '#ffffff',
    brightBlack: '#555555',
    brightRed: '#ff5555',
    brightGreen: '#55ff55',
    brightYellow: '#ffff55',
    brightBlue: '#5555ff',
    brightMagenta: '#ff55ff',
    brightCyan: '#55ffff',
    brightWhite: '#ffffff',
  },

  monokai: {
    background: '#272822',
    foreground: '#f8f8f2',
    cursor: '#f8f8f2',
    cursorAccent: '#272822',
    selectionBackground: 'rgba(73, 72, 62, 0.5)',
    black: '#272822',
    red: '#f92672',
    green: '#a6e22e',
    yellow: '#f4bf75',
    blue: '#66d9ef',
    magenta: '#ae81ff',
    cyan: '#a1efe4',
    white: '#f8f8f2',
    brightBlack: '#75715e',
    brightRed: '#f92672',
    brightGreen: '#a6e22e',
    brightYellow: '#f4bf75',
    brightBlue: '#66d9ef',
    brightMagenta: '#ae81ff',
    brightCyan: '#a1efe4',
    brightWhite: '#f9f8f5',
  },

  dracula: {
    background: '#282a36',
    foreground: '#f8f8f2',
    cursor: '#f8f8f2',
    cursorAccent: '#282a36',
    selectionBackground: 'rgba(68, 71, 90, 0.5)',
    black: '#21222c',
    red: '#ff5555',
    green: '#50fa7b',
    yellow: '#f1fa8c',
    blue: '#bd93f9',
    magenta: '#ff79c6',
    cyan: '#8be9fd',
    white: '#f8f8f2',
    brightBlack: '#6272a4',
    brightRed: '#ff6e6e',
    brightGreen: '#69ff94',
    brightYellow: '#ffffa5',
    brightBlue: '#d6acff',
    brightMagenta: '#ff92df',
    brightCyan: '#a4ffff',
    brightWhite: '#ffffff',
  },
};
```

### 2.6 Terminal Styles

```css
/* components/features/terminal/TerminalPanel.css */

.terminal-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

/* Tab Bar */
.terminal-tabs {
  display: flex;
  align-items: center;
  padding: 4px 8px;
  background: var(--bg-tertiary);
  border-bottom: 1px solid var(--border-primary);
  gap: 2px;
  overflow-x: auto;
}

.terminal-tab {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  background: transparent;
  border: none;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.15s ease;
}

.terminal-tab:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.terminal-tab.active {
  background: var(--bg-secondary);
  color: var(--text-primary);
}

.terminal-tab .status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.terminal-tab .status-dot.connected { background: var(--status-online); }
.terminal-tab .status-dot.connecting { background: var(--status-busy); }
.terminal-tab .status-dot.disconnected { background: var(--status-offline); }

.terminal-tab .close-btn {
  padding: 2px;
  border-radius: 2px;
  opacity: 0;
  transition: opacity 0.15s ease;
}

.terminal-tab:hover .close-btn {
  opacity: 1;
}

.terminal-tab .close-btn:hover {
  background: var(--bg-tertiary);
}

.add-tab-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  background: transparent;
  border: 1px dashed var(--border-primary);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.add-tab-btn:hover {
  border-color: var(--accent-primary);
  color: var(--accent-primary);
}

/* Header */
.terminal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 16px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-primary);
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.shell-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--text-secondary);
}

.shell-indicator .icon {
  font-size: 14px;
}

.path-display {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-primary);
  padding: 4px 8px;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

.session-timer {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  color: var(--text-secondary);
}

/* Terminal Content */
.terminal-content {
  flex: 1;
  position: relative;
  overflow: hidden;
}

.terminal-instance {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: none;
}

.terminal-instance.active {
  display: block;
}

.xterm-container {
  width: 100%;
  height: 100%;
}

.terminal-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  gap: 16px;
  color: var(--text-secondary);
}

/* Footer */
.terminal-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 16px;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-primary);
}

.quick-commands {
  display: flex;
  gap: 4px;
}

.quick-cmd-btn {
  padding: 4px 8px;
  background: var(--bg-tertiary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.quick-cmd-btn:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.file-transfer-btns {
  display: flex;
  gap: 8px;
}

/* Theme Selector */
.theme-selector {
  display: flex;
  gap: 4px;
}

.theme-option {
  width: 20px;
  height: 20px;
  border-radius: var(--radius-sm);
  border: 2px solid transparent;
  cursor: pointer;
  transition: all 0.15s ease;
}

.theme-option:hover {
  transform: scale(1.1);
}

.theme-option.active {
  border-color: var(--accent-primary);
}

.theme-option.dark { background: #0d1117; }
.theme-option.light { background: #ffffff; }
.theme-option.retro { background: #0a0a0a; }
.theme-option.monokai { background: #272822; }
.theme-option.dracula { background: #282a36; }
```

---

## 3. File Explorer Redesign

### 3.1 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TOOLBAR                                                                 │
│ [◀] [▶] [↑] [🔄]  │  🏠 > Users > Admin > Documents  │  [🔍 Search...] │
│                                                    [Grid] [List] [Upload]│
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │   📁     │  │   📁     │  │   📄     │  │   🖼️     │                │
│  │ Desktop  │  │ Downloads│  │ readme.md│  │ photo.png│                │
│  │          │  │          │  │  2.3 KB  │  │  1.2 MB  │                │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘                │
│                                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │   📁     │  │   📦     │  │   📝     │  │   📊     │                │
│  │  Music   │  │ app.zip  │  │ notes.txt│  │ data.csv │                │
│  │          │  │  45 MB   │  │  156 B   │  │  890 KB  │                │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘                │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ STATUS: 8 items │ 2 selected │ Free: 45.2 GB                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Structure

```
components/features/explorer/
├── FileExplorer.tsx            # Main container
├── FileExplorer.css            # Styles
├── components/
│   ├── Toolbar/
│   │   ├── Toolbar.tsx         # Main toolbar
│   │   ├── NavButtons.tsx      # Back/forward/up/refresh
│   │   ├── Breadcrumb.tsx      # Path breadcrumb
│   │   ├── SearchInput.tsx     # File search
│   │   └── ViewToggle.tsx      # Grid/list toggle
│   ├── FileView/
│   │   ├── FileGrid.tsx        # Grid view
│   │   ├── FileList.tsx        # List view
│   │   ├── FileItem.tsx        # Individual file item
│   │   └── FileIcon.tsx        # File type icons
│   ├── ContextMenu/
│   │   ├── ContextMenu.tsx     # Right-click menu
│   │   └── MenuItem.tsx        # Menu item
│   ├── Dialogs/
│   │   ├── RenameDialog.tsx    # Rename file dialog
│   │   ├── NewFolderDialog.tsx # Create folder dialog
│   │   ├── DeleteDialog.tsx    # Delete confirmation
│   │   └── PropertiesDialog.tsx# File properties
│   ├── Upload/
│   │   ├── UploadDropzone.tsx  # Drag & drop area
│   │   └── UploadProgress.tsx  # Upload progress indicator
│   └── Preview/
│       ├── ImagePreview.tsx    # Image viewer
│       ├── TextPreview.tsx     # Text/code viewer
│       └── VideoPreview.tsx    # Video player
├── hooks/
│   ├── useFileSystem.ts        # File operations
│   ├── useSelection.ts         # Multi-select logic
│   ├── useDragDrop.ts          # Drag and drop
│   └── useContextMenu.ts       # Right-click menu
└── types.ts
```

### 3.3 File Explorer Component

```tsx
// components/features/explorer/FileExplorer.tsx
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Toolbar } from './components/Toolbar/Toolbar';
import { FileGrid } from './components/FileView/FileGrid';
import { FileList } from './components/FileView/FileList';
import { ContextMenu } from './components/ContextMenu/ContextMenu';
import { UploadDropzone } from './components/Upload/UploadDropzone';
import { useFileSystem } from './hooks/useFileSystem';
import { useSelection } from './hooks/useSelection';
import { useContextMenu } from './hooks/useContextMenu';
import './FileExplorer.css';

interface FileExplorerProps {
  device: Device;
  onClose: () => void;
}

export const FileExplorer: React.FC<FileExplorerProps> = ({ device, onClose }) => {
  // State
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'size' | 'date'>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Refs
  const containerRef = useRef<HTMLDivElement>(null);

  // Custom hooks
  const {
    path,
    files,
    loading,
    error,
    history,
    freeSpace,
    navigate,
    goBack,
    goForward,
    goUp,
    refresh,
    createFolder,
    rename,
    deleteFiles,
    downloadFiles,
    uploadFiles,
  } = useFileSystem(device);

  const {
    selectedIds,
    selectFile,
    selectRange,
    toggleSelect,
    selectAll,
    clearSelection,
  } = useSelection();

  const {
    contextMenu,
    showContextMenu,
    hideContextMenu,
  } = useContextMenu();

  // Filter and sort files
  const filteredFiles = files
    .filter(f => f.name.toLowerCase().includes(searchTerm.toLowerCase()))
    .sort((a, b) => {
      // Folders first
      if (a.type !== b.type) {
        return a.type === 'folder' ? -1 : 1;
      }

      let comparison = 0;
      switch (sortBy) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'size':
          comparison = a.size - b.size;
          break;
        case 'date':
          comparison = a.modifiedTime - b.modifiedTime;
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

  // Handlers
  const handleFileDoubleClick = useCallback((file: FileItem) => {
    if (file.type === 'folder') {
      navigate(file.path);
      clearSelection();
    } else {
      // Open file or download
      downloadFiles([file.path]);
    }
  }, [navigate, clearSelection, downloadFiles]);

  const handleContextMenu = useCallback((e: React.MouseEvent, file?: FileItem) => {
    e.preventDefault();

    if (file && !selectedIds.includes(file.path)) {
      selectFile(file.path);
    }

    showContextMenu(e.clientX, e.clientY, file);
  }, [selectedIds, selectFile, showContextMenu]);

  const handleDrop = useCallback(async (acceptedFiles: File[]) => {
    await uploadFiles(acceptedFiles, path);
    refresh();
  }, [uploadFiles, path, refresh]);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Delete' && selectedIds.length > 0) {
      deleteFiles(selectedIds);
    }
    if (e.key === 'a' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      selectAll(files.map(f => f.path));
    }
    if (e.key === 'Escape') {
      clearSelection();
    }
  }, [selectedIds, deleteFiles, selectAll, clearSelection, files]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  const FileViewComponent = viewMode === 'grid' ? FileGrid : FileList;

  return (
    <div
      ref={containerRef}
      className="file-explorer"
      onClick={() => hideContextMenu()}
    >
      {/* Toolbar */}
      <Toolbar
        path={path}
        history={history}
        searchTerm={searchTerm}
        viewMode={viewMode}
        sortBy={sortBy}
        sortOrder={sortOrder}
        onSearchChange={setSearchTerm}
        onViewModeChange={setViewMode}
        onSortChange={(by, order) => { setSortBy(by); setSortOrder(order); }}
        onBack={goBack}
        onForward={goForward}
        onUp={goUp}
        onRefresh={refresh}
        onNavigate={navigate}
        onNewFolder={() => createFolder(path)}
        onUpload={() => {/* trigger file input */}}
      />

      {/* File View with Drop Zone */}
      <UploadDropzone onDrop={handleDrop}>
        <div className="file-view-container">
          {loading && (
            <div className="loading-overlay">
              <div className="spinner" />
              <span>Loading...</span>
            </div>
          )}

          {error && (
            <div className="error-message">
              <span>{error}</span>
              <button onClick={refresh}>Retry</button>
            </div>
          )}

          {!loading && !error && (
            <FileViewComponent
              files={filteredFiles}
              selectedIds={selectedIds}
              onSelect={selectFile}
              onToggleSelect={toggleSelect}
              onRangeSelect={selectRange}
              onDoubleClick={handleFileDoubleClick}
              onContextMenu={handleContextMenu}
            />
          )}

          {!loading && !error && filteredFiles.length === 0 && (
            <div className="empty-folder">
              <span>This folder is empty</span>
            </div>
          )}
        </div>
      </UploadDropzone>

      {/* Status Bar */}
      <div className="explorer-statusbar">
        <span>{filteredFiles.length} items</span>
        {selectedIds.length > 0 && (
          <span>{selectedIds.length} selected</span>
        )}
        <span>Free: {formatSize(freeSpace)}</span>
      </div>

      {/* Context Menu */}
      <ContextMenu
        visible={contextMenu.visible}
        x={contextMenu.x}
        y={contextMenu.y}
        file={contextMenu.file}
        selectedCount={selectedIds.length}
        onOpen={() => handleFileDoubleClick(contextMenu.file!)}
        onDownload={() => downloadFiles(selectedIds)}
        onRename={() => {/* open rename dialog */}}
        onDelete={() => deleteFiles(selectedIds)}
        onCopy={() => {/* copy to clipboard */}}
        onCut={() => {/* cut to clipboard */}}
        onPaste={() => {/* paste from clipboard */}}
        onNewFolder={() => createFolder(path)}
        onProperties={() => {/* show properties dialog */}}
        onClose={hideContextMenu}
      />
    </div>
  );
};
```

### 3.4 File Grid Component

```tsx
// components/features/explorer/components/FileView/FileGrid.tsx
import React from 'react';
import { motion } from 'framer-motion';
import { FileIcon } from './FileIcon';
import { formatSize, formatDate } from '@/utils/format';

interface FileGridProps {
  files: FileItem[];
  selectedIds: string[];
  onSelect: (id: string) => void;
  onToggleSelect: (id: string) => void;
  onRangeSelect: (id: string) => void;
  onDoubleClick: (file: FileItem) => void;
  onContextMenu: (e: React.MouseEvent, file: FileItem) => void;
}

export const FileGrid: React.FC<FileGridProps> = ({
  files,
  selectedIds,
  onSelect,
  onToggleSelect,
  onRangeSelect,
  onDoubleClick,
  onContextMenu,
}) => {
  const handleClick = (e: React.MouseEvent, file: FileItem) => {
    if (e.ctrlKey || e.metaKey) {
      onToggleSelect(file.path);
    } else if (e.shiftKey) {
      onRangeSelect(file.path);
    } else {
      onSelect(file.path);
    }
  };

  return (
    <div className="file-grid">
      {files.map((file, index) => (
        <motion.div
          key={file.path}
          className={`file-grid-item ${selectedIds.includes(file.path) ? 'selected' : ''}`}
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: index * 0.02 }}
          onClick={(e) => handleClick(e, file)}
          onDoubleClick={() => onDoubleClick(file)}
          onContextMenu={(e) => onContextMenu(e, file)}
        >
          <div className="file-icon-wrapper">
            <FileIcon type={file.type} extension={file.extension} size={48} />
            {file.type === 'folder' && (
              <div className="folder-badge">{file.childCount}</div>
            )}
          </div>

          <div className="file-name" title={file.name}>
            {file.name}
          </div>

          {file.type !== 'folder' && (
            <div className="file-size">
              {formatSize(file.size)}
            </div>
          )}
        </motion.div>
      ))}
    </div>
  );
};
```

### 3.5 File Icons

```tsx
// components/features/explorer/components/FileView/FileIcon.tsx
import React from 'react';
import {
  FolderOutlined,
  FileOutlined,
  FileTextOutlined,
  FileImageOutlined,
  FileZipOutlined,
  FilePdfOutlined,
  FileExcelOutlined,
  FileWordOutlined,
  FilePptOutlined,
  PlaySquareOutlined,
  SoundOutlined,
  CodeOutlined,
  DatabaseOutlined,
} from '@ant-design/icons';

interface FileIconProps {
  type: 'folder' | 'file';
  extension?: string;
  size?: number;
}

const iconMap: Record<string, React.ComponentType<any>> = {
  // Folders
  folder: FolderOutlined,

  // Documents
  pdf: FilePdfOutlined,
  doc: FileWordOutlined,
  docx: FileWordOutlined,
  xls: FileExcelOutlined,
  xlsx: FileExcelOutlined,
  ppt: FilePptOutlined,
  pptx: FilePptOutlined,
  txt: FileTextOutlined,
  md: FileTextOutlined,

  // Images
  jpg: FileImageOutlined,
  jpeg: FileImageOutlined,
  png: FileImageOutlined,
  gif: FileImageOutlined,
  svg: FileImageOutlined,
  webp: FileImageOutlined,
  ico: FileImageOutlined,

  // Archives
  zip: FileZipOutlined,
  rar: FileZipOutlined,
  '7z': FileZipOutlined,
  tar: FileZipOutlined,
  gz: FileZipOutlined,

  // Media
  mp4: PlaySquareOutlined,
  avi: PlaySquareOutlined,
  mkv: PlaySquareOutlined,
  mov: PlaySquareOutlined,
  mp3: SoundOutlined,
  wav: SoundOutlined,
  flac: SoundOutlined,

  // Code
  js: CodeOutlined,
  ts: CodeOutlined,
  jsx: CodeOutlined,
  tsx: CodeOutlined,
  py: CodeOutlined,
  go: CodeOutlined,
  rs: CodeOutlined,
  java: CodeOutlined,
  c: CodeOutlined,
  cpp: CodeOutlined,
  h: CodeOutlined,
  css: CodeOutlined,
  scss: CodeOutlined,
  html: CodeOutlined,
  json: CodeOutlined,
  xml: CodeOutlined,
  yaml: CodeOutlined,
  yml: CodeOutlined,

  // Data
  sql: DatabaseOutlined,
  db: DatabaseOutlined,
  sqlite: DatabaseOutlined,
  csv: FileExcelOutlined,

  // Default
  default: FileOutlined,
};

const colorMap: Record<string, string> = {
  folder: '#ffc107',
  pdf: '#f44336',
  doc: '#2196f3',
  docx: '#2196f3',
  xls: '#4caf50',
  xlsx: '#4caf50',
  ppt: '#ff9800',
  pptx: '#ff9800',
  zip: '#9c27b0',
  rar: '#9c27b0',
  jpg: '#e91e63',
  png: '#e91e63',
  mp4: '#673ab7',
  mp3: '#00bcd4',
  js: '#ffeb3b',
  ts: '#3f51b5',
  py: '#4caf50',
  go: '#00bcd4',
  default: '#9e9e9e',
};

export const FileIcon: React.FC<FileIconProps> = ({ type, extension, size = 24 }) => {
  const key = type === 'folder' ? 'folder' : (extension?.toLowerCase() || 'default');
  const IconComponent = iconMap[key] || iconMap.default;
  const color = colorMap[key] || colorMap.default;

  return (
    <IconComponent
      style={{
        fontSize: size,
        color,
      }}
    />
  );
};
```

### 3.6 File Explorer Styles

```css
/* components/features/explorer/FileExplorer.css */

.file-explorer {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--bg-primary);
  border-radius: var(--radius-lg);
  overflow: hidden;
}

/* Toolbar */
.explorer-toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 16px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-primary);
}

.nav-buttons {
  display: flex;
  gap: 4px;
}

.nav-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  background: transparent;
  border: none;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.nav-btn:hover:not(:disabled) {
  background: var(--bg-tertiary);
  color: var(--text-primary);
}

.nav-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

/* Breadcrumb */
.path-breadcrumb {
  flex: 1;
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 4px 8px;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  overflow-x: auto;
}

.breadcrumb-item {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  color: var(--text-secondary);
  font-size: 12px;
  white-space: nowrap;
  cursor: pointer;
  border-radius: var(--radius-sm);
  transition: all 0.15s ease;
}

.breadcrumb-item:hover {
  background: var(--bg-hover);
  color: var(--text-primary);
}

.breadcrumb-item:last-child {
  color: var(--text-primary);
  font-weight: 500;
}

.breadcrumb-separator {
  color: var(--text-tertiary);
  font-size: 10px;
}

/* Search */
.search-input {
  width: 200px;
  padding: 6px 10px 6px 32px;
  background: var(--bg-tertiary);
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-size: 12px;
  transition: all 0.15s ease;
}

.search-input:focus {
  outline: none;
  border-color: var(--accent-primary);
  background: var(--bg-primary);
}

.search-input::placeholder {
  color: var(--text-tertiary);
}

/* View Toggle */
.view-toggle {
  display: flex;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  padding: 2px;
}

.view-toggle-btn {
  padding: 4px 8px;
  background: transparent;
  border: none;
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.view-toggle-btn.active {
  background: var(--bg-secondary);
  color: var(--text-primary);
}

/* File View Container */
.file-view-container {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  position: relative;
}

/* File Grid */
.file-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(100px, 1fr));
  gap: 12px;
}

.file-grid-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 12px 8px;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: all 0.15s ease;
  user-select: none;
}

.file-grid-item:hover {
  background: var(--bg-tertiary);
}

.file-grid-item.selected {
  background: rgba(88, 166, 255, 0.15);
  outline: 2px solid var(--accent-primary);
}

.file-icon-wrapper {
  position: relative;
}

.folder-badge {
  position: absolute;
  bottom: -4px;
  right: -4px;
  min-width: 18px;
  height: 18px;
  padding: 0 4px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: 9px;
  font-size: 10px;
  font-weight: 500;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
}

.file-name {
  font-size: 12px;
  color: var(--text-primary);
  text-align: center;
  word-break: break-word;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.file-size {
  font-size: 10px;
  color: var(--text-tertiary);
}

/* File List */
.file-list {
  display: flex;
  flex-direction: column;
}

.file-list-header {
  display: grid;
  grid-template-columns: 40px 1fr 100px 140px 80px;
  gap: 8px;
  padding: 8px 12px;
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-primary);
  font-size: 11px;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.file-list-item {
  display: grid;
  grid-template-columns: 40px 1fr 100px 140px 80px;
  gap: 8px;
  padding: 8px 12px;
  align-items: center;
  border-bottom: 1px solid var(--border-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.file-list-item:hover {
  background: var(--bg-tertiary);
}

.file-list-item.selected {
  background: rgba(88, 166, 255, 0.15);
}

/* Status Bar */
.explorer-statusbar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 6px 16px;
  background: var(--bg-secondary);
  border-top: 1px solid var(--border-primary);
  font-size: 11px;
  color: var(--text-secondary);
}

/* Context Menu */
.context-menu {
  position: fixed;
  min-width: 180px;
  background: var(--bg-secondary);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-lg);
  padding: 4px;
  z-index: 1000;
}

.context-menu-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: var(--radius-sm);
  font-size: 12px;
  color: var(--text-primary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.context-menu-item:hover {
  background: var(--bg-tertiary);
}

.context-menu-item.danger {
  color: var(--status-offline);
}

.context-menu-item.danger:hover {
  background: rgba(248, 81, 73, 0.1);
}

.context-menu-divider {
  height: 1px;
  background: var(--border-primary);
  margin: 4px 8px;
}

/* Upload Dropzone */
.upload-dropzone {
  position: relative;
  flex: 1;
  display: flex;
  flex-direction: column;
}

.upload-dropzone.active::after {
  content: 'Drop files to upload';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(88, 166, 255, 0.1);
  border: 2px dashed var(--accent-primary);
  border-radius: var(--radius-md);
  font-size: 16px;
  font-weight: 500;
  color: var(--accent-primary);
  z-index: 10;
}

/* Empty & Loading States */
.empty-folder,
.loading-overlay,
.error-message {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 200px;
  gap: 12px;
  color: var(--text-secondary);
}

.loading-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(13, 17, 23, 0.8);
}
```

---

## 4. Implementation TODOs

### 4.1 Desktop Viewer
- [ ] Create `DesktopViewer.tsx` main component with state management
- [ ] Build `Toolbar` component with device indicator, connection status, and stats
- [ ] Implement `DesktopCanvas` with WebGL rendering support
- [ ] Create `ControlBar` with quality slider, FPS selector, and action buttons
- [ ] Build `MonitorSelector` for multi-display support
- [ ] Implement `useDesktopStream` hook for WebSocket management
- [ ] Create `useInputCapture` hook with pointer lock and event batching
- [ ] Add `useFullscreen` hook for fullscreen API
- [ ] Style with CSS variables for dark/light theme support
- [ ] Add keyboard shortcuts (ESC to release, F11 fullscreen)
- [ ] Implement screenshot download functionality
- [ ] Add clipboard sync (bidirectional)
- [ ] Add connection state overlays (connecting, disconnected, error)
- [ ] Implement reconnection logic with exponential backoff

### 4.2 Terminal
- [ ] Create `TerminalPanel.tsx` with multi-session support
- [ ] Build `TabBar` component for session management
- [ ] Implement `Header` with shell indicator, path, and session timer
- [ ] Create `XTermWrapper` with WebGL addon support
- [ ] Build `Footer` with quick commands and file transfer buttons
- [ ] Define terminal themes (dark, light, retro, monokai, dracula)
- [ ] Implement `useTerminalSession` hook for session lifecycle
- [ ] Create `useTerminalSocket` hook for WebSocket communication
- [ ] Add Zmodem file transfer integration
- [ ] Implement session persistence on reconnect
- [ ] Add theme selector UI
- [ ] Implement font size adjustment
- [ ] Add copy/paste handling
- [ ] Implement search within terminal buffer

### 4.3 File Explorer
- [ ] Create `FileExplorer.tsx` main component
- [ ] Build `Toolbar` with navigation, breadcrumb, search, and view toggle
- [ ] Implement `FileGrid` view with selection support
- [ ] Create `FileList` view with sortable columns
- [ ] Build `FileIcon` component with type-based icons and colors
- [ ] Create `ContextMenu` with file operations
- [ ] Implement `UploadDropzone` for drag-and-drop
- [ ] Create `useFileSystem` hook for file operations
- [ ] Implement `useSelection` hook for multi-select (Ctrl/Shift)
- [ ] Add `useDragDrop` hook for drag-and-drop
- [ ] Build rename/delete/new folder dialogs
- [ ] Implement file preview (images, text, code)
- [ ] Add file download progress indicator
- [ ] Implement upload progress with cancel support
- [ ] Add keyboard navigation (arrows, Enter, Delete, Ctrl+A)
- [ ] Implement clipboard operations (Ctrl+C, Ctrl+X, Ctrl+V)

### 4.4 Shared Components
- [ ] Create base `IconButton` component
- [ ] Build `Tooltip` component
- [ ] Create `Spinner` loading component
- [ ] Build `Badge` component for status indicators
- [ ] Implement `Modal` base component
- [ ] Create `Slider` component for quality/volume
- [ ] Build `Select` dropdown component

### 4.5 Hooks & Utils
- [ ] Create `useWebSocket` base hook with reconnection
- [ ] Implement `useKeyboardShortcuts` hook
- [ ] Build `useLocalStorage` for preferences
- [ ] Create encryption utilities (AES, XOR)
- [ ] Build format utilities (size, date, time)

---

## 5. References

### Design Inspiration
- [VS Code](https://code.visualstudio.com/) - File explorer, terminal
- [GitHub](https://github.com/) - Dark theme, file browser
- [MeshCentral](https://meshcentral.com/) - Remote desktop controls
- [Hyper Terminal](https://hyper.is/) - Terminal design
- [iTerm2](https://iterm2.com/) - Terminal themes

### Technical Resources
- [XTerm.js](https://xtermjs.org/) - Terminal emulator
- [Framer Motion](https://www.framer.com/motion/) - Animations
- [Pointer Lock API](https://developer.mozilla.org/en-US/docs/Web/API/Pointer_Lock_API)
- [File System Access API](https://developer.mozilla.org/en-US/docs/Web/API/File_System_Access_API)
- [Drag and Drop API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Drag_and_Drop_API)
