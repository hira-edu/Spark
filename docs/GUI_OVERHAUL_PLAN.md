# Spark GUI Complete Overhaul Plan

A comprehensive plan to modernize the Spark web interface with best-in-class UX patterns inspired by MeshCentral, TeamViewer, Datto RMM, and modern SaaS dashboards.

---

## Current State Analysis

### Existing Stack
- **React**: 17.0.2 (outdated)
- **UI Framework**: Ant Design 4.x with Pro Components
- **Bundler**: Webpack 5
- **Styling**: Less + inline styles
- **State Management**: Local component state (useState)
- **Routing**: React Router 6

### Current Issues
1. **Outdated Dependencies**: React 17, Ant Design 4.x
2. **No Dark Mode**: Single light theme only
3. **Poor Mobile Experience**: Not responsive
4. **Cluttered Dashboard**: Too many columns, hard to scan
5. **Modal-Heavy UX**: Everything opens in modals
6. **No Real-time Feedback**: Polling-based updates
7. **Limited Customization**: No user preferences
8. **Basic Accessibility**: Missing ARIA labels, keyboard nav

---

## Target Architecture

### New Stack
```
React 18.x          → Concurrent features, Suspense
Ant Design 5.x      → CSS-in-JS, better theming
Vite                → Faster builds, HMR
Zustand/Jotai       → Lightweight state management
TanStack Query      → Server state, caching
Tailwind CSS        → Utility-first styling
Framer Motion       → Animations
```

### Design Principles
1. **Device-Centric**: Devices as first-class citizens
2. **Real-time First**: WebSocket for live updates
3. **Dark Mode Default**: Modern dark theme with light option
4. **Keyboard Accessible**: Full keyboard navigation
5. **Mobile Responsive**: Works on tablets and phones
6. **Performance**: Sub-second interactions

---

## Phase 1: Foundation & Core Layout

### 1.1 Project Setup Migration

**New Directory Structure:**
```
web/
├── src/
│   ├── app/                    # App entry, providers
│   │   ├── App.tsx
│   │   ├── providers.tsx       # Theme, Query, Router
│   │   └── routes.tsx
│   ├── components/
│   │   ├── ui/                 # Base UI components
│   │   │   ├── Button/
│   │   │   ├── Card/
│   │   │   ├── Modal/
│   │   │   ├── Table/
│   │   │   └── index.ts
│   │   ├── layout/             # Layout components
│   │   │   ├── Sidebar/
│   │   │   ├── Header/
│   │   │   ├── MainContent/
│   │   │   └── StatusBar/
│   │   └── features/           # Feature components
│   │       ├── devices/
│   │       ├── desktop/
│   │       ├── terminal/
│   │       ├── explorer/
│   │       └── settings/
│   ├── hooks/                  # Custom hooks
│   │   ├── useDevices.ts
│   │   ├── useWebSocket.ts
│   │   ├── useTheme.ts
│   │   └── useKeyboard.ts
│   ├── stores/                 # State management
│   │   ├── deviceStore.ts
│   │   ├── uiStore.ts
│   │   └── settingsStore.ts
│   ├── services/               # API & WebSocket
│   │   ├── api.ts
│   │   ├── websocket.ts
│   │   └── encryption.ts
│   ├── styles/                 # Global styles
│   │   ├── themes/
│   │   │   ├── dark.ts
│   │   │   └── light.ts
│   │   └── globals.css
│   ├── types/                  # TypeScript types
│   │   ├── device.ts
│   │   ├── api.ts
│   │   └── index.ts
│   └── utils/                  # Utilities
│       ├── format.ts
│       ├── crypto.ts
│       └── helpers.ts
├── public/
├── index.html
├── vite.config.ts
├── tailwind.config.js
├── tsconfig.json
└── package.json
```

### 1.2 New Package Dependencies

```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "antd": "^5.12.0",
    "@ant-design/icons": "^5.2.6",
    "@tanstack/react-query": "^5.0.0",
    "zustand": "^4.4.0",
    "react-router-dom": "^6.20.0",
    "framer-motion": "^10.16.0",
    "xterm": "^5.3.0",
    "xterm-addon-fit": "^0.8.0",
    "xterm-addon-webgl": "^0.16.0",
    "dayjs": "^1.11.10",
    "lodash-es": "^4.17.21",
    "i18next": "^23.7.0",
    "react-i18next": "^13.5.0"
  },
  "devDependencies": {
    "vite": "^5.0.0",
    "@vitejs/plugin-react": "^4.2.0",
    "typescript": "^5.3.0",
    "tailwindcss": "^3.3.0",
    "autoprefixer": "^10.4.0",
    "postcss": "^8.4.0",
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0"
  }
}
```

### 1.3 Core Layout Design

```
┌─────────────────────────────────────────────────────────────────────┐
│  HEADER                                                    [👤][⚙️] │
│  ┌──────┐  Spark    [🔍 Search devices...]         Dark Mode Toggle │
│  │ Logo │                                                           │
├──┴──────┴───────────────────────────────────────────────────────────┤
│         │                                                           │
│  SIDE   │  MAIN CONTENT AREA                                        │
│  BAR    │                                                           │
│         │  ┌─────────────────────────────────────────────────────┐  │
│ ┌─────┐ │  │  DEVICE GRID / LIST VIEW                            │  │
│ │ 📊  │ │  │                                                     │  │
│ │Dash │ │  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │  │
│ └─────┘ │  │  │Device 1│ │Device 2│ │Device 3│ │Device 4│       │  │
│ ┌─────┐ │  │  │🟢 Online│ │🟢 Online│ │🔴 Offline│ │🟡 Busy │       │  │
│ │ 💻  │ │  │  │Win 11  │ │Ubuntu  │ │MacOS   │ │Win 10  │       │  │
│ │Devs │ │  │  │CPU: 45%│ │CPU: 12%│ │        │ │CPU: 89%│       │  │
│ └─────┘ │  │  └────────┘ └────────┘ └────────┘ └────────┘       │  │
│ ┌─────┐ │  │                                                     │  │
│ │ 📁  │ │  └─────────────────────────────────────────────────────┘  │
│ │Files│ │                                                           │
│ └─────┘ │  ┌─────────────────────────────────────────────────────┐  │
│ ┌─────┐ │  │  QUICK ACTIONS PANEL                                │  │
│ │ ⚙️  │ │  │  [Generate Client] [Bulk Actions] [Reports]         │  │
│ │Sett │ │  └─────────────────────────────────────────────────────┘  │
│ └─────┘ │                                                           │
│         │                                                           │
├─────────┴───────────────────────────────────────────────────────────┤
│  STATUS BAR    Connected: 4/6 │ Server: Online │ v1.0.0            │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 2: Device Management UI

### 2.1 Device Card Component

Replace table with modern card-based grid:

```tsx
// components/features/devices/DeviceCard.tsx
interface DeviceCardProps {
  device: Device;
  onAction: (action: string) => void;
}

const DeviceCard: React.FC<DeviceCardProps> = ({ device, onAction }) => {
  return (
    <motion.div
      className="device-card"
      whileHover={{ scale: 1.02 }}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
    >
      {/* Status Indicator */}
      <div className="absolute top-3 right-3">
        <StatusBadge status={device.status} />
      </div>

      {/* OS Icon */}
      <div className="device-icon">
        <OSIcon os={device.os} />
      </div>

      {/* Device Info */}
      <div className="device-info">
        <h3 className="device-name">{device.hostname}</h3>
        <span className="device-user">{device.username}</span>
        <span className="device-ip">{device.lan}</span>
      </div>

      {/* Stats Mini Graph */}
      <div className="device-stats">
        <MiniGraph label="CPU" value={device.cpu.usage} />
        <MiniGraph label="RAM" value={device.ram.usage} />
        <MiniGraph label="Disk" value={device.disk.usage} />
      </div>

      {/* Quick Actions */}
      <div className="device-actions">
        <IconButton icon={<TerminalIcon />} onClick={() => onAction('terminal')} />
        <IconButton icon={<FolderIcon />} onClick={() => onAction('explorer')} />
        <IconButton icon={<DesktopIcon />} onClick={() => onAction('desktop')} />
        <IconButton icon={<MoreIcon />} onClick={() => onAction('menu')} />
      </div>
    </motion.div>
  );
};
```

### 2.2 Device List View (Alternative)

```tsx
// components/features/devices/DeviceList.tsx
const DeviceList: React.FC = () => {
  return (
    <div className="device-list">
      <div className="list-header">
        <div className="col-status">Status</div>
        <div className="col-name">Device</div>
        <div className="col-user">User</div>
        <div className="col-os">OS</div>
        <div className="col-cpu">CPU</div>
        <div className="col-ram">RAM</div>
        <div className="col-network">Network</div>
        <div className="col-actions">Actions</div>
      </div>
      {devices.map(device => (
        <DeviceRow key={device.id} device={device} />
      ))}
    </div>
  );
};
```

### 2.3 View Toggle

```tsx
// Toggle between Grid and List views
const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

<ViewToggle value={viewMode} onChange={setViewMode}>
  <ViewToggle.Option value="grid" icon={<GridIcon />} />
  <ViewToggle.Option value="list" icon={<ListIcon />} />
</ViewToggle>
```

---

## Phase 3: Dark Theme & Design System

### 3.1 Color Palette

```typescript
// styles/themes/dark.ts
export const darkTheme = {
  colors: {
    // Base
    background: {
      primary: '#0d1117',      // Main background
      secondary: '#161b22',    // Cards, panels
      tertiary: '#21262d',     // Elevated elements
      hover: '#30363d',        // Hover states
    },
    text: {
      primary: '#f0f6fc',      // Main text
      secondary: '#8b949e',    // Muted text
      tertiary: '#6e7681',     // Disabled text
    },
    border: {
      primary: '#30363d',
      secondary: '#21262d',
    },
    // Status Colors
    status: {
      online: '#3fb950',       // Green
      offline: '#f85149',      // Red
      busy: '#d29922',         // Yellow
      away: '#8b949e',         // Gray
    },
    // Accent
    accent: {
      primary: '#58a6ff',      // Blue
      secondary: '#388bfd',
      success: '#3fb950',
      warning: '#d29922',
      error: '#f85149',
    },
  },
  shadows: {
    sm: '0 1px 2px rgba(0,0,0,0.4)',
    md: '0 4px 8px rgba(0,0,0,0.4)',
    lg: '0 8px 24px rgba(0,0,0,0.4)',
  },
  radius: {
    sm: '4px',
    md: '8px',
    lg: '12px',
    xl: '16px',
  },
};

// styles/themes/light.ts
export const lightTheme = {
  colors: {
    background: {
      primary: '#ffffff',
      secondary: '#f6f8fa',
      tertiary: '#eaeef2',
      hover: '#d8dee4',
    },
    text: {
      primary: '#1f2328',
      secondary: '#656d76',
      tertiary: '#8c959f',
    },
    // ... rest similar structure
  },
};
```

### 3.2 CSS Variables Integration

```css
/* styles/globals.css */
:root {
  /* Auto-detect system preference */
  color-scheme: dark light;
}

[data-theme='dark'] {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-tertiary: #21262d;
  --text-primary: #f0f6fc;
  --text-secondary: #8b949e;
  --border-primary: #30363d;
  --accent-primary: #58a6ff;
  --status-online: #3fb950;
  --status-offline: #f85149;
}

[data-theme='light'] {
  --bg-primary: #ffffff;
  --bg-secondary: #f6f8fa;
  --bg-tertiary: #eaeef2;
  --text-primary: #1f2328;
  --text-secondary: #656d76;
  --border-primary: #d0d7de;
  --accent-primary: #0969da;
  --status-online: #1a7f37;
  --status-offline: #cf222e;
}

body {
  background: var(--bg-primary);
  color: var(--text-primary);
}
```

---

## Phase 4: Remote Desktop Panel

### 4.1 Desktop Viewer Redesign

Replace modal with full panel/tab:

```tsx
// components/features/desktop/DesktopViewer.tsx
const DesktopViewer: React.FC<Props> = ({ device }) => {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [quality, setQuality] = useState(70);
  const [fps, setFps] = useState(30);

  return (
    <div className={`desktop-viewer ${isFullscreen ? 'fullscreen' : ''}`}>
      {/* Toolbar */}
      <div className="desktop-toolbar">
        <div className="toolbar-left">
          <DeviceIndicator device={device} />
          <ConnectionStatus status={status} latency={latency} />
        </div>

        <div className="toolbar-center">
          <StatDisplay label="FPS" value={currentFps} />
          <StatDisplay label="Bandwidth" value={bandwidth} />
          <StatDisplay label="Resolution" value={resolution} />
        </div>

        <div className="toolbar-right">
          <QualitySlider value={quality} onChange={setQuality} />
          <FPSSelector value={fps} onChange={setFps} />
          <Tooltip title="Screenshot">
            <IconButton icon={<CameraIcon />} onClick={takeScreenshot} />
          </Tooltip>
          <Tooltip title="Clipboard Sync">
            <IconButton icon={<ClipboardIcon />} onClick={syncClipboard} />
          </Tooltip>
          <Tooltip title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}>
            <IconButton
              icon={isFullscreen ? <ExitFullscreenIcon /> : <FullscreenIcon />}
              onClick={toggleFullscreen}
            />
          </Tooltip>
        </div>
      </div>

      {/* Canvas Container */}
      <div className="canvas-container" ref={containerRef}>
        <canvas
          ref={canvasRef}
          className="desktop-canvas"
          tabIndex={0}
        />

        {/* Input Overlay */}
        {inputEnabled && (
          <div className="input-overlay">
            <Badge>Input Active - Press ESC to release</Badge>
          </div>
        )}
      </div>

      {/* Status Bar */}
      <div className="desktop-statusbar">
        <span>Keyboard: {keyboardEnabled ? 'ON' : 'OFF'}</span>
        <span>Mouse: {mouseEnabled ? 'ON' : 'OFF'}</span>
        <span>Encryption: AES-256</span>
      </div>
    </div>
  );
};
```

### 4.2 Multi-Monitor Support UI

```tsx
// Monitor selector for multi-display
<MonitorSelector>
  {monitors.map((monitor, idx) => (
    <MonitorOption
      key={idx}
      monitor={monitor}
      selected={selectedMonitor === idx}
      onClick={() => selectMonitor(idx)}
    >
      <MonitorPreview src={monitor.thumbnail} />
      <span>Display {idx + 1}</span>
      <span>{monitor.width}x{monitor.height}</span>
    </MonitorOption>
  ))}
</MonitorSelector>
```

---

## Phase 5: Terminal Redesign

### 5.1 Modern Terminal Component

```tsx
// components/features/terminal/TerminalPanel.tsx
const TerminalPanel: React.FC<Props> = ({ device }) => {
  return (
    <div className="terminal-panel">
      {/* Terminal Tabs */}
      <div className="terminal-tabs">
        <Tab active>Session 1</Tab>
        <Tab>Session 2</Tab>
        <AddTabButton onClick={newSession} />
      </div>

      {/* Terminal Header */}
      <div className="terminal-header">
        <div className="header-left">
          <ShellIndicator shell={currentShell} />
          <span className="cwd">{currentDirectory}</span>
        </div>
        <div className="header-right">
          <ConnectionIndicator status={status} />
          <SessionTimer start={sessionStart} />
          <IconButton icon={<SettingsIcon />} onClick={openSettings} />
        </div>
      </div>

      {/* XTerm Container */}
      <div className="terminal-container" ref={termRef}>
        {/* XTerm renders here */}
      </div>

      {/* Terminal Footer */}
      <div className="terminal-footer">
        <div className="quick-commands">
          <QuickButton cmd="ls -la">ls</QuickButton>
          <QuickButton cmd="pwd">pwd</QuickButton>
          <QuickButton cmd="clear">clear</QuickButton>
        </div>
        <div className="transfer-buttons">
          <Button icon={<UploadIcon />}>Upload</Button>
          <Button icon={<DownloadIcon />}>Download</Button>
        </div>
      </div>
    </div>
  );
};
```

### 5.2 Terminal Themes

```typescript
// Terminal color schemes
const terminalThemes = {
  dark: {
    background: '#0d1117',
    foreground: '#c9d1d9',
    cursor: '#58a6ff',
    cursorAccent: '#0d1117',
    selection: 'rgba(88, 166, 255, 0.3)',
    black: '#484f58',
    red: '#ff7b72',
    green: '#3fb950',
    yellow: '#d29922',
    blue: '#58a6ff',
    magenta: '#bc8cff',
    cyan: '#39c5cf',
    white: '#b1bac4',
  },
  light: {
    background: '#ffffff',
    foreground: '#24292f',
    cursor: '#0969da',
    // ...
  },
  retro: {
    background: '#0a0a0a',
    foreground: '#00ff00',
    cursor: '#00ff00',
    // Classic green terminal
  },
};
```

---

## Phase 6: File Explorer Redesign

### 6.1 Modern File Browser

```tsx
// components/features/explorer/FileExplorer.tsx
const FileExplorer: React.FC<Props> = ({ device }) => {
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('list');
  const [selectedFiles, setSelectedFiles] = useState<string[]>([]);

  return (
    <div className="file-explorer">
      {/* Toolbar */}
      <div className="explorer-toolbar">
        <div className="nav-buttons">
          <IconButton icon={<BackIcon />} onClick={goBack} disabled={!canGoBack} />
          <IconButton icon={<ForwardIcon />} onClick={goForward} disabled={!canGoForward} />
          <IconButton icon={<UpIcon />} onClick={goUp} disabled={isRoot} />
          <IconButton icon={<RefreshIcon />} onClick={refresh} />
        </div>

        {/* Breadcrumb Path */}
        <Breadcrumb className="path-breadcrumb">
          {pathParts.map((part, idx) => (
            <Breadcrumb.Item key={idx} onClick={() => navigateTo(idx)}>
              {idx === 0 ? <HomeIcon /> : part}
            </Breadcrumb.Item>
          ))}
        </Breadcrumb>

        {/* Search */}
        <SearchInput
          placeholder="Search files..."
          value={searchTerm}
          onChange={setSearchTerm}
        />

        {/* View Toggle */}
        <ViewToggle value={viewMode} onChange={setViewMode} />

        {/* Actions */}
        <div className="toolbar-actions">
          <Button icon={<UploadIcon />}>Upload</Button>
          <Button icon={<NewFolderIcon />}>New Folder</Button>
        </div>
      </div>

      {/* File Grid/List */}
      <div className={`file-container ${viewMode}`}>
        {viewMode === 'grid' ? (
          <FileGrid files={files} selected={selectedFiles} onSelect={setSelectedFiles} />
        ) : (
          <FileList files={files} selected={selectedFiles} onSelect={setSelectedFiles} />
        )}
      </div>

      {/* Status Bar */}
      <div className="explorer-statusbar">
        <span>{files.length} items</span>
        {selectedFiles.length > 0 && (
          <span>{selectedFiles.length} selected</span>
        )}
        <span>Free: {formatSize(freeSpace)}</span>
      </div>

      {/* Context Menu */}
      <ContextMenu ref={contextMenuRef}>
        <MenuItem icon={<OpenIcon />}>Open</MenuItem>
        <MenuItem icon={<EditIcon />}>Edit</MenuItem>
        <MenuItem icon={<DownloadIcon />}>Download</MenuItem>
        <MenuDivider />
        <MenuItem icon={<CopyIcon />}>Copy</MenuItem>
        <MenuItem icon={<CutIcon />}>Cut</MenuItem>
        <MenuItem icon={<PasteIcon />}>Paste</MenuItem>
        <MenuDivider />
        <MenuItem icon={<RenameIcon />}>Rename</MenuItem>
        <MenuItem icon={<DeleteIcon />} danger>Delete</MenuItem>
      </ContextMenu>
    </div>
  );
};
```

### 6.2 File Icons by Type

```tsx
// utils/fileIcons.ts
const fileIcons: Record<string, React.ComponentType> = {
  folder: FolderIcon,
  // Documents
  pdf: PdfIcon,
  doc: WordIcon,
  docx: WordIcon,
  xls: ExcelIcon,
  xlsx: ExcelIcon,
  ppt: PowerPointIcon,
  // Code
  js: JavaScriptIcon,
  ts: TypeScriptIcon,
  py: PythonIcon,
  go: GoIcon,
  rs: RustIcon,
  // Media
  jpg: ImageIcon,
  png: ImageIcon,
  gif: ImageIcon,
  mp4: VideoIcon,
  mp3: AudioIcon,
  // Archives
  zip: ArchiveIcon,
  tar: ArchiveIcon,
  gz: ArchiveIcon,
  // Default
  default: FileIcon,
};

export const getFileIcon = (filename: string): React.ComponentType => {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  return fileIcons[ext] || fileIcons.default;
};
```

---

## Phase 7: Settings & Preferences

### 7.1 Settings Panel

```tsx
// components/features/settings/SettingsPanel.tsx
const SettingsPanel: React.FC = () => {
  return (
    <div className="settings-panel">
      <SettingsNav>
        <SettingsNavItem icon={<PaletteIcon />} active>Appearance</SettingsNavItem>
        <SettingsNavItem icon={<KeyboardIcon />}>Shortcuts</SettingsNavItem>
        <SettingsNavItem icon={<BellIcon />}>Notifications</SettingsNavItem>
        <SettingsNavItem icon={<ShieldIcon />}>Security</SettingsNavItem>
        <SettingsNavItem icon={<ServerIcon />}>Server</SettingsNavItem>
        <SettingsNavItem icon={<InfoIcon />}>About</SettingsNavItem>
      </SettingsNav>

      <SettingsContent>
        {/* Appearance Settings */}
        <SettingsSection title="Theme">
          <ThemeSelector>
            <ThemeOption value="dark" label="Dark" preview={darkPreview} />
            <ThemeOption value="light" label="Light" preview={lightPreview} />
            <ThemeOption value="system" label="System" preview={systemPreview} />
          </ThemeSelector>
        </SettingsSection>

        <SettingsSection title="Accent Color">
          <ColorPicker value={accentColor} onChange={setAccentColor} />
        </SettingsSection>

        <SettingsSection title="Language">
          <LanguageSelector value={language} onChange={setLanguage} />
        </SettingsSection>

        <SettingsSection title="Desktop Viewer">
          <SettingsRow label="Default Quality">
            <Slider min={30} max={100} value={defaultQuality} onChange={setDefaultQuality} />
          </SettingsRow>
          <SettingsRow label="Default FPS">
            <Select value={defaultFps} onChange={setDefaultFps}>
              <Option value={15}>15 FPS</Option>
              <Option value={30}>30 FPS</Option>
              <Option value={60}>60 FPS</Option>
            </Select>
          </SettingsRow>
        </SettingsSection>

        <SettingsSection title="Terminal">
          <SettingsRow label="Font Size">
            <NumberInput min={10} max={24} value={termFontSize} onChange={setTermFontSize} />
          </SettingsRow>
          <SettingsRow label="Color Scheme">
            <TerminalThemeSelector value={termTheme} onChange={setTermTheme} />
          </SettingsRow>
        </SettingsSection>
      </SettingsContent>
    </div>
  );
};
```

---

## Phase 8: Real-time & WebSocket

### 8.1 WebSocket Manager

```typescript
// services/websocket.ts
class WebSocketManager {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private listeners = new Map<string, Set<Function>>();

  connect(url: string) {
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      this.reconnectAttempts = 0;
      this.emit('connected');
    };

    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.emit(data.type, data.payload);
    };

    this.ws.onclose = () => {
      this.emit('disconnected');
      this.reconnect();
    };
  }

  on(event: string, callback: Function) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }

  emit(event: string, data?: any) {
    this.listeners.get(event)?.forEach(cb => cb(data));
  }

  send(type: string, payload: any) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }));
    }
  }

  private reconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      setTimeout(() => this.connect(this.url), 1000 * this.reconnectAttempts);
    }
  }
}

export const wsManager = new WebSocketManager();
```

### 8.2 Real-time Device Updates

```typescript
// hooks/useDevices.ts
export const useDevices = () => {
  const [devices, setDevices] = useState<Device[]>([]);

  useEffect(() => {
    // Initial fetch
    api.getDevices().then(setDevices);

    // Real-time updates
    wsManager.on('device:update', (device: Device) => {
      setDevices(prev => prev.map(d => d.id === device.id ? device : d));
    });

    wsManager.on('device:online', (device: Device) => {
      setDevices(prev => [...prev, device]);
    });

    wsManager.on('device:offline', (deviceId: string) => {
      setDevices(prev => prev.filter(d => d.id !== deviceId));
    });
  }, []);

  return devices;
};
```

---

## Phase 9: Responsive Design

### 9.1 Breakpoints

```css
/* Tailwind breakpoints */
@media (min-width: 640px) { /* sm */ }
@media (min-width: 768px) { /* md */ }
@media (min-width: 1024px) { /* lg */ }
@media (min-width: 1280px) { /* xl */ }
@media (min-width: 1536px) { /* 2xl */ }
```

### 9.2 Mobile Layout

```
┌─────────────────────────┐
│  ☰  Spark     [🔍] [👤] │  <- Collapsible header
├─────────────────────────┤
│                         │
│  ┌───────────────────┐  │
│  │  Device Card      │  │  <- Stack cards vertically
│  │  🟢 DESKTOP-001   │  │
│  │  Windows 11       │  │
│  │  CPU: ███░░ 65%   │  │
│  │  [Term] [Files]   │  │
│  └───────────────────┘  │
│                         │
│  ┌───────────────────┐  │
│  │  Device Card      │  │
│  │  ...              │  │
│  └───────────────────┘  │
│                         │
├─────────────────────────┤
│  [📊] [💻] [📁] [⚙️]   │  <- Bottom navigation
└─────────────────────────┘
```

---

## Implementation TODOs

### Phase 1: Foundation (Week 1-2)
- [ ] Set up Vite + React 18 + TypeScript
- [ ] Configure Tailwind CSS
- [ ] Create theme system (dark/light)
- [ ] Build base UI components (Button, Card, Modal, etc.)
- [ ] Set up Zustand stores
- [ ] Configure TanStack Query
- [ ] Implement core layout (Sidebar, Header, Content)

### Phase 2: Device Management (Week 3-4)
- [ ] Build DeviceCard component
- [ ] Build DeviceList component
- [ ] Implement view toggle (grid/list)
- [ ] Add device filtering and search
- [ ] Implement device status indicators
- [ ] Add device quick actions
- [ ] Build device detail panel

### Phase 3: Remote Features (Week 5-6)
- [ ] Redesign Desktop Viewer
- [ ] Add desktop toolbar and controls
- [ ] Implement quality/FPS selectors
- [ ] Redesign Terminal component
- [ ] Add terminal tabs support
- [ ] Build terminal themes
- [ ] Redesign File Explorer
- [ ] Add file grid view
- [ ] Implement drag & drop upload

### Phase 4: Polish (Week 7-8)
- [ ] Build Settings panel
- [ ] Add keyboard shortcuts
- [ ] Implement responsive breakpoints
- [ ] Add loading states and skeletons
- [ ] Add error boundaries
- [ ] Implement toast notifications
- [ ] Add animations with Framer Motion
- [ ] Performance optimization
- [ ] Accessibility audit (ARIA, keyboard nav)
- [ ] Cross-browser testing

### Phase 5: Advanced (Future)
- [ ] PWA support
- [ ] Offline mode
- [ ] Push notifications
- [ ] Multi-language support
- [ ] User preferences sync
- [ ] Dashboard customization
- [ ] Report generation
- [ ] Bulk operations UI

---

## References

### Design Inspiration
- [MeshCentral](https://meshcentral.com/) - Open source remote management
- [TeamViewer](https://www.teamviewer.com/) - Enterprise remote desktop
- [Datto RMM](https://www.datto.com/products/rmm) - Modern RMM dashboard
- [GitHub](https://github.com/) - Dark theme, layout patterns
- [Linear](https://linear.app/) - Modern SaaS UI patterns

### Technical Resources
- [Ant Design 5.x](https://ant.design/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Framer Motion](https://www.framer.com/motion/)
- [TanStack Query](https://tanstack.com/query)
- [Zustand](https://github.com/pmndrs/zustand)
- [Vite](https://vitejs.dev/)
