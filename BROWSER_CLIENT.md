# Rocket Browser Client Architecture

## Overview

The browser client establishes a **binary WebSocket connection** to the Rocket server to receive desktop frames, control messages, and send input events. The protocol uses **ArrayBuffer** for efficient binary data handling and supports both **raw binary frames** (desktop video) and **encrypted JSON packets** (control messages).

---

## WebSocket Connection

### Connection Establishment

```javascript
// Browser WebSocket client (React/TypeScript)
class RocketWebSocket {
    constructor(deviceId, sessionToken) {
        this.deviceId = deviceId;
        this.sessionToken = sessionToken;
        this.secret = null; // Derived from session
        this.ws = null;
    }

    connect() {
        // Use binary mode for efficient frame handling
        const wsUrl = `wss://${window.location.host}/ws`;

        this.ws = new WebSocket(wsUrl);

        // CRITICAL: Set binaryType to 'arraybuffer' for binary protocol
        this.ws.binaryType = 'arraybuffer';

        this.ws.onopen = this.onOpen.bind(this);
        this.ws.onmessage = this.onMessage.bind(this);
        this.ws.onerror = this.onError.bind(this);
        this.ws.onclose = this.onClose.bind(this);
    }

    onOpen() {
        console.log('WebSocket connected');

        // Send authentication/subscription message
        this.send({
            act: 'DESKTOP_INIT',
            data: {
                desktop: this.deviceId,
                token: this.sessionToken
            }
        });
    }
}
```

**Binary Mode Configuration**:
```javascript
// ❌ WRONG: Default is 'blob' (async, less efficient)
ws.binaryType = 'blob'; // DON'T USE

// ✅ CORRECT: Use 'arraybuffer' (sync, efficient)
ws.binaryType = 'arraybuffer'; // USE THIS

// Difference:
// - 'blob': Async, requires FileReader, slower
// - 'arraybuffer': Sync, direct access, faster, preferred for real-time
```

---

## Binary Protocol Format

### Protocol Overview

The Rocket protocol supports **two message types**:

1. **Raw Binary Frames** (Desktop video): Direct frame data, no encryption
2. **Encrypted JSON Packets** (Control): JSON encrypted with session secret

**Message Structure**:
```
┌──────────────────────────────────────────────────────────────┐
│                     Message Format                            │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│  Option A: Raw Binary Frame (Desktop Video)                  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ [12 byte header][N bytes JPEG/WebP/VP8 data]          │  │
│  │                                                         │  │
│  │ Header:                                                 │  │
│  │ [0-3]:   Block X coordinate (uint32, little-endian)   │  │
│  │ [4-7]:   Block Y coordinate (uint32, little-endian)   │  │
│  │ [8-11]:  Data length (uint32, little-endian)          │  │
│  │ [12+]:   Compressed image data (JPEG/WebP/VP8)        │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                                │
│  Option B: Encrypted JSON Packet (Control)                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ [4 byte magic][4 byte opcode][N byte encrypted JSON]  │  │
│  │                                                         │  │
│  │ Magic:  0x7B, 0x22, 0x61, 0x63 (ASCII: '{"ac')        │  │
│  │ Opcode: Message type identifier                        │  │
│  │ Body:   XOR-encrypted JSON string                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### Distinguishing Message Types

```javascript
function parseMessage(arrayBuffer) {
    const data = new Uint8Array(arrayBuffer);

    // Check for encrypted JSON packet magic bytes
    // Magic: 0x7B22616B = '{"ac' (start of '{"act":')
    if (data.length >= 8 &&
        data[0] === 0x7B && // '{'
        data[1] === 0x22 && // '"'
        data[2] === 0x61 && // 'a'
        data[3] === 0x63) { // 'c'

        // Encrypted JSON packet
        return parseEncryptedJSON(arrayBuffer);
    } else if (data.length >= 12) {
        // Raw binary frame (desktop video)
        return parseDesktopFrame(arrayBuffer);
    } else {
        console.error('Invalid message: too short');
        return null;
    }
}
```

---

## Raw Binary Frame Parsing (Desktop Video)

### Frame Header Format

```javascript
// Desktop frame header (12 bytes)
// Used for incremental/block-based updates (VNC-style)
class DesktopFrameHeader {
    static SIZE = 12;

    constructor(arrayBuffer) {
        const view = new DataView(arrayBuffer);

        // Parse header (little-endian)
        this.x = view.getUint32(0, true);       // Block X coordinate
        this.y = view.getUint32(4, true);       // Block Y coordinate
        this.length = view.getUint32(8, true);  // Payload length

        // Payload is remainder of buffer
        this.payload = arrayBuffer.slice(12);
    }
}

function parseDesktopFrame(arrayBuffer) {
    if (arrayBuffer.byteLength < 12) {
        console.error('Frame too short');
        return null;
    }

    const header = new DesktopFrameHeader(arrayBuffer);

    // Validate coordinates
    if (header.x < 0 || header.x > 10000 ||
        header.y < 0 || header.y > 10000) {
        console.error('Invalid frame coordinates');
        return null;
    }

    // Validate length
    if (header.length !== header.payload.byteLength) {
        console.error('Length mismatch');
        return null;
    }

    return {
        type: 'desktop_frame',
        x: header.x,
        y: header.y,
        data: header.payload // ArrayBuffer of JPEG/WebP/VP8
    };
}
```

### Rendering Desktop Frames

```javascript
class DesktopRenderer {
    constructor(canvasElement) {
        this.canvas = canvasElement;
        this.ctx = this.canvas.getContext('2d');
    }

    renderFrame(frame) {
        // Convert ArrayBuffer to Blob
        const blob = new Blob([frame.data], { type: 'image/jpeg' });

        // Create object URL
        const url = URL.createObjectURL(blob);

        // Load image
        const img = new Image();
        img.onload = () => {
            // Draw at specified coordinates (block-based update)
            this.ctx.drawImage(img, frame.x, frame.y);

            // Clean up
            URL.revokeObjectURL(url);
        };
        img.src = url;
    }

    // Alternative: Full-screen update (no coordinates)
    renderFullFrame(arrayBuffer) {
        const blob = new Blob([arrayBuffer], { type: 'image/jpeg' });
        const url = URL.createObjectURL(blob);

        const img = new Image();
        img.onload = () => {
            // Scale to fit canvas
            this.ctx.drawImage(img, 0, 0, this.canvas.width, this.canvas.height);
            URL.revokeObjectURL(url);
        };
        img.src = url;
    }
}
```

---

## Encrypted JSON Packet Parsing

### Packet Format

```javascript
// Encrypted JSON packet structure
// [4 byte magic][4 byte opcode][N byte encrypted body]

class EncryptedPacket {
    static MAGIC_SIZE = 4;
    static OPCODE_SIZE = 4;
    static HEADER_SIZE = 8;

    constructor(arrayBuffer) {
        const view = new DataView(arrayBuffer);

        // Parse magic (should be '{"ac' = 0x7B22616B)
        this.magic = view.getUint32(0, true);

        // Parse opcode (message type identifier)
        this.opcode = view.getUint32(4, true);

        // Encrypted body starts at byte 8
        this.encryptedBody = new Uint8Array(arrayBuffer, 8);
    }

    isValid() {
        // Validate magic bytes
        return this.magic === 0x6361227B; // '{"ac' in little-endian
    }
}
```

### Opcodes

```javascript
// Message type opcodes (examples)
const Opcodes = {
    DESKTOP_INIT:    0x0001,  // Desktop session initialized
    DESKTOP_CLOSE:   0x0002,  // Desktop session closed
    TERMINAL_OUTPUT: 0x0010,  // Terminal output data
    FILE_LIST:       0x0020,  // File system listing
    WEBCAM_INIT:     0x0030,  // Webcam initialized
    AUDIO_INIT:      0x0040,  // Audio initialized
    SHARE_UPDATE:    0x0050,  // Share status update
    ERROR:           0xFFFF,  // Error message
};

function getMessageType(opcode) {
    for (const [name, code] of Object.entries(Opcodes)) {
        if (code === opcode) return name;
    }
    return 'UNKNOWN';
}
```

---

## Decryption (Session Secret)

### Stream Cipher (XOR) Decryption

```javascript
// Simple XOR stream cipher (matches server-side encryption)
// NOTE: This is for non-sensitive control data. TLS provides transport encryption.
class StreamCipher {
    constructor(secret) {
        // Convert secret string to byte array
        this.secret = new TextEncoder().encode(secret);
        this.secretLength = this.secret.length;
    }

    // Decrypt encrypted data (XOR operation)
    decrypt(encryptedData) {
        const decrypted = new Uint8Array(encryptedData.length);

        for (let i = 0; i < encryptedData.length; i++) {
            // XOR with secret (cycling through secret bytes)
            decrypted[i] = encryptedData[i] ^ this.secret[i % this.secretLength];
        }

        return decrypted;
    }

    // Encrypt data (same operation, XOR is symmetric)
    encrypt(plainData) {
        return this.decrypt(plainData); // XOR is symmetric
    }
}
```

### Full Decryption Flow

```javascript
function parseEncryptedJSON(arrayBuffer) {
    const packet = new EncryptedPacket(arrayBuffer);

    // Validate magic bytes
    if (!packet.isValid()) {
        console.error('Invalid magic bytes');
        return null;
    }

    // Get session secret (from authentication response)
    const secret = getSessionSecret();
    if (!secret) {
        console.error('No session secret available');
        return null;
    }

    // Decrypt body
    const cipher = new StreamCipher(secret);
    const decryptedBytes = cipher.decrypt(packet.encryptedBody);

    // Convert to string
    const jsonString = new TextDecoder().decode(decryptedBytes);

    // Parse JSON
    try {
        const message = JSON.parse(jsonString);

        // Add metadata
        message._opcode = packet.opcode;
        message._type = getMessageType(packet.opcode);

        return message;
    } catch (err) {
        console.error('JSON parse error:', err);
        return null;
    }
}
```

---

## Complete Message Handler

```javascript
class RocketWebSocket {
    constructor(deviceId, sessionToken, secret) {
        this.deviceId = deviceId;
        this.sessionToken = sessionToken;
        this.secret = secret;
        this.ws = null;
        this.renderer = null;
        this.cipher = new StreamCipher(secret);

        // Callbacks
        this.onDesktopFrame = null;
        this.onControlMessage = null;
    }

    connect() {
        const wsUrl = `wss://${window.location.host}/ws`;
        this.ws = new WebSocket(wsUrl);

        // CRITICAL: Binary mode
        this.ws.binaryType = 'arraybuffer';

        this.ws.onmessage = this.handleMessage.bind(this);
    }

    handleMessage(event) {
        const arrayBuffer = event.data;

        if (!(arrayBuffer instanceof ArrayBuffer)) {
            console.error('Expected ArrayBuffer, got:', typeof event.data);
            return;
        }

        // Parse message
        const message = this.parseMessage(arrayBuffer);
        if (!message) return;

        // Route to appropriate handler
        switch (message.type) {
            case 'desktop_frame':
                this.handleDesktopFrame(message);
                break;

            case 'control_message':
                this.handleControlMessage(message);
                break;

            default:
                console.warn('Unknown message type:', message.type);
        }
    }

    parseMessage(arrayBuffer) {
        const data = new Uint8Array(arrayBuffer);

        // Check for encrypted JSON (magic bytes: '{"ac')
        if (data.length >= 8 &&
            data[0] === 0x7B && data[1] === 0x22 &&
            data[2] === 0x61 && data[3] === 0x63) {

            // Encrypted control message
            const decrypted = this.parseEncryptedJSON(arrayBuffer);
            return decrypted ? { type: 'control_message', ...decrypted } : null;
        }

        // Otherwise, assume raw binary frame
        if (data.length >= 12) {
            return this.parseDesktopFrame(arrayBuffer);
        }

        console.error('Message too short or invalid');
        return null;
    }

    parseDesktopFrame(arrayBuffer) {
        const view = new DataView(arrayBuffer);

        return {
            type: 'desktop_frame',
            x: view.getUint32(0, true),
            y: view.getUint32(4, true),
            length: view.getUint32(8, true),
            data: arrayBuffer.slice(12)
        };
    }

    parseEncryptedJSON(arrayBuffer) {
        const view = new DataView(arrayBuffer);

        const opcode = view.getUint32(4, true);
        const encryptedBody = new Uint8Array(arrayBuffer, 8);

        // Decrypt
        const decryptedBytes = this.cipher.decrypt(encryptedBody);
        const jsonString = new TextDecoder().decode(decryptedBytes);

        try {
            const obj = JSON.parse(jsonString);
            obj._opcode = opcode;
            return obj;
        } catch (err) {
            console.error('JSON parse failed:', err);
            return null;
        }
    }

    handleDesktopFrame(frame) {
        if (this.onDesktopFrame) {
            this.onDesktopFrame(frame);
        }
    }

    handleControlMessage(message) {
        console.log('Control message:', message.act, message);

        if (this.onControlMessage) {
            this.onControlMessage(message);
        }
    }

    // Send JSON message (encrypted)
    send(packet) {
        const jsonString = JSON.stringify(packet);
        const plainBytes = new TextEncoder().encode(jsonString);

        // Encrypt
        const encryptedBytes = this.cipher.encrypt(plainBytes);

        // Build packet: [magic][opcode][encrypted body]
        const buffer = new ArrayBuffer(8 + encryptedBytes.length);
        const view = new DataView(buffer);

        // Magic: '{"ac' = 0x7B22616B
        view.setUint32(0, 0x6361227B, true);

        // Opcode (derive from packet.act)
        const opcode = this.getOpcodeForAction(packet.act);
        view.setUint32(4, opcode, true);

        // Encrypted body
        const bodyView = new Uint8Array(buffer, 8);
        bodyView.set(encryptedBytes);

        // Send
        this.ws.send(buffer);
    }

    getOpcodeForAction(action) {
        // Map action strings to opcodes
        const mapping = {
            'DESKTOP_INIT': 0x0001,
            'DESKTOP_INPUT': 0x0002,
            'DESKTOP_WEBRTC_OFFER': 0x0003,
            'DESKTOP_WEBRTC_ANSWER': 0x0004,
            'DESKTOP_WEBRTC_ICE': 0x0005,
            // ... more mappings
        };
        return mapping[action] || 0x0000;
    }
}
```

---

## Usage Example

```javascript
// React component example
class DesktopViewer extends React.Component {
    constructor(props) {
        super(props);
        this.canvasRef = React.createRef();
        this.ws = null;
        this.renderer = null;
    }

    componentDidMount() {
        // Initialize renderer
        this.renderer = new DesktopRenderer(this.canvasRef.current);

        // Connect WebSocket
        this.ws = new RocketWebSocket(
            this.props.deviceId,
            this.props.sessionToken,
            this.props.secret
        );

        // Set up handlers
        this.ws.onDesktopFrame = this.handleFrame.bind(this);
        this.ws.onControlMessage = this.handleControl.bind(this);

        // Connect
        this.ws.connect();
    }

    handleFrame(frame) {
        // Render desktop frame to canvas
        this.renderer.renderFrame(frame);

        // Update FPS counter
        this.updateFPS();
    }

    handleControl(message) {
        switch (message.act) {
            case 'DESKTOP_INIT':
                console.log('Desktop initialized:', message.data);
                this.setState({ connected: true });
                break;

            case 'DESKTOP_CLOSE':
                console.log('Desktop closed');
                this.setState({ connected: false });
                break;

            case 'ERROR':
                console.error('Server error:', message.msg);
                break;

            default:
                console.log('Control message:', message);
        }
    }

    sendInput(event) {
        // Send input to device
        this.ws.send({
            act: 'DESKTOP_INPUT',
            data: {
                desktop: this.props.deviceId,
                events: [{
                    type: event.type,
                    x: event.clientX,
                    y: event.clientY,
                    button: event.button
                }]
            }
        });
    }

    render() {
        return (
            <div className="desktop-viewer">
                <canvas
                    ref={this.canvasRef}
                    width={1920}
                    height={1080}
                    onMouseDown={this.sendInput.bind(this)}
                    onMouseMove={this.sendInput.bind(this)}
                    onMouseUp={this.sendInput.bind(this)}
                />
            </div>
        );
    }

    componentWillUnmount() {
        if (this.ws) {
            this.ws.close();
        }
    }
}
```

---

## Performance Optimizations

### 1. ArrayBuffer Reuse (Pool)

```javascript
class ArrayBufferPool {
    constructor(bufferSize = 1024 * 1024) {
        this.bufferSize = bufferSize;
        this.pool = [];
        this.maxPoolSize = 10;
    }

    acquire() {
        if (this.pool.length > 0) {
            return this.pool.pop();
        }
        return new ArrayBuffer(this.bufferSize);
    }

    release(buffer) {
        if (this.pool.length < this.maxPoolSize) {
            this.pool.push(buffer);
        }
    }
}
```

### 2. Offscreen Canvas (Web Workers)

```javascript
// Main thread
const worker = new Worker('decoder-worker.js');
const offscreen = canvas.transferControlToOffscreen();
worker.postMessage({ canvas: offscreen }, [offscreen]);

// Worker receives frames and decodes
worker.onmessage = (e) => {
    const { arrayBuffer } = e.data;
    // Decode and render in worker
};

// decoder-worker.js
self.onmessage = async (e) => {
    const { canvas, arrayBuffer } = e.data;
    const ctx = canvas.getContext('2d');

    // Decode image
    const blob = new Blob([arrayBuffer], { type: 'image/jpeg' });
    const bitmap = await createImageBitmap(blob);

    // Draw to offscreen canvas
    ctx.drawImage(bitmap, 0, 0);
};
```

### 3. Frame Skipping (Drop if Behind)

```javascript
class AdaptiveRenderer {
    constructor(canvas) {
        this.canvas = canvas;
        this.ctx = canvas.getContext('2d');
        this.frameQueue = [];
        this.rendering = false;
    }

    queueFrame(frame) {
        // If queue is too long, drop oldest frames
        if (this.frameQueue.length > 3) {
            console.warn('Dropping frame (queue full)');
            this.frameQueue.shift();
        }

        this.frameQueue.push(frame);

        if (!this.rendering) {
            this.renderLoop();
        }
    }

    async renderLoop() {
        this.rendering = true;

        while (this.frameQueue.length > 0) {
            const frame = this.frameQueue.shift();
            await this.renderFrame(frame);
        }

        this.rendering = false;
    }
}
```

---

## Security Considerations

### 1. Secret Management

```javascript
// ❌ DON'T: Store secret in localStorage (XSS vulnerable)
localStorage.setItem('secret', secret);

// ✅ DO: Store in memory only (per-session)
class SecureSession {
    constructor() {
        this.secret = null; // In-memory only
    }

    setSecret(secret) {
        this.secret = secret;
    }

    getSecret() {
        return this.secret;
    }

    destroy() {
        this.secret = null; // Clear on logout
    }
}
```

### 2. Origin Validation

```javascript
// Validate WebSocket URL origin
function getWebSocketURL() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;

    // ONLY connect to same origin
    return `${protocol}//${host}/ws`;
}

// ❌ DON'T: Allow arbitrary WebSocket URLs
const ws = new WebSocket(userInput); // NEVER DO THIS
```

### 3. Frame Size Validation

```javascript
function parseDesktopFrame(arrayBuffer) {
    const header = new DesktopFrameHeader(arrayBuffer);

    // Validate frame size (prevent memory exhaustion)
    const MAX_FRAME_SIZE = 10 * 1024 * 1024; // 10 MB
    if (header.length > MAX_FRAME_SIZE) {
        console.error('Frame too large:', header.length);
        return null;
    }

    // Validate coordinates (prevent out-of-bounds)
    const MAX_COORD = 10000;
    if (header.x > MAX_COORD || header.y > MAX_COORD) {
        console.error('Invalid coordinates');
        return null;
    }

    return header;
}
```

---

## Error Handling

```javascript
class RocketWebSocket {
    connect() {
        this.ws = new WebSocket(wsUrl);
        this.ws.binaryType = 'arraybuffer';

        // Reconnection logic
        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.scheduleReconnect();
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket closed:', event.code, event.reason);

            if (!event.wasClean) {
                // Abnormal closure, attempt reconnect
                this.scheduleReconnect();
            }
        };
    }

    scheduleReconnect() {
        if (this.reconnectTimer) return;

        const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
        console.log(`Reconnecting in ${delay}ms...`);

        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.reconnectAttempts++;
            this.connect();
        }, delay);
    }
}
```

---

## Summary

The Rocket browser client:

✅ **Uses ArrayBuffer** for efficient binary data handling
✅ **Parses magic bytes** to distinguish message types
✅ **Decrypts JSON** with XOR stream cipher
✅ **Renders frames** to Canvas with optimal performance
✅ **Handles opcodes** for message routing
✅ **Validates inputs** to prevent attacks
✅ **Manages secrets** securely in memory
✅ **Reconnects** automatically on failure

**Protocol Benefits**:
- Binary mode: 30-50% faster than text mode
- Zero-copy rendering: Direct ArrayBuffer to Canvas
- Encrypted control: Sensitive data protected (+ TLS)
- Incremental updates: Block-based frame rendering
