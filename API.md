# API Document

---

## Common

Only `POST` requests are allowed.

### Authenticate

For every request, you should have `Authorization` on its header.
<br />
Authorization header is a string like `Basic <token>`(basic auth).

```
Authorization: Basic <base64('username:password')>
```
Example:
```
Authorization: Basic WFpCOjEyNDg=
```

After basic authentication, server will assign you an `Authorization` cookie.
<br />
You can use this token cookie to authenticate rest of your requests.

---

## Response

All responses are JSON encoded.

| code | meaning                   |
|------|---------------------------|
| -1   | invalid or missing params |
| 0    | success                   |
| 1    | failure and msg are given |

```
{
    "code": -1,
    "msg": "${i18n|COMMON.INVALID_PARAMETER}"
}
```
```
{
    "code": 0,
    "data": {
        ...
    }
}
```
```
{
    "code": 1,
    "msg": "${i18n|COMMON.DEVICE_NOT_EXIST}"
}
```

---

### List devices: `/device/list`

Parameters: **None**

The `id` of device is persistent, its length always equals 64.
<br />
It's unique for every device and won't change.
<br />
You're recommend to recognize your device by device ID.
<br />
The key of the device object is its connection UUID, it's random and temporary.

```
{
    "code": 0,
    "data": {
        "1de601ca-7738-4b77-a081-57d3fc9c4482": {
            "id": "1a23e7660cde01285ca241d5f5d3cf2c5bc39e02c1df7a30b58fbde2938b0375",
            "os": "windows",
            "arch": "amd64",
            "lan": "192.168.1.1",
            "wan": "1.1.1.1",
            "mac": "00:00:00:00:00:00",
            "net": {
                "sent": 0,
                "recv": 60
            },
            "cpu": {
                "model": "Intel(R) Core(TM) i5-9300H CPU @ 2.40GHz",
                "usage": 8.658854166666668,
                "cores": {
                    "logical": 8,
                    "physical": 4
                }
            },
            "ram": {
                "total": 8432967680,
                "used": 5109829632,
                "usage": 60.593492420452385
            },
            "disk": {
                "total": 1373932810240,
                "used": 185675567104,
                "usage": 13.51416646579435
            },
            "uptime": 1015,
            "latency": 10,
            "hostname": "LOCALHOST",
            "username": "EXAMPLE"
        }
    }
}
```
---

### Basic operations: `/device/:act`

Parameters: `:act` and `device` (device ID)

The `:act` could be `lock`, `logoff`, `hibernate`, `suspend`, `restart`, `shutdown` and `offline`.

For example, when you call `/device/restart`, your device will restart.

```
{
    "code": 0
}
```

---

### Execute command: `/device/exec`

Parameters: `cmd`, `args` and `device` (device ID)

Example:
```http request
POST http://localhost:8000/api/device/exec HTTP/1.1
Host: localhost:8000
Content-Length: 116
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47
Origin: http://localhost:8000
Referer: http://localhost:8000/

cmd=taskkill&args=%2Ff%20%2Fim%20regedit.exe&device=bc7e49f8f794f80ffb0032a4ba516c86d76041bf2023e1be6c5dda3b1ee0cf4c
```

```
{
    "code": 0
}
```

---

### Take screenshot: `/device/screenshot/get`

Parameters: `device` (device ID)

If screenshot is captured successfully, it gives you the image directly.
<br />
If failed, then the following response are given.

```
{
    "code": 1,
    "msg": "${i18n|DESKTOP.NO_DISPLAY_FOUND}"
}
```

---

### Get files: `/device/file/get`

Parameters: `files` (array of files) and `device` (device ID)

If files exist and are accessible, then the archive file or file itself is given directly.
<br />
If unable to read files, then the following response are given.
<br />
A zip file is given if multiple files (including directory) are given.

```
{
    "code": 1,
    "msg": "${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}"
}
```

---

### Delete files: `/device/file/remove`

Parameters: `files` (array of files) and `device` (device ID)

If files exist and are deleted successfully, then `code` will be `0`.

```
{
    "code": 0
}
```
```
{
    "code": 1,
    "msg": "${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}"
}
```

---

### Upload file: `/device/file/upload`

**Query Parameters**: `file` (file name), `path` and `device` (device ID)

File itself should be sent in the request **body**.
<br />
**Anything** represented in the request **body** will be saved to the device.
<br />
If same file exists, then it will be **overwritten**.

Example:
```http request
POST http://localhost:8000/api/device/file/upload?path=D%3A%5C&file=Test.txt&device=bc7e49f8f794f80ffb0032a4ba516c86d76041bf2023e1be6c5dda3b1ee0cf4c HTTP/1.1
Host: localhost:8000
Content-Length: 12
Content-Type: application/octet-stream
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47
Origin: http://localhost:8000
Referer: http://localhost:8000/

Hello World.
```

If file uploaded successfully, then `code` will be `0`.
<br />
And `D:\Test.txt` will be created with the content of `Hello World.`.

```
{
    "code": 0
}
```
```
{
    "code": 1,
    "msg": "${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}"
}
```

---

### List files: `/device/file/list`

Parameters: `path` (folder to be listed) and `device` (device ID)

If `path` is empty, then it gives you volumes list (windows) or gives files on `/`.

`type` `0` means file, `1` means folder and `2` means volume (windows).

```
{
    "code": 0,
    "data": {
        "files": [
            {
                "name": "home",
                "size": 4096,
                "time": 1629627926,
                "type": 1
            },
            {
                "name": "Rocket",
                "size": 8192,
                "time": 1629627926,
                "type": 0
            }
        ]
    }
}
```
```
{
    "code": 1,
    "msg": "${i18n|EXPLORER.FILE_OR_DIR_NOT_EXIST}"
}
```

---

### List processes: `/device/process/list`

Parameters: `device` (device ID)

```
{
    "code": 0,
    "data": {
        "processes": [
            {
                "name": "[System Process]",
                "pid": 0
            },
            {
                "name": "System",
                "pid": 4
            },
            {
                "name": "Registry",
                "pid": 124
            },
            {
                "name": "smss.exe",
                "pid": 392
            },
            {
                "name": "winlogon.exe",
                "pid": 456
            }
        ]
    }
}
```
---

### Kill a process: `/device/process/kill`

Parameters: `pid` and `device` (device ID)

```
{
    "code": 0
}
```
```
{
    "code": 1,
    "msg": "${i18n|COMMON.DEVICE_NOT_EXIST}"
}
```

---

## Desktop Remote Control

The desktop remote control feature allows real-time screen viewing and input control of remote devices.

### Desktop WebSocket: `/device/desktop`

**Query Parameters**: `device` (device ID) and `secret` (32-character hex string)

This is a WebSocket endpoint for real-time desktop streaming. The connection uses a binary protocol for efficiency.

#### Connection Example
```javascript
const secret = crypto.getRandomValues(new Uint8Array(16));
const secretHex = Array.from(secret).map(b => b.toString(16).padStart(2, '0')).join('');
const ws = new WebSocket(`wss://your-server/api/device/desktop?device=${deviceId}&secret=${secretHex}`);
ws.binaryType = 'arraybuffer';
```

#### Binary Protocol

All messages use a binary format with a 5-byte magic header: `[34, 22, 19, 17, 20]`

**Op Codes (6th byte):**
| Code | Direction | Description |
|------|-----------|-------------|
| 0x00 | Server→Client | First part of a frame |
| 0x01 | Server→Client | Rest parts of a frame |
| 0x02 | Server→Client | Resolution information |
| 0x03 | Both | JSON data (encrypted) |

**Sending Messages:**
```javascript
function sendData(data) {
    const json = JSON.stringify(data);
    const encrypted = encrypt(json, secret); // XOR encryption
    const buffer = new Uint8Array(encrypted.length + 8);
    buffer.set([34, 22, 19, 17, 20, 3], 0);
    buffer.set([encrypted.length >> 8, encrypted.length & 0xFF], 6);
    buffer.set(encrypted, 8);
    ws.send(buffer);
}
```

#### Desktop Actions

**Ping (keep-alive):**
```json
{"act": "DESKTOP_PING"}
```

**Request full frame refresh:**
```json
{"act": "DESKTOP_SHOT"}
```

**Kill desktop session:**
```json
{"act": "DESKTOP_KILL"}
```

**Send input events:**
```json
{
    "act": "DESKTOP_INPUT",
    "data": {
        "events": [
            {"type": "move", "x": 100, "y": 200},
            {"type": "button", "button": "left", "down": true},
            {"type": "button", "button": "left", "down": false},
            {"type": "scroll", "deltaX": 0, "deltaY": -120},
            {"type": "key", "key": "a", "keyCode": 65, "down": true}
        ]
    }
}
```

**Input Event Types:**
| Type | Fields | Description |
|------|--------|-------------|
| move | x, y | Absolute mouse position |
| move | deltaX, deltaY | Relative mouse movement (pointer lock) |
| button | button, down | Mouse button (left/middle/right) |
| scroll | deltaX, deltaY | Mouse wheel scroll |
| key | key, keyCode, down | Keyboard input |

---

### WebRTC Desktop: `/device/webrtc/config`

**Query Parameters**: `device` (device ID)

Get WebRTC ICE server configuration for the device.

```
{
    "code": 0,
    "data": {
        "ice": {
            "stun": ["stun:stun.l.google.com:19302"],
            "turn": []
        }
    }
}
```

#### WebRTC Signaling

WebRTC signaling messages are sent through the desktop WebSocket connection.

**Send WebRTC Offer:**
```json
{
    "act": "DESKTOP_WEBRTC_OFFER",
    "data": {
        "sdp": "v=0\r\no=...",
        "type": "offer"
    }
}
```

**Receive WebRTC Answer:**
```json
{
    "act": "DESKTOP_WEBRTC_ANSWER",
    "data": {
        "sdp": "v=0\r\no=...",
        "type": "answer"
    }
}
```

**Exchange ICE Candidates:**
```json
{
    "act": "DESKTOP_WEBRTC_ICE",
    "data": {
        "candidate": "candidate:...",
        "sdpMid": "0",
        "mLine": 0
    }
}
```

#### WebRTC Features

- **Video Track**: VP8 or VP9 encoded screen capture
- **Data Channel**: `desktop-input` for low-latency input transmission
- **ICE Restart**: Automatic reconnection on network changes

#### Environment Variables (Client)

| Variable | Description |
|----------|-------------|
| `SPARK_WEBRTC_ICE` | Custom ICE servers (format: `url\|user\|pass`) |
| `SPARK_WEBRTC_STUN` | STUN server URLs (comma-separated) |
| `SPARK_WEBRTC_TURN` | TURN server URLs (comma-separated) |
| `SPARK_WEBRTC_TURN_USERNAME` | TURN username |
| `SPARK_WEBRTC_TURN_PASSWORD` | TURN password |
| `SPARK_WEBRTC_CODEC` | Video codec (`vp8` or `vp9`, default: `vp8`) |

---

## Desktop Sharing (Guest Access)

Share desktop sessions with external users without requiring authentication.

### Create Share: `/share/create` (POST, Auth Required)

Create a shareable link for a desktop session.

**Parameters:**
| Field | Type | Description |
|-------|------|-------------|
| device | string | Device ID (required) |
| desktop | string | Desktop session ID (optional) |
| ttlSeconds | int | Time-to-live in seconds (default: 3600, max: 86400) |
| singleUse | bool | Token can only be used once (default: false) |
| viewOnly | bool | Guest can only view, not control (default: false) |
| turnOnly | bool | Filter ICE config to TURN-only for guests (default: false) |

**Response:**
```json
{
    "code": 0,
    "data": {
        "share": {
            "id": "share-uuid",
            "device": "device-id",
            "token": "guest-access-token",
            "expiresAt": "2024-01-01T12:00:00Z",
            "singleUse": false,
            "viewOnly": true,
            "turnOnly": false,
            "createdAt": "2024-01-01T11:00:00Z"
        }
    }
}
```

---

### List Shares: `/share/list` (GET, Auth Required)

List all active shares.

```json
{
    "code": 0,
    "data": {
        "shares": [...]
    }
}
```

---

### Get Share: `/share/:id` (GET, Auth Required)

Get details of a specific share.

---

### Get Share Token: `/share/:id/token` (GET, Auth Required)

Get the token for a share (for sharing with guests).

```json
{
    "code": 0,
    "data": {
        "token": "guest-access-token",
        "expiresAt": "2024-01-01T12:00:00Z",
        "singleUse": false,
        "used": false
    }
}
```

---

### Get Share Access Log: `/share/:id/access-log` (GET, Auth Required)

View access attempts for a share.

```json
{
    "code": 0,
    "data": {
        "accessLog": [
            {
                "timestamp": "2024-01-01T11:30:00Z",
                "ip": "192.168.1.100",
                "userAgent": "Mozilla/5.0...",
                "success": true,
                "reason": ""
            }
        ]
    }
}
```

---

### Revoke Share: `/share/revoke` (POST, Auth Required)

Revoke a share and disconnect any active guest sessions.

**Parameters:** `id` (share ID)

---

### Validate Token: `/share/validate` (GET, Public)

Validate a guest access token.

**Query Parameters:** `token`

```json
{
    "code": 0,
    "data": {
        "share": {
            "id": "share-uuid",
            "device": "device-id",
            "expiresAt": "2024-01-01T12:00:00Z",
            "viewOnly": true
        }
    }
}
```

---

### Guest ICE Config: `/share/ice` (GET, Public)

Get ICE server configuration for guest WebRTC connections.

**Query Parameters:** `token`

If the share has `turnOnly: true`, STUN servers will be excluded.

```json
{
    "code": 0,
    "data": {
        "ice": {
            "stun": ["stun:stun.l.google.com:19302"],
            "turn": []
        }
    }
}
```

---

### Guest Desktop WebSocket: `/share/desktop` (Public)

WebSocket endpoint for guest desktop access.

**Query Parameters:**
- `token` - Guest access token
- `secret` - 32-character hex string for encryption

Guest connections:
- Use the same binary protocol as authenticated desktop connections
- View-only shares will reject `DESKTOP_INPUT` messages with error code
- Share is auto-revoked when the device disconnects
- Single-use tokens are marked as used on first connection
