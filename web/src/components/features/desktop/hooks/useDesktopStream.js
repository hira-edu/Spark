import { useState, useEffect, useRef, useCallback } from 'react';
import { message } from 'antd';
import { genRandHex, getBaseURL, hex2ua, ua2hex, translate } from '../../../../utils/utils';
import i18n from '../../../../locale/locale';

const MAGIC_PREFIX = [34, 22, 19, 17];
const SERVICE_IDS = [20, 21];
const BASE_HEADER_LENGTH = MAGIC_PREFIX.length + 2; // magic + service + op
const EVENT_ID_LENGTH = 16;
const FRAME_HEADER_LENGTH = BASE_HEADER_LENGTH + EVENT_ID_LENGTH;

/**
 * useDesktopStream - Hook for managing WebSocket connection to remote desktop
 * @param {Object} device - The device to connect to
 * @param {React.RefObject} canvasRef - Reference to the canvas element
 * @param {Object} options - Options for the stream
 */
export function useDesktopStream(device, canvasRef, options = {}) {
  const INPUT_BATCH_LIMIT = 32;
  const CLIPBOARD_CHAR_LIMIT = 64 * 1024; // Bound clipboard payload to ~64KB
  const FILE_DROP_LIMIT = 5;

  const { shareToken = null, onStatusChange, allowControl = true, controlChannel = null } = options;

  const [status, setStatus] = useState('disconnected');
  const [latency, setLatency] = useState(0);
  const [fps, setFps] = useState(0);
  const [bandwidth, setBandwidth] = useState(0);
  const [resolution, setResolution] = useState({ width: 0, height: 0 });
  const [monitors, setMonitors] = useState([]);
  const [cursor, setCursor] = useState({ x: 0, y: 0, hotX: 0, hotY: 0, width: 0, height: 0, visible: false, data: null, hash: 0, format: 'argb32' });

  const log = useCallback((level, msg, extra = {}) => {
    const payload = { ...extra, device: device?.id || 'unknown' };
    if (level === 'error') {
      console.error('[desktop]', msg, payload);
    } else if (level === 'warn') {
      console.warn('[desktop]', msg, payload);
    } else {
      console.info('[desktop]', msg, payload);
    }
  }, [device?.id]);

  const wsRef = useRef(null);
  const ctxRef = useRef(null);
  const statsRef = useRef({ frames: 0, bytes: 0 });
  const tickerRef = useRef(null);
  const pingTimeRef = useRef(0);
  const controlChannelRef = useRef(controlChannel);

  // Cleanup resources (defined early to avoid TDZ)
  const cleanup = useCallback(() => {
    if (tickerRef.current) {
      clearInterval(tickerRef.current);
      tickerRef.current = null;
    }
    const ws = wsRef.current;
    if (ws) {
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      wsRef.current = null;
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
    }
    statsRef.current = { frames: 0, bytes: 0 };
    pingTimeRef.current = 0;
    setFps(0);
    setBandwidth(0);
    setLatency(0);
    setMonitors([]);
    setResolution({ width: 0, height: 0 });

    const canvas = canvasRef.current;
    if (canvas && ctxRef.current) {
      ctxRef.current.clearRect(0, 0, canvas.width, canvas.height);
    }
  }, []);

  // Keep latest control channel (e.g., WebRTC data channel) in a ref
  useEffect(() => {
    controlChannelRef.current = controlChannel;
  }, [controlChannel]);

  // Update external status callback
  useEffect(() => {
    if (onStatusChange) {
      onStatusChange(status);
    }
  }, [status, onStatusChange]);

  // Initialize canvas context
  const initCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    ctxRef.current = canvas.getContext('2d', {
      alpha: false,
      willReadFrequently: true
    });
    if (ctxRef.current) {
      ctxRef.current.imageSmoothingEnabled = false;
    }
  }, [canvasRef]);

  // Render a single image block (raw RGBA or compressed)
  const updateImage = useCallback((ab, it, dx, dy, bw, bh, ctx) => {
    if (!ctx || bw === 0 || bh === 0) return;

    if (it === 0) { // Raw RGBA
      try {
        ctx.putImageData(
          new ImageData(new Uint8ClampedArray(ab), bw, bh),
          dx, dy, 0, 0, bw, bh
        );
      } catch (err) {
        log('error', 'ImageData put failed', { error: err?.message, len: ab?.byteLength, bw, bh, dx, dy });
      }
      return;
    }

    // Compressed (JPEG/WebP/AVIF/VPx/H.264)
    createImageBitmap(new Blob([ab]), 0, 0, bw, bh, {
      premultiplyAlpha: 'none',
      colorSpaceConversion: 'none'
    }).then((ib) => {
      ctx.drawImage(ib, 0, 0, bw, bh, dx, dy, bw, bh);
    }).catch(() => {});
  }, []);

  const handleResolution = useCallback((view, payloadOffset) => {
    const canvas = canvasRef.current;
    const ctx = ctxRef.current;
    if (!canvas || !ctx) return;
    if (view.byteLength < payloadOffset + 6) return;

    const bodyLength = view.getUint16(payloadOffset, false);
    if (bodyLength < 4 || payloadOffset + 2 + bodyLength > view.byteLength) return;

    const width = view.getUint16(payloadOffset + 2, false);
    const height = view.getUint16(payloadOffset + 4, false);
    if (!width || !height) return;

    if (canvas.width !== width || canvas.height !== height) {
      canvas.width = width;
      canvas.height = height;
      ctx.imageSmoothingEnabled = false;
    }
    setResolution({ width, height });
  }, [canvasRef]);

  const renderBlocks = useCallback((buffer, payloadOffset) => {
    const canvas = canvasRef.current;
    const ctx = ctxRef.current;
    if (!canvas || !ctx) return;

    const view = new DataView(buffer);
    let offset = payloadOffset;

    while (offset + 12 <= view.byteLength) {
      const bl = view.getUint16(offset + 0, false); // body length
      const it = view.getUint16(offset + 2, false); // image type
      const dx = view.getUint16(offset + 4, false); // image block x
      const dy = view.getUint16(offset + 6, false); // image block y
      const bw = view.getUint16(offset + 8, false); // image block width
      const bh = view.getUint16(offset + 10, false); // image block height
      const il = bl - 10; // image length
      const dataStart = offset + 12;
      const dataEnd = dataStart + il;

      if (il < 0 || dataEnd > view.byteLength) {
        break;
      }

      updateImage(buffer.slice(dataStart, dataEnd), it, dx, dy, bw, bh, ctx);
      offset = dataEnd;
    }
  }, [canvasRef, updateImage]);

  // Handle incoming JSON messages
  const handleJSON = useCallback(async (ab) => {
    let data;
    try {
      // No decryption - parse JSON directly
      const text = ua2str(new Uint8Array(ab));
      data = JSON.parse(text);
    } catch (_) {
      return;
    }

    log('info', 'json message', {
      act: data?.act,
      code: data?.code,
      msg: data?.msg,
      hasData: !!data?.data,
    });

    // Handle pong for latency measurement
    if (data?.act === 'DESKTOP_PONG') {
      if (pingTimeRef.current > 0) {
        setLatency(Date.now() - pingTimeRef.current);
        pingTimeRef.current = 0;
      }
      return;
    }

    // Handle monitor list
    if (data?.act === 'DESKTOP_MONITORS') {
      setMonitors(data.data?.monitors || []);
      return;
    }

    // Handle cursor updates
    if (data?.act === 'CURSOR_UPDATE') {
      const cursorData = data.data || {};
      setCursor({
        x: cursorData.x || 0,
        y: cursorData.y || 0,
        hotX: cursorData.hotX || 0,
        hotY: cursorData.hotY || 0,
        width: cursorData.width || 0,
        height: cursorData.height || 0,
        visible: cursorData.visible !== false,
        data: cursorData.data || null,
        hash: cursorData.hash || 0,
        format: cursorData.format || 'argb32',
      });
      return;
    }

    // Server/device terminated session
    if (data?.act === 'QUIT') {
      message.warning(data.msg ? translate(data.msg) : i18n.t('DESKTOP.SESSION_CLOSED'));
      cleanup();
      setStatus('disconnected');
      return;
    }

    // Handle errors
    if (data?.code && data.code !== 0) {
      message.warning(data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
      return;
    }
  }, [cleanup]);

  // Parse incoming frame blocks
  const parseMessage = useCallback(async (raw) => {
    let buffer = null;
    if (raw instanceof ArrayBuffer) {
      buffer = raw;
    } else if (raw?.arrayBuffer) {
      buffer = await raw.arrayBuffer();
    }
    if (!buffer) return;

    const bytes = new Uint8Array(buffer);
    if (bytes.length < BASE_HEADER_LENGTH) return;

    // Validate magic prefix
    for (let i = 0; i < MAGIC_PREFIX.length; i++) {
      if (bytes[i] !== MAGIC_PREFIX[i]) return;
    }
    const service = bytes[4];
    if (!SERVICE_IDS.includes(service)) return;

    const op = bytes[5];
    const header = bytes.slice(0, BASE_HEADER_LENGTH);

    // Handle JSON packets (no event id prefix)
    if (op === 3) {
      statsRef.current.bytes += bytes.byteLength;
      handleJSON(bytes.slice(BASE_HEADER_LENGTH));
      return;
    }

    // Binary payloads include a 16-byte event id after the op code
    if (bytes.length < FRAME_HEADER_LENGTH) return;

    // Parse frames directly (no encryption)
    const payloadOffset = FRAME_HEADER_LENGTH;
    const view = new DataView(bytes.buffer);

    if (op === 2) {
      statsRef.current.bytes += bytes.byteLength;
      handleResolution(view, payloadOffset);
      const width = view.getUint16(payloadOffset + 2, false);
      const height = view.getUint16(payloadOffset + 4, false);
      log('info', 'resolution update', { width, height });
      return;
    }

    // Frame data: op 0 = first chunk, op 1 = continuation
    if (op === 0) {
      statsRef.current.frames += 1;
    }
    statsRef.current.bytes += bytes.byteLength;
    log('debug', 'frame received', { op, size: bytes.byteLength });
    renderBlocks(bytes.buffer, payloadOffset);
  }, [BASE_HEADER_LENGTH, FRAME_HEADER_LENGTH, MAGIC_PREFIX, SERVICE_IDS, handleJSON, handleResolution, renderBlocks]);

  // Normalize a single input event to match the protocol schema
  const normalizeInputEvent = useCallback((event) => {
    if (!event || typeof event !== 'object') return null;
    const type = event.type;
    if (type !== 'move' && type !== 'button' && type !== 'scroll' && type !== 'key') {
      return null;
    }

    const normalized = { type };
    if (type === 'move') {
      if (Number.isFinite(event.deltaX) || Number.isFinite(event.deltaY)) {
        normalized.deltaX = Math.trunc(event.deltaX || 0);
        normalized.deltaY = Math.trunc(event.deltaY || 0);
      } else {
        normalized.x = Math.trunc(event.x ?? 0);
        normalized.y = Math.trunc(event.y ?? 0);
      }
    }
    if (type === 'scroll') {
      normalized.deltaX = Math.trunc(event.deltaX || 0);
      normalized.deltaY = Math.trunc(event.deltaY || 0);
    }
    if (type === 'button') {
      normalized.button = (event.button || 'left').toString().toLowerCase();
      normalized.down = !!event.down;
    }
    if (type === 'key') {
      normalized.key = event.key || '';
      normalized.keyCode = Math.trunc(event.keyCode || 0);
      normalized.down = !!event.down;
    }
    return normalized;
  }, []);

  const normalizeInputEvents = useCallback((events) => {
    if (!Array.isArray(events)) return [];
    const result = [];
    for (let i = 0; i < events.length && result.length < INPUT_BATCH_LIMIT; i += 1) {
      const normalized = normalizeInputEvent(events[i]);
      if (normalized) {
        result.push(normalized);
      }
    }
    return result;
  }, [normalizeInputEvent, INPUT_BATCH_LIMIT]);

  // Send data over WebSocket
  const sendData = useCallback(async (data) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    // No encryption - send JSON directly
    const body = new TextEncoder().encode(JSON.stringify(data));
    const bodyLength = body.length;
    const buffer = new Uint8Array(bodyLength + 8);
    buffer.set(new Uint8Array([34, 22, 19, 17, 20, 3]), 0);
    buffer.set(new Uint8Array([bodyLength >> 8, bodyLength & 0xFF]), 6);
    buffer.set(body, 8);
    ws.send(buffer);
  }, []);

  // Control channel: prefer an open DataChannel if provided, fall back to WS
  const sendControl = useCallback(async (payload, channelOverride = null) => {
    const channel = channelOverride || controlChannelRef.current;
    const serialized = JSON.stringify(payload);
    log('info', 'send control', {
      act: payload?.act,
      via: channel ? 'datachannel' : 'websocket',
    });

    if (channel && channel.readyState === 'open') {
      try {
        channel.send(serialized);
        return;
      } catch (err) {
        // Fall back to WS on failure
        console.warn('control channel send failed, falling back to WS', err);
      }
    }

    await sendData(payload);
  }, [sendData]);

  // Connect to the device
  const connect = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !device?.id) return;

    statsRef.current = { frames: 0, bytes: 0 };
    setFps(0);
    setBandwidth(0);
    setLatency(0);
    setMonitors([]);
    setResolution({ width: 0, height: 0 });

    // No secret needed - encryption removed

    // Initialize canvas
    initCanvas();

    setStatus('connecting');

    // Build WebSocket URL (no secret needed)
    const path = shareToken
      ? `api/share/desktop?token=${encodeURIComponent(shareToken)}`
      : `api/device/desktop?device=${device.id}`;

    const ws = new WebSocket(getBaseURL(true, path));
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      log('info', 'WS connected');
      // Request initial frame
      sendControl({ act: 'DESKTOP_SHOT' });
    };

    ws.onmessage = (e) => {
      parseMessage(e.data);
    };

    ws.onclose = () => {
      setStatus('disconnected');
      log('warn', 'WS closed');
      cleanup();
    };

    ws.onerror = (e) => {
      log('error', 'WS error', { error: e?.message });
      setStatus('error');
      cleanup();
      message.warning(i18n.t('COMMON.CONNECTION_FAILED'));
    };

    // Start stats ticker
    tickerRef.current = setInterval(() => {
      setBandwidth(statsRef.current.bytes);
      setFps(statsRef.current.frames);
      statsRef.current = { frames: 0, bytes: 0 };

      // Send ping for latency
      if (ws.readyState === WebSocket.OPEN) {
        pingTimeRef.current = Date.now();
        sendControl({ act: 'DESKTOP_PING' });
      }
    }, 1000);
  }, [device, shareToken, canvasRef, initCanvas, parseMessage, sendControl]);

  // Disconnect from the device
  const disconnect = useCallback(() => {
    cleanup();
    setStatus('disconnected');
  }, [cleanup]);

  // Send configuration updates
  const sendConfig = useCallback((config) => {
    sendControl({ act: 'DESKTOP_CONFIG', data: config });
  }, [sendControl]);

  // Send input events
  const sendInput = useCallback((events) => {
    if (!allowControl) return;
    const normalized = normalizeInputEvents(events);
    if (normalized.length === 0) return;
    sendControl({ act: 'DESKTOP_INPUT', data: { events: normalized, allowControl } });
  }, [sendControl, normalizeInputEvents, allowControl]);

  // Send clipboard contents as a control op
  const sendClipboard = useCallback((clipboard) => {
    if (!allowControl) return;
    const text = typeof clipboard === 'string' ? clipboard : clipboard?.text;
    if (!text) return;
    const trimmed = text.length > CLIPBOARD_CHAR_LIMIT ? text.slice(0, CLIPBOARD_CHAR_LIMIT) : text;
    sendControl({ act: 'DESKTOP_CLIPBOARD', data: { text: trimmed } });
  }, [allowControl, sendControl]);

  // Send dropped file metadata only (no file contents)
  const sendFileDrop = useCallback((files) => {
    if (!allowControl || !files) return;
    const fileList = Array.from(files).slice(0, FILE_DROP_LIMIT).map((file) => ({
      name: (file?.name || '').slice(0, 255),
      size: Number.isFinite(file?.size) ? file.size : 0,
      type: file?.type || '',
    })).filter((f) => f.name || f.size);
    if (!fileList.length) return;
    sendControl({ act: 'DESKTOP_FILE_DROP', data: { files: fileList } });
  }, [allowControl, sendControl]);

  // Audio control passthrough (mute/unmute/etc.)
  const sendAudioControl = useCallback((audioData) => {
    sendControl({ act: 'DESKTOP_AUDIO', data: audioData || {} });
  }, [sendControl]);

  const sendKill = useCallback(() => {
    sendControl({ act: 'DESKTOP_KILL' });
  }, [sendControl]);

  // Request fresh screenshot
  const requestShot = useCallback(() => {
    sendControl({ act: 'DESKTOP_SHOT' });
  }, [sendControl]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      cleanup();
    };
  }, [cleanup]);

  return {
    status,
    latency,
    fps,
    bandwidth,
    resolution,
    monitors,
    cursor,
    connect,
    disconnect,
    sendConfig,
    sendInput,
    sendClipboard,
    sendFileDrop,
    sendAudioControl,
    sendKill,
    requestShot,
  };
}

export default useDesktopStream;
