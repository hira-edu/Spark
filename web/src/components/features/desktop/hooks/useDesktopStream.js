import { useState, useEffect, useRef, useCallback } from 'react';
import { message } from 'antd';
import { encrypt, decrypt, genRandHex, getBaseURL, hex2ua, ua2hex, translate } from '../../../../utils/utils';
import i18n from '../../../../locale/locale';

/**
 * useDesktopStream - Hook for managing WebSocket connection to remote desktop
 * @param {Object} device - The device to connect to
 * @param {React.RefObject} canvasRef - Reference to the canvas element
 * @param {Object} options - Options for the stream
 */
export function useDesktopStream(device, canvasRef, options = {}) {
  const { shareToken = null, onStatusChange, allowControl = true } = options;

  const [status, setStatus] = useState('disconnected');
  const [latency, setLatency] = useState(0);
  const [fps, setFps] = useState(0);
  const [bandwidth, setBandwidth] = useState(0);
  const [resolution, setResolution] = useState({ width: 0, height: 0 });
  const [monitors, setMonitors] = useState([]);

  const wsRef = useRef(null);
  const ctxRef = useRef(null);
  const secretRef = useRef(null);
  const statsRef = useRef({ frames: 0, bytes: 0 });
  const tickerRef = useRef(null);
  const pingTimeRef = useRef(0);

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

    ctxRef.current = canvas.getContext('2d', { alpha: false });
    if (ctxRef.current) {
      ctxRef.current.imageSmoothingEnabled = false;
    }
  }, [canvasRef]);

  // Parse incoming frame blocks
  const parseBlocks = useCallback((ab) => {
    const canvas = canvasRef.current;
    const ctx = ctxRef.current;
    if (!canvas || !ctx) return;

    ab = ab.slice(5);
    const dv = new DataView(ab);
    const op = dv.getUint8(0);

    // Handle JSON messages
    if (op === 3) {
      handleJSON(ab.slice(1));
      return;
    }

    // Handle resolution update
    if (op === 2) {
      const width = dv.getUint16(3, false);
      const height = dv.getUint16(5, false);
      if (width === 0 || height === 0) return;
      canvas.width = width;
      canvas.height = height;
      setResolution({ width, height });
      return;
    }

    // Count frames
    if (op === 0) statsRef.current.frames++;
    statsRef.current.bytes += ab.byteLength;

    // Parse and render image blocks
    let offset = 1;
    while (offset < ab.byteLength) {
      const bl = dv.getUint16(offset + 0, false); // body length
      const it = dv.getUint16(offset + 2, false); // image type
      const dx = dv.getUint16(offset + 4, false); // image block x
      const dy = dv.getUint16(offset + 6, false); // image block y
      const bw = dv.getUint16(offset + 8, false); // image block width
      const bh = dv.getUint16(offset + 10, false); // image block height
      const il = bl - 10; // image length
      offset += 12;

      updateImage(ab.slice(offset, offset + il), it, dx, dy, bw, bh, ctx);
      offset += il;
    }
  }, [canvasRef]);

  // Update image block on canvas
  const updateImage = useCallback((ab, it, dx, dy, bw, bh, ctx) => {
    switch (it) {
      case 0: // Raw RGBA
        ctx.putImageData(
          new ImageData(new Uint8ClampedArray(ab), bw, bh),
          dx, dy, 0, 0, bw, bh
        );
        break;
      case 1: // JPEG/WebP
        createImageBitmap(new Blob([ab]), 0, 0, bw, bh, {
          premultiplyAlpha: 'none',
          colorSpaceConversion: 'none'
        }).then((ib) => {
          ctx.drawImage(ib, 0, 0, bw, bh, dx, dy, bw, bh);
        });
        break;
      default:
        break;
    }
  }, []);

  // Handle incoming JSON messages
  const handleJSON = useCallback(async (ab) => {
    const secret = secretRef.current;
    if (!secret) return;

    let data;
    try {
      const decrypted = await decrypt(ab, secret);
      data = JSON.parse(decrypted);
    } catch (_) {
      return;
    }

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

    // Handle errors
    if (data?.code && data.code !== 0) {
      message.warn(data.msg ? translate(data.msg) : i18n.t('COMMON.UNKNOWN_ERROR'));
      return;
    }
  }, []);

  // Send data over WebSocket
  const sendData = useCallback(async (data) => {
    const ws = wsRef.current;
    const secret = secretRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || !secret) return;

    const body = await encrypt(new TextEncoder().encode(JSON.stringify(data)), secret);
    const buffer = new Uint8Array(body.length + 8);
    buffer.set(new Uint8Array([34, 22, 19, 17, 20, 3]), 0);
    buffer.set(new Uint8Array([body.length >> 8, body.length & 0xFF]), 6);
    buffer.set(body, 8);
    ws.send(buffer);
  }, []);

  // Connect to the device
  const connect = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !device?.id) return;

    // Generate new secret
    secretRef.current = hex2ua(genRandHex(32));
    const secretHex = ua2hex(secretRef.current);

    // Initialize canvas
    initCanvas();

    setStatus('connecting');

    // Build WebSocket URL
    const path = shareToken
      ? `api/share/desktop?token=${encodeURIComponent(shareToken)}&secret=${secretHex}`
      : `api/device/desktop?device=${device.id}&secret=${secretHex}`;

    const ws = new WebSocket(getBaseURL(true, path));
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      // Request initial frame
      sendData({ act: 'DESKTOP_SHOT' });
    };

    ws.onmessage = (e) => {
      parseBlocks(e.data);
    };

    ws.onclose = () => {
      setStatus('disconnected');
      cleanup();
    };

    ws.onerror = (e) => {
      console.error('WebSocket error:', e);
      setStatus('error');
      cleanup();
      message.warn(i18n.t('COMMON.CONNECTION_FAILED'));
    };

    // Start stats ticker
    tickerRef.current = setInterval(() => {
      setBandwidth(statsRef.current.bytes);
      setFps(statsRef.current.frames);
      statsRef.current = { frames: 0, bytes: 0 };

      // Send ping for latency
      if (ws.readyState === WebSocket.OPEN) {
        pingTimeRef.current = Date.now();
        sendData({ act: 'DESKTOP_PING' });
      }
    }, 1000);
  }, [device, shareToken, canvasRef, initCanvas, parseBlocks, sendData]);

  // Disconnect from the device
  const disconnect = useCallback(() => {
    cleanup();
    setStatus('disconnected');
  }, []);

  // Cleanup resources
  const cleanup = useCallback(() => {
    if (tickerRef.current) {
      clearInterval(tickerRef.current);
      tickerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    statsRef.current = { frames: 0, bytes: 0 };
  }, []);

  // Send configuration updates
  const sendConfig = useCallback((config) => {
    sendData({ act: 'DESKTOP_CONFIG', data: config });
  }, [sendData]);

  // Send input events
  const sendInput = useCallback((events) => {
    if (!allowControl) return;
    sendData({ act: 'DESKTOP_INPUT', data: { events, allowControl } });
  }, [sendData, allowControl]);

  // Request fresh screenshot
  const requestShot = useCallback(() => {
    sendData({ act: 'DESKTOP_SHOT' });
  }, [sendData]);

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
    connect,
    disconnect,
    sendConfig,
    sendInput,
    requestShot,
  };
}

export default useDesktopStream;
