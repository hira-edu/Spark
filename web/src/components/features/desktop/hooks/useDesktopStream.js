import { useState, useEffect, useRef, useCallback } from 'react';
import { message } from 'antd';
import { genRandHex, getBaseURL, hex2ua, ua2hex, ua2str, translate } from '../../../../utils/utils';
import i18n from '../../../../locale/locale';

// Version identifier for debugging cache issues
const STREAM_VERSION = 'v2.1-versioned-blocks';

const MAGIC_PREFIX = [34, 22, 19, 17];
const SERVICE_IDS = [20, 21];
const SERVICE_OP_LENGTH = 2; // service + op bytes
const EVENT_ID_LENGTH = 16;
const FRAME_META_LENGTH = 8; // frameSeq(4) + chunkIndex(2) + chunkTotal(2)
const MAX_PENDING_FRAMES = 64; // Safety cap for frames buffered before resolution

// Binary frame header (op=0,1,2):
// v1: magic(4) + service(1) + op(1) + eventID(16) = 22 bytes
// v2: v1 + frameMeta(8) = 30 bytes
const LEGACY_FRAME_HEADER_LENGTH = MAGIC_PREFIX.length + SERVICE_OP_LENGTH + EVENT_ID_LENGTH; // 22 bytes
const FRAME_HEADER_LENGTH = LEGACY_FRAME_HEADER_LENGTH + FRAME_META_LENGTH; // 30 bytes

// Server-to-browser JSON packets (op=3) are sent via server/handler/desktop/sendPack,
// which only prepends the 6-byte header (magic + service + op). There is no event ID
// or length prefix on this leg of the protocol.
const JSON_BODY_OFFSET = MAGIC_PREFIX.length + SERVICE_OP_LENGTH; // 6 bytes

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

	  const {
	    shareToken = null,
	    shareSecret = null,
	    onStatusChange,
	    allowControl = true,
	    controlChannel = null,
	    keyframeIntervalMs = 30000,
	    onJSONMessage = null,
	    suppressFrames = false,
	  } = options;
  const deviceId = device?.id || null;

  const [status, setStatus] = useState('disconnected');
  const [latency, setLatency] = useState(0);
  const [fps, setFps] = useState(0);
  const [bandwidth, setBandwidth] = useState(0);
  const [resolution, setResolution] = useState({ width: 0, height: 0 });
  const [monitors, setMonitors] = useState([]);
  const [cursor, setCursor] = useState({ x: 0, y: 0, hotX: 0, hotY: 0, width: 0, height: 0, visible: false, data: null, hash: 0, format: 'argb32' });
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  // Network quality classification: "good" (latency < 50ms, stale < 5%), "fair" (< 150ms, < 15%), "poor" (else), "unknown"
  const [networkQuality, setNetworkQuality] = useState('unknown');

  const log = useCallback((level, msg, extra = {}) => {
    const payload = { ...extra, device: deviceId || 'unknown' };
    if (level === 'debug') {
      const debugEnabled = typeof window !== 'undefined' && window.__rocketDesktopDebug?.enabled === true;
      if (!debugEnabled) return;
      console.debug('[desktop]', msg, payload);
      return;
    }
    if (level === 'error') {
      console.error('[desktop]', msg, payload);
    } else if (level === 'warn') {
      console.warn('[desktop]', msg, payload);
    } else {
      console.info('[desktop]', msg, payload);
    }
  }, [deviceId]);

  const wsRef = useRef(null);
  // Ensure WS messages are processed in arrival order even when `Blob.arrayBuffer()`
  // introduces async gaps that can otherwise interleave frame chunks.
  const messageQueueRef = useRef(Promise.resolve());
  const ctxRef = useRef(null);
  const mountedRef = useRef(true); // Track component mount state for async safety
  const blockStatsRef = useRef({ rendered: 0, failed: 0, skipped: 0, stale: 0 }); // Track async block outcomes
  const statsRef = useRef({ frames: 0, bytes: 0 });
  // Legacy-only: local counters for old agents that don't send frame meta.
  const frameSeqRef = useRef(0);
  const chunkFrameSeqRef = useRef(0);
  // Protocol v2 tracking (frame meta in the binary header).
  const wireHeaderLengthRef = useRef(FRAME_HEADER_LENGTH);
  const lastWireFrameSeqRef = useRef(0);
  const chunkMetaStateRef = useRef({ frameSeq: 0, nextIndex: 0, total: 0 });
  // Block version tracking: prevents out-of-order async rendering from overwriting newer blocks
  // Key: "x,y,width,height" string, Value: highest frame sequence rendered/queued for that region
  // This is the industrial-standard fix for async image decode race conditions
  const blockVersionRef = useRef(new Map());
  // CRITICAL: Track if we've received resolution to avoid rendering frames on 0x0 canvas
  // Frames arriving before resolution are discarded, then a full frame is requested
  const hasResolutionRef = useRef(false);
  const pendingFramesRef = useRef([]); // Buffer for frames arriving before resolution
  // Ref to hold sendControl function for use in deferred callbacks
  const sendControlRef = useRef(null);
  const lastShotRequestAtRef = useRef(0);
  const shotFallbackTimerRef = useRef(null);
  // Track approximate keyframe coverage after a DESKTOP_SHOT request.
  // Some agents (or lossy transport) can deliver incomplete tiles; this enables
  // bounded retries to recover a full screen.
  const keyframeCoverageRef = useRef({
    active: false,
    requestedAt: 0,
    attempt: 0,
    seenArea: 0,
    seenKeys: new Set(),
  });
  const tickerRef = useRef(null);
  const pingTimersRef = useRef({ server: 0, device: 0 }); // Track server vs device RTT
  const controlChannelRef = useRef(controlChannel);
  const onJSONMessageRef = useRef(onJSONMessage);
  const suppressFramesRef = useRef(!!suppressFrames);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptRef = useRef(0);
  const shouldReconnectRef = useRef(true);
  const connectionStartTimeRef = useRef(0);
  // Track frame sequences by event ID to handle async message processing correctly
  // Key: eventID hex string (first 8 bytes for efficiency), Value: frame sequence
  const eventFrameMapRef = useRef(new Map());
  const MAX_RECONNECT_ATTEMPTS = 5;
  const BASE_RECONNECT_DELAY = 1000; // 1 second

  // Cleanup resources (defined early to avoid TDZ)
  const cleanup = useCallback((clearReconnect = false) => {
    if (tickerRef.current) {
      clearInterval(tickerRef.current);
      tickerRef.current = null;
    }
    if (clearReconnect && reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (shotFallbackTimerRef.current) {
      clearTimeout(shotFallbackTimerRef.current);
      shotFallbackTimerRef.current = null;
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
    frameSeqRef.current = 0;
    chunkFrameSeqRef.current = 0;
    wireHeaderLengthRef.current = FRAME_HEADER_LENGTH;
    lastWireFrameSeqRef.current = 0;
    chunkMetaStateRef.current = { frameSeq: 0, nextIndex: 0, total: 0 };
    pingTimersRef.current = { server: 0, device: 0 };
    // Clear block version tracking on cleanup to ensure fresh state on reconnect
    blockVersionRef.current.clear();
    blockStatsRef.current = { rendered: 0, failed: 0, skipped: 0, stale: 0 };
    // Reset resolution tracking - critical for proper frame buffering on reconnect
    hasResolutionRef.current = false;
    pendingFramesRef.current = [];
    // Clear event-to-frame mapping to prevent stale data on reconnect
    eventFrameMapRef.current.clear();
    keyframeCoverageRef.current = { active: false, requestedAt: 0, attempt: 0, seenArea: 0, seenKeys: new Set() };
    // Reset message processing chain to avoid holding old closures/data
    messageQueueRef.current = Promise.resolve();
    setFps(0);
    setBandwidth(0);
    setLatency(0);
    setMonitors([]);
    setResolution({ width: 0, height: 0 });
    setCursor({ x: 0, y: 0, hotX: 0, hotY: 0, width: 0, height: 0, visible: false, data: null, hash: 0, format: 'argb32' });

    const canvas = canvasRef.current;
    if (canvas && ctxRef.current) {
      ctxRef.current.clearRect(0, 0, canvas.width, canvas.height);
    }
  }, []);

  // Keep latest control channel (e.g., WebRTC data channel) in a ref
  useEffect(() => {
    controlChannelRef.current = controlChannel;
  }, [controlChannel]);

  useEffect(() => {
    onJSONMessageRef.current = onJSONMessage;
  }, [onJSONMessage]);

  useEffect(() => {
    suppressFramesRef.current = !!suppressFrames;
  }, [suppressFrames]);

  // Update external status callback
  useEffect(() => {
    if (onStatusChange) {
      onStatusChange(status);
    }
  }, [status, onStatusChange]);

  const incrementShotCounter = useCallback((reason = '') => {
    const now = Date.now();
    lastShotRequestAtRef.current = now;
    if (typeof window !== 'undefined') {
      window.__shotRequests = (window.__shotRequests || 0) + 1;
      window.__rocketDesktopDebug = window.__rocketDesktopDebug || {};
      window.__rocketDesktopDebug.shotRequests = (window.__rocketDesktopDebug.shotRequests || 0) + 1;
      window.__rocketDesktopDebug.lastShotRequest = now;
      if (reason) {
        window.__rocketDesktopDebug.lastShotReason = reason;
      }
    }
  }, []);

  const requestFullFrame = useCallback((reason = '') => {
    if (suppressFramesRef.current) return;
    if (!sendControlRef.current) return;
    const now = Date.now();
    const prev = keyframeCoverageRef.current || { requestedAt: 0, attempt: 0 };
    const nextAttempt = prev.requestedAt > 0 && now - prev.requestedAt < 15000 ? (prev.attempt || 0) + 1 : 1;
    keyframeCoverageRef.current = { active: true, requestedAt: now, attempt: nextAttempt, seenArea: 0, seenKeys: new Set() };
    incrementShotCounter(reason);
    sendControlRef.current({ act: 'DESKTOP_SHOT' });
  }, [incrementShotCounter]);

  // Request a full frame only if the stream appears stalled (no frames arrive within a short window).
  // This avoids redundant DESKTOP_SHOT bursts during startup (device already sends an initial keyframe after DESKTOP_INIT).
  const scheduleShotIfStalled = useCallback((reason = '', timeoutMs = 1200) => {
    if (suppressFramesRef.current) return;
    if (shotFallbackTimerRef.current) {
      clearTimeout(shotFallbackTimerRef.current);
      shotFallbackTimerRef.current = null;
    }

    const startFrames = statsRef.current.frames || 0;
    shotFallbackTimerRef.current = setTimeout(() => {
      shotFallbackTimerRef.current = null;
      if (!mountedRef.current) return;
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      if ((statsRef.current.frames || 0) !== startFrames) return;
      requestFullFrame(reason || 'stalled');
    }, Math.max(0, timeoutMs));
  }, [requestFullFrame]);

  // Viewport resize (including DevTools dock changes) can expose latent "missing tiles"
  // if a full sync frame was dropped earlier. Debounce a fresh shot on resize.
  useEffect(() => {
    if (status !== 'connected') return undefined;

    let resizeTimer = null;
    const onResize = () => {
      if (!hasResolutionRef.current) return;
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (!mountedRef.current) return;
        requestFullFrame('resize');
      }, 250);
    };

    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      if (resizeTimer) clearTimeout(resizeTimer);
    };
  }, [status, requestFullFrame]);

  // Periodic keyframe refresh to recover from dropped chunks/tiles.
  // Keep this conservative to avoid saturating the link with full-frame updates.
  useEffect(() => {
    if (status !== 'connected') return undefined;
    const intervalMs = Number.isFinite(keyframeIntervalMs) ? keyframeIntervalMs : 0;
    if (intervalMs <= 0) return undefined;

    const timer = setInterval(() => {
      if (!mountedRef.current) return;
      if (!hasResolutionRef.current) return;
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;

      const now = Date.now();
      const last = lastShotRequestAtRef.current || 0;
      if (last > 0 && now - last < intervalMs) return;

      requestFullFrame('periodic');
    }, intervalMs);

    return () => clearInterval(timer);
  }, [status, keyframeIntervalMs, requestFullFrame]);

  // Initialize canvas context
  const initCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    ctxRef.current = canvas.getContext('2d', {
      alpha: false,
      desynchronized: true
    });
    if (ctxRef.current) {
      ctxRef.current.imageSmoothingEnabled = false;
    }
  }, [canvasRef]);

  // Render a single image block (raw RGBA or compressed) with version tracking
  //
  // INDUSTRIAL BEST PRACTICE: Versioned Block Rendering
  //
  // Problem: createImageBitmap is async, so blocks can complete out-of-order.
  // If block A (frame 5) takes longer to decode than block B (frame 6) at the
  // same position, block A would overwrite block B, showing stale data.
  //
  // Solution: Track the frame sequence for each block position. Before rendering
  // an async-decoded block, check if a newer block has already been rendered at
  // that position. If so, skip the stale block.
  //
  // This is the same pattern used by VNC/noVNC and other professional remote
  // desktop implementations to handle async tile/block updates.
  //
  const updateImage = useCallback((data, it, dx, dy, bw, bh, ctx, frameSeq) => {
    if (!ctx || bw === 0 || bh === 0) return;
    if (!data || data.byteLength === 0) return;

    // Create position key for version tracking (include block dimensions for safety)
    const posKey = `${dx},${dy},${bw},${bh}`;
    // Pre-register latest frame version so older async renders skip immediately
    const currentSeq = frameSeq || 0;
    blockVersionRef.current.set(posKey, currentSeq);

    if (it === 0) { // Raw RGBA - synchronous rendering, always safe
      try {
        const clamped = new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength);
        ctx.putImageData(
          new ImageData(clamped, bw, bh),
          dx, dy, 0, 0, bw, bh
        );
        blockStatsRef.current.rendered++;
      } catch (err) {
        blockStatsRef.current.failed++;
        log('error', 'ImageData put failed', { error: err?.message, len: data?.byteLength, bw, bh, dx, dy });
      }
      return;
    }

    // Compressed (JPEG/WebP/AVIF/VPx/H.264/PNG) - async rendering with version check
    // PNG (type 7) is lossless, best for text/terminals/diagrams
    // Capture the frame sequence at decode start time
    const capturedSeq = currentSeq;

    createImageBitmap(new Blob([data]), {
      premultiplyAlpha: 'none',
      colorSpaceConversion: 'none'
    }).then((ib) => {
      // Guard 1: Check component mount state and context validity
      if (!mountedRef.current || ctx !== ctxRef.current) {
        blockStatsRef.current.skipped++;
        if (typeof ib.close === 'function') {
          ib.close();
        }
        return;
      }

      // Guard 2: VERSION CHECK - Skip if a newer block has already rendered here
      // This is the critical fix for the async race condition
      const latestVersion = blockVersionRef.current.get(posKey) || 0;
      if (capturedSeq < latestVersion) {
        // This block is stale - a newer frame's block already rendered at this position
        blockStatsRef.current.stale++;
        if (typeof ib.close === 'function') {
          ib.close();
        }
        return;
      }

      // Update version and render
      blockVersionRef.current.set(posKey, capturedSeq);
      // Always scale to the declared block size; some agents may encode blocks at
      // a different intrinsic size (e.g., adaptive downscale) while keeping the
      // destination rect in the header.
      ctx.drawImage(ib, 0, 0, ib.width || bw, ib.height || bh, dx, dy, bw, bh);
      blockStatsRef.current.rendered++;

      if (typeof ib.close === 'function') {
        ib.close();
      }
    }).catch((err) => {
      blockStatsRef.current.failed++;
      // Only log if component is still mounted (avoid noise during cleanup)
      if (mountedRef.current) {
        log('warn', 'createImageBitmap failed', { error: err?.message, it, bw, bh, dx, dy, frameSeq: capturedSeq });
      }
    });
  }, [log]);

  const renderBlocks = useCallback((buffer, payloadOffset, frameSeq) => {
    const canvas = canvasRef.current;
    const ctx = ctxRef.current;
    if (!canvas || !ctx) return;

    // CRITICAL: Skip rendering if canvas has no size (resolution not received yet)
    // This prevents silent failures and wasted work
    if (canvas.width === 0 || canvas.height === 0) {
      log('warn', 'renderBlocks: canvas has no size, skipping', { width: canvas.width, height: canvas.height });
      return;
    }

    const view = new DataView(buffer);
    const bytes = new Uint8Array(buffer);
    let offset = payloadOffset;
    let blockCount = 0;
    let parseErrors = 0;
    let minX = Number.POSITIVE_INFINITY;
    let minY = Number.POSITIVE_INFINITY;
    let maxX = 0;
    let maxY = 0;

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
        parseErrors++;
        log('warn', 'renderBlocks: block parse error', { bl, il, offset, bufLen: view.byteLength, blockCount });
        break;
      }

      // Validate block bounds against canvas
      if (dx + bw > canvas.width || dy + bh > canvas.height) {
        log('warn', 'renderBlocks: block out of bounds', {
          dx, dy, bw, bh,
          canvasW: canvas.width,
          canvasH: canvas.height,
          blockCount
        });
      }

      if (dx < minX) minX = dx;
      if (dy < minY) minY = dy;
      if (dx + bw > maxX) maxX = dx + bw;
      if (dy + bh > maxY) maxY = dy + bh;

      // Track best-effort coverage after an explicit screenshot request.
      const coverage = keyframeCoverageRef.current;
      if (coverage?.active) {
        const key = `${dx},${dy},${bw},${bh}`;
        if (!coverage.seenKeys.has(key)) {
          coverage.seenKeys.add(key);
          coverage.seenArea += bw * bh;
        }
      }

      // Pass chunk frame sequence for versioned block tracking
      updateImage(bytes.subarray(dataStart, dataEnd), it, dx, dy, bw, bh, ctx, frameSeq);
      offset = dataEnd;
      blockCount++;
    }

    const canvasArea = canvas.width * canvas.height;
    const coverage = keyframeCoverageRef.current;
    const coverageRatio = coverage?.active && canvasArea > 0 ? Math.min(1, coverage.seenArea / canvasArea) : null;

    if (coverage?.active && coverageRatio !== null) {
      const now = Date.now();
      const elapsed = now - (coverage.requestedAt || now);
      // If a shot doesn't fill most of the screen quickly, retry a few times.
      if (elapsed > 3000 && coverageRatio < 0.5 && (coverage.attempt || 0) < 3) {
        log('warn', 'low keyframe coverage; retrying DESKTOP_SHOT', { coverageRatio, elapsedMs: elapsed, attempt: coverage.attempt });
        requestFullFrame('coverage_retry');
      } else if (coverageRatio >= 0.95) {
        keyframeCoverageRef.current = { active: false, requestedAt: 0, attempt: 0, seenArea: 0, seenKeys: new Set() };
      }
    }

    // Log block counts periodically for first frame diagnostics
    if (frameSeq <= 3 || blockCount > 50) {
      log('debug', 'renderBlocks completed', {
        blockCount,
        parseErrors,
        frameSeq,
        canvasW: canvas.width,
        canvasH: canvas.height,
        minX: Number.isFinite(minX) ? minX : null,
        minY: Number.isFinite(minY) ? minY : null,
        maxX,
        maxY,
        coverageRatio,
        version: STREAM_VERSION
      });
    }
  }, [canvasRef, updateImage, log, requestFullFrame]);

  // Replay any frames that arrived before we knew the resolution.
  const flushPendingFrames = useCallback(() => {
    if (!hasResolutionRef.current || pendingFramesRef.current.length === 0) {
      return;
    }
    const queued = pendingFramesRef.current;
    pendingFramesRef.current = [];
    queued.forEach(({ buffer, payloadOffset, frameSeq }) => {
      renderBlocks(buffer, payloadOffset, frameSeq);
    });
    log('info', 'flushed pending frames after resolution', {
      count: queued.length,
      latestFrameSeq: queued[queued.length - 1]?.frameSeq || 0,
    });
  }, [renderBlocks, log]);

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

    const wasResized = canvas.width !== width || canvas.height !== height;
    const isFirstResolution = !hasResolutionRef.current;

    if (wasResized) {
      canvas.width = width;
      canvas.height = height;
      ctx.imageSmoothingEnabled = false;
      // Resolution changes invalidate previous block versions
      blockVersionRef.current.clear();
      log('info', 'canvas resized (binary resolution)', { width, height, version: STREAM_VERSION, isFirstResolution });
    }

    // CRITICAL: Mark that we now have resolution
    hasResolutionRef.current = true;

    if (isFirstResolution || wasResized) {
      scheduleShotIfStalled('resolution_update', 800);
    }

    setResolution({ width, height });
    flushPendingFrames();
  }, [canvasRef, log, flushPendingFrames, scheduleShotIfStalled]);

  // Handle incoming JSON messages
  const handleJSON = useCallback(async (payload) => {
    const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
    let data;
    try {
      // No decryption - parse JSON directly
      const text = ua2str(bytes);
      data = JSON.parse(text);
    } catch (err) {
      log('error', 'JSON parse failed', {
        error: err?.message,
        byteLength: bytes?.byteLength,
        preview: bytes?.byteLength > 0 ? ua2str(bytes.subarray(0, Math.min(100, bytes.byteLength))) : ''
      });
      return;
    }

    log('debug', 'json message', {
      act: data?.act,
      code: data?.code,
      msg: data?.msg,
      hasData: !!data?.data,
    });

    if (onJSONMessageRef.current) {
      try {
        onJSONMessageRef.current(data);
      } catch (err) {
        log('warn', 'onJSONMessage handler failed', { error: err?.message });
      }
    }

    // Handle pong for latency measurement
    if (data?.act === 'DESKTOP_PONG') {
      const source = data?.data?.source || 'device';
      const now = Date.now();
      if (source === 'server') {
        const serverStart = pingTimersRef.current.server;
        if (serverStart > 0) {
          log('debug', 'DESKTOP_PONG (server ack)', { latency: now - serverStart });
          pingTimersRef.current.server = 0;
        }
      } else {
        const deviceStart = pingTimersRef.current.device;
        if (deviceStart > 0) {
          setLatency(now - deviceStart);
          pingTimersRef.current.device = 0;
        }
      }
      return;
    }

    // Handle initial desktop setup - CRITICAL: resize canvas before first frame arrives
    if (data?.act === 'DESKTOP_INIT') {
      const canvas = canvasRef.current;
      const ctx = ctxRef.current;
      const initData = data.data || {};
      const width = initData.width || 0;
      const height = initData.height || 0;

      log('info', 'DESKTOP_INIT received', { width, height, monitors: initData.monitors?.length || 0 });

      // Check if this is the first time we're receiving resolution info
      // If so, we need to request a full frame after sizing the canvas
      const isFirstResolution = !hasResolutionRef.current;

      if (canvas && ctx && width > 0 && height > 0) {
        const wasResized = canvas.width !== width || canvas.height !== height;
        if (wasResized) {
          canvas.width = width;
          canvas.height = height;
          ctx.imageSmoothingEnabled = false;
          // Clear block versions on resize (same as handleResolution)
          blockVersionRef.current.clear();
          log('info', 'canvas resized from DESKTOP_INIT', { width, height });
        }
        // CRITICAL: Mark that we have resolution (same as handleResolution)
        hasResolutionRef.current = true;
        setResolution({ width, height });

        if (isFirstResolution || wasResized) {
          scheduleShotIfStalled('desktop_init', 800);
        }
        flushPendingFrames();
      }

      // Also update monitors if provided
      if (initData.monitors && Array.isArray(initData.monitors)) {
        setMonitors(initData.monitors);
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
        visible: cursorData.visible === true, // Explicit check - only true if server says true
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
  }, [cleanup, flushPendingFrames, scheduleShotIfStalled]);

  const MAX_EVENT_MAP_SIZE = 64; // Limit event->frame map size to prevent memory leak

  // Helper to extract event ID from binary payload (bytes 6-21, 16 bytes)
  const getEventIdHex = useCallback((bytes) => {
    if (bytes.length < LEGACY_FRAME_HEADER_LENGTH) return null;
    // Use first 8 bytes of event ID for key (sufficient for uniqueness in short time window)
    let hex = '';
    for (let i = 6; i < 14; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }, []);

  // Parse incoming frame blocks
  // CRITICAL FIX: Use synchronous message processing to avoid race conditions
  // The async arrayBuffer() call was causing chunks from different frames to interleave
  const parseMessage = useCallback(async (raw) => {
    let buffer = null;
    if (raw instanceof ArrayBuffer) {
      buffer = raw;
    } else if (raw?.arrayBuffer) {
      buffer = await raw.arrayBuffer();
    }
    if (!buffer) return;

    const bytes = new Uint8Array(buffer);
    if (bytes.length < JSON_BODY_OFFSET) return;

    // Validate magic prefix
    for (let i = 0; i < MAGIC_PREFIX.length; i++) {
      if (bytes[i] !== MAGIC_PREFIX[i]) return;
    }
    const service = bytes[4];
    if (!SERVICE_IDS.includes(service)) return;

    const op = bytes[5];
    // Log ALL incoming packets for debugging protocol issues
    log('debug', 'packet received', { op, size: bytes.length, service });

    // Handle JSON packets (no event id prefix)
    if (op === 3) {
      statsRef.current.bytes += bytes.byteLength;
      handleJSON(bytes.subarray(JSON_BODY_OFFSET));
      return;
    }

    // Binary payloads include a 16-byte event id after the op code (v1+v2).
    if (bytes.length < LEGACY_FRAME_HEADER_LENGTH) return;

    const view = new DataView(bytes.buffer);

    // Resolution packets are the most reliable discriminator for header version.
    if (op === 2) {
      let headerLen = wireHeaderLengthRef.current || FRAME_HEADER_LENGTH;

      const tryHeader = (candidateLen) => {
        if (bytes.length < candidateLen + 6) return false; // bodyLen(2) + width(2) + height(2)
        const bodyLength = view.getUint16(candidateLen, false);
        return bodyLength === 4 && candidateLen + 2 + bodyLength <= bytes.length;
      };

      if (tryHeader(FRAME_HEADER_LENGTH)) {
        headerLen = FRAME_HEADER_LENGTH;
      } else if (tryHeader(LEGACY_FRAME_HEADER_LENGTH)) {
        headerLen = LEGACY_FRAME_HEADER_LENGTH;
      } else {
        return;
      }

      if (wireHeaderLengthRef.current !== headerLen) {
        wireHeaderLengthRef.current = headerLen;
        log('info', 'desktop protocol header detected', { headerLen });
      }

      const payloadOffset = headerLen;
      statsRef.current.bytes += bytes.byteLength;
      handleResolution(view, payloadOffset);
      const width = view.getUint16(payloadOffset + 2, false);
      const height = view.getUint16(payloadOffset + 4, false);
      log('info', 'resolution update', { width, height });
      return;
    }

    if (suppressFramesRef.current && (op === 0 || op === 1)) {
      statsRef.current.bytes += bytes.byteLength;
      if (op === 0) {
        statsRef.current.frames += 1;
      }
      return;
    }

    const hasPlausibleV2Meta = () => {
      if (bytes.length < FRAME_HEADER_LENGTH) return false;
      const chunkIndex = view.getUint16(LEGACY_FRAME_HEADER_LENGTH + 4, false);
      const chunkTotal = view.getUint16(LEGACY_FRAME_HEADER_LENGTH + 6, false);
      if (chunkTotal === 0 || chunkTotal > 4096) return false;
      if (chunkIndex >= chunkTotal) return false;
      return true;
    };

    const isPlausibleBlockHeader = (candidateOffset) => {
      if (bytes.length < candidateOffset + 12) return false;
      const bodyLen = view.getUint16(candidateOffset, false);
      const imageType = view.getUint16(candidateOffset + 2, false);
      const dx = view.getUint16(candidateOffset + 4, false);
      const dy = view.getUint16(candidateOffset + 6, false);
      const bw = view.getUint16(candidateOffset + 8, false);
      const bh = view.getUint16(candidateOffset + 10, false);

      if (bodyLen < 10) return false;
      if (candidateOffset + 2 + bodyLen > bytes.length) return false;
      // Current browser decoder supports image codecs (raw/jpeg/webp/avif/png); reject obviously invalid values.
      if (imageType > 16) return false;
      if (bw === 0 || bh === 0) return false;
      if (bw > 8192 || bh > 8192) return false;
      if (dx > 32768 || dy > 32768) return false;
      return true;
    };

    let headerLen = wireHeaderLengthRef.current || FRAME_HEADER_LENGTH;

    // Detect header length from frame chunks too; older agents may never emit op=2.
    // This prevents misaligned block parsing (black screen / partial tiles).
    if (op === 0 || op === 1) {
      const v2Candidate = bytes.length >= FRAME_HEADER_LENGTH && hasPlausibleV2Meta() && isPlausibleBlockHeader(FRAME_HEADER_LENGTH);
      const legacyCandidate = isPlausibleBlockHeader(LEGACY_FRAME_HEADER_LENGTH);

      if (v2Candidate && !legacyCandidate) {
        headerLen = FRAME_HEADER_LENGTH;
      } else if (legacyCandidate && !v2Candidate) {
        headerLen = LEGACY_FRAME_HEADER_LENGTH;
      } else if (v2Candidate) {
        headerLen = FRAME_HEADER_LENGTH;
      } else if (legacyCandidate) {
        headerLen = LEGACY_FRAME_HEADER_LENGTH;
      }

      if (wireHeaderLengthRef.current !== headerLen) {
        wireHeaderLengthRef.current = headerLen;
        log('info', 'desktop protocol header detected (frame)', { headerLen });
      }
    }
    if (bytes.length < headerLen) return;

    // Parse frames directly (no encryption)
    const payloadOffset = headerLen;

    const hasMeta = headerLen === FRAME_HEADER_LENGTH;
    const metaOffset = LEGACY_FRAME_HEADER_LENGTH;
    let chunkFrameSeq = chunkFrameSeqRef.current;
    let chunkIndex = null;
    let chunkTotal = null;

    if (hasMeta) {
      const wireFrameSeq = view.getUint32(metaOffset, false);
      chunkIndex = view.getUint16(metaOffset + 4, false);
      chunkTotal = view.getUint16(metaOffset + 6, false);
      chunkFrameSeq = wireFrameSeq;

      // FPS should reflect capture frames, not sub-chunks.
      if (op === 0 && wireFrameSeq !== lastWireFrameSeqRef.current) {
        lastWireFrameSeqRef.current = wireFrameSeq;
        statsRef.current.frames += 1;
      }

      // Best-effort chunk integrity tracking (detect missing/duplicate chunks).
      if (chunkTotal > 0) {
        if (op === 0) {
          if (chunkIndex !== 0) {
            log('warn', 'frame chunk index invalid (first chunk)', { wireFrameSeq, chunkIndex, chunkTotal });
          }
          chunkMetaStateRef.current = { frameSeq: wireFrameSeq, nextIndex: 1, total: chunkTotal };
          if (chunkTotal === 1) {
            chunkMetaStateRef.current = { frameSeq: wireFrameSeq, nextIndex: 0, total: 0 };
          }
        } else if (op === 1) {
          const state = chunkMetaStateRef.current || { frameSeq: 0, nextIndex: 0, total: 0 };
          const expectedFrameSeq = state.frameSeq;
          const expectedNext = state.nextIndex;
          const expectedTotal = state.total;

          if (expectedTotal === 0 || expectedFrameSeq !== wireFrameSeq || expectedTotal !== chunkTotal || chunkIndex !== expectedNext) {
            log('warn', 'frame chunk order mismatch', {
              wireFrameSeq,
              chunkIndex,
              chunkTotal,
              expectedFrameSeq,
              expectedNext,
              expectedTotal
            });
            chunkMetaStateRef.current = { frameSeq: wireFrameSeq, nextIndex: chunkIndex + 1, total: chunkTotal };
          } else {
            chunkMetaStateRef.current = { frameSeq: wireFrameSeq, nextIndex: expectedNext + 1, total: expectedTotal };
          }

          if (chunkIndex + 1 >= chunkTotal) {
            chunkMetaStateRef.current = { frameSeq: wireFrameSeq, nextIndex: 0, total: 0 };
          }
        }
      }
    } else {
      // Legacy protocol: local sequencing (op=0 starts a new frame).
      const eventId = getEventIdHex(bytes);
      if (op === 0) {
        frameSeqRef.current += 1;
        chunkFrameSeq = frameSeqRef.current;
        chunkFrameSeqRef.current = chunkFrameSeq;
        statsRef.current.frames += 1;

        if (eventId) {
          eventFrameMapRef.current.set(eventId, chunkFrameSeq);
          if (eventFrameMapRef.current.size > MAX_EVENT_MAP_SIZE) {
            const firstKey = eventFrameMapRef.current.keys().next().value;
            eventFrameMapRef.current.delete(firstKey);
          }
        }
      } else if (op === 1) {
        if (eventId && eventFrameMapRef.current.has(eventId)) {
          chunkFrameSeq = eventFrameMapRef.current.get(eventId);
        } else {
          chunkFrameSeq = chunkFrameSeqRef.current;
          if (eventId) {
            log('warn', 'continuation chunk missing event mapping', { eventId, op, fallbackSeq: chunkFrameSeq });
          }
        }
      } else {
        chunkFrameSeq = chunkFrameSeqRef.current;
      }
    }

    statsRef.current.bytes += bytes.byteLength;
    log('debug', 'frame received', { op, size: bytes.byteLength, frameSeq: chunkFrameSeq, chunkIndex, chunkTotal });

    if (!hasResolutionRef.current) {
      // Buffer frame chunks until the canvas is properly sized
      if (pendingFramesRef.current.length >= MAX_PENDING_FRAMES) {
        pendingFramesRef.current.shift();
        log('warn', 'pending frame buffer full, dropping oldest', { max: MAX_PENDING_FRAMES });
      }
      pendingFramesRef.current.push({
        buffer,
        payloadOffset,
        frameSeq: chunkFrameSeq,
      });
      log('info', 'queued frame pending resolution', { frameSeq: chunkFrameSeq, op, queued: pendingFramesRef.current.length });
      return;
    }

    renderBlocks(bytes.buffer, payloadOffset, chunkFrameSeq);
  }, [JSON_BODY_OFFSET, MAGIC_PREFIX, SERVICE_IDS, handleJSON, handleResolution, renderBlocks, getEventIdHex, log]);

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
    ws.send(buffer.buffer);
  }, []);

  // Explicit WS-only sender (used for signaling and server-side telemetry).
  const sendSignal = useCallback(async (payload) => {
    await sendData(payload);
  }, [sendData]);

  // Control channel: prefer an open DataChannel if provided, fall back to WS
  const sendControl = useCallback(async (payload, channelOverride = null) => {
    const channel = channelOverride || controlChannelRef.current;
    const serialized = JSON.stringify(payload);
    log('debug', 'send control', {
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

  // Keep latest sendControl for callbacks defined earlier
  sendControlRef.current = sendControl;

  // Schedule a reconnection attempt
  const scheduleReconnect = useCallback(() => {
    if (!shouldReconnectRef.current) return;
    if (reconnectAttemptRef.current >= MAX_RECONNECT_ATTEMPTS) {
      log('error', 'Max reconnect attempts reached', { attempts: MAX_RECONNECT_ATTEMPTS });
      setStatus('error');
      message.error(i18n.t('DESKTOP.CONNECTION_LOST'));
      return;
    }

    const delay = BASE_RECONNECT_DELAY * Math.pow(2, reconnectAttemptRef.current);
    reconnectAttemptRef.current += 1;
    setReconnectAttempt(reconnectAttemptRef.current);
    log('info', 'Scheduling reconnect', { attempt: reconnectAttemptRef.current, delay });

    setStatus('reconnecting');
    reconnectTimeoutRef.current = setTimeout(() => {
      log('info', 'Attempting reconnect', { attempt: reconnectAttemptRef.current });
      connectInternal();
    }, delay);
  }, []);

  // Internal connect function (used for initial connect and reconnects)
  const connectInternal = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !deviceId) return;

    // Clear any existing connection
    cleanup(false);

    statsRef.current = { frames: 0, bytes: 0 };
    setFps(0);
    setBandwidth(0);
    setLatency(0);
    setMonitors([]);
    setResolution({ width: 0, height: 0 });

    // Initialize canvas
    initCanvas();

    setStatus('connecting');
    connectionStartTimeRef.current = Date.now();

    // Build WebSocket URL
    const path = shareToken
      ? `api/share/desktop?token=${encodeURIComponent(shareToken)}&secret=${encodeURIComponent(shareSecret || '')}`
      : `api/device/desktop?device=${deviceId}`;

    const ws = new WebSocket(getBaseURL(true, path));
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onopen = () => {
      // Reset reconnect counter on successful connection
      reconnectAttemptRef.current = 0;
      setReconnectAttempt(0);
      setStatus('connected');
      log('info', 'WS connected', {
        version: STREAM_VERSION,
        canvasWidth: canvas.width,
        canvasHeight: canvas.height
      });
      // Device sends an initial keyframe after DESKTOP_INIT; only request a shot if the stream stalls.
      scheduleShotIfStalled('ws_open', 1200);
    };

    ws.onmessage = (e) => {
      // Process WS messages strictly in arrival order.
      // Without this, async `Blob.arrayBuffer()` can interleave chunks from different frames,
      // which shows up as missing/black tiles until later deltas repaint them.
      messageQueueRef.current = messageQueueRef.current
        .then(() => parseMessage(e.data))
        .catch((err) => {
          log('error', 'parseMessage failed', { error: err?.message });
        });
    };

    ws.onclose = (event) => {
      const connectionDuration = Date.now() - connectionStartTimeRef.current;
      log('warn', 'WS closed', {
        code: event.code,
        reason: event.reason,
        wasClean: event.wasClean,
        duration: connectionDuration
      });

      cleanup(false);

      // Differentiated error codes for share/auth failures
      // 4001 = auth failure, 4002 = expired, 4003 = revoked, 4004 = rate limited
      // Code 1006 is "Abnormal Closure" and happens for many reasons:
      // device offline, not found, network issues, origin validation, etc.
      // We should NOT redirect to login based on 1006 heuristics.
      const shareErrorCodes = {
        4001: { key: 'SHARE.AUTH_FAILED', fallback: 'Authentication failed', isAuthError: true },
        4002: { key: 'SHARE.TOKEN_EXPIRED', fallback: 'Share link has expired', isAuthError: false },
        4003: { key: 'SHARE.TOKEN_REVOKED', fallback: 'Share link has been revoked', isAuthError: false },
        4004: { key: 'SHARE.RATE_LIMITED', fallback: 'Too many requests, please try again later', isAuthError: false },
      };

      if (shareErrorCodes[event.code]) {
        const errorInfo = shareErrorCodes[event.code];
        log('error', `Share error (${event.code})`, { reason: errorInfo.fallback });
        setStatus('error');

        if (shareToken) {
          message.error(i18n.t(errorInfo.key) || errorInfo.fallback);
        } else if (errorInfo.isAuthError) {
          message.error(i18n.t('AUTH.SESSION_EXPIRED') || 'Session expired, please login again');
          setTimeout(() => {
            if (window.location.pathname !== '/login') {
              window.location.href = '/login';
            }
          }, 1500);
        } else {
          message.error(errorInfo.fallback);
        }
        return;
      }

      // For share pages with quick connection failure, show specific error (no redirect)
      if (shareToken && event.code === 1006 && connectionDuration < 500) {
        log('warn', 'Share connection failed quickly', { duration: connectionDuration });
        setStatus('error');
        message.error(i18n.t('SHARE.CONNECTION_FAILED') || 'Failed to connect to shared desktop');
        return;
      }

      // For normal disconnections (including quick 1006), attempt reconnect
      if (shouldReconnectRef.current && !event.wasClean) {
        scheduleReconnect();
      } else {
        setStatus('disconnected');
      }
    };

    ws.onerror = (e) => {
      log('error', 'WS error', { error: e?.message });
      // onerror is usually followed by onclose, so we don't set status here
    };

    // Start stats ticker - updates stats every second, pings every 5 seconds
    // Ping interval reduced from 1s to 5s to avoid connection overhead while still
    // providing responsive latency measurements. Stats update remains at 1s for smooth UI.
    let pingCounter = 0;
    const PING_INTERVAL_TICKS = 5; // Ping every 5 seconds (5 ticks)

    tickerRef.current = setInterval(() => {
      setBandwidth(statsRef.current.bytes);
      setFps(statsRef.current.frames);
      statsRef.current = { frames: 0, bytes: 0 };

      // Send ping for latency every 5 seconds (not every second)
      // This reduces server load while still providing latency measurement
      pingCounter++;
      if (pingCounter >= PING_INTERVAL_TICKS && ws.readyState === WebSocket.OPEN) {
        pingCounter = 0;
        const now = Date.now();
        pingTimersRef.current = { server: now, device: now };
        sendSignal({ act: 'DESKTOP_PING' });

        // Log async block rendering stats every 5 seconds for diagnostics
        const stats = blockStatsRef.current;
        if (stats.rendered > 0 || stats.failed > 0 || stats.skipped > 0 || stats.stale > 0) {
          const total = stats.rendered + stats.failed + stats.skipped + stats.stale;
          const successRate = total > 0 ? Math.round(stats.rendered / total * 100) : 0;
          const staleRate = total > 0 ? Math.round(stats.stale / total * 100) : 0;

          log('info', 'block render stats (5s)', {
            rendered: stats.rendered,
            failed: stats.failed,
            skipped: stats.skipped,
            stale: stats.stale, // Blocks skipped due to version check (newer block already rendered)
            successRate,
            staleRate
          });

          // Export browser-side telemetry to server for unified monitoring (DESKTOP_BROWSER_STATS)
          // This allows Prometheus/Grafana to correlate browser rendering issues with server-side metrics
          sendSignal({
            act: 'DESKTOP_BROWSER_STATS',
            data: {
              rendered: stats.rendered,
              failed: stats.failed,
              skipped: stats.skipped,
              stale: stats.stale,
              staleRate,
              latency: latency,
              fps: statsRef.current.frames || 0,
            }
          });

          // Update network quality classification based on latency and stale rate
          // Thresholds based on RustDesk/Sunshine quality indicators
          let quality = 'unknown';
          if (latency > 0) {
            if (latency < 50 && staleRate < 5) {
              quality = 'good';
            } else if (latency < 150 && staleRate < 15) {
              quality = 'fair';
            } else {
              quality = 'poor';
            }
          }
          setNetworkQuality(quality);

          // Reset stats
          blockStatsRef.current = { rendered: 0, failed: 0, skipped: 0, stale: 0 };
        }
      }
    }, 1000);
  }, [device, shareToken, shareSecret, canvasRef, initCanvas, parseMessage, sendControl, sendSignal, cleanup, scheduleReconnect, requestFullFrame]);

  // Public connect function
  const connect = useCallback(() => {
    shouldReconnectRef.current = true;
    reconnectAttemptRef.current = 0;
    setReconnectAttempt(0);
    connectInternal();
  }, [connectInternal]);

  // Disconnect from the device
  const disconnect = useCallback(() => {
    shouldReconnectRef.current = false;
    cleanup(true); // clear reconnect timeout
    setStatus('disconnected');
    setReconnectAttempt(0);
    reconnectAttemptRef.current = 0;
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
    requestFullFrame('manual');
  }, [requestFullFrame]);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false; // Prevent async callbacks from rendering after unmount
      shouldReconnectRef.current = false;
      cleanup(true);
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
    reconnectAttempt,
    networkQuality, // "good", "fair", "poor", or "unknown" based on latency/stale rate
    connect,
    disconnect,
    sendConfig,
    sendInput,
    sendClipboard,
	    sendFileDrop,
	    sendAudioControl,
	    sendKill,
	    requestShot,
	    sendSignal,
	  };
}

export default useDesktopStream;
