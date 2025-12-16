import { test, expect } from '@playwright/test';
import { readFileSync } from 'fs';
import path from 'path';

function readEnv() {
  const envFile = path.join(process.cwd(), '.playwright', 'perf-env.json');
  const raw = readFileSync(envFile, 'utf-8');
  return JSON.parse(raw);
}

function quantile(sorted, q) {
  if (sorted.length === 0) return 0;
  const pos = (sorted.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  const a = sorted[base];
  const b = sorted[Math.min(sorted.length - 1, base + 1)];
  return a + (b - a) * rest;
}

function unwrapTs24(nowMs, ts24) {
  const wrap = 1 << 24;
  const base = nowMs - (nowMs % wrap);
  let candidate = base + ts24;
  if (candidate > nowMs + wrap / 2) candidate -= wrap;
  if (candidate < nowMs - wrap / 2) candidate += wrap;
  return candidate;
}

function buildRegion(markerGrid) {
  const x = markerGrid.x | 0;
  const y = markerGrid.y | 0;
  const pad = Math.max(0, markerGrid.pad | 0);
  const cell = Math.max(6, markerGrid.cell | 0);
  const gap = Math.max(0, markerGrid.gap | 0);
  const cols = Math.max(1, markerGrid.cols | 0);
  const rows = Math.max(1, markerGrid.rows | 0);
  return {
    cols,
    rows,
    cell,
    gap,
    left: x + pad,
    top: y + pad,
    width: cols * cell + (cols - 1) * gap,
    height: rows * cell + (rows - 1) * gap,
  };
}

async function readMarkerOnce(page, markerGrid) {
  return page.evaluate(({ markerGrid }) => {
    const nowMs = Date.now();
    const grid = (() => {
      const x = markerGrid.x | 0;
      const y = markerGrid.y | 0;
      const pad = Math.max(0, markerGrid.pad | 0);
      const cell = Math.max(6, markerGrid.cell | 0);
      const gap = Math.max(0, markerGrid.gap | 0);
      const cols = Math.max(1, markerGrid.cols | 0);
      const rows = Math.max(1, markerGrid.rows | 0);
      return {
        cols,
        rows,
        cell,
        gap,
        left: x + pad,
        top: y + pad,
        width: cols * cell + (cols - 1) * gap,
        height: rows * cell + (rows - 1) * gap,
      };
    })();

    const decodeTs24 = (imageData) => {
      const d = imageData?.data;
      const w = imageData?.width | 0;
      const h = imageData?.height | 0;
      if (!d || w <= 0 || h <= 0) return null;
      if (w < grid.width || h < grid.height) return null;

      let ts24 = 0;
      for (let r = 0; r < grid.rows; r++) {
        for (let c = 0; c < grid.cols; c++) {
          const xr = c * (grid.cell + grid.gap) + Math.floor(grid.cell / 2);
          const yr = r * (grid.cell + grid.gap) + Math.floor(grid.cell / 2);
          const idx = (yr * w + xr) * 4;
          const v = (d[idx] + d[idx + 1] + d[idx + 2]) / 3;
          const bit = v > 127 ? 1 : 0;
          ts24 = (ts24 << 1) | bit;
        }
      }
      return ts24 & 0x00ffffff;
    };

    const selectCanvas = () => document.querySelector('canvas.desktop-canvas') || document.querySelector('canvas');
    const selectVideo = () => document.querySelector('video.desktop-webrtc-video') || document.querySelector('video');

    const canvas = selectCanvas();
    const video = selectVideo();
    const dims = {
      canvas: canvas ? { w: canvas.width || 0, h: canvas.height || 0 } : null,
      video: video ? { w: video.videoWidth || 0, h: video.videoHeight || 0 } : null,
      region: { left: grid.left, top: grid.top, w: grid.width, h: grid.height },
    };

    const tryReadVideo = () => {
      if (!video || video.videoWidth <= 0 || video.videoHeight <= 0) return { ok: false, error: 'no_video' };
      if (grid.left < 0 || grid.top < 0) return { ok: false, error: 'bad_coords' };
      if (grid.left + grid.width > video.videoWidth) return { ok: false, error: 'oob_video_x' };
      if (grid.top + grid.height > video.videoHeight) return { ok: false, error: 'oob_video_y' };

      const offscreen = window.__rocketPerfOffscreen || (window.__rocketPerfOffscreen = document.createElement('canvas'));
      const offctx = offscreen.getContext('2d');
      if (!offctx) return { ok: false, error: 'no_offscreen_2d' };
      if (offscreen.width !== video.videoWidth || offscreen.height !== video.videoHeight) {
        offscreen.width = video.videoWidth;
        offscreen.height = video.videoHeight;
      }
      offctx.drawImage(video, 0, 0);
      try {
        const img = offctx.getImageData(grid.left, grid.top, grid.width, grid.height);
        const ts24 = decodeTs24(img);
        return ts24 === null ? { ok: false, error: 'decode_failed', dims } : { ok: true, ts24, source: 'webrtc-video', dims };
      } catch {
        return { ok: false, error: 'getImageData_failed', dims };
      }
    };

    const tryReadCanvas = () => {
      if (!canvas || canvas.width <= 0 || canvas.height <= 0) return { ok: false, error: 'no_canvas' };
      if (grid.left < 0 || grid.top < 0) return { ok: false, error: 'bad_coords' };
      if (grid.left + grid.width > canvas.width) return { ok: false, error: 'oob_canvas_x' };
      if (grid.top + grid.height > canvas.height) return { ok: false, error: 'oob_canvas_y' };

      const ctx = canvas.getContext('2d');
      if (!ctx) return { ok: false, error: 'no_2d' };
      try {
        const img = ctx.getImageData(grid.left, grid.top, grid.width, grid.height);
        const ts24 = decodeTs24(img);
        return ts24 === null ? { ok: false, error: 'decode_failed', dims } : { ok: true, ts24, source: 'tiles-canvas', dims };
      } catch {
        return { ok: false, error: 'getImageData_failed', dims };
      }
    };

    const fromVideo = tryReadVideo();
    if (fromVideo.ok) return { nowMs, ...fromVideo };
    const fromCanvas = tryReadCanvas();
    if (fromCanvas.ok) return { nowMs, ...fromCanvas };
    return { nowMs, ok: false, error: fromVideo.error || fromCanvas.error || 'no_source', dims };
  }, { markerGrid });
}

test('desktop perf (hardware) - latency/fps/stalls', async ({ page, context }) => {
  if (process.env.ROCKET_HARDWARE_PERF !== '1') {
    test.skip(true, 'Set ROCKET_HARDWARE_PERF=1 to run hardware perf test');
  }

  const env = readEnv();
  const baseURL = env.baseURL;
  const deviceId = env.deviceId;
  const cookie = env.authCookie;

  const transport = env.transport || 'tiles';
  const durationMs = Math.max(5_000, (env.durationSec || 30) * 1000);
  const marker = env.marker || { x: 16, y: 16, pad: 8, size: 24 };
  const markerPad = Number.isFinite(marker.pad) ? marker.pad : 8;
  const markerCell = Number.isFinite(marker.size) ? marker.size : 24;
  const markerGap = Number.isFinite(marker.gap) ? marker.gap : 2;

  const markerGrid = {
    x: Math.floor(marker.x || 0),
    y: Math.floor(marker.y || 0),
    pad: Math.floor(markerPad),
    cell: Math.floor(markerCell),
    gap: Math.floor(markerGap),
    cols: 6,
    rows: 4,
  };
  test.info().annotations.push({ type: 'debug', description: `marker_grid=${JSON.stringify(markerGrid)}` });
  test.info().annotations.push({ type: 'debug', description: `marker_region=${JSON.stringify(buildRegion(markerGrid))}` });

  // Perf harness hooks (must run before app code):
  // - tiles: disable WebRTC so we strictly test the WS tile pipeline.
  if (String(transport).toLowerCase() === 'tiles') {
    await page.addInitScript(() => {
      try { delete window.RTCPeerConnection; } catch {}
      try { window.RTCPeerConnection = undefined; } catch {}
      try { delete window.RTCDataChannel; } catch {}
      try { delete window.RTCRtpReceiver; } catch {}
    });
  }

  // Auth cookie for /api/device/desktop.
  const token = String(cookie).split('=')[1] || '';
  await context.addCookies([{ name: 'Authorization', value: token, url: baseURL }]);

  await page.goto(`/mock-desktop?device=${encodeURIComponent(deviceId)}&name=Perf`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => document.body && document.body.innerText.includes('Connected'), { timeout: 30000 });
  await page.waitForTimeout(500);

  const domSnapshot = await page.evaluate(() => {
    const canvas = document.querySelector('canvas.desktop-canvas') || document.querySelector('canvas');
    const video = document.querySelector('video.desktop-webrtc-video') || document.querySelector('video');
    const text = document.body ? document.body.innerText : '';
    return {
      hasCanvas: !!canvas,
      canvasWidth: canvas ? canvas.width : 0,
      canvasHeight: canvas ? canvas.height : 0,
      hasCanvas2D: !!(canvas && canvas.getContext && canvas.getContext('2d')),
      hasVideo: !!video,
      videoWidth: video ? video.videoWidth : 0,
      videoHeight: video ? video.videoHeight : 0,
      textSnippet: text.slice(0, 500),
    };
  });
  test.info().annotations.push({ type: 'debug', description: JSON.stringify(domSnapshot) });

  // Force at least one immediate DESKTOP_SHOT via the viewer's resize handler.
  const currentViewport = page.viewportSize();
  if (currentViewport) {
    await page.setViewportSize({ width: currentViewport.width - 1, height: currentViewport.height });
    await page.setViewportSize(currentViewport);
  } else {
    await page.evaluate(() => window.dispatchEvent(new Event('resize')));
  }

  // Wait until the UI reports some FPS or bandwidth so we know frames are flowing.
  await page.waitForFunction(() => {
    const t = document.body ? document.body.innerText : '';
    const fpsMatch = t.match(/FPS\\s*(\\d+)/);
    const fps = fpsMatch ? parseInt(fpsMatch[1], 10) : 0;
    const hasBw = t.includes('BW') && !t.includes('0 B/s');
    return fps > 0 || hasBw;
  }, { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(500);

  const intervalMs = Math.max(5, parseInt(process.env.PERF_SAMPLE_INTERVAL_MS || '20', 10) || 20);
  const startedAt = Date.now();
  const deadline = startedAt + durationMs;

  const samples = [];
  const debug = {
    intervalMs,
    markerGrid,
    markerRegion: buildRegion(markerGrid),
    loops: 0,
    nullReads: 0,
    errorReads: 0,
    decodeFailures: 0,
    lastSource: 'none',
    lastDims: null,
    successfulReads: 0,
    firstTs24Values: [],
    rejectedLatencies: [],
    lastTs24: null,
    lastLatencyMs: null,
  };

  let lastSeenTs24 = null;
  let lastChangeAt = startedAt;
  let maxStallMs = 0;

  while (Date.now() < deadline) {
    debug.loops += 1;
    const nowMs = Date.now();

    // eslint-disable-next-line no-await-in-loop
    const r = await readMarkerOnce(page, markerGrid);
    debug.lastDims = r?.dims || debug.lastDims;

    if (!r) {
      debug.nullReads += 1;
      debug.errorReads += 1;
    } else if (!r.ok) {
      debug.errorReads += 1;
      if (r.error === 'decode_failed') debug.decodeFailures += 1;
    } else {
      debug.successfulReads += 1;
      debug.lastSource = r.source || debug.lastSource;
      debug.lastTs24 = r.ts24;
      // Track first few ts24 values for debugging
      if (debug.firstTs24Values.length < 10) {
        debug.firstTs24Values.push(r.ts24);
      }
      if (r.ts24 !== lastSeenTs24) {
        lastSeenTs24 = r.ts24;
        lastChangeAt = nowMs;
        const markerMs = unwrapTs24(nowMs, r.ts24);
        const latencyMs = nowMs - markerMs;
        debug.lastLatencyMs = latencyMs;
        if (latencyMs >= 0 && latencyMs < 10_000) {
          samples.push({ nowMs, ts24: r.ts24, latencyMs, source: r.source });
        } else {
          // Track rejected latencies for debugging
          if (debug.rejectedLatencies.length < 10) {
            debug.rejectedLatencies.push({ ts24: r.ts24, latencyMs, nowMs, markerMs });
          }
        }
      }
    }

    const stallMs = nowMs - lastChangeAt;
    if (stallMs > maxStallMs) maxStallMs = stallMs;

    // eslint-disable-next-line no-await-in-loop
    await page.waitForTimeout(intervalMs);
  }

  const elapsedSec = Math.max(0.001, (Date.now() - startedAt) / 1000);
  const distinctFrames = new Set(samples.map((s) => s.ts24)).size;
  const fpsApprox = distinctFrames / elapsedSec;

  const results = {
    durationMs,
    elapsedSec,
    samples,
    sampleCount: samples.length,
    distinctFrames,
    fpsApprox,
    maxStallMs,
    lastSource: debug.lastSource,
    readErrors: debug.errorReads,
    debug,
  };

  // Get WebSocket-level diagnostics from browser
  const diagnostics = await page.evaluate(() => {
    const dbg = window.__rocketDesktopDebug || {};
    return {
      wsMessageCount: dbg.wsMessageCount || 0,
      lastWsDataType: dbg.lastWsDataType || null,
      lastWsDataLen: dbg.lastWsDataLen || 0,
      lastWsHeader: dbg.lastWsHeader || null,
      renderBlocksCalls: dbg.renderBlocksCalls || 0,
      parseMessageFrames: dbg.parseMessageFrames || 0,
      lastHasResolution: dbg.lastHasResolution,
      bufferedFrames: dbg.bufferedFrames || 0,
      directRenderCalls: dbg.directRenderCalls || 0,
      lastRenderBlocks: dbg.lastRenderBlocks || null,
      blockStats: dbg.blockStats || null,
    };
  });
  console.log('[perf] diagnostics', JSON.stringify(diagnostics, null, 2));

  // Always print key diagnostics; this suite is opt-in and used for debugging.
  // eslint-disable-next-line no-console
  console.log('[perf] results', JSON.stringify({
    fpsApprox: results.fpsApprox,
    distinctFrames: results.distinctFrames,
    sampleCount: results.sampleCount,
    readErrors: results.readErrors,
    maxStallMs: results.maxStallMs,
    lastSource: results.lastSource,
    debug: results.debug,
  }, null, 2));

  test.info().annotations.push({ type: 'debug', description: `readErrors=${results.readErrors}` });
  expect(results.sampleCount).toBeGreaterThan(50);

  const latencies = results.samples.map((s) => s.latencyMs).sort((a, b) => a - b);
  const p50 = quantile(latencies, 0.5);
  const p95 = quantile(latencies, 0.95);
  const p99 = quantile(latencies, 0.99);
  const max = latencies[latencies.length - 1] || 0;

  const thresholds = env.thresholds || {};
  const minFps = thresholds.minFps || 15;
  const maxStall = thresholds.maxStallMs || 800;
  const maxP95 = thresholds.p95Ms || 150;
  const maxP99 = thresholds.p99Ms || 250;
  const maxMax = thresholds.maxMs || 500;

  test.info().annotations.push(
    { type: 'perf', description: `source=${results.lastSource}` },
    { type: 'perf', description: `fps÷${results.fpsApprox.toFixed(1)} distinct=${results.distinctFrames} samples=${results.sampleCount}` },
    { type: 'perf', description: `lat_ms p50=${p50.toFixed(1)} p95=${p95.toFixed(1)} p99=${p99.toFixed(1)} max=${max.toFixed(1)}` },
    { type: 'perf', description: `max_stall_ms=${results.maxStallMs.toFixed(0)}` },
  );

  expect(results.fpsApprox).toBeGreaterThanOrEqual(minFps);
  expect(results.maxStallMs).toBeLessThanOrEqual(maxStall);
  expect(p95).toBeLessThanOrEqual(maxP95);
  expect(p99).toBeLessThanOrEqual(maxP99);
  expect(max).toBeLessThanOrEqual(maxMax);
});
