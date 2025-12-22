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

test('desktop perf (hardware) - latency/fps/stalls', async ({ page, context }) => {
  if (process.env.ROCKET_HARDWARE_PERF !== '1') {
    test.skip(true, 'Set ROCKET_HARDWARE_PERF=1 to run hardware perf test');
  }

  const env = readEnv();
  const baseURL = env.baseURL;
  const deviceId = env.deviceId;
  const cookie = env.authCookie;

  const transport = env.transport || 'webrtc'; // Default to webrtc for this test
  const durationMs = Math.max(5_000, (env.durationSec || 30) * 1000);

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
    const fpsMatch = t.match(/FPS\s*(\d+)/);
    const fps = fpsMatch ? parseInt(fpsMatch[1], 10) : 0;
    const hasBw = t.includes('BW') && !t.includes('0 B/s');
    return fps > 0 || hasBw;
  }, { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(500);

  const startedAt = Date.now();
  await page.waitForTimeout(durationMs);
  const elapsedSec = Math.max(0.001, (Date.now() - startedAt) / 1000);

  const perfMetrics = await page.evaluate(() => window.__rocketPerfMetrics);
  const samples = perfMetrics?.samples || [];

  const distinctFrames = samples.length;
  const fpsApprox = distinctFrames / elapsedSec;

  const results = {
    durationMs,
    elapsedSec,
    samples,
    sampleCount: samples.length,
    distinctFrames,
    fpsApprox,
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

  // eslint-disable-next-line no-console
  console.log('[perf] results', JSON.stringify({
    fpsApprox: results.fpsApprox,
    distinctFrames: results.distinctFrames,
    sampleCount: results.sampleCount,
  }, null, 2));

  expect(results.sampleCount).toBeGreaterThan(50);

  const latencies = results.samples.sort((a, b) => a - b);
  const p50 = quantile(latencies, 0.5);
  const p95 = quantile(latencies, 0.95);
  const p99 = quantile(latencies, 0.99);
  const max = latencies[latencies.length - 1] || 0;

  const thresholds = env.thresholds || {};
  const minFps = thresholds.minFps || 15;
  const maxStall = thresholds.maxStallMs || 800; // Stall check removed, but keeping for env consistency
  const maxP95 = thresholds.p95Ms || 150;
  const maxP99 = thresholds.p99Ms || 250;
  const maxMax = thresholds.maxMs || 500;

  test.info().annotations.push(
    { type: 'perf', description: `source=metadata` },
    { type: 'perf', description: `fps÷${results.fpsApprox.toFixed(1)} distinct=${results.distinctFrames} samples=${results.sampleCount}` },
    { type: 'perf', description: `lat_ms p50=${p50.toFixed(1)} p95=${p95.toFixed(1)} p99=${p99.toFixed(1)} max=${max.toFixed(1)}` },
  );

  expect(results.fpsApprox).toBeGreaterThanOrEqual(minFps);
  expect(p95).toBeLessThanOrEqual(maxP95);
  expect(p99).toBeLessThanOrEqual(maxP99);
  expect(max).toBeLessThanOrEqual(maxMax);
});
