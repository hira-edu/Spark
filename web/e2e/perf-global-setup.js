import { mkdirSync, writeFileSync } from 'fs';
import path from 'path';

const BASE_URL = process.env.BASE_URL || 'http://localhost:18080';
const STATE_DIR = path.join(process.cwd(), '.playwright');
const ENV_FILE = path.join(STATE_DIR, 'perf-env.json');

function parseCookie(setCookieHeader) {
  if (!setCookieHeader) return '';
  const first = String(setCookieHeader).split(';')[0] || '';
  return first.trim();
}

async function postJSON(url, body, { cookie } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (cookie) headers.cookie = cookie;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body || {}),
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { res, text, json };
}

async function waitForServer(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${BASE_URL}/`);
      if (res.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`Server at ${BASE_URL} not ready`);
}

async function createAuthSession() {
  const { res, json } = await postJSON(`${BASE_URL}/api/auth/login`, { username: 'admin', password: 'admin123' });
  const cookie = parseCookie(res.headers.get('set-cookie'));
  if (!cookie || !cookie.startsWith('Authorization=')) {
    throw new Error(`Login failed (status=${res.status}, code=${json?.code})`);
  }
  return { cookie, token: cookie.split('=')[1] || '' };
}

async function waitForAnyDevice(cookie, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { json } = await postJSON(`${BASE_URL}/api/device/list`, {}, { cookie }).catch(() => ({ json: null }));
    const data = json?.data || null;
    if (json?.code === 0 && data && typeof data === 'object') {
      const keys = Object.keys(data);
      if (keys.length > 0) {
        const info = data[keys[0]] || {};
        const deviceId = info?.id || keys[0];
        return { deviceId, info };
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Timed out waiting for a device to register');
}

export default async function globalSetup() {
  await waitForServer(30000);
  const { cookie, token } = await createAuthSession();
  const { deviceId } = await waitForAnyDevice(cookie, 45000);

  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(ENV_FILE, JSON.stringify({
    baseURL: BASE_URL,
    authCookie: cookie,
    authToken: token,
    deviceId,
    marker: {
      x: parseInt(process.env.PERF_MARKER_X || '16', 10) || 16,
      y: parseInt(process.env.PERF_MARKER_Y || '16', 10) || 16,
      pad: parseInt(process.env.PERF_MARKER_PAD || '8', 10) || 8,
      size: parseInt(process.env.PERF_MARKER_SIZE || '24', 10) || 24,
      gap: parseInt(process.env.PERF_MARKER_GAP || '2', 10) || 2,
    },
    durationSec: parseInt(process.env.PERF_DURATION_SEC || '30', 10) || 30,
    transport: process.env.PERF_TRANSPORT || 'tiles',
    thresholds: {
      minFps: parseFloat(process.env.PERF_MIN_FPS || '15') || 15,
      p95Ms: parseFloat(process.env.PERF_MAX_P95_MS || '150') || 150,
      p99Ms: parseFloat(process.env.PERF_MAX_P99_MS || '250') || 250,
      maxMs: parseFloat(process.env.PERF_MAX_MAX_MS || '500') || 500,
      maxStallMs: parseFloat(process.env.PERF_MAX_STALL_MS || '800') || 800,
    },
  }, null, 2));
}
