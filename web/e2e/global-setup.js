/**
 * Playwright Global Setup
 * Runs once before all tests
 */
import { existsSync, mkdirSync, writeFileSync } from 'fs';
import path from 'path';
import { ensureMockDeviceRunning } from './utils/mockServer.js';
import { ensureMockAgentRunning, getMockAgentLogPath } from './utils/mockAgent.js';

const SERVER_URL = process.env.BASE_URL || 'http://localhost:18080';
const STATE_DIR = path.join(process.cwd(), '.playwright');
const ENV_FILE = path.join(STATE_DIR, 'e2e-env.json');

async function waitForServer(url, timeout = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const response = await fetch(url);
      if (response.ok) return true;
    } catch (e) {
      // Server not ready yet
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`Server at ${url} did not start within ${timeout}ms`);
}

function parseCookie(setCookieHeader) {
  if (!setCookieHeader) return '';
  // Get first "name=value" segment before ';'
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

async function createAuthSession() {
  const loginUrl = `${SERVER_URL}/api/auth/login`;
  const { res, json } = await postJSON(loginUrl, { username: 'admin', password: 'admin123' });
  const setCookie = res.headers.get('set-cookie');
  const cookie = parseCookie(setCookie);
  if (!cookie || !cookie.startsWith('Authorization=')) {
    throw new Error(`Login failed or missing Authorization cookie (status=${res.status}, code=${json?.code})`);
  }
  return { cookie, token: cookie.split('=')[1] || '' };
}

async function fetchDevices(cookie, timeoutMs = 15000) {
  const url = `${SERVER_URL}/api/device/list`;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { json } = await postJSON(url, null, { cookie }).catch(() => ({ json: null }));
    const data = json?.data || null;
    if (json?.code === 0 && data && typeof data === 'object' && Object.keys(data).length > 0) {
      const connUUID = Object.keys(data)[0];
      const info = data[connUUID] || {};
      const deviceID = info?.id || '';
      return { connUUID, deviceID, info };
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('Timed out waiting for a device to register');
}

function randomHex(len) {
  const alphabet = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < len; i++) {
    out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

export default async function globalSetup() {
  console.log('[Setup] Starting Rocket E2E test environment...');

  await waitForServer(SERVER_URL, 30000);
  console.log('[Setup] Server ready at', SERVER_URL);

  // Start mock device if test_client exists
  const testClientPath = path.join(process.cwd(), '..', 'test_client.go');
  if (existsSync(testClientPath)) {
    try {
      const result = await ensureMockDeviceRunning({
        logPrefix: '[Setup]',
        waitTimeout: 15000,
        forceRestart: true,
      });
      if (result.alreadyRunning) {
        console.log(`[Setup] Mock device already running on port ${result.port}`);
      } else {
        console.log(`[Setup] Mock device started on port ${result.port} (PID ${result.pid})`);
      }
    } catch (err) {
      console.error('[Setup] Failed to start mock device:', err?.message || err);
      throw err;
    }
  } else {
    console.log('[Setup] No test_client.go found - skipping mock device');
  }

  // Start a real mock agent connected to Rocket (for full-stack share tests).
  const agentLogPath = getMockAgentLogPath();
  await ensureMockAgentRunning({
    host: '127.0.0.1',
    port: Number(new URL(SERVER_URL).port || 18080),
    salt: 'testsalt1234567890123',
    uuidHex: '00112233445566778899aabbccddeeff',
    logPrefix: '[Setup]',
    forceRestart: true,
  });

  // Auth + create share token for guest WebSocket E2E tests.
  const { cookie } = await createAuthSession();
  const device = await fetchDevices(cookie, 20000);

  // Persist env for fixtures/tests.
  if (!existsSync(STATE_DIR)) {
    mkdirSync(STATE_DIR, { recursive: true });
  }
  const payload = {
    baseURL: SERVER_URL,
    authCookie: cookie,
    deviceId: device.deviceID || device.connUUID,
    agentLogPath,
    // Convenience nonce for tests that need random strings (kept in one place for reproducibility).
    nonce: randomHex(12),
  };
  writeFileSync(ENV_FILE, JSON.stringify(payload, null, 2));
  console.log('[Setup] Wrote E2E env to', ENV_FILE);

  console.log('[Setup] E2E environment ready');
}
