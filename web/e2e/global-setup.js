/**
 * Playwright Global Setup
 * Runs once before all tests
 */
import { existsSync } from 'fs';
import path from 'path';
import { ensureMockDeviceRunning } from './utils/mockServer.js';

const SERVER_URL = process.env.BASE_URL || 'http://localhost:18080';

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

export default async function globalSetup() {
  console.log('[Setup] Starting Rocket E2E test environment...');

  // Check if server is already running
  try {
    await waitForServer(SERVER_URL, 5000);
    console.log('[Setup] Server already running at', SERVER_URL);
  } catch (e) {
    console.log('[Setup] Server not running - tests will use webServer config');
  }

  // Start mock device if test_client exists
  const testClientPath = path.join(process.cwd(), '..', 'test_client.go');
  if (existsSync(testClientPath)) {
    try {
      const result = await ensureMockDeviceRunning({
        logPrefix: '[Setup]',
        waitTimeout: 15000,
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

  console.log('[Setup] E2E environment ready');
}
