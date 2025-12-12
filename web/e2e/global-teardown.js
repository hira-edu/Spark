/**
 * Playwright Global Teardown
 * Runs once after all tests
 */
import { stopMockDevice } from './utils/mockServer.js';

export default async function globalTeardown() {
  console.log('[Teardown] Cleaning up E2E test environment...');

  // Kill mock device process if running
  try {
    stopMockDevice('[Teardown]');
  } catch (err) {
    console.log('[Teardown] Mock device stop skipped:', err?.message || err);
  }

  console.log('[Teardown] Cleanup complete');
}
