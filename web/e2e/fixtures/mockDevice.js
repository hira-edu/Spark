import { test as base } from '@playwright/test';
import { ensureMockDeviceRunning } from '../utils/mockServer.js';

const MOCK_PORT = process.env.MOCK_DEVICE_PORT;
const MOCK_HTTP = process.env.MOCK_DEVICE_HTTP || (MOCK_PORT ? `http://127.0.0.1:${MOCK_PORT}` : null);
const MOCK_WS = process.env.MOCK_DEVICE_WS || (MOCK_PORT ? `ws://127.0.0.1:${MOCK_PORT}/mock-desktop` : null);

class MockDeviceController {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.onConnectionError = null;
  }

  async ready(timeout = 5000) {
    if (!this.baseUrl) return;
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const res = await fetch(`${this.baseUrl}/mock/health`);
        if (res.ok) return;
      } catch (err) {
        // Retry
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error('Mock device server did not become ready in time');
  }

  async waitForClient(count = 1, timeout = 5000) {
    if (!this.baseUrl) return;
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const info = await this.getHealth();
      if ((info?.clients || 0) >= count) return;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error(`Timed out waiting for ${count} mock device client(s)`);
  }

  async getHealth() {
    if (!this.baseUrl) return {};
    const res = await fetch(`${this.baseUrl}/mock/health`);
    if (!res.ok) return {};
    return res.json();
  }

  async sendInit(width = 1920, height = 1080) {
    return this.#post('/mock/init', { width, height });
  }

  async sendResolution(width, height) {
    return this.#post('/mock/resolution', { width, height });
  }

  async sendTestFrame(options = {}) {
    return this.#post('/mock/frame', options);
  }

  async sendPong(source = 'device') {
    return this.#post('/mock/pong', { source });
  }

  async sendCursor(data) {
    return this.#post('/mock/cursor', data || {});
  }

  async enableAutoFrames(intervalMs = 500, color = '#3478ff') {
    return this.#post('/mock/auto', { enabled: true, interval_ms: intervalMs, color });
  }

  async disableAutoFrames() {
    return this.#post('/mock/auto', { enabled: false });
  }

  async simulateDisconnect(code = 1006, reason = 'Test disconnect') {
    return this.#post('/mock/disconnect', { code, reason });
  }

  async fetchInputEvents() {
    if (!this.baseUrl) return [];
    const res = await fetch(`${this.baseUrl}/mock/events`);
    if (!res.ok) return [];
    const payload = await res.json();
    return payload?.events || [];
  }

  async resetEvents() {
    return this.#post('/mock/reset', {});
  }

  async #post(path, body) {
    if (!this.baseUrl) return;
    const url = `${this.baseUrl}${path}`;
    const request = async () => {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body || {}),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Mock device request failed: ${res.status} ${text}`);
      }
      try {
        return await res.json();
      } catch (err) {
        return {};
      }
    };

    try {
      return await request();
    } catch (err) {
      const connectionRefused =
        err?.cause?.code === 'ECONNREFUSED' ||
        (typeof err?.message === 'string' && err.message.includes('ECONNREFUSED'));
      if (connectionRefused && typeof this.onConnectionError === 'function') {
        await this.onConnectionError(err);
        return request();
      }
      throw err;
    }
  }

  setConnectionErrorHandler(handler) {
    this.onConnectionError = handler;
  }
}

export const test = base.extend({
  mockDevice: async ({ page }, use) => {
    const controller = new MockDeviceController(MOCK_HTTP);
    const targetPort = MOCK_PORT || '18081';

    // Patch WebSocket to redirect device desktop connections to mock server
    if (MOCK_WS) {
      await page.addInitScript(({ wsUrl }) => {
        const OriginalWebSocket = window.WebSocket;
        window.WebSocket = function patchedWebSocket(url, protocols) {
          const target =
            typeof url === 'string' &&
            (url.includes('/api/device/desktop') || url.includes('/api/share/desktop'))
              ? wsUrl
              : url;
          const socket = new OriginalWebSocket(target, protocols);
          if (target === wsUrl) {
            window.__testWsRef = socket;
          }
          return socket;
        };
        window.WebSocket.prototype = OriginalWebSocket.prototype;
        Object.assign(window.WebSocket, OriginalWebSocket);
      }, { wsUrl: MOCK_WS });
    } else {
      await page.addInitScript(() => {
        const OriginalWebSocket = window.WebSocket;
        window.WebSocket = function patchedWebSocket(url, protocols) {
          const socket = new OriginalWebSocket(url, protocols);
          window.__testWsRef = socket;
          return socket;
        };
        window.WebSocket.prototype = OriginalWebSocket.prototype;
        Object.assign(window.WebSocket, OriginalWebSocket);
      });
    }

    // On connection error, try to restart the mock server
    controller.setConnectionErrorHandler(async () => {
      console.warn('[MockDevice] Mock server unreachable, attempting restart...');
      await ensureMockDeviceRunning({ port: targetPort, forceRestart: true, logPrefix: '[Fixture]' });
    });

    // Wait for mock server to be ready (global-setup should have started it)
    try {
      await controller.ready(8000);
    } catch (err) {
      // If not ready, try to start it
      console.warn('[MockDevice] Server not ready, starting...', err?.message);
      await ensureMockDeviceRunning({ port: targetPort, logPrefix: '[Fixture]' });
      await controller.ready(8000);
    }

    await use(controller);
  },
});

export { expect } from '@playwright/test';
