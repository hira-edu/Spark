/**
 * Rocket Terminal Full-Stack E2E (browser ↔ Rocket server ↔ mock agent)
 *
 * Validates terminal WebSocket handshake and raw stream echo.
 */
import { test, expect } from './fixtures/rocketStack.js';

function randomHex(len) {
  const alphabet = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}

test.describe('Terminal Full-Stack (Device WS)', () => {
  test('connects and echoes raw input', async ({ page, rocket }) => {
    const cookie = rocket.getAuthCookie();
    if (cookie) {
      await page.context().addCookies([cookie]);
    }

    const base = new URL(rocket.env.baseURL || process.env.BASE_URL || 'http://localhost:18080');
    const wsURL = new URL(`${base.protocol === 'https:' ? 'wss:' : 'ws:'}//${base.host}/api/device/terminal`);
    wsURL.searchParams.set('device', rocket.env.deviceId);
    wsURL.searchParams.set('secret', randomHex(32));

    await page.goto(`${base.origin}/mock-desktop?device=${encodeURIComponent(rocket.env.deviceId)}&name=TerminalE2E`);

    const echoed = await page.evaluate((url) => {
      return new Promise((resolve, reject) => {
        const ws = new WebSocket(url);
        ws.binaryType = 'arraybuffer';

        const timeout = setTimeout(() => reject(new Error('terminal timeout')), 15000);
        const decoder = new TextDecoder();

        const sendRaw = (text) => {
          const payload = new TextEncoder().encode(text);
          const len = payload.length;
          const buf = new Uint8Array(8 + len);
          // magic(4) + service(21) + op(0) + length(2) + payload
          buf.set([34, 22, 19, 17, 21, 0, (len >> 8) & 0xff, len & 0xff], 0);
          buf.set(payload, 8);
          ws.send(buf);
        };

        ws.onopen = () => {
          // Wait for welcome first, then send an input line.
          sendRaw('ping\n');
        };

        ws.onmessage = (e) => {
          const data = new Uint8Array(e.data);
          // Expect full header: magic(4)+service+op+event(16)+len(2)+payload
          if (data.length >= 24 && data[0] === 34 && data[4] === 21 && data[5] === 0) {
            const payload = data.slice(24);
            const text = decoder.decode(payload);
            if (text.includes('[echo]')) {
              clearTimeout(timeout);
              ws.close();
              resolve(text);
            }
          }
        };

        ws.onerror = () => reject(new Error('terminal websocket error'));
      });
    }, wsURL.toString());

    expect(String(echoed)).toContain('[echo]');
  });
});

