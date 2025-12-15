/**
 * Rocket Audio Full-Stack E2E (browser ↔ Rocket server ↔ mock agent)
 *
 * Validates audio WebSocket control path and that AUDIO_DATA packets reach the browser WS.
 */
import { test, expect } from './fixtures/rocketStack.js';

test.describe('Audio Full-Stack (Device WS)', () => {
  test('lists devices and receives audio packets', async ({ page, rocket }) => {
    const cookie = rocket.getAuthCookie();
    if (cookie) {
      await page.context().addCookies([cookie]);
    }

    const base = new URL(rocket.env.baseURL || process.env.BASE_URL || 'http://localhost:18080');
    const wsURL = new URL(`${base.protocol === 'https:' ? 'wss:' : 'ws:'}//${base.host}/api/device/audio`);
    wsURL.searchParams.set('device', rocket.env.deviceId);

    await page.goto(`${base.origin}/mock-desktop?device=${encodeURIComponent(rocket.env.deviceId)}&name=AudioE2E`);

    const result = await page.evaluate((url) => {
      return new Promise((resolve, reject) => {
        const ws = new WebSocket(url);
        ws.binaryType = 'arraybuffer';

        const decoder = new TextDecoder();
        const timeout = setTimeout(() => reject(new Error('audio timeout')), 15000);

        let gotList = false;
        let gotPacket = false;

        ws.onopen = () => {
          ws.send(JSON.stringify({ act: 'AUDIO_LIST' }));
          ws.send(JSON.stringify({ act: 'AUDIO_SELECT', data: { device: 'default', mode: 'output' } }));
        };

        ws.onmessage = (e) => {
          const bytes = new Uint8Array(e.data);
          // Control messages are framed: magic(4)+service(23)+op(5)+json
          if (bytes.length >= 6 && bytes[0] === 34 && bytes[4] === 23 && bytes[5] === 5) {
            try {
              const json = JSON.parse(decoder.decode(bytes.slice(6)));
              if (json?.act === 'AUDIO_LIST') {
                gotList = true;
              }
            } catch {
              // ignore
            }
          } else if (bytes.length > 0) {
            // Raw packets forwarded by broadcastAudioPacket().
            gotPacket = true;
          }

          if (gotList && gotPacket) {
            clearTimeout(timeout);
            ws.close();
            resolve({ gotList, gotPacket });
          }
        };

        ws.onerror = () => reject(new Error('audio websocket error'));
      });
    }, wsURL.toString());

    expect(result.gotList).toBeTruthy();
    expect(result.gotPacket).toBeTruthy();
  });
});

