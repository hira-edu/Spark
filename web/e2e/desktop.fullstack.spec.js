/**
 * Rocket Desktop Full-Stack E2E (browser ↔ Rocket server ↔ mock agent)
 *
 * Uses a guest share token created in `global-setup.js`.
 */
import { test, expect } from './fixtures/rocketStack.js';

test.describe('Desktop Full-Stack (Device WS)', () => {
  test('renders frames and forwards input events', async ({ page, rocket }) => {
    const cookie = rocket.getAuthCookie();
    if (cookie) {
      await page.context().addCookies([cookie]);
    }

    await page.goto(rocket.buildDeviceURL({ control: 'true', name: 'E2E Device' }));

    const canvas = page.locator('canvas');
    await expect(canvas).toBeVisible({ timeout: 15000 });

    // Wait for at least one non-black pixel to prove decode/render happened.
    await page.waitForFunction(() => {
      const c = document.querySelector('canvas');
      if (!c || c.width === 0 || c.height === 0) return false;
      const ctx = c.getContext('2d');
      if (!ctx) return false;
      const x = Math.min(10, c.width - 1);
      const y = Math.min(10, c.height - 1);
      const data = ctx.getImageData(x, y, 1, 1).data;
      return (data[0] | data[1] | data[2]) !== 0;
    }, { timeout: 15000 });

    // Give latency ping a chance to update (every 5s).
    await page.waitForTimeout(6500);

    const statusText = await page.locator('.connection-status').innerText().catch(() => '');
    expect(statusText.toLowerCase()).toContain('connected');

    // Input: click + move + type should be forwarded to the agent.
    await canvas.click({ timeout: 5000 });
    await page.mouse.move(120, 120);
    await page.keyboard.press('a');

    await rocket.waitForAgentLog(/INPUT_RECEIVED/, 8000);
  });
});
