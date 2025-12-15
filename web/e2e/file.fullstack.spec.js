/**
 * Rocket File Explorer Full-Stack E2E (browser ↔ Rocket server ↔ mock agent)
 *
 * Exercises the device file API endpoints against the mock agent's sandboxed filesystem.
 */
import { test, expect } from './fixtures/rocketStack.js';

function cookieHeader(rocket) {
  const cookie = rocket.getAuthCookie();
  if (!cookie) return {};
  return { cookie: `${cookie.name}=${cookie.value}` };
}

test.describe('File Explorer Full-Stack (Device WS)', () => {
  test('mkdir + upload + copy + move + remove', async ({ request, rocket }) => {
    const baseURL = rocket.env.baseURL || process.env.BASE_URL || 'http://localhost:18080';
    const device = rocket.env.deviceId;
    expect(device).toBeTruthy();

    const nonce = rocket.env.nonce || String(Date.now());
    const dir = `/e2e-${nonce}`;
    const file = 'hello.txt';
    const content = Buffer.from(`hello-${nonce}\n`, 'utf-8');

    // mkdir
    const mkdirRes = await request.post(`${baseURL}/api/device/file/mkdir`, {
      headers: cookieHeader(rocket),
      form: { device, path: dir },
    });
    if (!mkdirRes.ok()) {
      // eslint-disable-next-line no-console
      console.log('mkdir failed', mkdirRes.status(), await mkdirRes.text());
    }
    expect(mkdirRes.ok()).toBeTruthy();
    const mkdirJSON = await mkdirRes.json();
    expect(mkdirJSON.code).toBe(0);

    // upload
    const uploadRes = await request.post(
      `${baseURL}/api/device/file/upload?device=${encodeURIComponent(device)}&path=${encodeURIComponent(dir)}&file=${encodeURIComponent(file)}`,
      {
        headers: {
          ...cookieHeader(rocket),
          'content-type': 'application/octet-stream',
        },
        data: content,
      }
    );
    expect(uploadRes.ok()).toBeTruthy();
    const uploadJSON = await uploadRes.json();
    expect(uploadJSON.code).toBe(0);

    // list
    const listRes = await request.post(`${baseURL}/api/device/file/list`, {
      headers: cookieHeader(rocket),
      form: { device, path: dir },
    });
    expect(listRes.ok()).toBeTruthy();
    const listJSON = await listRes.json();
    expect(listJSON.code).toBe(0);
    const files = listJSON?.data?.files || [];
    expect(files.some((f) => f?.name === file)).toBeTruthy();

    // copy
    const copyRes = await request.post(`${baseURL}/api/device/file/copy`, {
      headers: cookieHeader(rocket),
      form: { device, src: `${dir}/${file}`, dst: `${dir}/copy-${file}` },
    });
    expect(copyRes.ok()).toBeTruthy();
    const copyJSON = await copyRes.json();
    expect(copyJSON.code).toBe(0);

    // move
    const moveRes = await request.post(`${baseURL}/api/device/file/move`, {
      headers: cookieHeader(rocket),
      form: { device, src: `${dir}/copy-${file}`, dst: `${dir}/moved-${file}` },
    });
    expect(moveRes.ok()).toBeTruthy();
    const moveJSON = await moveRes.json();
    expect(moveJSON.code).toBe(0);

    // remove
    const rmRes = await request.post(`${baseURL}/api/device/file/remove`, {
      headers: cookieHeader(rocket),
      form: { device, files: [`${dir}/${file}`, `${dir}/moved-${file}`, dir] },
    });
    expect(rmRes.ok()).toBeTruthy();
    const rmJSON = await rmRes.json();
    expect(rmJSON.code).toBe(0);
  });
});
