import { test as base, expect } from '@playwright/test';
import { existsSync, readFileSync } from 'fs';
import path from 'path';

const STATE_DIR = path.join(process.cwd(), '.playwright');
const ENV_FILE = path.join(STATE_DIR, 'e2e-env.json');

function loadEnv() {
  if (!existsSync(ENV_FILE)) {
    throw new Error(`E2E env file not found: ${ENV_FILE}. Did global-setup run?`);
  }
  const raw = readFileSync(ENV_FILE, 'utf-8');
  return JSON.parse(raw);
}

class RocketE2EController {
  constructor(env) {
    this.env = env;
  }

  #baseURL() {
    const baseURL = this.env.baseURL || process.env.BASE_URL || 'http://localhost:18080';
    return baseURL;
  }

  getAuthCookie() {
    const raw = String(this.env.authCookie || '');
    const parts = raw.split('=');
    const value = parts.length >= 2 ? parts.slice(1).join('=').trim() : '';
    if (!value) return null;
    return {
      url: this.#baseURL(),
      name: 'Authorization',
      value,
      httpOnly: true,
    };
  }

  buildDeviceURL(params = {}) {
    const url = new URL(`${this.#baseURL()}/mock-desktop`);
    url.searchParams.set('device', this.env.deviceId);
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, String(v));
    }
    return url.toString();
  }

  readAgentLog() {
    const p = this.env.agentLogPath;
    if (!p || !existsSync(p)) return '';
    try {
      return readFileSync(p, 'utf-8');
    } catch {
      return '';
    }
  }

  async waitForAgentLog(pattern, timeoutMs = 5000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const content = this.readAgentLog();
      const ok = pattern instanceof RegExp ? pattern.test(content) : content.includes(String(pattern));
      if (ok) return true;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`Timed out waiting for agent log pattern: ${pattern}`);
  }
}

export const test = base.extend({
  rocket: async ({}, use) => {
    const env = loadEnv();
    await use(new RocketE2EController(env));
  },
});

export { expect };
