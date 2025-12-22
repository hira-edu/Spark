// @ts-check
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: /.*perf\.hardware\.spec\.js$/,

  timeout: parseInt(process.env.PERF_TEST_TIMEOUT_MS || '600000', 10),

  fullyParallel: false,
  workers: 1,
  retries: 0,

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report-perf' }],
  ],

  use: {
    baseURL: process.env.BASE_URL || 'http://localhost:18080',
    headless: process.env.PERF_HEADED === '1' ? false : true,
    launchOptions: {
      args: [
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-renderer-backgrounding',
        '--disable-features=WebRtcHideLocalIpsWithMdns',
      ],
    },
    video: 'retain-on-failure',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  globalSetup: './e2e/perf-global-setup.js',
});
