// @ts-check
import { defineConfig, devices } from '@playwright/test';

/**
 * Rocket E2E Test Configuration
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: './e2e',

  /* Run tests sequentially - WebSocket state requires this */
  fullyParallel: false,

  /* Fail the build on CI if you accidentally left test.only in the source code */
  forbidOnly: !!process.env.CI,

  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,

  /* Single worker for WebSocket state consistency */
  workers: 1,

  /* Reporter to use */
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['list'],
  ],

  /* Shared settings for all the projects below */
  use: {
    /* Base URL to use in actions like `await page.goto('/')` */
    baseURL: process.env.BASE_URL || 'http://localhost:18080',

    /* Collect trace on first retry */
    trace: 'on-first-retry',

    /* Capture video on failure */
    video: 'retain-on-failure',

    /* Screenshot on failure */
    screenshot: 'only-on-failure',
  },

  /* Timeouts */
  timeout: 30000,
  expect: {
    timeout: 5000,
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    // Uncomment to test on Firefox
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },
  ],

  /* Run Rocket server before starting the tests */
  webServer: {
    command: process.platform === 'win32'
      ? 'go run ..\\\\server -config ..\\\\config.e2e.json'
      : 'go run ../server -config ../config.e2e.json',
    url: process.env.BASE_URL || 'http://localhost:18080',
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
  },

  /* Global setup/teardown */
  globalSetup: './e2e/global-setup.js',
  globalTeardown: './e2e/global-teardown.js',
});
