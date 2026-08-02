import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the accessibility (axe-core) gate.
 * Serves the built app via `vite preview` on a unique port and scans it in a
 * single Chromium project in the dark (default) color scheme.
 */

const PORT = 4222;
const BASE = '/crypto-lab-drbg-arena/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Build before serving. `vite preview` only serves whatever already sits in
    // dist/, so without this the suite can pass against a stale bundle — even one
    // built before a source change that no longer compiles. Building here makes a
    // failed build abort the run instead of silently going green.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
