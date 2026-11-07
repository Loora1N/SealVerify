import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', testMatch: '**/*.local.js', workers: 1, timeout: 60_000,
  expect: { timeout: 15_000 },
  use: { viewport: { width: 1440, height: 1000 }, screenshot: 'off', trace: 'off', video: 'off' },
  outputDir: '../local-data/private-browser-results', reporter: 'list',
});
