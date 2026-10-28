import {defineConfig} from '@playwright/test';

/**
 * TraceBack Playwright configuration (T09/T10/T11).
 *
 * Default suite (`npm run test:e2e`) is fully self-contained:
 *  - a Vite dev server is started on 127.0.0.1:4173 (`webServer` below);
 *  - every `/api/v1/**` request is intercepted in-test with the synthetic
 *    `src/test/fixtures.json` bundle (`e2e/support/fixtures.ts`);
 *  - no real backend and no real AIT-ADS dataset are required.
 *
 * Real-dataset tests are tagged `@real`, declared inside `test.describe(...)`
 * guarded by `test.skip(!realEnabled, ...)`, and can only run with:
 *   TRACEBACK_REAL_DATA=1 TRACEBACK_WEB_URL=http://127.0.0.1:8000 npm run test:e2e:real
 *
 * Browser: Playwright's bundled Chromium may be missing on this machine, so the
 * installed Google Chrome is used by default (`channel: 'chrome'`). Override the
 * binary with `TRACEBACK_BROWSER_EXECUTABLE=/path/to/chrome`.
 */
const realMode = process.env.TRACEBACK_REAL_DATA === '1';
const externalWebUrl = process.env.TRACEBACK_WEB_URL;
// 4173 is the documented preferred port, but this shared workspace also runs
// preview servers for other UI experiments; 4174 is the documented fallback.
// Override with TRACEBACK_E2E_PORT when both are taken.
const e2ePort = Number(process.env.TRACEBACK_E2E_PORT || 4174);
const localBaseURL = `http://127.0.0.1:${e2ePort}`;
const baseURL = externalWebUrl || (realMode ? 'http://127.0.0.1:8000' : localBaseURL);
const browserExecutable = process.env.TRACEBACK_BROWSER_EXECUTABLE;
// F25: allow the self-contained suite to run on WebKit/Firefox too.
const browserName = process.env.TRACEBACK_BROWSER as 'chromium' | 'firefox' | 'webkit' | undefined;

export default defineConfig({
  testDir: './e2e',
  timeout: 120000,
  expect: {timeout: 15000},
  workers: 1,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [['list'], ['junit', {outputFile: '../outputs/task08/browser.xml'}]],
  outputDir: '../outputs/task08/browser-artifacts',
  webServer: externalWebUrl || realMode ? undefined : {
    command: `npm run dev -- --port ${e2ePort} --strictPort`,
    url: localBaseURL,
    reuseExistingServer: !process.env.CI,
    timeout: 120000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
  use: {
    baseURL,
    viewport: {width: 1440, height: 1050},
    // T12 determinism: no motion, animated states settle immediately.
    reducedMotion: 'reduce',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    ...(browserExecutable ? {launchOptions: {executablePath: browserExecutable}} : browserName ? {browserName} : {channel: 'chrome'}),
  },
});
