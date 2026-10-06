import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  // One worker: the tests sign the same user in and share one simulator.
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:5173',
    // The simulator serves a certificate from a CA it generated itself. Trusting it properly
    // would mean installing mkcert into the runner's trust store, which is awkward on Linux and
    // is not what these tests are about.
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
})
