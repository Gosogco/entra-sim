import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  // One worker: the tests sign the same user in and share one simulator.
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://localhost:5173',
    // The simulator serves a certificate from a CA it generated itself, which no trust store
    // knows about. CI therefore does not verify it: installing a CA into the runner's trust
    // store is awkward on Linux and is not what these tests are about.
    //
    // Set STRICT_TLS=1 when the simulator is using an mkcert certificate. The browser then
    // verifies it like any other site, which is the only way to check that the mkcert setup in
    // the README actually works.
    ignoreHTTPSErrors: process.env.STRICT_TLS !== '1',
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
