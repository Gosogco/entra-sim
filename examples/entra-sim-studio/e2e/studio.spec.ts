import { expect, test } from '@playwright/test'

/// The user `../react-spa/scripts/setup.sh` creates. Override it when the setup ran with `UPN=`.
const USER = process.env.E2E_USER ?? 'alice@example.test'

/// The registration the simulator creates on start, so it exists even without any setup.
const BOOTSTRAP_APP = 'entra-sim bootstrap client'

// These read a running simulator and never write to it. Seeding is the job of
// ../react-spa/scripts/setup.sh, run beforehand: a smoke test for a read-only viewer should not
// itself be what changes the directory it is looking at.

test('the Users tab lists the seeded user', async ({ page }) => {
  await page.goto('/#users')
  const table = page.getByTestId('users-table')
  await expect(table.getByRole('cell', { name: USER, exact: true })).toBeVisible({ timeout: 15_000 })
  await expect(page.getByTestId('failure')).toHaveCount(0)
})

test('the App registrations tab lists the bootstrap application', async ({ page }) => {
  await page.goto('/#applications')
  const table = page.getByTestId('applications-table')
  // The name column specifically: the bootstrap client's principal also appears as an owner.
  const name = table.getByTestId('app-name').getByText(BOOTSTRAP_APP, { exact: true })
  await expect(name).toBeVisible({ timeout: 15_000 })

  // Its secret is masked until the row is expanded and the value clicked.
  await name.click()
  const secret = table.getByTestId('masked').first()
  await expect(secret).toHaveText('••••••••')
  await secret.click()
  await expect(secret).not.toHaveText('••••••••')
})

/// Where the studio reads the simulator, so the test talks to the same one.
const SIM = (process.env.VITE_SIM_URL ?? 'http://localhost:8080').replace(/\/$/, '')

test('the Tokens tab lists a token as soon as one is issued', async ({ page, request }) => {
  // A 0.3.x simulator has no token log. The studio must say so rather than fail.
  if ((await request.get(`${SIM}/__sim__/tokens`)).status() === 404) {
    await page.goto('/#tokens')
    await expect(page.getByTestId('tokens-unsupported')).toContainText('needs ≥ 0.4.0', {
      timeout: 15_000,
    })
    return
  }

  // Issue a token here rather than rely on one left behind: setup.sh resets the simulator after
  // its own token request, and a reset empties the log. This adds to the log, not the directory.
  const health = await (await request.get(`${SIM}/__sim__/health`)).json()
  const metadata = await (await request.get(`${SIM}/metadata/endpoints`)).json()
  const resource = String(metadata.microsoftGraphResourceId).replace(/\/$/, '')
  const issued = await request.post(`${SIM}/${health.tenant_id}/oauth2/v2.0/token`, {
    form: {
      grant_type: 'client_credentials',
      client_id: '11111111-1111-1111-1111-111111111111',
      client_secret: 'entra-sim-bootstrap-secret',
      scope: `${resource}/.default`,
    },
  })
  expect(issued.ok()).toBe(true)

  await page.goto('/#tokens')
  const row = page.getByTestId('issued-table').locator('tbody tr:not(:has(td.empty))')
  await expect(row.filter({ hasText: BOOTSTRAP_APP }).first()).toBeVisible({ timeout: 15_000 })
})
