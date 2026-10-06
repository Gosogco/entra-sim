import { expect, test } from '@playwright/test'

/// The user Terraform creates in the simulator, matching a real tenant's principal name.
const USER = 'alice@example.test'

test('MSAL signs the user in against the simulator', async ({ page }) => {
  // Every console line is kept. When MSAL rejects something the simulator returned, its own
  // log is the only place that says what and why.
  const log: string[] = []
  page.on('console', (message) => log.push(`${message.type()}: ${message.text()}`))
  page.on('pageerror', (error) => log.push(`pageerror: ${error.message}`))

  // Every request the browser makes, so the test can prove where MSAL went.
  const requests: string[] = []
  page.on('request', (r) => requests.push(r.url()))

  await page.goto('/')
  await expect(page.getByTestId('auth-state')).toHaveText('Not signed in')

  await page.getByTestId('sign-in').click()

  // The simulator's sign-in page lists the tenant's users as buttons.
  await page.getByRole('button', { name: new RegExp(USER) }).click()

  await expect(page.getByTestId('auth-state')).toHaveText('Signed in', { timeout: 15_000 })
  await expect(page.getByTestId('upn')).toHaveText(USER)

  // MSAL must not have contacted Microsoft. If it did, the simulator is not actually serving
  // the whole flow and the test proves less than it appears to.
  const toMicrosoft = requests.filter((url) => /microsoft|windows\.net|live\.com/i.test(url))
  expect(toMicrosoft, `MSAL called out to ${toMicrosoft.join(', ')}`).toHaveLength(0)

  // The endpoints the simulator had to serve for this to work.
  const paths = requests
    .filter((url) => url.startsWith('https://localhost:8443'))
    .map((url) => new URL(url).pathname)
  expect(paths.some((p) => p.endsWith('/v2.0/.well-known/openid-configuration'))).toBe(true)
  expect(paths.some((p) => p.endsWith('/oauth2/v2.0/authorize'))).toBe(true)
  expect(paths.some((p) => p.endsWith('/oauth2/v2.0/token'))).toBe(true)

  console.log('simulator endpoints MSAL used:')
  for (const path of [...new Set(paths)].sort()) console.log('  ', path)

  // Printed so a failure shows MSAL's own account of what happened.
  if (test.info().status !== 'passed') console.log(log.join('\n'))
})
