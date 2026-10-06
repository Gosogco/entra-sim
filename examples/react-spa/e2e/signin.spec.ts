import { expect, test } from '@playwright/test'

/// The user Terraform creates in the simulator. Override it to sign in as a real account,
/// which is the closest the simulator run gets to the real tenant.
const USER = process.env.E2E_USER ?? 'alice@example.test'

const SIMULATOR = process.env.SIMULATOR_URL ?? 'https://localhost:8443'
const TENANT = process.env.SIMULATOR_TENANT ?? '00000000-0000-0000-0000-000000000001'
const BOOTSTRAP_CLIENT_ID =
  process.env.SIMULATOR_CLIENT_ID ?? '11111111-1111-1111-1111-111111111111'
const BOOTSTRAP_CLIENT_SECRET =
  process.env.SIMULATOR_CLIENT_SECRET ?? 'entra-sim-bootstrap-secret'

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

  // Printed so a failure shows MSAL's own account of what happened.
  if (test.info().status !== 'passed') console.log(log.join('\n'))
})

test('the Graph call shows the user', async ({ page }) => {
  await signIn(page)

  // Signing in records consent for the requested scope, so the token carries User.Read and
  // the call succeeds. This is the assertion that proves the access token is usable, which the
  // ID token claims alone do not.
  await expect(page.getByTestId('me-upn')).toHaveText(USER, { timeout: 15_000 })
  await expect(page.getByTestId('me-display-name')).toHaveText(
    process.env.E2E_DISPLAY_NAME ?? 'Alice Example',
  )
  await expect(page.getByTestId('me-error')).toHaveCount(0)
})

test('revoking consent narrows the next token in the browser', async ({ page, request }) => {
  // Sign in first. Signing in records consent, so doing it after the revocation would simply
  // grant the permission again, exactly as a real consent prompt would.
  await signIn(page)
  await expect(page.getByTestId('me-upn')).toHaveText(USER, { timeout: 15_000 })

  const token = await appOnlyToken(request)
  const grant = await findGrant(request, token)

  const deleted = await request.delete(
    `${SIMULATOR}/v1.0/oauth2PermissionGrants/${grant.id}`,
    { headers: { Authorization: `Bearer ${token}` } },
  )
  expect(deleted.status()).toBe(204)

  try {
    // The access token already issued stays valid until it expires, which is correct. Forcing
    // a new one redeems the refresh token, and the simulator reads the directory again when it
    // mints the replacement.
    await page.getByTestId('me-refresh').click()

    const error = page.getByTestId('me-error')
    await expect(error).toBeVisible({ timeout: 15_000 })
    await expect(error).toContainText('403')
    await expect(error).toContainText('Authorization_RequestDenied')
  } finally {
    // Put it back, because the tests share one simulator.
    await request.post(`${SIMULATOR}/v1.0/oauth2PermissionGrants`, {
      headers: { Authorization: `Bearer ${token}` },
      data: {
        clientId: grant.clientId,
        consentType: grant.consentType,
        principalId: grant.principalId,
        resourceId: grant.resourceId,
        scope: grant.scope,
      },
    })
  }
})

/// Sign in through the simulator's own sign-in page.
async function signIn(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByTestId('sign-in').click()
  await page.getByRole('button', { name: new RegExp(USER) }).click()
  await expect(page.getByTestId('auth-state')).toHaveText('Signed in', { timeout: 15_000 })
}

/// An app-only token for the bootstrap client, to administer the directory from a test.
async function appOnlyToken(request: import('@playwright/test').APIRequestContext) {
  const response = await request.post(`${SIMULATOR}/${TENANT}/oauth2/v2.0/token`, {
    form: {
      grant_type: 'client_credentials',
      client_id: BOOTSTRAP_CLIENT_ID,
      client_secret: BOOTSTRAP_CLIENT_SECRET,
      scope: `${SIMULATOR}/.default`,
    },
  })
  expect(response.ok()).toBeTruthy()
  return (await response.json()).access_token as string
}

interface Grant {
  id: string
  clientId: string
  consentType: string
  principalId?: string
  resourceId: string
  scope: string
}

async function findGrant(
  request: import('@playwright/test').APIRequestContext,
  token: string,
): Promise<Grant> {
  const response = await request.get(`${SIMULATOR}/v1.0/oauth2PermissionGrants`, {
    headers: { Authorization: `Bearer ${token}` },
  })
  const grants = (await response.json()).value as Grant[]
  const grant = grants.find((candidate) => candidate.scope.includes('User.Read'))
  expect(grant, 'signing in should have recorded a User.Read consent grant').toBeDefined()
  return grant!
}
