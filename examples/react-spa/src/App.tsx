import { InteractionStatus, type AccountInfo } from '@azure/msal-browser'
import { useIsAuthenticated, useMsal } from '@azure/msal-react'

import { scopes } from './authConfig'

export function App() {
  const { instance, accounts, inProgress } = useMsal()
  const isAuthenticated = useIsAuthenticated()
  const account = accounts[0]

  const signIn = () => {
    void instance.loginRedirect({ scopes })
  }
  const signOut = () => {
    void instance.logoutRedirect()
  }

  // MSAL performs two full page loads during a redirect sign-in. Without this the page shows
  // "signed out" in between, which looks like a failure and confuses a test.
  if (inProgress !== InteractionStatus.None) {
    return (
      <main>
        <h1>entra-sim React example</h1>
        <p data-testid="status">Signing in…</p>
      </main>
    )
  }

  return (
    <main>
      <h1>entra-sim React example</h1>
      <p className="sub">
        The same build runs against the simulator and against a real Microsoft Entra tenant. Only
        the environment differs.
      </p>

      <div className="row">
        {isAuthenticated ? (
          <button onClick={signOut} data-testid="sign-out">
            Sign out
          </button>
        ) : (
          <button onClick={signIn} data-testid="sign-in">
            Sign in
          </button>
        )}
        <span data-testid="auth-state">
          {isAuthenticated ? 'Signed in' : 'Not signed in'}
        </span>
      </div>

      {account && <IdTokenClaims account={account} />}
    </main>
  )
}

/// What the ID token says about the signed-in user.
///
/// Shown separately from the Graph result, because the two answer different questions: these
/// claims prove the sign-in worked, while a Graph call proves the access token is usable.
function IdTokenClaims({ account }: { account: AccountInfo }) {
  const claims = (account.idTokenClaims ?? {}) as Record<string, unknown>

  return (
    <section>
      <h2>ID token claims</h2>
      <table>
        <tbody>
          <Row label="preferred_username" value={claims.preferred_username} testId="upn" />
          <Row label="name" value={claims.name} />
          <Row label="oid" value={claims.oid} />
          <Row label="tid" value={claims.tid} />
          <Row label="iss" value={claims.iss} />
          <Row label="aud" value={claims.aud} />
        </tbody>
      </table>
    </section>
  )
}

function Row({
  label,
  value,
  testId,
}: {
  label: string
  value: unknown
  testId?: string
}) {
  return (
    <tr>
      <th>{label}</th>
      <td data-testid={testId}>{value === undefined ? '—' : String(value)}</td>
    </tr>
  )
}
