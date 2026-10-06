import { InteractionStatus, type AccountInfo } from '@azure/msal-browser'
import { useIsAuthenticated, useMsal } from '@azure/msal-react'
import { useCallback, useEffect, useState } from 'react'

import { graphBase, scopes } from './authConfig'
import { fetchMe, GraphError, type GraphUser } from './graph'

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
      {account && <Me account={account} />}
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

/// The signed-in user, read from Graph.
///
/// Separate from the ID token claims on purpose. The claims prove the sign-in worked. This
/// proves the access token is accepted by an API, which is a different thing and the one more
/// likely to be misconfigured.
function Me({ account }: { account: AccountInfo }) {
  const { instance } = useMsal()
  const [user, setUser] = useState<GraphUser | null>(null)
  const [error, setError] = useState<GraphError | Error | null>(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback(async (forceRefresh = false) => {
    setLoading(true)
    setError(null)
    try {
      setUser(await fetchMe(instance, account, forceRefresh))
    } catch (caught) {
      setUser(null)
      setError(caught instanceof Error ? caught : new Error(String(caught)))
    } finally {
      setLoading(false)
    }
  }, [instance, account])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <section>
      <h2>GET {graphBase}/v1.0/me</h2>

      <div className="row">
        <button onClick={() => void load(true)} data-testid="me-refresh">
          Get a new token and reload
        </button>
      </div>

      {loading && <p data-testid="me-loading">Loading…</p>}

      {error && (
        <div data-testid="me-error">
          <p className="error">
            {error instanceof GraphError
              ? `${error.status} ${error.code ?? 'error'}`
              : 'Request failed'}
          </p>
          <pre>{error.message}</pre>
          <button onClick={() => void load(true)}>Try again</button>
        </div>
      )}

      {user && (
        <table>
          <tbody>
            <Row label="displayName" value={user.displayName} testId="me-display-name" />
            <Row label="userPrincipalName" value={user.userPrincipalName} testId="me-upn" />
            <Row label="id" value={user.id} testId="me-id" />
            <Row label="jobTitle" value={user.jobTitle ?? undefined} />
          </tbody>
        </table>
      )}
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
