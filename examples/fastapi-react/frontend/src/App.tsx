import { InteractionStatus } from '@azure/msal-browser'
import { useIsAuthenticated, useMsal } from '@azure/msal-react'
import { useState } from 'react'

import { apiScopes } from './authConfig'

type Call = { method: 'GET' | 'POST'; path: string; withToken: boolean }

const CALLS: Call[] = [
  { method: 'GET', path: '/api/orders', withToken: true },
  { method: 'POST', path: '/api/orders', withToken: true },
  { method: 'GET', path: '/api/me', withToken: true },
  { method: 'GET', path: '/api/orders', withToken: false },
]

type Result = { call: Call; status: number; body: Record<string, unknown> }

export function App() {
  const { instance, accounts, inProgress } = useMsal()
  const isAuthenticated = useIsAuthenticated()
  const account = accounts[0]
  const [results, setResults] = useState<Result[]>([])
  const [claims, setClaims] = useState<Record<string, unknown> | null>(null)

  // select_account, so the simulator shows its user picker each time and switching between
  // alice, bob and carol needs no sign-out.
  const signIn = () => {
    void instance.loginRedirect({ scopes: apiScopes, prompt: 'select_account' })
  }
  const signOut = () => {
    void instance.logoutRedirect()
  }

  const send = async (call: Call) => {
    const headers: Record<string, string> = {}
    if (call.withToken && account) {
      const { accessToken } = await instance.acquireTokenSilent({ scopes: apiScopes, account })
      headers.Authorization = `Bearer ${accessToken}`
      setClaims(decode(accessToken))
    }
    const response = await fetch(call.path, { method: call.method, headers })
    const body = (await response.json()) as Record<string, unknown>
    setResults((previous) => [{ call, status: response.status, body }, ...previous])
  }

  if (inProgress !== InteractionStatus.None) {
    return (
      <main>
        <h1>entra-sim FastAPI example</h1>
        <p>Signing in…</p>
      </main>
    )
  }

  return (
    <main>
      <h1>entra-sim FastAPI example</h1>
      <p className="sub">
        Sign in as alice (both roles, through a group), bob (Orders.Read) or carol (no roles),
        then call the backend. It validates the access token and allows or denies the call.
      </p>

      <div className="row">
        {isAuthenticated ? (
          <button onClick={signOut}>Sign out</button>
        ) : (
          <button onClick={signIn}>Sign in</button>
        )}
        {isAuthenticated && <button onClick={signIn}>Sign in as someone else</button>}
        <span>{account ? `Signed in as ${account.username}` : 'Not signed in'}</span>
      </div>

      <section>
        <h2>Call the backend</h2>
        <div className="row">
          {CALLS.map((call) => (
            <button
              key={label(call)}
              onClick={() => void send(call)}
              disabled={call.withToken && !isAuthenticated}
            >
              {label(call)}
            </button>
          ))}
        </div>
      </section>

      {claims && (
        <section>
          <h2>Access token sent</h2>
          <table>
            <tbody>
              {['preferred_username', 'aud', 'iss', 'scp', 'roles'].map((name) => (
                <tr key={name}>
                  <th>{name}</th>
                  <td>{claims[name] === undefined ? '—' : JSON.stringify(claims[name])}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {results.length > 0 && (
        <section>
          <h2>Results, newest first</h2>
          <table>
            <tbody>
              {results.map((result, index) => (
                <tr key={index}>
                  <th className={result.status < 300 ? 'ok' : 'error'}>
                    {result.status} {label(result.call)}
                  </th>
                  <td>{String(result.body.reason ?? JSON.stringify(result.body))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </main>
  )
}

function label(call: Call): string {
  return `${call.method} ${call.path}${call.withToken ? '' : ' without a token'}`
}

/// The token's payload, for display only. The backend is what verifies it.
function decode(token: string): Record<string, unknown> {
  const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(atob(payload)) as Record<string, unknown>
}
