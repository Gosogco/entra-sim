import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { fetchAll, simUrl, UnreachableError, type SimState } from './api'
import { ClockOffsetContext, DirectoryContext } from './context'
import { buildDirectory } from './directory'
import { TABS, tabFromHash, type Tab } from './tabs'
import { ApplicationsView } from './views/Applications'
import { DirectoryRolesView } from './views/DirectoryRoles'
import { GroupsView } from './views/Groups'
import { OverviewView } from './views/Overview'
import { PermissionsView } from './views/Permissions'
import { ServicePrincipalsView } from './views/ServicePrincipals'
import { TokensView } from './views/Tokens'
import { UsersView } from './views/Users'

/// How often to re-read the simulator. The snapshot is small and local, and five seconds is
/// short enough that a change made from a test or a Terraform run shows up while you look.
const POLL_MS = 5000

type Failure = { kind: 'unreachable' | 'error'; message: string }

export function App() {
  const [state, setState] = useState<SimState | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)
  const [paused, setPaused] = useState(false)
  const [loading, setLoading] = useState(false)
  const [tab, setTab] = useState<Tab>(tabFromHash)
  const inFlight = useRef<AbortController | null>(null)

  const refresh = useCallback(async () => {
    // A slow response must not land after a newer one and overwrite it.
    inFlight.current?.abort()
    const controller = new AbortController()
    inFlight.current = controller
    setLoading(true)
    try {
      const next = await fetchAll(controller.signal)
      setState(next)
      setFailure(null)
    } catch (error) {
      if (controller.signal.aborted) return
      // The last good data stays on screen. Losing it because the simulator restarted would
      // throw away exactly what you were looking at when it went away.
      setFailure({
        kind: error instanceof UnreachableError ? 'unreachable' : 'error',
        message: error instanceof Error ? error.message : String(error),
      })
    } finally {
      if (inFlight.current === controller) {
        inFlight.current = null
        setLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    void refresh()
    if (paused) return
    const timer = setInterval(() => void refresh(), POLL_MS)
    return () => clearInterval(timer)
  }, [paused, refresh])

  useEffect(() => {
    const onHash = () => setTab(tabFromHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const open = (next: Tab) => {
    window.location.hash = next
    setTab(next)
  }

  const directory = useMemo(() => (state ? buildDirectory(state.snapshot) : null), [state])

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <h1>entra-sim studio</h1>
          <span className="sub">
            Read-only view of <code>{simUrl}</code>
            {state && (
              <>
                {' · '}v{state.health.version}
              </>
            )}
          </span>
        </div>
        <div className="controls">
          <span className="updated" data-testid="last-updated">
            {state ? `Updated ${new Date(state.fetchedAt).toLocaleTimeString()}` : 'Not loaded'}
            {loading && <span className="spinner" aria-label="Loading" />}
          </span>
          <button type="button" onClick={() => void refresh()}>
            Refresh
          </button>
          <button type="button" onClick={() => setPaused(!paused)} data-testid="pause">
            {paused ? 'Resume' : 'Pause'}
          </button>
        </div>
      </header>

      <nav className="tabs" role="tablist">
        {TABS.map((t) => (
          <a
            key={t.id}
            href={`#${t.id}`}
            role="tab"
            aria-selected={tab === t.id}
            className={tab === t.id ? 'active' : undefined}
            onClick={(event) => {
              event.preventDefault()
              open(t.id)
            }}
          >
            {t.label}
          </a>
        ))}
      </nav>

      {failure && <FailureBanner failure={failure} hasData={state !== null} />}

      <main>
        {!state || !directory ? (
          !failure && <p className="muted">Loading…</p>
        ) : (
          <ClockOffsetContext.Provider value={state.clockOffsetMs}>
            <DirectoryContext.Provider value={directory}>
              {tab === 'overview' && <OverviewView state={state} onOpen={open} />}
              {tab === 'users' && <UsersView />}
              {tab === 'groups' && <GroupsView />}
              {tab === 'applications' && <ApplicationsView />}
              {tab === 'servicePrincipals' && <ServicePrincipalsView />}
              {tab === 'permissions' && <PermissionsView />}
              {tab === 'roles' && <DirectoryRolesView />}
              {tab === 'tokens' && <TokensView tokens={state.tokens} version={state.health.version} />}
            </DirectoryContext.Provider>
          </ClockOffsetContext.Provider>
        )}
      </main>
    </div>
  )
}

function FailureBanner({ failure, hasData }: { failure: Failure; hasData: boolean }) {
  return (
    <div className="banner" role="alert" data-testid="failure">
      {failure.kind === 'unreachable' ? (
        <>
          <strong>The simulator is not reachable at {simUrl}.</strong>
          {hasData && ' Showing the last data received.'} Start it with:
          <pre>
            {`docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443 \\
  -e ENTRA_SIM_TENANT_DOMAIN=example.test \\
  ghcr.io/gosogco/entra-sim:latest`}
          </pre>
          Or point the studio elsewhere with <code>VITE_SIM_URL</code> and restart{' '}
          <code>npm run dev</code>.
        </>
      ) : (
        <>
          <strong>The simulator answered with an error.</strong>
          {hasData && ' Showing the last data received.'}
          <pre>{failure.message}</pre>
        </>
      )}
    </div>
  )
}
