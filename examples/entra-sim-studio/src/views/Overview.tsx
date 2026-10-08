import type { SimState } from '../api'
import { DAY, MINUTE, useSimNow } from '../clock'
import { Expiry } from '../components/Expiry'
import { useDirectory } from '../context'
import type { Tab } from '../tabs'

/// The tenant at a glance: what exists, and what is live right now.
export function OverviewView({ state, onOpen }: { state: SimState; onOpen: (tab: Tab) => void }) {
  const dir = useDirectory()
  const now = useSimNow()
  const s = dir.snapshot
  const tokens = state.tokens

  const activeAccess = tokens?.issued.filter(
    (t) => t.kind === 'access' && Date.parse(t.expiresAt) > now,
  )
  const activeRefresh = tokens?.refreshTokens.filter((r) => Date.parse(r.expiresAt) > now)

  // The next thing to stop working, across everything that expires. A client secret running out
  // in a long-lived simulator is as confusing as a token doing so, and rarer, so worth surfacing.
  const upcoming: { label: string; at: string; warn: number }[] = [
    ...(activeAccess ?? []).map((t) => ({
      label: `access token for ${t.subjectName}`,
      at: t.expiresAt,
      warn: 5 * MINUTE,
    })),
    ...(activeRefresh ?? []).map((r) => ({
      label: `refresh token ${r.prefix}…`,
      at: r.expiresAt,
      warn: 7 * DAY,
    })),
    ...s.applications.flatMap((app) =>
      (app.passwordCredentials ?? []).map((c) => ({
        label: `secret "${c.displayName ?? c.keyId}" on ${app.displayName}`,
        at: c.endDateTime,
        warn: 7 * DAY,
      })),
    ),
  ]
    .filter((e) => Date.parse(e.at) > now)
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
  const next = upcoming[0]

  const counts: { label: string; value: number; tab: Tab }[] = [
    { label: 'Users', value: s.users.length, tab: 'users' },
    { label: 'Groups', value: s.groups.length, tab: 'groups' },
    { label: 'App registrations', value: s.applications.length, tab: 'applications' },
    { label: 'Enterprise apps', value: s.servicePrincipals.length, tab: 'servicePrincipals' },
    { label: 'App role assignments', value: s.appRoleAssignments.length, tab: 'permissions' },
    { label: 'Delegated grants', value: s.oauth2PermissionGrants.length, tab: 'permissions' },
    { label: 'Directory roles', value: s.directoryRoles.length, tab: 'roles' },
    {
      label: 'Client secrets',
      value: s.applications.reduce((n, a) => n + (a.passwordCredentials?.length ?? 0), 0),
      tab: 'applications',
    },
  ]

  return (
    <div className="overview" data-testid="overview">
      <dl className="kv wide">
        <dt>Simulator</dt>
        <dd data-testid="sim-version">entra-sim {state.health.version}</dd>
        <dt>Tenant ID</dt>
        <dd>
          <code>{state.health.tenant_id}</code>
        </dd>
        <dt>Clock offset</dt>
        <dd title="Simulator clock minus this browser's clock. Expiry countdowns use the simulator's.">
          {Math.abs(state.clockOffsetMs) < 1000
            ? 'in sync'
            : `${(state.clockOffsetMs / 1000).toFixed(1)} s`}
        </dd>
      </dl>

      <div className="tiles">
        {counts.map((c) => (
          <button type="button" className="tile" key={c.label} onClick={() => onOpen(c.tab)}>
            <span className="tile-value">{c.value}</span>
            <span className="tile-label">{c.label}</span>
          </button>
        ))}
      </div>

      <div className="tiles">
        <button type="button" className="tile" onClick={() => onOpen('tokens')}>
          <span className="tile-value">{activeAccess ? activeAccess.length : '—'}</span>
          <span className="tile-label">Active access tokens</span>
        </button>
        <button type="button" className="tile" onClick={() => onOpen('tokens')}>
          <span className="tile-value">{activeRefresh ? activeRefresh.length : '—'}</span>
          <span className="tile-label">Active refresh tokens</span>
        </button>
        <div className="tile tile-wide">
          <span className="tile-value small">
            {next ? <Expiry at={next.at} warnBelowMs={next.warn} /> : '—'}
          </span>
          <span className="tile-label">Next expiry{next ? `: ${next.label}` : ''}</span>
        </div>
      </div>

      {!tokens && (
        <p className="muted">
          Token counts need <code>/__sim__/tokens</code>, which this simulator version does not have
          (needs ≥ 0.4.0).
        </p>
      )}
    </div>
  )
}
