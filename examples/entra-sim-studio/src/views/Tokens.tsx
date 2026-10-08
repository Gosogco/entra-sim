import { DAY, MINUTE, useSimNow } from '../clock'
import { DataTable } from '../components/DataTable'
import { Expiry, isExpired } from '../components/Expiry'
import { Pills } from '../components/Pills'
import { Ref } from '../components/Ref'
import { Time } from '../components/Time'
import { useDirectory } from '../context'
import { nameOf, resolveAudience } from '../directory'
import type { Tokens } from '../types'

const GRANT_LABEL: Record<string, string> = {
  client_credentials: 'client credentials',
  authorization_code: 'auth code',
  refresh_token: 'refresh',
}

/// Shown instead of the token tables when the simulator has no `/__sim__/tokens`.
export function TokensUnsupported({ version }: { version: string }) {
  return (
    <div className="notice" data-testid="tokens-unsupported">
      <strong>This simulator version doesn't record tokens (needs ≥ 0.4.0).</strong> It is running{' '}
      {version}. Until 0.4.0 is released, run the simulator from source with{' '}
      <code>cargo run -- --bind 127.0.0.1</code>.
    </div>
  )
}

export function TokensView({ tokens, version }: { tokens: Tokens | null; version: string }) {
  const dir = useDirectory()
  const now = useSimNow()
  if (!tokens) return <TokensUnsupported version={version} />

  return (
    <>
      <DataTable
        title="Issued tokens"
        testId="issued-table"
        rows={tokens.issued}
        rowKey={(t) => t.id}
        rowClassName={(t) => (isExpired(t.expiresAt, now) ? 'is-expired' : undefined)}
        searchText={(t) =>
          [
            t.id,
            t.kind,
            t.grant,
            t.clientId,
            nameOf(dir, t.clientId),
            t.subjectId,
            t.subjectName,
            t.audience,
            ...t.scopes,
            ...t.roles,
          ].join(' ')
        }
        columns={[
          {
            header: 'Kind',
            cell: (t) => <span className={`badge badge-${t.kind}`}>{t.kind}</span>,
          },
          { header: 'Grant', cell: (t) => GRANT_LABEL[t.grant] ?? t.grant },
          { header: 'Client', cell: (t) => <Ref id={t.clientId} by="appId" /> },
          {
            header: 'Subject',
            cell: (t) => (
              <span title={`${t.subjectKind}\n${t.subjectId}`}>
                <span className={`kind kind-${t.subjectKind}`}>
                  {t.subjectKind === 'user' ? 'user' : 'app'}
                </span>
                {t.subjectName}
              </span>
            ),
          },
          {
            header: 'Audience',
            cell: (t) => {
              const sp = resolveAudience(dir, t.audience)
              return sp ? (
                <span className="ref" title={t.audience}>
                  {sp.displayName}
                </span>
              ) : (
                <code>{t.audience}</code>
              )
            },
          },
          {
            header: 'Scopes / roles',
            cell: (t) => <Pills values={[...t.scopes, ...t.roles]} />,
          },
          { header: 'Issued', cell: (t) => <Time at={t.issuedAt} /> },
          { header: 'Expires', cell: (t) => <Expiry at={t.expiresAt} warnBelowMs={5 * MINUTE} /> },
        ]}
        empty="No tokens issued yet. Sign in with the React example, or request a client credentials token."
      />

      <DataTable
        title="Refresh tokens"
        testId="refresh-table"
        rows={tokens.refreshTokens}
        rowKey={(r) => `${r.prefix}/${r.clientId}/${r.userId}`}
        rowClassName={(r) => (isExpired(r.expiresAt, now) ? 'is-expired' : undefined)}
        searchText={(r) =>
          [r.prefix, r.clientId, nameOf(dir, r.clientId), r.userId, nameOf(dir, r.userId), r.scope].join(' ')
        }
        columns={[
          {
            header: 'Token',
            // Only a prefix: the simulator never exposes a whole refresh token, since one
            // copied from here would be a working credential.
            cell: (r) => <code>{r.prefix}…</code>,
          },
          { header: 'Client', cell: (r) => <Ref id={r.clientId} by="appId" /> },
          { header: 'User', cell: (r) => <Ref id={r.userId} /> },
          { header: 'Scope', cell: (r) => <Pills values={r.scope.split(/\s+/).filter(Boolean)} /> },
          { header: 'Expires', cell: (r) => <Expiry at={r.expiresAt} warnBelowMs={7 * DAY} /> },
        ]}
        empty="No refresh tokens. One is issued when a user signs in with the offline_access scope."
      />

      <DataTable
        title="Pending authorization codes"
        testId="codes-table"
        rows={tokens.pendingCodes}
        rowKey={(c) => `${c.prefix}/${c.clientId}/${c.userId}`}
        rowClassName={(c) => (isExpired(c.expiresAt, now) ? 'is-expired' : undefined)}
        searchText={(c) =>
          [c.prefix, c.clientId, nameOf(dir, c.clientId), c.userId, nameOf(dir, c.userId), c.redirectUri, c.scope].join(
            ' ',
          )
        }
        columns={[
          { header: 'Code', cell: (c) => <code>{c.prefix}…</code> },
          { header: 'Client', cell: (c) => <Ref id={c.clientId} by="appId" /> },
          { header: 'User', cell: (c) => <Ref id={c.userId} /> },
          { header: 'Redirect URI', cell: (c) => <code>{c.redirectUri}</code> },
          { header: 'Scope', cell: (c) => <Pills values={c.scope.split(/\s+/).filter(Boolean)} /> },
          { header: 'Expires', cell: (c) => <Expiry at={c.expiresAt} warnBelowMs={5 * MINUTE} /> },
        ]}
        empty="No codes waiting to be redeemed. A code lives only between sign-in and the token request."
      />
    </>
  )
}
