import { DAY } from '../clock'
import { DataTable } from '../components/DataTable'
import { Expiry } from '../components/Expiry'
import { Masked } from '../components/Masked'
import { Pills } from '../components/Pills'
import { Ref, RefList } from '../components/Ref'
import { Section } from '../components/Section'
import { Time } from '../components/Time'
import { useDirectory } from '../context'
import { grantScopes, nameOf, resolveRole, resolveScope, type Directory } from '../directory'
import type { Application } from '../types'

export function ApplicationsView() {
  const dir = useDirectory()
  return (
    <DataTable
      title="App registrations"
      testId="applications-table"
      rows={dir.snapshot.applications}
      rowKey={(a) => a.id}
      searchText={(a) =>
        [
          a.id,
          a.appId,
          a.displayName,
          a.signInAudience,
          ...(a.identifierUris ?? []),
          ...(dir.owners.get(a.id) ?? []).map((id) => nameOf(dir, id)),
        ].join(' ')
      }
      columns={[
        { header: 'Name', cell: (a) => <span data-testid="app-name">{a.displayName}</span> },
        { header: 'Application (client) ID', cell: (a) => <code>{a.appId}</code> },
        { header: 'Object ID', cell: (a) => <code className="dim">{a.id}</code> },
        { header: 'Audience', cell: (a) => a.signInAudience ?? '—' },
        { header: 'Identifier URIs', cell: (a) => <Pills values={a.identifierUris} /> },
        { header: 'Owners', cell: (a) => <RefList ids={dir.owners.get(a.id)} empty="—" /> },
      ]}
      details={(a) => <ApplicationDetails app={a} dir={dir} />}
    />
  )
}

function ApplicationDetails({ app, dir }: { app: Application; dir: Directory }) {
  const federated = dir.snapshot.federatedCredentials
  const credentials =
    federated && (federated.find((links) => links.applicationId === app.id)?.credentials ?? [])
  const ownSp = dir.spByAppId.get(app.appId)
  const redirects = [
    ...(app.spa?.redirectUris ?? []).map((uri) => ({ platform: 'SPA', uri })),
    ...(app.web?.redirectUris ?? []).map((uri) => ({ platform: 'Web', uri })),
    ...(app.publicClient?.redirectUris ?? []).map((uri) => ({ platform: 'Public client', uri })),
  ]

  return (
    <div className="detail-stack">
      <div className="detail-grid">
        <Section title="Registration">
          <dl className="kv">
            <dt>Enterprise app</dt>
            <dd>{ownSp ? <Ref id={ownSp.id} /> : <span className="muted">none created</span>}</dd>
            <dt>Created</dt>
            <dd>
              <Time at={app.createdDateTime} />
            </dd>
          </dl>
        </Section>
        <Section title="Redirect URIs">
          {redirects.length === 0 ? (
            <span className="muted">None</span>
          ) : (
            <ul className="plain">
              {redirects.map((r) => (
                <li key={`${r.platform}${r.uri}`}>
                  <span className="muted">{r.platform}</span> <code>{r.uri}</code>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <Section title="App roles defined">
        {(app.appRoles ?? []).length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <table className="mini">
            <thead>
              <tr>
                <th>Value</th>
                <th>Display name</th>
                <th>Allowed member types</th>
                <th>Enabled</th>
              </tr>
            </thead>
            <tbody>
              {app.appRoles!.map((role) => (
                <tr key={role.id}>
                  <td>
                    <code title={role.id}>{role.value ?? '—'}</code>
                  </td>
                  <td title={role.description}>{role.displayName}</td>
                  <td>{role.allowedMemberTypes.join(', ')}</td>
                  <td>{role.isEnabled ? 'yes' : 'no'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="API permissions requested">
        <ApiPermissions app={app} dir={dir} />
      </Section>

      <Section title="Client secrets">
        {(app.passwordCredentials ?? []).length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <table className="mini">
            <thead>
              <tr>
                <th>Description</th>
                <th>Hint</th>
                <th>Starts</th>
                <th>Ends</th>
                <th>Expires</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {app.passwordCredentials!.map((c) => (
                <tr key={c.keyId}>
                  <td title={c.keyId}>{c.displayName ?? <span className="muted">—</span>}</td>
                  <td>
                    <code>{c.hint ?? '—'}</code>
                  </td>
                  <td>
                    <Time at={c.startDateTime} />
                  </td>
                  <td>
                    <Time at={c.endDateTime} />
                  </td>
                  <td>
                    <Expiry at={c.endDateTime} warnBelowMs={7 * DAY} />
                  </td>
                  <td>
                    <Masked value={dir.secrets.get(`${app.id}/${c.keyId}`)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Certificates">
        {(app.keyCredentials ?? []).length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <table className="mini">
            <thead>
              <tr>
                <th>Description</th>
                <th>Type</th>
                <th>Usage</th>
                <th>Starts</th>
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {app.keyCredentials!.map((c) => (
                <tr key={c.keyId}>
                  <td title={c.keyId}>{c.displayName ?? <span className="muted">—</span>}</td>
                  <td>{c.type}</td>
                  <td>{c.usage}</td>
                  <td>
                    <Time at={c.startDateTime} />
                  </td>
                  <td>
                    <Expiry at={c.endDateTime} warnBelowMs={7 * DAY} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section title="Federated credentials">
        {credentials === undefined ? (
          // Before 0.4.0 the snapshot left these out entirely, so their absence here says
          // nothing about whether the application has any.
          <span className="muted">Not included in this simulator's snapshot (needs ≥ 0.4.0).</span>
        ) : credentials.length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <table className="mini">
            <thead>
              <tr>
                <th>Name</th>
                <th>Issuer</th>
                <th>Subject</th>
                <th>Audiences</th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((f) => (
                <tr key={f.id}>
                  <td title={f.description ?? f.id}>{f.name}</td>
                  <td>
                    <code>{f.issuer}</code>
                  </td>
                  <td>
                    <code>{f.subject}</code>
                  </td>
                  <td>
                    <Pills values={f.audiences} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  )
}

/// The permissions the registration asks for, resolved against the resource's own definitions,
/// with whether each has actually been granted.
///
/// Requesting a permission and holding it are different things in Entra, and confusing them is
/// the commonest reason a token lacks a claim. An application permission is held when the
/// app's service principal has the matching app role assignment; a delegated one when an
/// admin-consent grant lists it.
function ApiPermissions({ app, dir }: { app: Application; dir: Directory }) {
  const requested = app.requiredResourceAccess ?? []
  if (requested.length === 0) return <span className="muted">None</span>

  const ownSp = dir.spByAppId.get(app.appId)
  const assignments = ownSp
    ? dir.snapshot.appRoleAssignments.filter((a) => a.principalId === ownSp.id)
    : []
  const grants = ownSp
    ? dir.snapshot.oauth2PermissionGrants.filter((g) => g.clientId === ownSp.id)
    : []

  const rows = requested.flatMap((block) => {
    const resource = dir.spByAppId.get(block.resourceAppId)
    return block.resourceAccess.map((access) => {
      const application = access.type === 'Role'
      const permission = application
        ? resolveRole(resource, access.id)
        : resolveScope(resource, access.id)
      let status: string
      if (application) {
        status = assignments.some(
          (a) => a.resourceId === resource?.id && a.appRoleId === access.id,
        )
          ? 'granted'
          : 'not granted'
      } else {
        const matching = grants.filter(
          (g) => g.resourceId === resource?.id && grantScopes(g).includes(permission.value),
        )
        status = matching.some((g) => g.consentType === 'AllPrincipals')
          ? 'admin consent'
          : matching.length > 0
            ? `consented by ${matching.length} user${matching.length === 1 ? '' : 's'}`
            : 'not consented'
      }
      return { block, access, application, permission, status }
    })
  })

  return (
    <table className="mini">
      <thead>
        <tr>
          <th>Resource</th>
          <th>Permission</th>
          <th>Type</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(({ block, access, application, permission, status }) => (
          <tr key={`${block.resourceAppId}/${access.id}/${access.type}`}>
            <td>
              <Ref id={block.resourceAppId} by="appId" />
            </td>
            <td>
              <code
                title={`${permission.description ? `${permission.description}\n` : ''}${access.id}`}
                className={permission.resolved ? undefined : 'unknown'}
              >
                {permission.value}
              </code>
            </td>
            <td>{application ? 'Application' : 'Delegated'}</td>
            <td className={status.startsWith('not') ? 'warn' : 'ok'}>{status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
