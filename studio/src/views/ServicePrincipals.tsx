import { DataTable } from '../components/DataTable'
import { Pills } from '../components/Pills'
import { Ref, RefList } from '../components/Ref'
import { Section } from '../components/Section'
import { useDirectory } from '../context'
import { assignmentRole, grantScopes, type Directory } from '../directory'
import type { ServicePrincipal } from '../types'

export function ServicePrincipalsView() {
  const dir = useDirectory()
  return (
    <DataTable
      title="Enterprise apps"
      testId="service-principals-table"
      rows={dir.snapshot.servicePrincipals}
      rowKey={(sp) => sp.id}
      searchText={(sp) =>
        [sp.id, sp.appId, sp.displayName, ...(sp.servicePrincipalNames ?? []), ...(sp.tags ?? [])].join(
          ' ',
        )
      }
      columns={[
        { header: 'Name', cell: (sp) => <span title={sp.id}>{sp.displayName}</span> },
        { header: 'Application ID', cell: (sp) => <code>{sp.appId}</code> },
        {
          header: 'App registration',
          cell: (sp) => {
            const app = dir.appByAppId.get(sp.appId)
            // Microsoft Graph and other first-party principals have no registration in the
            // tenant: the application lives in Microsoft's own tenant.
            return app ? <Ref id={app.id} /> : <span className="muted">external</span>
          },
        },
        {
          header: 'Service principal names',
          cell: (sp) => <Pills values={sp.servicePrincipalNames} />,
        },
        { header: 'Tags', cell: (sp) => <Pills values={sp.tags} /> },
        {
          header: 'Assignment required',
          cell: (sp) => (sp.appRoleAssignmentRequired ? <strong>yes</strong> : 'no'),
        },
      ]}
      details={(sp) => <ServicePrincipalDetails sp={sp} dir={dir} />}
    />
  )
}

function ServicePrincipalDetails({ sp, dir }: { sp: ServicePrincipal; dir: Directory }) {
  const held = dir.snapshot.appRoleAssignments.filter((a) => a.principalId === sp.id)
  const assignedTo = dir.snapshot.appRoleAssignments.filter((a) => a.resourceId === sp.id)
  const grants = dir.snapshot.oauth2PermissionGrants.filter((g) => g.clientId === sp.id)

  return (
    <div className="detail-stack">
      <div className="detail-grid">
        <Section title="Principal">
          <dl className="kv">
            <dt>Object ID</dt>
            <dd>
              <code>{sp.id}</code>
            </dd>
            <dt>App roles defined</dt>
            <dd>{sp.appRoles?.length ?? 0}</dd>
            <dt>Delegated scopes defined</dt>
            <dd>{sp.oauth2PermissionScopes?.length ?? 0}</dd>
            <dt>Owners</dt>
            <dd>
              <RefList ids={dir.owners.get(sp.id)} />
            </dd>
          </dl>
        </Section>

        <Section title="App roles granted to it">
          {held.length === 0 ? (
            <span className="muted">None</span>
          ) : (
            <ul className="plain">
              {held.map((a) => {
                const role = assignmentRole(dir, a)
                return (
                  <li key={a.id}>
                    <Ref id={a.resourceId} /> :{' '}
                    <code title={role.description ?? a.appRoleId}>{role.value}</code>
                  </li>
                )
              })}
            </ul>
          )}
        </Section>

        <Section title="Delegated permissions granted to it">
          {grants.length === 0 ? (
            <span className="muted">None</span>
          ) : (
            <ul className="plain">
              {grants.map((g) => (
                <li key={g.id}>
                  <Ref id={g.resourceId} />: <Pills values={grantScopes(g)} />{' '}
                  <span className="muted">
                    {g.consentType === 'AllPrincipals' ? (
                      'for all users'
                    ) : (
                      <>
                        for <Ref id={g.principalId} />
                      </>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <Section title="Assigned to it">
        {assignedTo.length === 0 ? (
          <span className="muted">Nobody holds a role on this app.</span>
        ) : (
          <table className="mini">
            <thead>
              <tr>
                <th>Principal</th>
                <th>Type</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              {assignedTo.map((a) => {
                const role = assignmentRole(dir, a)
                return (
                  <tr key={a.id}>
                    <td>
                      <Ref id={a.principalId} />
                    </td>
                    <td>{a.principalType}</td>
                    <td>
                      <code title={role.description ?? a.appRoleId}>{role.value}</code>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  )
}
