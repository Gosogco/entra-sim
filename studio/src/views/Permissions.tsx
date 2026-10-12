import { DataTable } from '../components/DataTable'
import { Pills } from '../components/Pills'
import { Ref } from '../components/Ref'
import { Time } from '../components/Time'
import { useDirectory } from '../context'
import { assignmentRole, grantScopes, nameOf, scopeByValue } from '../directory'

/// Both halves of "what may this token contain": app role assignments put values in `roles`,
/// delegated grants put them in `scp`.
export function PermissionsView() {
  const dir = useDirectory()
  return (
    <>
      <DataTable
        title="App role assignments"
        testId="assignments-table"
        rows={dir.snapshot.appRoleAssignments}
        rowKey={(a) => a.id}
        searchText={(a) =>
          [
            a.id,
            a.principalId,
            a.resourceId,
            a.appRoleId,
            a.principalType,
            nameOf(dir, a.principalId),
            nameOf(dir, a.resourceId),
            assignmentRole(dir, a).value,
          ].join(' ')
        }
        columns={[
          { header: 'Principal', cell: (a) => <Ref id={a.principalId} showKind /> },
          { header: 'Resource', cell: (a) => <Ref id={a.resourceId} /> },
          {
            header: 'Role',
            cell: (a) => {
              const role = assignmentRole(dir, a)
              return (
                <code
                  title={`${role.description ? `${role.description}\n` : ''}${a.appRoleId}`}
                  className={role.resolved ? undefined : 'unknown'}
                >
                  {role.value}
                </code>
              )
            },
          },
          { header: 'Created', cell: (a) => <Time at={a.createdDateTime} /> },
        ]}
      />

      <DataTable
        title="Delegated permission grants"
        testId="grants-table"
        rows={dir.snapshot.oauth2PermissionGrants}
        rowKey={(g) => g.id}
        searchText={(g) =>
          [
            g.id,
            g.clientId,
            g.resourceId,
            g.principalId,
            g.scope,
            g.consentType,
            nameOf(dir, g.clientId),
            nameOf(dir, g.resourceId),
            nameOf(dir, g.principalId),
          ].join(' ')
        }
        columns={[
          { header: 'Client', cell: (g) => <Ref id={g.clientId} /> },
          { header: 'Resource', cell: (g) => <Ref id={g.resourceId} /> },
          {
            header: 'Scopes',
            cell: (g) => {
              const resource = dir.spById.get(g.resourceId)
              return (
                <Pills
                  values={grantScopes(g).map((value) => (
                    <span title={scopeByValue(resource, value)?.adminConsentDisplayName}>{value}</span>
                  ))}
                />
              )
            },
          },
          {
            header: 'Consent',
            cell: (g) => (g.consentType === 'AllPrincipals' ? 'Admin (all users)' : 'User'),
          },
          {
            header: 'Principal',
            cell: (g) =>
              g.consentType === 'AllPrincipals' ? <span className="muted">—</span> : <Ref id={g.principalId} />,
          },
        ]}
      />
    </>
  )
}
