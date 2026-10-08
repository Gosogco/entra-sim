import { DataTable } from '../components/DataTable'
import { Masked } from '../components/Masked'
import { Ref } from '../components/Ref'
import { Section } from '../components/Section'
import { Time } from '../components/Time'
import { useDirectory } from '../context'
import { assignmentRole, nameOf, transitiveGroups, type Directory } from '../directory'
import type { User } from '../types'

export function UsersView() {
  const dir = useDirectory()
  return (
    <DataTable
      title="Users"
      testId="users-table"
      rows={dir.snapshot.users}
      rowKey={(u) => u.id}
      searchText={(u) =>
        [u.id, u.userPrincipalName, u.displayName, u.mail, u.jobTitle, u.userType].join(' ')
      }
      columns={[
        {
          header: 'User principal name',
          cell: (u) => <span title={u.id}>{u.userPrincipalName}</span>,
        },
        { header: 'Name', cell: (u) => u.displayName },
        {
          header: 'Enabled',
          cell: (u) =>
            u.accountEnabled ? <span className="ok">yes</span> : <span className="bad">no</span>,
        },
        { header: 'Job title', cell: (u) => u.jobTitle ?? <span className="muted">—</span> },
        { header: 'Mail', cell: (u) => u.mail ?? <span className="muted">—</span> },
        { header: 'Type', cell: (u) => u.userType ?? 'Member' },
        { header: 'Created', cell: (u) => <Time at={u.createdDateTime} /> },
      ]}
      details={(u) => <UserDetails user={u} dir={dir} />}
      empty="No users. Create one with POST /v1.0/users, or run ../react-spa/scripts/setup.sh."
    />
  )
}

function UserDetails({ user, dir }: { user: User; dir: Directory }) {
  const groups = transitiveGroups(dir, user.id)
  const groupIds = new Set(groups.map((g) => g.groupId))
  const roles = dir.snapshot.directoryRoles.filter((role) =>
    (dir.roleMembers.get(role.id) ?? []).includes(user.id),
  )
  // Assignments to a group reach its members, so they are part of what the user holds.
  const assignments = dir.snapshot.appRoleAssignments.filter(
    (a) => a.principalId === user.id || groupIds.has(a.principalId),
  )

  return (
    <div className="detail-grid">
      <Section title="Identity">
        <dl className="kv">
          <dt>Object ID</dt>
          <dd>
            <code>{user.id}</code>
          </dd>
          <dt>Given name</dt>
          <dd>{user.givenName ?? '—'}</dd>
          <dt>Surname</dt>
          <dd>{user.surname ?? '—'}</dd>
          <dt>Mail nickname</dt>
          <dd>{user.mailNickname ?? '—'}</dd>
          <dt>Password</dt>
          <dd>
            <Masked value={dir.passwords.get(user.id)} />
          </dd>
        </dl>
      </Section>

      <Section title="Group memberships">
        {groups.length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <ul className="plain">
            {groups.map((g) => (
              <li key={g.groupId}>
                <Ref id={g.groupId} />
                {g.via && (
                  <span className="muted">
                    {' '}
                    via <Ref id={g.via} />
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Directory roles">
        {roles.length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <ul className="plain">
            {roles.map((role) => (
              <li key={role.id} title={role.description}>
                {role.displayName}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="App role assignments">
        {assignments.length === 0 ? (
          <span className="muted">None</span>
        ) : (
          <ul className="plain">
            {assignments.map((a) => {
              const role = assignmentRole(dir, a)
              return (
                <li key={a.id}>
                  <Ref id={a.resourceId} /> :{' '}
                  <code title={role.description ?? a.appRoleId}>{role.value}</code>
                  {a.principalId !== user.id && (
                    <span className="muted"> via {nameOf(dir, a.principalId)}</span>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </Section>
    </div>
  )
}
