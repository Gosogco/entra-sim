import { DataTable } from '../components/DataTable'
import { Pills } from '../components/Pills'
import { RefList } from '../components/Ref'
import { Section } from '../components/Section'
import { Time } from '../components/Time'
import { useDirectory } from '../context'
import { nameOf } from '../directory'
import type { Group } from '../types'

/// The kind of group as the Entra portal names it. Graph encodes it across three properties,
/// which is easy to misread: a Microsoft 365 group is also mail-enabled and security-enabled.
export function groupKind(group: Group): string {
  const types = group.groupTypes ?? []
  const base = types.includes('Unified')
    ? 'Microsoft 365'
    : group.mailEnabled && group.securityEnabled
      ? 'Mail-enabled security'
      : group.mailEnabled
        ? 'Distribution'
        : 'Security'
  return types.includes('DynamicMembership') ? `${base} (dynamic)` : base
}

export function GroupsView() {
  const dir = useDirectory()
  return (
    <DataTable
      title="Groups"
      testId="groups-table"
      rows={dir.snapshot.groups}
      rowKey={(g) => g.id}
      searchText={(g) =>
        [
          g.id,
          g.displayName,
          g.description,
          g.mail,
          groupKind(g),
          ...(dir.groupMembers.get(g.id) ?? []).map((id) => nameOf(dir, id)),
          ...(dir.groupOwners.get(g.id) ?? []).map((id) => nameOf(dir, id)),
        ].join(' ')
      }
      columns={[
        { header: 'Name', cell: (g) => <span title={g.id}>{g.displayName}</span> },
        { header: 'Type', cell: (g) => groupKind(g) },
        { header: 'Mail', cell: (g) => g.mail ?? <span className="muted">—</span> },
        { header: 'Members', cell: (g) => <RefList ids={dir.groupMembers.get(g.id)} showKind /> },
        { header: 'Owners', cell: (g) => <RefList ids={dir.groupOwners.get(g.id)} showKind /> },
        { header: 'Created', cell: (g) => <Time at={g.createdDateTime} /> },
      ]}
      details={(g) => (
        <div className="detail-grid">
          <Section title="Properties">
            <dl className="kv">
              <dt>Object ID</dt>
              <dd>
                <code>{g.id}</code>
              </dd>
              <dt>Description</dt>
              <dd>{g.description ?? '—'}</dd>
              <dt>Mail nickname</dt>
              <dd>{g.mailNickname ?? '—'}</dd>
              <dt>groupTypes</dt>
              <dd>
                <Pills values={g.groupTypes} />
              </dd>
              <dt>mailEnabled</dt>
              <dd>{String(g.mailEnabled)}</dd>
              <dt>securityEnabled</dt>
              <dd>{String(g.securityEnabled)}</dd>
            </dl>
          </Section>
          <Section title="Member of">
            <RefList ids={dir.memberOf.get(g.id)} />
          </Section>
        </div>
      )}
    />
  )
}
