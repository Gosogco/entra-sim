import { DataTable } from '../components/DataTable'
import { RefList } from '../components/Ref'
import { useDirectory } from '../context'
import { nameOf } from '../directory'

/// Only activated roles exist as objects. Entra activates a role the first time someone is
/// added to it, so an empty list means nobody holds any admin role, not that roles are missing.
export function DirectoryRolesView() {
  const dir = useDirectory()
  return (
    <DataTable
      title="Directory roles"
      testId="roles-table"
      rows={dir.snapshot.directoryRoles}
      rowKey={(r) => r.id}
      searchText={(r) =>
        [
          r.id,
          r.roleTemplateId,
          r.displayName,
          r.description,
          ...(dir.roleMembers.get(r.id) ?? []).map((id) => nameOf(dir, id)),
        ].join(' ')
      }
      columns={[
        { header: 'Role', cell: (r) => <span title={r.description}>{r.displayName}</span> },
        { header: 'Template ID', cell: (r) => <code className="dim">{r.roleTemplateId}</code> },
        { header: 'Members', cell: (r) => <RefList ids={dir.roleMembers.get(r.id)} showKind /> },
      ]}
      empty="No directory roles are activated."
    />
  )
}
