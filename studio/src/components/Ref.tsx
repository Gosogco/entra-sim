import { useDirectory } from '../context'

const KIND_LABEL: Record<string, string> = {
  user: 'user',
  group: 'group',
  servicePrincipal: 'enterprise app',
  application: 'app registration',
  directoryRole: 'role',
}

/// A GUID, shown as the name of what it refers to.
///
/// The snapshot is wall-to-wall GUIDs, and a page of them is unreadable. The GUID stays one
/// hover away in the tooltip, because it is what you paste into a Graph call or a log search.
/// An unknown GUID is shown as-is, which is itself useful: it means a dangling reference.
export function Ref({
  id,
  by = 'id',
  showKind = false,
}: {
  id: string | null | undefined
  /// `appId` for client IDs, which is what tokens and permission requests use.
  by?: 'id' | 'appId'
  /// Label the object's type, for lists that mix users, groups and principals.
  showKind?: boolean
}) {
  const dir = useDirectory()
  if (!id) return <span className="muted">—</span>

  const named =
    by === 'appId' ? (dir.byAppId.get(id) ?? dir.byId.get(id)) : (dir.byId.get(id) ?? dir.byAppId.get(id))
  if (!named) {
    return (
      <code className="ref unknown" title="Not found in the snapshot">
        {id}
      </code>
    )
  }
  return (
    <span className="ref" title={`${named.detail ? `${named.detail}\n` : ''}${id}`}>
      {showKind && <span className={`kind kind-${named.kind}`}>{KIND_LABEL[named.kind]}</span>}
      {named.name}
    </span>
  )
}

/// A list of references, one per line.
export function RefList({
  ids,
  showKind = false,
  empty = 'None',
}: {
  ids: string[] | undefined
  showKind?: boolean
  empty?: string
}) {
  if (!ids || ids.length === 0) return <span className="muted">{empty}</span>
  return (
    <ul className="plain">
      {ids.map((id) => (
        <li key={id}>
          <Ref id={id} showKind={showKind} />
        </li>
      ))}
    </ul>
  )
}
