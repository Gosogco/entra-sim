import type {
  AppRole,
  Application,
  AppRoleAssignment,
  OAuth2PermissionGrant,
  PermissionScope,
  ServicePrincipal,
  Snapshot,
} from './types'

export type ObjectKind = 'user' | 'group' | 'servicePrincipal' | 'application' | 'directoryRole'

export interface NamedObject {
  id: string
  kind: ObjectKind
  name: string
  /// A second line of identification, such as a user's UPN.
  detail?: string
}

/// Everything in the snapshot, cross-referenced.
///
/// The snapshot is a flat dump: objects refer to each other by GUID, and the links that Graph
/// models as navigation properties (members, owners) live in their own sections. Every view
/// needs the same joins, so they are built once per fetch here rather than in each table.
export interface Directory {
  snapshot: Snapshot
  /// Object ID to name, across users, groups, service principals, applications and roles.
  byId: Map<string, NamedObject>
  /// appId to name. A service principal wins over its application, because the principal is
  /// what tokens and assignments actually refer to.
  byAppId: Map<string, NamedObject>
  spByAppId: Map<string, ServicePrincipal>
  spById: Map<string, ServicePrincipal>
  appByAppId: Map<string, Application>
  groupMembers: Map<string, string[]>
  groupOwners: Map<string, string[]>
  /// Member object ID to the groups it is directly in.
  memberOf: Map<string, string[]>
  roleMembers: Map<string, string[]>
  /// Application or service principal object ID to its owners.
  owners: Map<string, string[]>
  /// `${applicationObjectId}/${keyId}` to the secret's plaintext.
  secrets: Map<string, string>
  passwords: Map<string, string>
}

export function buildDirectory(snapshot: Snapshot): Directory {
  const byId = new Map<string, NamedObject>()
  const byAppId = new Map<string, NamedObject>()

  for (const user of snapshot.users) {
    byId.set(user.id, {
      id: user.id,
      kind: 'user',
      name: user.displayName,
      detail: user.userPrincipalName,
    })
  }
  for (const group of snapshot.groups) {
    byId.set(group.id, { id: group.id, kind: 'group', name: group.displayName })
  }
  for (const app of snapshot.applications) {
    const named: NamedObject = { id: app.id, kind: 'application', name: app.displayName }
    byId.set(app.id, named)
    byAppId.set(app.appId, named)
  }
  for (const sp of snapshot.servicePrincipals) {
    const named: NamedObject = { id: sp.id, kind: 'servicePrincipal', name: sp.displayName }
    byId.set(sp.id, named)
    byAppId.set(sp.appId, named)
  }
  for (const role of snapshot.directoryRoles) {
    byId.set(role.id, { id: role.id, kind: 'directoryRole', name: role.displayName })
  }

  const groupMembers = new Map<string, string[]>()
  const groupOwners = new Map<string, string[]>()
  const memberOf = new Map<string, string[]>()
  for (const links of snapshot.groupLinks) {
    groupMembers.set(links.groupId, links.members ?? [])
    groupOwners.set(links.groupId, links.owners ?? [])
    for (const member of links.members ?? []) push(memberOf, member, links.groupId)
  }

  return {
    snapshot,
    byId,
    byAppId,
    spByAppId: new Map(snapshot.servicePrincipals.map((sp) => [sp.appId, sp])),
    spById: new Map(snapshot.servicePrincipals.map((sp) => [sp.id, sp])),
    appByAppId: new Map(snapshot.applications.map((app) => [app.appId, app])),
    groupMembers,
    groupOwners,
    memberOf,
    roleMembers: new Map(snapshot.roleMembers.map((r) => [r.roleId, r.members ?? []])),
    owners: new Map(snapshot.owners.map((o) => [o.objectId, o.owners ?? []])),
    secrets: new Map(snapshot.secrets.map((s) => [`${s.applicationId}/${s.keyId}`, s.secretText])),
    passwords: new Map(snapshot.passwords.map((p) => [p.userId, p.password])),
  }
}

/// A name for any GUID, for searching. Falls back to the GUID itself.
export function nameOf(dir: Directory, id: string | undefined | null): string {
  if (!id) return ''
  return dir.byId.get(id)?.name ?? dir.byAppId.get(id)?.name ?? id
}

/// Every group the object is in, directly or through nesting, each with the group it was
/// reached through. Groups can contain groups, and access granted to the outer group reaches
/// members of the inner one, so direct membership alone understates what a user can do.
export function transitiveGroups(
  dir: Directory,
  memberId: string,
): { groupId: string; via?: string }[] {
  const result: { groupId: string; via?: string }[] = []
  const seen = new Set<string>()
  const queue: { id: string; via?: string }[] = [{ id: memberId }]
  while (queue.length > 0) {
    const current = queue.shift()!
    for (const groupId of dir.memberOf.get(current.id) ?? []) {
      // A cycle is possible in a simulator that does not police it, so stop at the first visit.
      if (seen.has(groupId)) continue
      seen.add(groupId)
      const via = current.id === memberId ? undefined : current.id
      result.push({ groupId, via })
      queue.push({ id: groupId, via })
    }
  }
  return result
}

export interface ResolvedPermission {
  id: string
  /// The permission's value, such as `User.Read`, or the GUID when it cannot be resolved.
  value: string
  description?: string
  resolved: boolean
}

/// Resolve an app role GUID against the service principal that defines it.
export function resolveRole(sp: ServicePrincipal | undefined, roleId: string): ResolvedPermission {
  // The all-zero GUID is Entra's "default access" assignment: access to the app with no role.
  if (/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(roleId)) {
    return { id: roleId, value: 'Default access', resolved: true }
  }
  const role: AppRole | undefined = sp?.appRoles?.find((r) => r.id === roleId)
  return role
    ? { id: roleId, value: role.value ?? role.displayName, description: role.displayName, resolved: true }
    : { id: roleId, value: roleId, resolved: false }
}

/// Resolve a delegated permission GUID against the service principal that exposes it.
export function resolveScope(
  sp: ServicePrincipal | undefined,
  scopeId: string,
): ResolvedPermission {
  const scope: PermissionScope | undefined = sp?.oauth2PermissionScopes?.find((s) => s.id === scopeId)
  return scope
    ? {
        id: scopeId,
        value: scope.value ?? scope.adminConsentDisplayName,
        description: scope.adminConsentDisplayName,
        resolved: true,
      }
    : { id: scopeId, value: scopeId, resolved: false }
}

/// Look up a delegated permission by value, as grants store them, to recover its description.
export function scopeByValue(sp: ServicePrincipal | undefined, value: string) {
  return sp?.oauth2PermissionScopes?.find((s) => s.value === value)
}

/// The assignment's role, resolved against its resource.
export function assignmentRole(dir: Directory, assignment: AppRoleAssignment) {
  return resolveRole(dir.spById.get(assignment.resourceId), assignment.appRoleId)
}

export function grantScopes(grant: OAuth2PermissionGrant): string[] {
  return grant.scope.split(/\s+/).filter(Boolean)
}

/// A resource named by a token's audience: an appId, a service principal name, or an
/// identifier URI with a trailing slash or scope path.
export function resolveAudience(dir: Directory, audience: string): ServicePrincipal | undefined {
  const direct = dir.spByAppId.get(audience)
  if (direct) return direct
  const trimmed = audience.replace(/\/+$/, '')
  return dir.snapshot.servicePrincipals.find((sp) =>
    (sp.servicePrincipalNames ?? []).some((name) => name.replace(/\/+$/, '') === trimmed),
  )
}

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const list = map.get(key)
  if (list) list.push(value)
  else map.set(key, [value])
}
