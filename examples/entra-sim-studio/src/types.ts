/// The shapes the simulator's control endpoints return.
///
/// These mirror `src/store/model.rs` and `src/store/snapshot.rs` in the simulator, which
/// serialise in camelCase. Optional fields are the ones the Rust side skips when empty or
/// unset, so a missing array means "none", never "unknown".

export interface Health {
  status: string
  version: string
  tenant_id: string
}

export interface User {
  id: string
  userPrincipalName: string
  displayName: string
  accountEnabled: boolean
  mailNickname?: string
  givenName?: string
  surname?: string
  jobTitle?: string
  mail?: string
  userType?: string | null
  createdDateTime: string
}

export interface Group {
  id: string
  displayName: string
  description?: string
  mailNickname?: string
  mail?: string
  mailEnabled: boolean
  securityEnabled: boolean
  groupTypes?: string[]
  createdDateTime: string
}

export interface AppRole {
  id: string
  value: string | null
  displayName: string
  description: string
  isEnabled: boolean
  allowedMemberTypes: string[]
}

export interface PermissionScope {
  id: string
  value: string | null
  adminConsentDisplayName: string
  adminConsentDescription: string
  userConsentDisplayName?: string | null
  userConsentDescription?: string | null
  isEnabled: boolean
  type: string
}

export interface RequiredResourceAccess {
  resourceAppId: string
  resourceAccess: { id: string; type: 'Role' | 'Scope' | string }[]
}

/// A client secret as the application carries it. The value is not here: Graph never returns
/// it on read, so the snapshot carries it separately in `secrets`.
export interface PasswordCredential {
  keyId: string
  displayName: string | null
  hint: string | null
  startDateTime: string
  endDateTime: string
}

export interface KeyCredential {
  keyId: string
  displayName: string | null
  type: string
  usage: string
  key: string | null
  startDateTime: string
  endDateTime: string
}

export interface FederatedIdentityCredential {
  id: string
  name: string
  issuer: string
  subject: string
  audiences?: string[]
  description?: string
}

export interface Application {
  id: string
  appId: string
  displayName: string
  identifierUris?: string[]
  appRoles?: AppRole[]
  oauth2PermissionScopes?: PermissionScope[]
  requiredResourceAccess?: RequiredResourceAccess[]
  signInAudience?: string
  passwordCredentials?: PasswordCredential[]
  keyCredentials?: KeyCredential[]
  createdDateTime: string
  /// Unmodelled properties pass through untouched, including the platform blocks that hold
  /// redirect URIs.
  spa?: { redirectUris?: string[] }
  web?: { redirectUris?: string[] }
  publicClient?: { redirectUris?: string[] }
}

export interface ServicePrincipal {
  id: string
  appId: string
  displayName: string
  appRoles?: AppRole[]
  oauth2PermissionScopes?: PermissionScope[]
  servicePrincipalNames?: string[]
  appRoleAssignmentRequired: boolean
  tags?: string[]
  passwordCredentials?: PasswordCredential[]
  keyCredentials?: KeyCredential[]
  createdDateTime: string
}

export interface AppRoleAssignment {
  id: string
  appRoleId: string
  principalId: string
  principalDisplayName: string | null
  principalType: string
  resourceId: string
  resourceDisplayName: string | null
  createdDateTime: string
}

export interface OAuth2PermissionGrant {
  id: string
  /// Object ID of the client service principal, not its appId.
  clientId: string
  consentType: 'AllPrincipals' | 'Principal' | string
  principalId?: string
  resourceId: string
  /// Space-separated permission values, not GUIDs.
  scope: string
}

export interface DirectoryRole {
  id: string
  roleTemplateId: string
  displayName: string
  description: string
}

export interface Snapshot {
  users: User[]
  groups: Group[]
  applications: Application[]
  servicePrincipals: ServicePrincipal[]
  appRoleAssignments: AppRoleAssignment[]
  oauth2PermissionGrants: OAuth2PermissionGrant[]
  directoryRoles: DirectoryRole[]
  groupLinks: { groupId: string; members: string[]; owners: string[] }[]
  roleMembers: { roleId: string; members: string[] }[]
  owners: { objectId: string; owners: string[] }[]
  /// Absent before simulator 0.4.0, which left federated credentials out of the snapshot.
  federatedCredentials?: { applicationId: string; credentials: FederatedIdentityCredential[] }[]
  /// `applicationId` is the application's object ID, not its appId.
  secrets: { applicationId: string; keyId: string; secretText: string }[]
  passwords: { userId: string; password: string }[]
}

export interface IssuedToken {
  id: string
  kind: 'access' | 'id'
  grant: 'client_credentials' | 'authorization_code' | 'refresh_token' | string
  clientId: string
  subjectId: string
  subjectKind: 'user' | 'servicePrincipal'
  subjectName: string
  audience: string
  scopes: string[]
  roles: string[]
  issuedAt: string
  expiresAt: string
}

export interface RefreshTokenRecord {
  prefix: string
  clientId: string
  userId: string
  scope: string
  expiresAt: string
}

export interface PendingCode {
  prefix: string
  clientId: string
  userId: string
  redirectUri: string
  scope: string
  expiresAt: string
}

export interface Tokens {
  serverTime: string
  /// Newest first, and including tokens that have already expired.
  issued: IssuedToken[]
  refreshTokens: RefreshTokenRecord[]
  pendingCodes: PendingCode[]
}
