import type { Health, Snapshot, Tokens } from './types'

/// Where the simulator is. The plain HTTP listener by default, so the browser does not have to
/// trust the simulator's self-generated TLS certificate just to read from it.
export const simUrl = (import.meta.env.VITE_SIM_URL ?? 'http://localhost:8080').replace(/\/+$/, '')

export interface SimState {
  health: Health
  snapshot: Snapshot
  /// `null` when the simulator predates `/__sim__/tokens`. That is a version gap, not a fault,
  /// so it must not take the rest of the studio down with it.
  tokens: Tokens | null
  /// Simulator clock minus browser clock, in milliseconds. Expiry countdowns add this to
  /// `Date.now()`, so a skewed laptop clock (or a container with its own idea of the time) does
  /// not make a live token look expired or the other way round.
  clockOffsetMs: number
  fetchedAt: number
}

/// Raised when the simulator cannot be reached at all, as opposed to answering with an error.
/// The two need different advice: one means "start it", the other means "look at its log".
export class UnreachableError extends Error {}

export async function fetchAll(signal?: AbortSignal): Promise<SimState> {
  const [health, snapshot, tokens] = await Promise.all([
    getJson<Health>('/__sim__/health', signal),
    getJson<Snapshot>('/__sim__/snapshot', signal, true),
    getTokens(signal),
  ])
  const fetchedAt = Date.now()

  // The token endpoint states the simulator's time explicitly. Older simulators do not have
  // it, and then the HTTP Date header is the next best thing, at one-second resolution.
  const serverTime = tokens.body ? Date.parse(tokens.body.serverTime) : snapshot.date
  const clockOffsetMs = Number.isFinite(serverTime) ? serverTime - fetchedAt : 0

  return {
    health: health.body,
    snapshot: normalise(snapshot.body),
    tokens: tokens.body,
    clockOffsetMs,
    fetchedAt,
  }
}

async function getTokens(signal?: AbortSignal): Promise<{ body: Tokens | null }> {
  const response = await request('/__sim__/tokens', signal)
  if (response.status === 404) return { body: null }
  if (!response.ok) throw new Error(`GET /__sim__/tokens returned ${response.status}`)
  return { body: (await response.json()) as Tokens }
}

async function getJson<T>(
  path: string,
  signal?: AbortSignal,
  withDate = false,
): Promise<{ body: T; date: number }> {
  const response = await request(path, signal)
  if (!response.ok) throw new Error(`GET ${path} returned ${response.status}`)
  const date = withDate ? Date.parse(response.headers.get('date') ?? '') : NaN
  return { body: (await response.json()) as T, date }
}

async function request(path: string, signal?: AbortSignal): Promise<Response> {
  try {
    return await fetch(`${simUrl}${path}`, { signal, cache: 'no-store' })
  } catch (error) {
    // fetch rejects only when no HTTP response arrived at all: refused connection, DNS, CORS.
    if (signal?.aborted) throw error
    throw new UnreachableError(`Cannot reach ${simUrl}: ${String(error)}`)
  }
}

/// The snapshot's sections are serialised with `default`, so a section can in principle be
/// absent. Filling them in once here saves every view from guarding against it.
function normalise(raw: Partial<Snapshot>): Snapshot {
  return {
    users: raw.users ?? [],
    groups: raw.groups ?? [],
    applications: raw.applications ?? [],
    servicePrincipals: raw.servicePrincipals ?? [],
    appRoleAssignments: raw.appRoleAssignments ?? [],
    oauth2PermissionGrants: raw.oauth2PermissionGrants ?? [],
    directoryRoles: raw.directoryRoles ?? [],
    groupLinks: raw.groupLinks ?? [],
    roleMembers: raw.roleMembers ?? [],
    owners: raw.owners ?? [],
    secrets: raw.secrets ?? [],
    passwords: raw.passwords ?? [],
    // Left undefined when absent: before 0.4.0 the section did not exist, which is different from
    // an application having no federated credentials.
    federatedCredentials: raw.federatedCredentials,
  }
}
