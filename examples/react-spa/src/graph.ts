import {
  InteractionRequiredAuthError,
  type AccountInfo,
  type IPublicClientApplication,
} from '@azure/msal-browser'

import { graphBase, scopes } from './authConfig'

/// A Microsoft Graph user, limited to what this example shows.
export interface GraphUser {
  id: string
  displayName: string
  userPrincipalName: string
  mail?: string | null
  jobTitle?: string | null
}

/// What a failed Graph call says, kept whole so the page can show it.
///
/// A 403 from permission enforcement is a useful result, not noise. Reducing every failure to
/// "something went wrong" would hide exactly the faults the simulator exists to surface.
export class GraphError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message)
    this.name = 'GraphError'
  }
}

/// Read the signed-in user from Graph.
export async function fetchMe(
  instance: IPublicClientApplication,
  account: AccountInfo,
  forceRefresh = false,
): Promise<GraphUser> {
  const token = await acquireToken(instance, account, forceRefresh)
  const response = await fetch(`${graphBase}/v1.0/me`, {
    headers: { Authorization: `Bearer ${token}` },
  })

  if (!response.ok) {
    const body: unknown = await response.json().catch(() => undefined)
    const error = (body as { error?: { code?: string; message?: string } } | undefined)?.error
    throw new GraphError(
      response.status,
      error?.code,
      error?.message ?? `Graph returned ${response.status}`,
    )
  }

  return (await response.json()) as GraphUser
}

/// Get an access token, falling back to a redirect when the user must act.
///
/// `acquireTokenSilent` uses the cache and then the refresh token. It throws
/// `InteractionRequiredAuthError` when neither can serve the request, for example because
/// consent is missing. That is the only case where sending the user away is correct; doing it
/// for every failure would turn a plain error into a redirect loop.
async function acquireToken(
  instance: IPublicClientApplication,
  account: AccountInfo,
  forceRefresh: boolean,
): Promise<string> {
  try {
    // `forceRefresh` skips the cached access token and redeems the refresh token instead. That
    // is how a permission change in the directory reaches a client that is already signed in.
    const result = await instance.acquireTokenSilent({ scopes, account, forceRefresh })
    return result.accessToken
  } catch (error) {
    if (error instanceof InteractionRequiredAuthError) {
      await instance.acquireTokenRedirect({ scopes, account })
      // The redirect navigates away, so this line is not reached.
      throw error
    }
    throw error
  }
}
