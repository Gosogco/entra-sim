import { LogLevel, ProtocolMode, type Configuration } from '@azure/msal-browser'

/// Every value that differs between the simulator and a real tenant comes from the
/// environment. No source file changes between the two targets, which is the property this
/// example exists to demonstrate.
const authority = requireEnv('VITE_AUTHORITY')

/// The Graph base URL is configuration because the simulator serves Graph itself, at its own
/// address. A real tenant serves it from graph.microsoft.com.
export const graphBase = requireEnv('VITE_GRAPH_BASE').replace(/\/$/, '')

/// The permissions to ask for. `User.Read` is the delegated permission that `GET /me` needs.
export const scopes = (import.meta.env.VITE_SCOPES ?? 'User.Read')
  .split(/[ ,]+/)
  .filter(Boolean)

export const msalConfig: Configuration = {
  auth: {
    clientId: requireEnv('VITE_CLIENT_ID'),
    authority,

    // MSAL validates the authority's host. For anything other than a Microsoft cloud it would
    // otherwise ask Microsoft's instance-discovery service whether the host is genuine, which
    // for a local simulator is both wrong and unreachable.
    knownAuthorities: [new URL(authority).host],

    // The instance-discovery answer, supplied inline so MSAL makes no call to Microsoft. Unset
    // against a real tenant, where MSAL should use the real service.
    cloudDiscoveryMetadata: import.meta.env.VITE_CLOUD_DISCOVERY_METADATA,

    // The discovery document, supplied inline only if the simulator's own endpoint cannot be
    // used. Normally unset, so MSAL fetches it and the simulator's endpoint is exercised.
    authorityMetadata: import.meta.env.VITE_AUTHORITY_METADATA,

    // AAD, not OIDC. A real tenant uses AAD mode, so the simulator has to be driven through the
    // same MSAL code path or the configuration swap proves very little.
    protocolMode: ProtocolMode.AAD,

    redirectUri: window.location.origin,
    postLogoutRedirectUri: window.location.origin,
    navigateToLoginRequestUrl: false,
  },
  cache: {
    // Survives a page reload, which a redirect flow performs twice.
    cacheLocation: 'sessionStorage',
  },
  system: {
    loggerOptions: {
      logLevel: LogLevel.Info,
      // Logged to the console on purpose. When MSAL rejects something the simulator returned,
      // this is the only place that says what and why.
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return
        const line = `[msal:${LogLevel[level]}] ${message}`
        if (level === LogLevel.Error) console.error(line)
        else console.log(line)
      },
    },
  },
}

function requireEnv(name: string): string {
  const value = import.meta.env[name]
  if (!value) {
    // Failing loudly here, rather than letting MSAL fail later with a vaguer message about an
    // endpoint it could not resolve.
    throw new Error(
      `${name} is not set. Copy .env.simulator or .env.entra to .env before starting.`,
    )
  }
  return value
}
