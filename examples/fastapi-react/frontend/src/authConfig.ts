import { LogLevel, ProtocolMode, type Configuration } from '@azure/msal-browser'

const authority = requireEnv('VITE_AUTHORITY')

/// The orders API's delegated scope. The access token MSAL returns for it is the one the site
/// sends to the backend.
export const apiScopes = [requireEnv('VITE_API_SCOPE')]

export const msalConfig: Configuration = {
  auth: {
    clientId: requireEnv('VITE_CLIENT_ID'),
    authority,

    // MSAL would otherwise ask Microsoft's instance-discovery service whether the simulator's
    // host is genuine. The answer is supplied inline instead.
    knownAuthorities: [new URL(authority).host],
    cloudDiscoveryMetadata: import.meta.env.VITE_CLOUD_DISCOVERY_METADATA,

    protocolMode: ProtocolMode.AAD,

    // With a trailing slash, because that is what is registered and Entra matches it exactly.
    redirectUri: `${window.location.origin}/`,
    postLogoutRedirectUri: `${window.location.origin}/`,
    navigateToLoginRequestUrl: false,
  },
  cache: {
    cacheLocation: 'sessionStorage',
  },
  system: {
    loggerOptions: {
      logLevel: LogLevel.Warning,
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return
        if (level === LogLevel.Error) console.error(`[msal] ${message}`)
        else console.log(`[msal] ${message}`)
      },
    },
  },
}

function requireEnv(name: string): string {
  const value = import.meta.env[name]
  if (!value) {
    throw new Error(`${name} is not set. Run ../run.sh, which writes ../.env.`)
  }
  return value
}
