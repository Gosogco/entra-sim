export const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'users', label: 'Users' },
  { id: 'groups', label: 'Groups' },
  { id: 'applications', label: 'App registrations' },
  { id: 'servicePrincipals', label: 'Enterprise apps' },
  { id: 'permissions', label: 'Permissions' },
  { id: 'roles', label: 'Directory roles' },
  { id: 'tokens', label: 'Tokens' },
] as const

export type Tab = (typeof TABS)[number]['id']

/// The tab lives in the URL hash, so a reload or a shared link lands on the same view without
/// pulling in a router for eight static pages.
export function tabFromHash(): Tab {
  const hash = window.location.hash.slice(1)
  return TABS.find((t) => t.id === hash)?.id ?? 'overview'
}
