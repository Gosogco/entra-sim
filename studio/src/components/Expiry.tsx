import { relative, useSimNow } from '../clock'

/// A live countdown to an expiry time, measured on the simulator's clock.
///
/// `warnBelowMs` is how close counts as "soon". It differs by what is expiring: five minutes is
/// alarming for a refresh token but routine for an access token's last stretch, while a client
/// secret wants a week's notice.
export function Expiry({ at, warnBelowMs }: { at: string; warnBelowMs: number }) {
  const now = useSimNow()
  const when = Date.parse(at)
  if (!Number.isFinite(when)) return <span className="muted">{at}</span>
  const remaining = when - now
  const expired = remaining <= 0
  const soon = !expired && remaining < warnBelowMs
  return (
    <span
      className={`expiry${expired ? ' expired' : soon ? ' soon' : ''}`}
      title={new Date(when).toISOString()}
    >
      {expired ? `expired ${relative(remaining)}` : relative(remaining)}
    </span>
  )
}

/// Whether a time has passed, on the simulator's clock.
export function isExpired(at: string, now: number): boolean {
  return Date.parse(at) <= now
}
