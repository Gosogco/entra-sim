/// A timestamp in the browser's locale, with the exact RFC 3339 value on hover.
export function Time({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="muted">—</span>
  const date = new Date(at)
  if (Number.isNaN(date.getTime())) return <span>{at}</span>
  return (
    <time dateTime={at} title={at}>
      {date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
    </time>
  )
}
