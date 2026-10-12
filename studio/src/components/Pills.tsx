import type { ReactNode } from 'react'

/// Short values, such as scopes or tags, as a wrapping row of chips.
export function Pills({
  values,
  empty = '—',
}: {
  values: ReactNode[] | undefined
  empty?: string
}) {
  if (!values || values.length === 0) return <span className="muted">{empty}</span>
  return (
    <span className="pills">
      {values.map((value, i) => (
        <span className="pill" key={i}>
          {value}
        </span>
      ))}
    </span>
  )
}
