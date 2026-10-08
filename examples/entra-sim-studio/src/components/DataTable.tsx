import { Fragment, useMemo, useState, type ReactNode } from 'react'

export interface Column<T> {
  header: string
  cell: (row: T) => ReactNode
  className?: string
}

/// A filterable table whose rows expand to show details.
///
/// Every tab is one or more of these, so they all search and expand the same way. Filtering is
/// a plain case-insensitive substring match over `searchText`, which each view builds from
/// resolved names as well as GUIDs: you search for "alice", not for her object ID, but pasting
/// an ID from a log still finds the row.
export function DataTable<T>({
  title,
  rows,
  columns,
  rowKey,
  searchText,
  details,
  empty = 'Nothing here.',
  testId,
  rowClassName,
}: {
  title?: string
  rows: T[]
  columns: Column<T>[]
  rowKey: (row: T) => string
  searchText: (row: T) => string
  details?: (row: T) => ReactNode
  empty?: ReactNode
  testId?: string
  rowClassName?: (row: T) => string | undefined
}) {
  const [query, setQuery] = useState('')
  // Keyed by row key, not index, so an expanded row stays expanded across a poll that
  // reorders or adds rows.
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())

  const filtered = useMemo(() => {
    const terms = query.toLowerCase().split(/\s+/).filter(Boolean)
    if (terms.length === 0) return rows
    return rows.filter((row) => {
      const text = searchText(row).toLowerCase()
      return terms.every((term) => text.includes(term))
    })
  }, [rows, query, searchText])

  const toggle = (key: string) => {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const span = columns.length + (details ? 1 : 0)

  return (
    <div className="table-block" data-testid={testId}>
      <div className="table-head">
        {title && <h2>{title}</h2>}
        <span className="count">
          {filtered.length === rows.length ? rows.length : `${filtered.length} of ${rows.length}`}
        </span>
        <input
          type="search"
          placeholder="Filter…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label={title ? `Filter ${title}` : 'Filter'}
        />
      </div>
      <div className="table-scroll">
        <table className="data">
          <thead>
            <tr>
              {details && <th className="toggle-col" aria-label="Expand" />}
              {columns.map((column) => (
                <th key={column.header} className={column.className}>
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={span} className="empty">
                  {rows.length === 0 ? empty : 'No rows match the filter.'}
                </td>
              </tr>
            )}
            {filtered.map((row) => {
              const key = rowKey(row)
              const open = expanded.has(key)
              return (
                <Fragment key={key}>
                  <tr
                    className={[details ? 'expandable' : '', open ? 'open' : '', rowClassName?.(row) ?? '']
                      .filter(Boolean)
                      .join(' ')}
                    onClick={details ? () => toggle(key) : undefined}
                    aria-expanded={details ? open : undefined}
                  >
                    {details && <td className="toggle-col">{open ? '▾' : '▸'}</td>}
                    {columns.map((column) => (
                      <td key={column.header} className={column.className}>
                        {column.cell(row)}
                      </td>
                    ))}
                  </tr>
                  {details && open && (
                    <tr className="details">
                      <td colSpan={span}>{details(row)}</td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
