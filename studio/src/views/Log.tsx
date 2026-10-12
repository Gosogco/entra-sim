import { Fragment, useEffect, useMemo, useRef, useState } from 'react'

import { getLog } from '../api'
import { DataTable } from '../components/DataTable'
import { Section } from '../components/Section'
import type { EventLogEntry, LogEntry, RequestLogEntry } from '../types'

/// Shown instead of the log when the simulator has no `/__sim__/logs`.
function LogUnsupported({ version }: { version: string }) {
  return (
    <div className="notice" data-testid="log-unsupported">
      <strong>This simulator version doesn't keep a log.</strong> It is running {version}. Run the
      simulator from source with <code>./run.sh</code>.
    </div>
  )
}

/// Everything the simulator recorded, newest first.
///
/// Reads only what is new each time the rest of the studio refreshes, so the whole log, which
/// has no size limit, is never fetched at once. Older entries load a page at a time on request.
export function LogView({ fetchedAt, version }: { fetchedAt: number; version: string }) {
  // `undefined` until the first answer, `null` when the simulator has no log endpoint.
  const [status, setStatus] = useState<{ enabled: boolean; total: number } | null | undefined>()
  const [entries, setEntries] = useState<LogEntry[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const newest = useRef<number | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    const after = newest.current
    getLog(after === null ? {} : { after }, controller.signal)
      .then((page) => {
        setError(null)
        setStatus(page && { enabled: page.enabled, total: page.total })
        if (!page) return
        // Fewer entries than the newest one shown means the log was deleted and started over.
        // Starting over here too, on the next refresh, beats waiting for numbers never reused.
        if (after !== null && page.total <= after) {
          newest.current = null
          setEntries([])
          return
        }
        if (page.entries.length === 0) return
        newest.current = page.entries[0].seq
        setEntries((current) => (after === null ? page.entries : [...page.entries, ...current]))
      })
      .catch((failure) => {
        if (!controller.signal.aborted) setError(String(failure))
      })
    return () => controller.abort()
  }, [fetchedAt])

  const eventsByRequest = useMemo(() => {
    const byRequest = new Map<string, EventLogEntry[]>()
    for (const entry of entries) {
      if (entry.kind !== 'event' || !entry.requestId) continue
      const events = byRequest.get(entry.requestId) ?? []
      events.push(entry)
      byRequest.set(entry.requestId, events)
    }
    return byRequest
  }, [entries])

  const oldest = entries.at(-1)?.seq

  const loadOlder = async () => {
    if (oldest === undefined) return
    setLoadingOlder(true)
    try {
      const page = await getLog({ before: oldest })
      if (page) setEntries((current) => [...current, ...page.entries])
    } catch (failure) {
      setError(String(failure))
    } finally {
      setLoadingOlder(false)
    }
  }

  if (status === undefined) return error ? <ErrorNotice error={error} /> : <p className="muted">Loading…</p>
  if (status === null) return <LogUnsupported version={version} />
  if (!status.enabled) {
    return (
      <div className="notice" data-testid="log-off">
        <strong>This simulator keeps no log.</strong> Start it with <code>ENTRA_SIM_LOG_DIR</code> set to a
        directory, or with <code>./run.sh</code>, which keeps the log on a Docker volume.
      </div>
    )
  }

  return (
    <>
      {error && <ErrorNotice error={error} />}
      <DataTable
        title="Log"
        testId="log-table"
        rows={entries}
        rowKey={(entry) => String(entry.seq)}
        searchText={(entry) => JSON.stringify(entry)}
        columns={[
          { header: 'Time', cell: (entry) => <LogTime at={entry.time} />, className: 'nowrap' },
          {
            header: 'Kind',
            cell: (entry) =>
              entry.kind === 'request' ? (
                <span className="badge badge-access">HTTP</span>
              ) : (
                <span className={`badge badge-${entry.level.toLowerCase()}`}>{entry.level}</span>
              ),
          },
          {
            header: 'What',
            cell: (entry) =>
              entry.kind === 'request' ? (
                <code>
                  {entry.method} {entry.uri}
                </code>
              ) : (
                <EventSummary event={entry} />
              ),
          },
          {
            header: 'Status',
            cell: (entry) =>
              entry.kind === 'request' && <span className={statusClass(entry.status)}>{entry.status}</span>,
          },
          {
            header: 'Duration',
            cell: (entry) => entry.kind === 'request' && `${entry.durationMs.toFixed(1)} ms`,
            className: 'nowrap',
          },
          {
            header: 'Source',
            cell: (entry) => entry.kind === 'event' && <code className="dim">{entry.target}</code>,
          },
        ]}
        details={(entry) =>
          entry.kind === 'request' ? (
            <RequestDetails request={entry} events={eventsByRequest.get(entry.requestId) ?? []} />
          ) : (
            <EventDetails
              event={entry}
              request={entries.find((other) => other.kind === 'request' && other.requestId === entry.requestId)}
            />
          )
        }
        empty="Nothing logged yet. Request a token or call Graph, and it shows up here."
      />
      <p className="muted">
        {entries.length} of {status.total} entries loaded.{' '}
        {oldest !== undefined && oldest > 0 && (
          <button type="button" onClick={() => void loadOlder()} disabled={loadingOlder} data-testid="log-older">
            {loadingOlder ? 'Loading…' : 'Load older'}
          </button>
        )}
      </p>
    </>
  )
}

function ErrorNotice({ error }: { error: string }) {
  return (
    <div className="banner" role="alert">
      <strong>Could not read the log.</strong>
      <pre>{error}</pre>
    </div>
  )
}

/// Down to the second: a log is read for the order things happened in.
function LogTime({ at }: { at: string }) {
  const date = new Date(at)
  if (Number.isNaN(date.getTime())) return <span>{at}</span>
  return (
    <time dateTime={at} title={at}>
      {date.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' })}
    </time>
  )
}

function statusClass(status: number): string {
  if (status >= 500) return 'bad'
  if (status >= 400) return 'warn'
  return 'ok'
}

function EventSummary({ event }: { event: EventLogEntry }) {
  return (
    <>
      {event.message}
      {Object.entries(event.fields).map(([name, value]) => (
        <span key={name} className="dim">
          {' '}
          {name}={String(value)}
        </span>
      ))}
    </>
  )
}

function RequestDetails({ request, events }: { request: RequestLogEntry; events: EventLogEntry[] }) {
  return (
    <div className="detail-stack">
      <div className="detail-grid">
        <Section title="Request">
          <Headers headers={request.requestHeaders} />
          <Body body={request.requestBody} />
        </Section>
        <Section title="Response">
          <Headers headers={request.responseHeaders} />
          <Body body={request.responseBody} />
        </Section>
      </div>
      <Section title="Events during this request">
        {events.length === 0 ? (
          <span className="muted">None.</span>
        ) : (
          <table className="mini">
            <tbody>
              {events.map((event) => (
                <tr key={event.seq}>
                  <td>
                    <span className={`badge badge-${event.level.toLowerCase()}`}>{event.level}</span>
                  </td>
                  <td>
                    <EventSummary event={event} />
                  </td>
                  <td>
                    <code className="dim">{event.target}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>
    </div>
  )
}

function EventDetails({ event, request }: { event: EventLogEntry; request: LogEntry | undefined }) {
  return (
    <div className="detail-grid">
      <Section title="Fields">
        {Object.keys(event.fields).length === 0 ? (
          <span className="muted">None.</span>
        ) : (
          <dl className="kv">
            {Object.entries(event.fields).map(([name, value]) => (
              <Fragment key={name}>
                <dt>{name}</dt>
                <dd>{String(value)}</dd>
              </Fragment>
            ))}
          </dl>
        )}
      </Section>
      <Section title="Request">
        {!event.requestId ? (
          <span className="muted">Outside any request.</span>
        ) : request && request.kind === 'request' ? (
          <code>
            {request.method} {request.uri} → {request.status}
          </code>
        ) : (
          <code className="dim">{event.requestId}</code>
        )}
      </Section>
    </div>
  )
}

function Headers({ headers }: { headers: Record<string, string> }) {
  return (
    <dl className="kv">
      {Object.entries(headers).map(([name, value]) => (
        <Fragment key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </Fragment>
      ))}
    </dl>
  )
}

/// JSON is indented; anything else, such as a token request's form, is shown as sent.
function Body({ body }: { body: string | null }) {
  if (body === null) return <p className="muted">No body.</p>
  let shown = body
  try {
    shown = JSON.stringify(JSON.parse(body), null, 2)
  } catch {
    // Not JSON.
  }
  return <pre className="body">{shown}</pre>
}
