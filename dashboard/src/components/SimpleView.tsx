import { useMemo, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import type { Alert, Stats } from '../lib'
import {
  threatMeta, describeAlert, relTime, compact, SEV_COLOR, SEV_LABEL, SEV_RANK,
  THREAT_ORDER, SEVERITY_ORDER,
} from '../lib'
import { Info } from './Info'
import { exportCsv, exportPdf } from '../report'
import type { DemoState } from '../useDemoSimulation'

interface Props {
  alerts: Alert[]
  stats: Stats | null
  now: number
  demoState: DemoState
  onRunDemo: () => void
}

/* Rolling window backing the "live" summary — kept short so the counts track
   current activity rather than stale history. */
const RECENT_WINDOW_SEC = 600

export function SimpleView({ alerts, stats, now, demoState: demo, onRunDemo: runDemo }: Props) {
  const [sel, setSel] = useState<Alert | null>(null)
  const [fType, setFType] = useState<string>('')
  const [fSev, setFSev] = useState<string>('')

  /* Threat types that have ever appeared, for the filter dropdown. */
  const typeOptions = useMemo(() => {
    const set = new Set(alerts.map(a => a.threat_class))
    return THREAT_ORDER.filter(k => set.has(k))
  }, [alerts])

  const filtersActive = !!fType || !!fSev
  const clearFilters = () => { setFType(''); setFSev('') }

  const passesFilter = (a: Alert) =>
    (!fType || a.threat_class === fType) && (!fSev || a.severity === fSev)

  const filterSummary = [
    fType ? `Type: ${threatMeta(fType).label}` : '',
    fSev ? `Severity: ${SEV_LABEL[fSev] ?? fSev}` : '',
  ].filter(Boolean).join(' · ') || 'All threats'

  /* Alerts within the recent window, newest first, honouring filters. */
  const recent = useMemo(() => {
    const cutoff = now / 1000 - RECENT_WINDOW_SEC
    return alerts.filter(a => a.timestamp >= cutoff && passesFilter(a))
  }, [alerts, now, fType, fSev])

  /* Full filtered set (all time) — used for exports so a report can cover
     everything the monitor retains, not just the live window. */
  const filteredAll = useMemo(
    () => alerts.filter(passesFilter),
    [alerts, fType, fSev]
  )

  const runPdf = () => exportPdf({ alerts: filteredAll, stats, filterSummary })
  const runCsv = () => exportCsv({ alerts: filteredAll, stats, filterSummary })

  const recentCrit = recent.filter(a => a.severity === 'CRITICAL').length
  const recentHigh = recent.filter(a => a.severity === 'HIGH').length
  const recentMed = recent.filter(a => a.severity === 'MEDIUM').length

  /* Status level drives the banner. */
  const level: 'clear' | 'elevated' | 'attack' =
    recentCrit > 0 ? 'attack' : (recentHigh > 0 || recentMed > 2) ? 'elevated' : 'clear'

  /* Worst recent alert + its top source, for the banner detail line. */
  const worst = useMemo(() => {
    const sorted = [...recent].sort((a, b) =>
      (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) || b.timestamp - a.timestamp)
    return sorted[0] ?? null
  }, [recent])

  const topSource = useMemo(() => {
    const counts = new Map<string, number>()
    for (const a of recent) counts.set(a.src_ip, (counts.get(a.src_ip) ?? 0) + 1)
    let best: [string, number] | null = null
    for (const e of counts) if (!best || e[1] > best[1]) best = e
    return best
  }, [recent])

  /* Which threat types are active right now, ordered by our canonical order. */
  const activeTypes = useMemo(() => {
    const set = new Set(recent.map(a => a.threat_class))
    return THREAT_ORDER.filter(k => set.has(k))
  }, [recent])

  /* Simple per-minute timeline (last ~15 min) — total events per minute. */
  const timeline = useMemo(() => {
    const buckets = new Map<number, number>()
    const startMin = Math.floor((now / 1000 - 15 * 60) / 60)
    const nowMin = Math.floor(now / 1000 / 60)
    for (let m = startMin; m <= nowMin; m++) buckets.set(m, 0)
    for (const a of alerts) {
      const m = Math.floor(a.timestamp / 60)
      if (buckets.has(m)) buckets.set(m, (buckets.get(m) ?? 0) + 1)
    }
    return Array.from(buckets.entries()).map(([m, v]) => ({
      t: new Date(m * 60000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
      v,
    }))
  }, [alerts, now])

  const feed = recent.slice(0, 12)
  const total = stats?.total_alerts ?? 0

  return (
    <div className="simple">
      {/* ── Status banner ── */}
      <section className={`status-banner ${level}`} aria-live="polite">
        <div className="sb-icon" aria-hidden="true">
          {level === 'attack' ? 'ALERT' : level === 'elevated' ? 'WATCH' : 'CLEAR'}
        </div>
        <div className="sb-text">
          <h1 className="sb-title">
            {level === 'attack' && 'Active threats detected'}
            {level === 'elevated' && 'Elevated activity'}
            {level === 'clear' && 'All clear'}
          </h1>
          <p className="sb-desc">
            {level === 'attack' && worst && (
              <>
                {recentCrit} critical {recentCrit === 1 ? 'threat' : 'threats'} active right now.
                {' '}Most serious: <strong>{threatMeta(worst.threat_class).label}</strong>
                {topSource && <> · busiest source <span className="mono">{topSource[0]}</span></>}.
              </>
            )}
            {level === 'elevated' && (
              <>
                {recentHigh + recentMed} notable {recentHigh + recentMed === 1 ? 'event' : 'events'} happening
                live. Worth a look, but nothing critical right now.
              </>
            )}
            {level === 'clear' && (
              <>No active threats right now. The system is watching traffic live, in real time.</>
            )}
          </p>
        </div>
        <div className="sb-count">
          <div className="sb-count-n">{recent.length}</div>
          <div className="sb-count-l">events · live</div>
        </div>
      </section>

      {/* ── Plain-language cards ── */}
      <section className="cards" aria-label="Summary">
        <div className="card">
          <div className="card-k">
            Critical now
            <Info text="Live events that need immediate attention (highest confidence detections)." />
          </div>
          <div className="card-v" style={{ color: 'var(--crit)' }}>{recentCrit}</div>
          <div className="card-s">live</div>
        </div>
        <div className="card">
          <div className="card-k">
            Needs a look
            <Info text="High and medium live events — suspicious, but not confirmed critical." />
          </div>
          <div className="card-v" style={{ color: 'var(--high)' }}>{recentHigh + recentMed}</div>
          <div className="card-s">high &amp; medium · live</div>
        </div>
        <div className="card">
          <div className="card-k">
            Threat types active
            <Info text="How many of the six kinds of threat the system has seen recently." />
          </div>
          <div className="card-v" style={{ color: 'var(--gov-blue)' }}>{activeTypes.length}<span className="card-of"> / 6</span></div>
          <div className="card-s">
            {activeTypes.length ? activeTypes.map(k => threatMeta(k).label.split(' ')[0]).join(', ') : 'none right now'}
          </div>
        </div>
        <div className="card">
          <div className="card-k">
            Total seen
            <Info text="Every threat event recorded since the monitor started running." />
          </div>
          <div className="card-v">{compact(total)}</div>
          <div className="card-s">since start</div>
        </div>
      </section>

      {/* ── Filter + export toolbar ── */}
      <section className="simple-toolbar" aria-label="Filters and export">
        <div className="stb-filters">
          <span className="stb-label">Filter</span>
          <label className="stb-field">
            <span className="stb-field-l">Threat type</span>
            <select value={fType} onChange={e => setFType(e.target.value)} aria-label="Filter by threat type">
              <option value="">All types</option>
              {typeOptions.map(k => (
                <option key={k} value={k}>{threatMeta(k).label}</option>
              ))}
            </select>
          </label>
          <label className="stb-field">
            <span className="stb-field-l">Threat level</span>
            <select value={fSev} onChange={e => setFSev(e.target.value)} aria-label="Filter by threat level">
              <option value="">All levels</option>
              {SEVERITY_ORDER.map(s => (
                <option key={s} value={s}>{SEV_LABEL[s]}</option>
              ))}
            </select>
          </label>
          {filtersActive && (
            <button className="stb-clear" onClick={clearFilters}>Clear filters</button>
          )}
        </div>
        <div className="stb-exports">
          <button className="stb-btn pdf" onClick={runPdf} disabled={!filteredAll.length}
            title="Download a formatted PDF report of the filtered threats">PDF report</button>
          <button className="stb-btn csv" onClick={runCsv} disabled={!filteredAll.length}
            title="Download the filtered threats as a CSV file">CSV</button>
        </div>
      </section>

      {/* ── Demo / Simulate Attack ── */}
      <section className="demo-bar" aria-label="Attack simulation">
        <div className="demo-bar-left">
          <div className="demo-bar-title">Live attack simulation</div>
          <div className="demo-bar-desc">
            Injects synthetic DDoS, port scan, DGA, C2 beaconing and data exfiltration
            into the detection pipeline. Alerts appear above within 15–30 seconds.
          </div>
          {demo.error && <div className="demo-error" role="alert">{demo.error}</div>}
        </div>
        <div className="demo-bar-right">
          {demo.running ? (
            <div className="demo-progress">
              <div className="demo-phase">{demo.phase}</div>
              <div className="demo-rail"><div className="demo-fill" style={{ width: `${demo.progress}%` }} /></div>
              <div className="demo-pct">{demo.progress}%</div>
            </div>
          ) : (
            <button className="demo-btn" onClick={runDemo} title="Inject all 5 attack types into the live pipeline">
              ▶ Simulate Attack
            </button>
          )}
          {!demo.running && demo.phase === 'Complete' && (
            <div className="demo-done">✓ Simulation complete — check alerts above</div>
          )}
        </div>
      </section>

      <div className="simple-grid">
        <section className="panel-lite">
          <div className="pl-head">
            <h2 className="pl-title">Activity over the last 15 minutes</h2>
            <span className="pl-note">events per minute</span>
          </div>
          <div style={{ height: 200, padding: '8px 8px 0 0' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 6, right: 10, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="simpleFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--gov-blue)" stopOpacity={0.28} />
                    <stop offset="100%" stopColor="var(--gov-blue)" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 4" stroke="var(--line)" vertical={false} />
                <XAxis dataKey="t" tickLine={false} axisLine={{ stroke: 'var(--line)' }}
                  minTickGap={40} tick={{ fill: 'var(--ink-3)', fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} allowDecimals={false} width={40}
                  tick={{ fill: 'var(--ink-3)', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    background: 'var(--surface)', border: '1px solid var(--line-2)',
                    borderRadius: 8, fontSize: 12, color: 'var(--ink)',
                  }}
                  labelStyle={{ color: 'var(--ink-3)' }}
                  formatter={(v: number) => [`${v} events`, '']} />
                <Area type="monotone" dataKey="v" stroke="var(--gov-blue)" strokeWidth={2}
                  fill="url(#simpleFill)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        {/* ── What kinds of threats ── */}
        <section className="panel-lite">
          <div className="pl-head">
            <h2 className="pl-title">What we're seeing</h2>
            <span className="pl-note">recent threat types</span>
          </div>
          <div className="types">
            {activeTypes.length ? activeTypes.map(k => {
              const m = threatMeta(k)
              const n = recent.filter(a => a.threat_class === k).length
              return (
                <div className="type-row" key={k}>
                  <span className="type-icon" aria-hidden="true"
                    style={{ color: m.color, borderColor: m.color }}>{m.code}</span>
                  <div className="type-body">
                    <div className="type-name" style={{ color: m.color }}>{m.label}</div>
                    <div className="type-plain">{m.plain}</div>
                  </div>
                  <span className="type-n">{n}</span>
                </div>
              )
            }) : (
              <div className="empty">
                <div className="empty-t">Nothing suspicious right now</div>
                <div className="empty-s">Active threats will appear here the moment they're detected.</div>
              </div>
            )}
          </div>
        </section>
      </div>

      {/* ── Recent threats in plain English ── */}
      <section className="panel-lite">
        <div className="pl-head">
          <h2 className="pl-title">Recent threats{filtersActive ? ' (filtered)' : ''}</h2>
          <span className="pl-note">newest first · select a row for details</span>
        </div>
        {feed.length ? (
          <ul className="feed">
            {feed.map(a => {
              const m = threatMeta(a.threat_class)
              return (
                <li key={a.alert_id}>
                  <button className="feed-row" onClick={() => setSel(a)}>
                    <span className="feed-sev" style={{ background: SEV_COLOR[a.severity] }} aria-hidden="true" />
                    <span className="feed-icon" aria-hidden="true"
                      style={{ color: m.color, borderColor: m.color }}>{m.code}</span>
                    <span className="feed-main">
                      <span className="feed-desc">{describeAlert(a)}</span>
                      <span className="feed-meta">
                        <span className="sev-chip" style={{ color: SEV_COLOR[a.severity] }}>
                          {SEV_LABEL[a.severity] ?? a.severity}
                        </span>
                        <span className="feed-time">{relTime(a.timestamp, now)}</span>
                      </span>
                    </span>
                    <span className="feed-go" aria-hidden="true">&rsaquo;</span>
                  </button>
                </li>
              )
            })}
          </ul>
        ) : (
          <div className="empty">
            <div className="empty-t">{filtersActive ? 'No threats match your filters' : 'No recent threats'}</div>
            <div className="empty-s">
              {filtersActive
                ? 'Try clearing the filters above to see everything.'
                : 'The monitor is running and will surface threats here as they happen.'}
            </div>
          </div>
        )}
      </section>

      {/* ── Detail modal ── */}
      {sel && <SimpleDetail alert={sel} onClose={() => setSel(null)} now={now} />}
    </div>
  )
}

/* Plain-language detail card shown when a feed row is selected. */
function SimpleDetail({ alert, onClose, now }: { alert: Alert; onClose: () => void; now: number }) {
  const m = threatMeta(alert.threat_class)
  return (
    <div className="modal-scrim" onClick={onClose} role="presentation">
      <div className="modal" role="dialog" aria-modal="true" aria-label={m.label}
        onClick={e => e.stopPropagation()}>
        <div className="modal-head" style={{ borderColor: m.color }}>
          <span className="modal-icon" aria-hidden="true"
            style={{ color: m.color, borderColor: m.color }}>{m.code}</span>
          <div>
            <div className="modal-title" style={{ color: m.color }}>{m.label}</div>
            <div className="modal-sub">
              <span className="sev-chip" style={{ color: SEV_COLOR[alert.severity] }}>
                {SEV_LABEL[alert.severity] ?? alert.severity}
              </span>
              · detected {relTime(alert.timestamp, now)}
            </div>
          </div>
          <button className="modal-x" onClick={onClose} aria-label="Close">Close</button>
        </div>

        <div className="modal-body">
          <p className="modal-plain">{m.plain}</p>

          <div className="modal-flow">
            <div className="mf-node">
              <div className="mf-k">From</div>
              <div className="mf-v mono">{alert.src_ip || '—'}{alert.src_port ? `:${alert.src_port}` : ''}</div>
            </div>
            <div className="mf-arrow" aria-hidden="true">→</div>
            <div className="mf-node tgt">
              <div className="mf-k">To</div>
              <div className="mf-v mono">{alert.dst_ip || '—'}{alert.dst_port ? `:${alert.dst_port}` : ''}</div>
            </div>
          </div>

          <div className="modal-conf">
            <div className="mc-row">
              <span>How sure the system is</span>
              <span className="mono" style={{ fontWeight: 700 }}>{(alert.confidence * 100).toFixed(0)}%</span>
            </div>
            <div className="mc-rail">
              <div className="mc-fill" style={{ width: `${alert.confidence * 100}%`, background: m.color }} />
            </div>
          </div>

          <div className="modal-advice">
            <div className="ma-h">What to do</div>
            <p>{m.action}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
