import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, RadarChart, PolarGrid, PolarAngleAxis, Radar,
} from 'recharts'

/* ── Types ─────────────────────────────────────── */
interface Alert {
  alert_id: string
  timestamp: number
  threat_class: string
  confidence: number
  severity: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  flow_id: string
  evidence: Record<string, unknown>
  model_version: string
}

interface Stats {
  total_alerts: number
  by_threat_class: Record<string, number>
  by_severity: Record<string, number>
  alerts_per_minute: number
  top_sources: Record<string, number>
  uptime_seconds: number
}

interface Slot {
  t: string
  DDoS: number
  PortScan: number
  DGA: number
  total: number
}

/* ── Palette ───────────────────────────────────── */
const K = {
  fg: '#e3e7ec',
  fg2: '#99a3b0',
  dim: '#6b7684',
  mute: '#4d5663',
  line: '#1e232b',
  elev: '#1a1f27',
  ok: '#17b8a6',
  info: '#3b9eff',
  crit: '#e5484d',
  high: '#f2760a',
  med: '#e2b100',
  low: '#2f9e64',
}

const TC: Record<string, string> = {
  DDoS: K.crit,
  PortScan: K.high,
  DGA: K.med,
  C2: K.info,
  Exfil: '#b58900',
  Recon: K.fg2,
}

const SC: Record<string, string> = {
  CRITICAL: K.crit,
  HIGH: K.high,
  MEDIUM: K.med,
  LOW: K.low,
}

const MODULES = [
  { n: 'Volumetric DDoS', a: 'STANDBY · pending retrain', k: 'DDoS', on: false },
  { n: 'Recon / Port Scan', a: 'LogisticRegression · 18f · calibrated', k: 'PortScan', on: true },
  { n: 'DGA & DNS Tunnel', a: 'GB + char n-gram', k: 'DGA', on: true },
  { n: 'C2 Beaconing', a: 'IAT periodicity', k: 'C2', on: false },
  { n: 'Encrypted Malware', a: 'JA4 · TLS metadata', k: 'TLS', on: false },
  { n: 'Data Exfiltration', a: 'Byte-ratio anomaly', k: 'Exfil', on: false },
]

const TABS = ['Threat Posture', 'Live Feed', 'Detection Engines', 'Telemetry', 'Flow Records']

const WS_URL = `ws://${window.location.host}/ws/alerts`

/* ── Utils ─────────────────────────────────────── */
const hhmmss = (d: Date) =>
  d.toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })

const confHue = (c: number) => (c >= 0.95 ? K.crit : c >= 0.9 ? K.high : c >= 0.8 ? K.med : K.low)

const compact = (n: number) =>
  n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}K` : `${n}`

const evNum = (v: unknown) =>
  typeof v === 'number' ? (Number.isInteger(v) ? v.toLocaleString() : v.toFixed(3)) : String(v)

/* Behavioural score from evidence spread + confidence */
const behav = (a: Alert) => {
  const nums = Object.values(a.evidence).filter(v => typeof v === 'number') as number[]
  const spread = nums.length
    ? Math.min(nums.reduce((s, n) => s + Math.log10(Math.abs(n) + 10), 0) / (nums.length * 3), 1)
    : 0.5
  return Math.min(0.55 * a.confidence + 0.45 * spread, 1)
}

/* ── Bits ──────────────────────────────────────── */
interface TP { name?: string; value?: number; color?: string }
function Tip({ active, payload, label }: { active?: boolean; payload?: TP[]; label?: string | number }) {
  if (!active || !payload?.length) return null
  const rows = payload.filter(p => (p.value ?? 0) > 0)
  if (!rows.length) return null
  return (
    <div className="tt">
      {label !== undefined && <div className="tt-l">{String(label)}</div>}
      {rows.map((p, i) => (
        <div className="tt-r" key={i}>
          <span className="tt-sw" style={{ background: p.color }} />
          <span className="tt-n">{p.name}</span>
          <span className="tt-v">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

function Panel({ name, tools = true, foot, children, style }: {
  name: string; tools?: boolean; foot?: string
  children: React.ReactNode; style?: React.CSSProperties
}) {
  return (
    <section className="panel" style={style}>
      <div className="panel-bar">
        <span className="panel-grip">⣿</span>
        <span className="panel-name">{name}</span>
        {tools && (
          <span className="panel-tools">
            <button className="ptool" title="Expand">⤢</button>
            <button className="ptool" title="Refresh">⟳</button>
            <button className="ptool" title="Options">⋮</button>
          </span>
        )}
      </div>
      <div className="panel-body tight">{children}</div>
      {foot && <div className="panel-foot">{foot}</div>}
    </section>
  )
}

function Spark({ data, color }: { data: { v: number }[]; color: string }) {
  if (data.length < 2) return null
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
        <defs>
          <linearGradient id={`sp${color.slice(1)}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.34} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.4}
          fill={`url(#sp${color.slice(1)})`} dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function Kpi({ name, value, unit, tone, sub, trend, spark, sparkColor }: {
  name: string; value: string; unit?: string
  tone?: 'crit' | 'ok' | 'med'; sub?: string
  trend?: { dir: 'up' | 'down' | 'flat'; txt: string }
  spark?: { v: number }[]; sparkColor?: string
}) {
  return (
    <section className="panel">
      <div className="kpi">
        <div className="kpi-top">
          <span className="kpi-name">{name}</span>
          <span className="kpi-i" title={sub}>ⓘ</span>
        </div>
        <div className={`kpi-val ${tone ?? ''}`}>
          {value}{unit && <span className="kpi-unit">{unit}</span>}
        </div>
        <div className="kpi-sub">
          {trend && (
            <span className={`kpi-trend ${trend.dir}`}>
              {trend.dir === 'up' ? '▲' : trend.dir === 'down' ? '▼' : '—'} {trend.txt}
            </span>
          )}
          {sub && <span>{sub}</span>}
        </div>
        {spark && spark.length > 1 && (
          <div className="kpi-spark"><Spark data={spark} color={sparkColor ?? K.ok} /></div>
        )}
      </div>
    </section>
  )
}

/* ── App ───────────────────────────────────────── */
export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [live, setLive] = useState(false)
  const [sel, setSel] = useState<Alert | null>(null)
  const [slots, setSlots] = useState<Slot[]>([])
  const [pulse, setPulse] = useState<{ v: number }[]>([])
  const [now, setNow] = useState(new Date())
  const [tab, setTab] = useState(0)
  const [scope, setScope] = useState<'all' | 'crit'>('all')
  const [synced, setSynced] = useState(new Date())
  const ws = useRef<WebSocket | null>(null)
  const retry = useRef<number | null>(null)
  const seen = useRef(0)

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000)
    return () => clearInterval(id)
  }, [])

  /* rolling 2s pulse of alert arrivals */
  useEffect(() => {
    const id = setInterval(() => {
      setPulse(p => {
        const delta = alerts.length - seen.current
        seen.current = alerts.length
        return [...p, { v: Math.max(delta, 0) }].slice(-32)
      })
    }, 2000)
    return () => clearInterval(id)
  }, [alerts.length])

  const connect = useCallback(() => {
    const s = new WebSocket(WS_URL)
    s.onopen = () => setLive(true)
    s.onmessage = e => {
      try {
        const d = JSON.parse(e.data)
        if (d.type === 'heartbeat' || d.type === 'pong') return
        const a = d as Alert
        setAlerts(p => [a, ...p].slice(0, 400))
        setSlots(p => {
          const t = hhmmss(new Date())
          const last = p[p.length - 1]
          if (last && last.t === t) {
            const nx = { ...last, total: last.total + 1 }
            if (a.threat_class === 'DDoS') nx.DDoS += 1
            else if (a.threat_class === 'PortScan') nx.PortScan += 1
            else if (a.threat_class === 'DGA') nx.DGA += 1
            return [...p.slice(0, -1), nx]
          }
          return [...p, {
            t, total: 1,
            DDoS: a.threat_class === 'DDoS' ? 1 : 0,
            PortScan: a.threat_class === 'PortScan' ? 1 : 0,
            DGA: a.threat_class === 'DGA' ? 1 : 0,
          }].slice(-34)
        })
      } catch { /* noop */ }
    }
    s.onclose = () => { setLive(false); retry.current = window.setTimeout(connect, 3000) }
    s.onerror = () => s.close()
    ws.current = s
  }, [])

  const pull = useCallback(async () => {
    try {
      const r = await fetch('/api/stats')
      if (r.ok) { setStats(await r.json()); setSynced(new Date()) }
    } catch { /* noop */ }
  }, [])

  useEffect(() => {
    connect(); pull()
    const id = setInterval(pull, 4000)
    return () => {
      clearInterval(id)
      if (retry.current) clearTimeout(retry.current)
      ws.current?.close()
    }
  }, [connect, pull])

  /* ── derived ── */
  const total = stats?.total_alerts ?? 0
  const perMin = stats?.alerts_per_minute ?? 0
  const crit = stats?.by_severity?.CRITICAL ?? 0
  const high = stats?.by_severity?.HIGH ?? 0
  const srcN = stats ? Object.keys(stats.top_sources).length : 0
  const up = stats
    ? `${Math.floor(stats.uptime_seconds / 3600)}h ${String(Math.floor((stats.uptime_seconds % 3600) / 60)).padStart(2, '0')}m`
    : '—'

  const dist = useMemo(
    () => (stats ? Object.entries(stats.by_threat_class).map(([name, value]) => ({ name, value })) : []),
    [stats]
  )
  const topSrc = useMemo(
    () => (stats
      ? Object.entries(stats.top_sources).slice(0, 6).map(([ip, count]) => ({
        ip: ip.length > 15 ? `${ip.slice(0, 13)}…` : ip, full: ip, count,
      }))
      : []),
    [stats]
  )
  const radar = useMemo(
    () => MODULES.map(m => ({
      k: m.n.split(' ')[0],
      cov: m.on ? 100 : 30,
      act: Math.min((stats?.by_threat_class?.[m.k] ?? 0) * 4 + (m.on ? 18 : 4), 100),
    })),
    [stats]
  )
  const avgConf = useMemo(
    () => (alerts.length ? alerts.reduce((s, a) => s + a.confidence, 0) / alerts.length : 0),
    [alerts]
  )
  const peak = useMemo(() => slots.reduce((m, s) => Math.max(m, s.total), 0), [slots])
  const lastPulse = pulse.length ? pulse[pulse.length - 1].v : 0
  const classSpark = useCallback(
    (k: 'DDoS' | 'PortScan' | 'DGA') => slots.slice(-18).map(s => ({ v: s[k] })),
    [slots]
  )
  const rows = useMemo(
    () => (scope === 'crit' ? alerts.filter(a => a.severity === 'CRITICAL') : alerts),
    [alerts, scope]
  )

  return (
    <div className="app">
      {/* ── Icon rail ── */}
      <nav className="rail">
        <div className="rail-logo">TL</div>
        <button className="rail-btn on" title="Threat posture">◈</button>
        <button className="rail-btn" title="Incidents">☰</button>
        <button className="rail-btn" title="Engines">◉</button>
        <button className="rail-btn" title="Flows">⇄</button>
        <button className="rail-btn" title="Telemetry">◱</button>
        <span className="rail-spacer" />
        <button className="rail-btn" title="Alerts">△</button>
        <button className="rail-btn" title="Settings">⚙</button>
      </nav>

      <div className="main">
        {/* ── Tabs ── */}
        <div className="tabs">
          {TABS.map((t, i) => (
            <button key={t} className={`tab ${i === tab ? 'on' : ''}`} onClick={() => setTab(i)}>{t}</button>
          ))}
          <div className="tabs-right">
            <span className={`chip-live ${live ? 'up' : 'down'}`}>
              <span className={`dot ${live ? 'ok beat' : 'bad'}`} />
              {live ? 'STREAMING' : 'RECONNECTING'}
            </span>
            <span className="mono" style={{ fontSize: 11, color: K.dim }}>{hhmmss(now)}</span>
          </div>
        </div>

        {/* ── Toolbar ── */}
        <div className="toolbar">
          <div className="seg">
            <button className={scope === 'all' ? 'on' : ''} onClick={() => setScope('all')}>All severities</button>
            <button className={scope === 'crit' ? 'on' : ''} onClick={() => setScope('crit')}>Critical only</button>
          </div>
          <button className="tool-btn">⧉ Enclave: read-only</button>
          <button className="tool-btn">◷ Window 10s</button>
          <button className="tool-btn">⌗ v{alerts[0]?.model_version ?? '1.0.0'}</button>
          <span className="tool-note">
            <span className="mono">Synced {hhmmss(synced)}</span>
            <button className="ptool" title="Refresh now" onClick={pull}>⟳</button>
            <button className="ptool" title="Export">⭳</button>
            <button className="ptool" title="Layout">⚙</button>
          </span>
        </div>

        {/* ── Canvas ── */}
        <div className="canvas">
          {/* Pipeline health */}
          <div className="grid" style={{ gridTemplateColumns: '1fr' }}>
            <Panel name="Pipeline health" tools={false}>
              <div className="health">
                {[
                  ['Ingest engine', 'READ-ONLY', 'ok'],
                  ['Packet parser', 'ACTIVE', 'ok'],
                  ['Data diode', 'ENFORCED', 'ok'],
                  ['Payload decrypt', 'DISABLED', 'ok'],
                  ['Inference (gRPC)', '3 MODELS', 'ok'],
                  ['Alert bus', live ? 'LIVE' : 'DOWN', live ? 'ok' : 'bad'],
                ].map(([k, v, d]) => (
                  <div className="health-c" key={k}>
                    <span className={`dot ${d}`} />
                    <div className="health-b">
                      <div className="health-k">{k}</div>
                      <div className="health-v">{v}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          {/* KPI strip */}
          <div className="grid g-kpi">
            <Kpi name="Total alerts" value={compact(total)}
              sub="since enclave start" spark={pulse} sparkColor={K.ok}
              trend={{ dir: lastPulse ? 'up' : 'flat', txt: `${lastPulse}/2s` }} />
            <Kpi name="Critical" value={compact(crit)} tone="crit"
              sub="confidence ≥ 95%" spark={classSpark('DDoS')} sparkColor={K.crit}
              trend={{ dir: crit ? 'up' : 'flat', txt: total ? `${((crit / total) * 100).toFixed(0)}%` : '0%' }} />
            <Kpi name="High" value={compact(high)} tone="med"
              sub="confidence 90–95%" spark={classSpark('PortScan')} sparkColor={K.high} />
            <Kpi name="Alerts / min" value={perMin.toFixed(1)}
              sub="observed arrival rate" spark={pulse} sparkColor={K.info} />
            <Kpi name="Mean confidence" value={`${(avgConf * 100).toFixed(0)}`} unit="%" tone="ok"
              sub={`across ${alerts.length} buffered events`} />
            <Kpi name="Threat sources" value={compact(srcN)}
              sub="distinct origin addresses" spark={classSpark('DGA')} sparkColor={K.med} />
          </div>

          {/* Timeline + distribution + severity */}
          <div className="grid g-main">
            <Panel name="Alert volume over time — by threat class"
              foot={`${slots.length} windows retained · peak ${peak} alerts/window`}>
              <div style={{ height: 224, padding: '12px 12px 0 0' }}>
                {slots.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={slots} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                      <defs>
                        {(['DDoS', 'PortScan', 'DGA'] as const).map(k => (
                          <linearGradient key={k} id={`a${k}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={TC[k]} stopOpacity={0.42} />
                            <stop offset="100%" stopColor={TC[k]} stopOpacity={0.03} />
                          </linearGradient>
                        ))}
                      </defs>
                      <CartesianGrid strokeDasharray="2 4" stroke={K.line} vertical={false} />
                      <XAxis dataKey="t" tickLine={false} axisLine={{ stroke: K.line }} minTickGap={30} />
                      <YAxis tickLine={false} axisLine={false} allowDecimals={false} width={42} />
                      <Tooltip content={<Tip />} cursor={{ stroke: K.mute, strokeDasharray: '3 3' }} />
                      <Area type="monotone" stackId="1" dataKey="DGA" name="DGA" stroke={TC.DGA} strokeWidth={1.3} fill="url(#aDGA)" />
                      <Area type="monotone" stackId="1" dataKey="PortScan" name="Port Scan" stroke={TC.PortScan} strokeWidth={1.3} fill="url(#aPortScan)" />
                      <Area type="monotone" stackId="1" dataKey="DDoS" name="DDoS" stroke={TC.DDoS} strokeWidth={1.3} fill="url(#aDDoS)" />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : <div className="chart-blank">awaiting first detection window</div>}
              </div>
            </Panel>

            <Panel name="Threat class mix" foot={`${dist.length} active classes of 6 defined`}>
              <div style={{ height: 224, position: 'relative' }}>
                {dist.length ? (
                  <>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={dist} dataKey="value" nameKey="name" cx="50%" cy="50%"
                          innerRadius={56} outerRadius={82} paddingAngle={2} stroke="none">
                          {dist.map(d => <Cell key={d.name} fill={TC[d.name] ?? K.mute} />)}
                        </Pie>
                        <Tooltip content={<Tip />} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div style={{ position: 'absolute', inset: 0, display: 'grid', placeContent: 'center', textAlign: 'center', pointerEvents: 'none' }}>
                      <div className="mono" style={{ fontSize: 24, fontWeight: 700 }}>{compact(total)}</div>
                      <div className="eyebrow" style={{ fontSize: 9 }}>events</div>
                    </div>
                  </>
                ) : <div className="chart-blank">no classified events</div>}
              </div>
              <div style={{ padding: '0 12px 12px', display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                {dist.map(d => (
                  <span key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: K.fg2 }}>
                    <span style={{ width: 7, height: 7, borderRadius: 2, background: TC[d.name] ?? K.mute }} />
                    {d.name}
                    <span className="mono" style={{ fontWeight: 600, color: K.fg }}>{d.value}</span>
                  </span>
                ))}
              </div>
            </Panel>

            <Panel name="Severity distribution" foot="bands: ≥95 crit · ≥90 high · ≥80 med">
              <div style={{ padding: 14 }}>
                {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => {
                  const n = stats?.by_severity?.[s] ?? 0
                  const pct = total ? (n / total) * 100 : 0
                  return (
                    <div className="meter" key={s}>
                      <div className="meter-hd">
                        <span className="meter-k" style={{ color: SC[s] }}>{s}</span>
                        <span className="meter-v">{n} · {pct.toFixed(0)}%</span>
                      </div>
                      <div className="meter-rail">
                        <div className="meter-fill" style={{ width: `${pct}%`, background: SC[s] }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            </Panel>
          </div>

          {/* Sources + radar + modules + rank */}
          <div className="grid g-quad">
            <Panel name="Top source addresses" foot="ranked by alert count in buffer">
              <div style={{ height: 196, padding: '12px 12px 0 0' }}>
                {topSrc.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={topSrc} layout="vertical" margin={{ top: 0, right: 14, left: 4, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="2 4" stroke={K.line} horizontal={false} />
                      <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                      <YAxis type="category" dataKey="ip" width={96} tickLine={false} axisLine={false} />
                      <Tooltip content={<Tip />} cursor={{ fill: 'rgba(255,255,255,.03)' }} />
                      <Bar dataKey="count" name="Alerts" radius={[0, 3, 3, 0]} barSize={11}>
                        {topSrc.map((_, i) => (
                          <Cell key={i} fill={i === 0 ? K.crit : i === 1 ? K.high : i === 2 ? K.med : K.dim} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                ) : <div className="chart-blank">no sources observed</div>}
              </div>
            </Panel>

            <Panel name="Engine coverage vs activity" foot="coverage = deployed · activity = observed hits">
              <div style={{ height: 196, padding: 6 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <RadarChart data={radar} outerRadius="70%">
                    <PolarGrid stroke={K.line} />
                    <PolarAngleAxis dataKey="k" tick={{ fontSize: 9, fill: K.mute, fontFamily: 'Inter' }} />
                    <Radar name="Coverage" dataKey="cov" stroke={K.info} fill={K.info} fillOpacity={0.14} strokeWidth={1.2} />
                    <Radar name="Activity" dataKey="act" stroke={K.crit} fill={K.crit} fillOpacity={0.22} strokeWidth={1.2} />
                    <Tooltip content={<Tip />} />
                  </RadarChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            <Panel name="Detection modules" foot="3 in production · 3 staged">
              {MODULES.map(m => {
                const hits = stats?.by_threat_class?.[m.k] ?? 0
                return (
                  <div className="mod" key={m.n}>
                    <span className={`dot ${m.on ? 'ok' : 'warn'}`} />
                    <div className="mod-b">
                      <div className="mod-n">{m.n}</div>
                      <div className="mod-a">{m.a}</div>
                    </div>
                    <span className={`mod-state ${m.on ? 'on' : 'sb'}`}>{m.on ? 'ACTIVE' : 'STANDBY'}</span>
                    <span className="mod-hits" style={{ color: m.on ? K.fg : K.mute }}>
                      {m.on ? hits : '—'}
                    </span>
                  </div>
                )
              })}
            </Panel>

            <Panel name="Highest-risk sources" foot="score = alert volume × mean confidence">
              {topSrc.length ? topSrc.slice(0, 6).map((s, i) => {
                const hits = alerts.filter(a => a.src_ip === s.full)
                const mc = hits.length ? hits.reduce((x, a) => x + a.confidence, 0) / hits.length : 0
                const risk = Math.min(Math.round((s.count * 6) + mc * 40), 100)
                const hue = risk >= 80 ? K.crit : risk >= 55 ? K.high : K.med
                const cls = hits[0]?.threat_class
                return (
                  <div className="rank" key={s.full}>
                    <span className="rank-ord">{String(i + 1).padStart(2, '0')}</span>
                    <div className="rank-body">
                      <div className="rank-t">{s.full}</div>
                      <div className="rank-s">{s.count} alerts{cls ? ` · ${cls}` : ''}</div>
                    </div>
                    {cls && (
                      <span className="rank-tag" style={{ color: TC[cls] ?? K.dim, background: `${(TC[cls] ?? K.dim)}14` }}>
                        {cls}
                      </span>
                    )}
                    <span className="rank-n" style={{ color: hue }}>{risk}</span>
                  </div>
                )
              }) : (
                <div className="blank">
                  <div className="blank-t">No sources scored</div>
                  <div className="blank-s">awaiting alerts</div>
                </div>
              )}
            </Panel>
          </div>

          {/* Incident ledger */}
          <div className="grid" style={{ gridTemplateColumns: '1fr' }}>
            <Panel name={`Incident ledger — ${rows.length} record${rows.length === 1 ? '' : 's'}`}
              foot="select a row to inspect flow, scores and supporting evidence">
              {rows.length ? (
                <div className="tbl-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Target</th>
                        <th>Threat class</th>
                        <th>Severity</th>
                        <th>ML confidence</th>
                        <th>Evidence features</th>
                        <th>Flow id</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.slice(0, 80).map(a => (
                        <tr key={a.alert_id} onClick={() => setSel(a)}
                          className={sel?.alert_id === a.alert_id ? 'sel' : ''}>
                          <td className="td-time">{hhmmss(new Date(a.timestamp * 1000))}</td>
                          <td className="td-ip">{a.src_ip}{a.src_port ? `:${a.src_port}` : ''}</td>
                          <td>
                            <span className="td-arrow">→</span>
                            <span className="td-ip">{a.dst_ip}{a.dst_port ? `:${a.dst_port}` : ''}</span>
                          </td>
                          <td>
                            <span className="tclass" style={{ color: TC[a.threat_class] ?? K.fg2 }}>
                              <span className="tclass-sq" style={{ background: TC[a.threat_class] ?? K.mute }} />
                              {a.threat_class}
                            </span>
                          </td>
                          <td><span className={`sevtag ${a.severity}`}>{a.severity}</span></td>
                          <td>
                            <span className="cf">
                              <span className="cf-rail">
                                <span className="cf-fill" style={{ width: `${a.confidence * 100}%`, background: confHue(a.confidence) }} />
                              </span>
                              <span className="cf-n">{(a.confidence * 100).toFixed(1)}%</span>
                            </span>
                          </td>
                          <td>
                            {Object.keys(a.evidence).slice(0, 2).map(k => (
                              <span className="ftag" key={k}>{k}</span>
                            ))}
                            {Object.keys(a.evidence).length > 2 && (
                              <span className="ftag">+{Object.keys(a.evidence).length - 2}</span>
                            )}
                          </td>
                          <td className="td-time">{a.flow_id}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="blank">
                  <div className="blank-t">
                    {scope === 'crit' ? 'No critical incidents in buffer' : 'No incidents detected'}
                  </div>
                  <div className="blank-s">enclave observing · alerts appear within one window</div>
                </div>
              )}
            </Panel>
          </div>

          <div className="mono" style={{ fontSize: 10, color: K.mute, textAlign: 'right', paddingTop: 2 }}>
            uptime {up} · window 10s · read-only ingest · no payload decryption
          </div>
        </div>
      </div>

      {/* ── Drawer ── */}
      <div className={`scrim ${sel ? 'open' : ''}`} onClick={() => setSel(null)} />
      <aside className={`drawer ${sel ? 'open' : ''}`}>
        {sel && (() => {
          const b = behav(sel)
          const fused = 0.6 * sel.confidence + 0.4 * b
          const bars = Object.entries(sel.evidence)
            .filter(([, v]) => typeof v === 'number')
            .map(([k, v]) => ({ k: k.replace(/_/g, ' '), v: Number(v) }))
          return (
            <>
              <div className="dr-hd">
                <div className="dr-hd-row">
                  <div style={{ minWidth: 0 }}>
                    <div className="eyebrow">Incident detail</div>
                    <div className="dr-title" style={{ color: TC[sel.threat_class] ?? K.fg }}>
                      {sel.threat_class}
                    </div>
                    <div className="dr-meta">
                      <span className={`sevtag ${sel.severity}`}>{sel.severity}</span>
                      <span className="chip-live" style={{ color: K.fg2 }}>
                        {hhmmss(new Date(sel.timestamp * 1000))}
                      </span>
                      <span className="chip-live" style={{ color: K.dim }}>model v{sel.model_version}</span>
                    </div>
                  </div>
                  <button className="xbtn" onClick={() => setSel(null)} aria-label="Close">✕</button>
                </div>
              </div>

              <div className="dr-body">
                <div className="dr-sec">
                  <div className="dr-lab">Observed flow</div>
                  <div className="flow">
                    <div className="fnode">
                      <div className="fnode-k">Source</div>
                      <div className="fnode-ip">{sel.src_ip}</div>
                      <div className="fnode-p">port {sel.src_port || '—'}</div>
                    </div>
                    <div className="fmid">→</div>
                    <div className="fnode tgt">
                      <div className="fnode-k">Target</div>
                      <div className="fnode-ip">{sel.dst_ip}</div>
                      <div className="fnode-p">port {sel.dst_port || '—'}</div>
                    </div>
                  </div>
                </div>

                <div className="dr-sec">
                  <div className="dr-lab">Scoring</div>
                  <div className="sc">
                    <div className="sc-hd">
                      <span className="sc-k">ML confidence</span>
                      <span className="sc-v" style={{ color: confHue(sel.confidence) }}>
                        {(sel.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="sc-rail">
                      <div className="sc-fill" style={{ width: `${sel.confidence * 100}%`, background: confHue(sel.confidence) }} />
                    </div>
                    <div className="sc-note">Classifier probability for the winning class.</div>
                  </div>
                  <div className="sc">
                    <div className="sc-hd">
                      <span className="sc-k">Behavioural score</span>
                      <span className="sc-v" style={{ color: K.high }}>{(b * 100).toFixed(1)}%</span>
                    </div>
                    <div className="sc-rail">
                      <div className="sc-fill" style={{ width: `${b * 100}%`, background: K.high }} />
                    </div>
                    <div className="sc-note">Deviation magnitude across extracted evidence features.</div>
                  </div>
                  <div className="sc">
                    <div className="sc-hd">
                      <span className="sc-k">Fused threat score</span>
                      <span className="sc-v" style={{ color: K.crit }}>{(fused * 100).toFixed(1)}%</span>
                    </div>
                    <div className="sc-rail">
                      <div className="sc-fill" style={{ width: `${fused * 100}%`, background: `linear-gradient(90deg,${K.high},${K.crit})` }} />
                    </div>
                    <div className="sc-note">Weighted fusion — 60% model, 40% behavioural.</div>
                  </div>
                </div>

                <div className="dr-sec">
                  <div className="dr-lab">Evidence magnitude</div>
                  {bars.length ? (
                    <div style={{ height: Math.max(bars.length * 30, 80) }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={bars} layout="vertical" margin={{ top: 0, right: 46, left: 0, bottom: 0 }}>
                          <XAxis type="number" hide domain={[0, 'dataMax']} />
                          <YAxis type="category" dataKey="k" width={128} tickLine={false} axisLine={false}
                            tick={{ fontSize: 10, fill: K.dim, fontFamily: 'Inter' }} />
                          <Tooltip content={<Tip />} cursor={{ fill: 'rgba(255,255,255,.03)' }} />
                          <Bar dataKey="v" name="value" radius={[0, 3, 3, 0]} barSize={10} fill={K.info} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  ) : <div className="chart-blank" style={{ height: 70 }}>no numeric features</div>}
                </div>

                <div className="dr-sec">
                  <div className="dr-lab">Supporting evidence</div>
                  <div className="json">
                    <div className="json-hd"><span className="dot warn" /> evidence.json</div>
                    <div className="json-bd">
                      <div className="j-p">{'{'}</div>
                      {Object.entries(sel.evidence).map(([k, v], i, arr) => (
                        <div key={k} style={{ paddingLeft: 16 }}>
                          <span className="j-k">"{k}"</span><span className="j-p">: </span>
                          <span className={typeof v === 'number' ? 'j-n' : 'j-s'}>
                            {typeof v === 'number' ? evNum(v) : `"${String(v)}"`}
                          </span>
                          {i < arr.length - 1 && <span className="j-p">,</span>}
                        </div>
                      ))}
                      <div className="j-p">{'}'}</div>
                    </div>
                  </div>
                </div>

                <div className="dr-sec">
                  <div className="dr-lab">Record</div>
                  <div className="kvg">
                    <div className="kv full">
                      <div className="kv-k">Flow identifier</div>
                      <div className="kv-v">{sel.flow_id}</div>
                    </div>
                    <div className="kv full">
                      <div className="kv-k">Alert id</div>
                      <div className="kv-v" style={{ fontSize: 11 }}>{sel.alert_id}</div>
                    </div>
                    <div className="kv">
                      <div className="kv-k">Timestamp (UTC)</div>
                      <div className="kv-v" style={{ fontSize: 11 }}>
                        {new Date(sel.timestamp * 1000).toISOString().replace('T', ' ').slice(0, 19)}
                      </div>
                    </div>
                    <div className="kv">
                      <div className="kv-k">Detection window</div>
                      <div className="kv-v">10 s tumbling</div>
                    </div>
                    <div className="kv">
                      <div className="kv-k">Model version</div>
                      <div className="kv-v">{sel.model_version}</div>
                    </div>
                    <div className="kv">
                      <div className="kv-k">Ingest mode</div>
                      <div className="kv-v">read-only</div>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )
        })()}
      </aside>
    </div>
  )
}
