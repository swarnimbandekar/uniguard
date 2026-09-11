/* ══════════════════════════════════════════════════════════════════
   Report + export utilities — shared by Simple and Advanced views.

   PDF: opens a print-styled report window and invokes the browser's
   "Save as PDF" (no external dependency, produces a clean A4 report).
   CSV: standards-friendly comma file with proper escaping.
   Both operate on an already-filtered set of alerts.
   ════════════════════════════════════════════════════════════════════ */

import type { Alert, Stats } from './lib'
import { threatMeta, SEV_LABEL, SEV_RANK } from './lib'

export interface ReportContext {
  alerts: Alert[]
  stats: Stats | null
  filterSummary?: string   // e.g. "Type: Port scanning · Severity: Critical"
}

const fmtUtc = (ts: number) =>
  new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'

const fmtLocal = (d: Date) =>
  d.toLocaleString('en-GB', { hour12: false })

const esc = (v: unknown) => {
  const s = String(v ?? '')
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

const tsName = () => new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)

/* ── CSV ──────────────────────────────────────── */
export function exportCsv(ctx: ReportContext) {
  const cols = [
    'timestamp_utc', 'threat_type', 'severity', 'confidence_pct',
    'source_ip', 'source_port', 'destination_ip', 'destination_port',
    'flow_id', 'model_version', 'alert_id',
  ]
  const lines = [cols.join(',')]
  for (const a of ctx.alerts) {
    lines.push([
      fmtUtc(a.timestamp),
      threatMeta(a.threat_class).label,
      SEV_LABEL[a.severity] ?? a.severity,
      (a.confidence * 100).toFixed(1),
      a.src_ip, a.src_port || '',
      a.dst_ip, a.dst_port || '',
      a.flow_id, a.model_version, a.alert_id,
    ].map(esc).join(','))
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' })
  triggerDownload(blob, `ntro-threat-report-${tsName()}.csv`)
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/* ── PDF (print-to-PDF report window) ───────────── */
export function exportPdf(ctx: ReportContext) {
  const { alerts, stats, filterSummary } = ctx
  const now = new Date()

  const bySev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  const byType: Record<string, number> = {}
  for (const a of alerts) {
    bySev[a.severity] = (bySev[a.severity] ?? 0) + 1
    byType[a.threat_class] = (byType[a.threat_class] ?? 0) + 1
  }

  const sorted = [...alerts].sort((a, b) =>
    (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) || b.timestamp - a.timestamp)

  const sevColor: Record<string, string> = {
    CRITICAL: '#c62828', HIGH: '#e65100', MEDIUM: '#b58100', LOW: '#2e7d32',
  }

  const rows = sorted.map((a, i) => {
    const m = threatMeta(a.threat_class)
    return `
      <tr>
        <td class="num">${i + 1}</td>
        <td class="mono nowrap">${fmtUtc(a.timestamp)}</td>
        <td>${escapeHtml(m.label)}</td>
        <td><span class="sev" style="color:${sevColor[a.severity] ?? '#333'}">${SEV_LABEL[a.severity] ?? a.severity}</span></td>
        <td class="mono">${(a.confidence * 100).toFixed(1)}%</td>
        <td class="mono nowrap">${escapeHtml(a.src_ip)}${a.src_port ? ':' + a.src_port : ''}</td>
        <td class="mono nowrap">${escapeHtml(a.dst_ip)}${a.dst_port ? ':' + a.dst_port : ''}</td>
      </tr>`
  }).join('')

  const typeRows = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `<tr><td>${escapeHtml(threatMeta(k).label)}</td><td class="mono">${n}</td></tr>`)
    .join('') || '<tr><td colspan="2" class="muted">No threats in this report</td></tr>'

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<title>NTRO Threat Report ${tsName()}</title>
<style>
  @page { size: A4; margin: 18mm 16mm; }
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #14243a; font-size: 11px; line-height: 1.5; margin: 0; }
  .mono { font-family: 'Consolas', monospace; }
  .nowrap { white-space: nowrap; }
  .muted { color: #64748b; }
  .tricolour { display: flex; height: 5px; }
  .tricolour span { flex: 1; }
  header { display: flex; align-items: center; gap: 14px; padding: 14px 0 12px; border-bottom: 2px solid #0b3d91; }
  .emblem { width: 42px; height: 56px; }
  .org { font-size: 15px; font-weight: 700; color: #0b3d91; }
  .org small { display: block; font-size: 10px; color: #64748b; font-weight: 400; }
  .sys { margin-left: auto; text-align: right; }
  .sys .t { font-size: 13px; font-weight: 700; }
  .sys .d { font-size: 10px; color: #64748b; }
  h1 { font-size: 16px; margin: 16px 0 2px; }
  .meta { font-size: 10px; color: #64748b; margin-bottom: 14px; }
  .cards { display: flex; gap: 10px; margin: 12px 0 18px; }
  .card { flex: 1; border: 1px solid #dbe2ec; border-radius: 6px; padding: 8px 10px; }
  .card .n { font-size: 20px; font-weight: 700; font-family: 'Consolas', monospace; }
  .card .l { font-size: 9px; text-transform: uppercase; letter-spacing: .04em; color: #64748b; }
  h2 { font-size: 12px; margin: 16px 0 6px; color: #0b3d91; border-bottom: 1px solid #dbe2ec; padding-bottom: 3px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 9px; text-transform: uppercase; letter-spacing: .04em; color: #40506a;
       border-bottom: 1.5px solid #c7d1df; padding: 5px 6px; }
  td { padding: 5px 6px; border-bottom: 1px solid #eef2f8; vertical-align: top; }
  td.num { color: #8a97a8; width: 22px; }
  .sev { font-weight: 700; }
  .small-tbl { width: 45%; }
  footer { margin-top: 18px; padding-top: 8px; border-top: 1px solid #dbe2ec; font-size: 9px; color: #64748b;
           display: flex; justify-content: space-between; }
  tr { break-inside: avoid; }
</style></head>
<body>
  <div class="tricolour"><span style="background:#ff9933"></span><span style="background:#fff"></span><span style="background:#138808"></span></div>
  <header>
    <img class="emblem" src="/ntro-logo.svg" alt="NTRO logo"
      onerror="this.style.display='none'" />
    <div class="org">National Technical Research Organisation<small>राष्ट्रीय तकनीकी अनुसंधान संगठन · Government of India</small></div>
    <div class="sys"><div class="t">Network Threat Monitor</div><div class="d">Cyber Threat Detection Report</div></div>
  </header>

  <h1>Threat Detection Report</h1>
  <div class="meta">
    Generated: ${fmtLocal(now)} &nbsp;·&nbsp; Records: ${alerts.length}
    ${filterSummary ? '&nbsp;·&nbsp; Filter: ' + escapeHtml(filterSummary) : ''}
    ${stats ? '&nbsp;·&nbsp; Total observed since start: ' + stats.total_alerts : ''}
  </div>

  <div class="cards">
    <div class="card"><div class="n" style="color:#c62828">${bySev.CRITICAL}</div><div class="l">Critical</div></div>
    <div class="card"><div class="n" style="color:#e65100">${bySev.HIGH}</div><div class="l">High</div></div>
    <div class="card"><div class="n" style="color:#b58100">${bySev.MEDIUM}</div><div class="l">Medium</div></div>
    <div class="card"><div class="n" style="color:#2e7d32">${bySev.LOW}</div><div class="l">Low</div></div>
    <div class="card"><div class="n">${alerts.length}</div><div class="l">Total in report</div></div>
  </div>

  <h2>Threats by type</h2>
  <table class="small-tbl">
    <thead><tr><th>Threat type</th><th>Count</th></tr></thead>
    <tbody>${typeRows}</tbody>
  </table>

  <h2>Detected threats — source to destination</h2>
  <table>
    <thead><tr>
      <th>#</th><th>Detected (UTC)</th><th>Threat type</th><th>Severity</th>
      <th>Confidence</th><th>Source</th><th>Destination</th>
    </tr></thead>
    <tbody>${rows || '<tr><td colspan="7" class="muted">No threats match the current filters.</td></tr>'}</tbody>
  </table>

  <footer>
    <span>© ${now.getFullYear()} NTRO, Government of India · Metadata-only, read-only monitoring</span>
    <span>सत्यमेव जयते</span>
  </footer>

  <script>window.onload = function(){ setTimeout(function(){ window.print(); }, 300); };</script>
</body></html>`

  const w = window.open('', '_blank')
  if (!w) {
    alert('Please allow pop-ups for this site to generate the PDF report.')
    return
  }
  w.document.open()
  w.document.write(html)
  w.document.close()
}

function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
