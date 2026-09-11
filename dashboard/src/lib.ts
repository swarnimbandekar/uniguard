/* ══════════════════════════════════════════════════════════════════
   Shared domain model + plain-language mappings.
   One source of truth used by both Simple and Advanced views, so the
   human-readable names and colours never drift apart.
   ════════════════════════════════════════════════════════════════════ */

export interface Alert {
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

export interface Stats {
  total_alerts: number
  by_threat_class: Record<string, number>
  by_severity: Record<string, number>
  alerts_per_minute: number
  top_sources: Record<string, number>
  uptime_seconds: number
}

/* ── Threat vocabulary ──────────────────────────────
   label   — short human name (no acronyms)
   plain   — one-line description a non-analyst understands
   action  — what a responder should consider doing
   color   — severity-family hue used for this class
   icon    — inline emoji marker (kept minimal, works without an icon font)
*/
export interface ThreatMeta {
  key: string
  label: string
  plain: string
  action: string
  color: string
  icon: string
}

export const THREATS: Record<string, ThreatMeta> = {
  DDoS: {
    key: 'DDoS',
    label: 'Denial-of-service flood',
    plain: 'A target is being buried under a flood of traffic to knock it offline.',
    action: 'Check if the targeted service is still reachable; consider rate-limiting the source.',
    color: 'var(--crit)',
    icon: '🌊',
  },
  PortScan: {
    key: 'PortScan',
    label: 'Port scanning / reconnaissance',
    plain: 'Someone is probing many ports to map out which services are open.',
    action: 'Note the scanning source; scanning often precedes a real attack.',
    color: 'var(--high)',
    icon: '🔎',
  },
  DGA: {
    key: 'DGA',
    label: 'Suspicious auto-generated domains',
    plain: 'A host is contacting randomly-generated domain names — a common malware trait.',
    action: 'Inspect the host making these lookups; it may be infected.',
    color: 'var(--med)',
    icon: '🧬',
  },
  C2_BEACONING: {
    key: 'C2_BEACONING',
    label: 'Command-and-control beaconing',
    plain: 'A host is "phoning home" at steady intervals, as malware does to its operator.',
    action: 'Isolate the calling host and identify the destination it keeps contacting.',
    color: 'var(--info)',
    icon: '📡',
  },
  EncryptedMalware: {
    key: 'EncryptedMalware',
    label: 'Encrypted malware traffic',
    plain: 'Encrypted traffic on unusual ports that matches known malware behaviour.',
    action: 'Review the flow endpoints; the encryption hides the payload but the pattern is suspicious.',
    color: '#8a6d00',
    icon: '🔐',
  },
  DataExfiltration: {
    key: 'DataExfiltration',
    label: 'Possible data theft',
    plain: 'An unusually large upload is leaving the network — data may be being stolen.',
    action: 'Identify what is being sent and to where before more data leaves.',
    color: '#6d3fbf',
    icon: '📤',
  },
}

export const THREAT_ORDER = [
  'DDoS', 'PortScan', 'C2_BEACONING', 'DataExfiltration', 'EncryptedMalware', 'DGA',
]

export function threatMeta(key: string): ThreatMeta {
  return THREATS[key] ?? {
    key, label: key, plain: 'Unclassified network event.',
    action: 'Review the flow details.', color: 'var(--ink-3)', icon: '•',
  }
}

/* ── Severity ── */
export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
export type Severity = typeof SEVERITY_ORDER[number]

export const SEV_COLOR: Record<string, string> = {
  CRITICAL: 'var(--crit)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--med)',
  LOW: 'var(--low)',
}

export const SEV_LABEL: Record<string, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

export const SEV_RANK: Record<string, number> = {
  CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0,
}

/* ── Formatting helpers ── */
export const hhmmss = (d: Date) =>
  d.toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })

export const compact = (n: number) =>
  n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : n >= 1e4 ? `${(n / 1e3).toFixed(1)}K` : `${n}`

/* "just now", "3 min ago", "14:22:07" fallback */
export function relTime(tsSeconds: number, now: number = Date.now()): string {
  const diff = Math.max(0, Math.floor(now / 1000 - tsSeconds))
  if (diff < 5) return 'just now'
  if (diff < 60) return `${diff} sec ago`
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`
  return hhmmss(new Date(tsSeconds * 1000))
}

/* Turn one alert into a single plain-English sentence for the Simple feed. */
export function describeAlert(a: Alert): string {
  const m = threatMeta(a.threat_class)
  const src = a.src_ip || 'an unknown host'
  const dst = a.dst_ip || 'a target'
  switch (a.threat_class) {
    case 'DDoS':
      return `Traffic flood aimed at ${dst} from ${src}.`
    case 'PortScan':
      return `${src} is scanning ports on ${dst}.`
    case 'DGA':
      return `${src} is looking up suspicious auto-generated domains.`
    case 'C2_BEACONING':
      return `${src} is beaconing to ${dst} at regular intervals.`
    case 'EncryptedMalware':
      return `Suspicious encrypted traffic from ${src} to ${dst}.`
    case 'DataExfiltration':
      return `Large upload from ${src} to ${dst} — possible data theft.`
    default:
      return `${m.label}: ${src} → ${dst}.`
  }
}

/* Format uptime seconds → "3h 07m". */
export function fmtUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${String(m).padStart(2, '0')}m`
}
