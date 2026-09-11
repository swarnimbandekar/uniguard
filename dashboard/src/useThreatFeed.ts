/* ══════════════════════════════════════════════════════════════════
   Live threat feed hook — WebSocket stream + REST history/stats.
   Extracted from the original App so Simple and Advanced views share one
   connection and one buffer. Endpoints and data shapes are unchanged.
   ════════════════════════════════════════════════════════════════════ */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { Alert, Stats } from './lib'

const WS_URL = `ws://${window.location.host}/ws/alerts`

export interface ThreatFeed {
  alerts: Alert[]
  stats: Stats | null
  live: boolean
  synced: Date
  refresh: () => void
}

export function useThreatFeed(): ThreatFeed {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [live, setLive] = useState(false)
  const [synced, setSynced] = useState(new Date())
  const ws = useRef<WebSocket | null>(null)
  const retry = useRef<number | null>(null)

  const connect = useCallback(() => {
    const s = new WebSocket(WS_URL)
    s.onopen = () => setLive(true)
    s.onmessage = e => {
      try {
        const d = JSON.parse(e.data)
        if (d.type === 'heartbeat' || d.type === 'pong') return
        const a = d as Alert
        setAlerts(p => (p.some(x => x.alert_id === a.alert_id) ? p : [a, ...p]).slice(0, 5000))
      } catch { /* noop */ }
    }
    s.onclose = () => { setLive(false); retry.current = window.setTimeout(connect, 3000) }
    s.onerror = () => s.close()
    ws.current = s
  }, [])

  const refresh = useCallback(async () => {
    try {
      const r = await fetch('/api/stats')
      if (r.ok) { setStats(await r.json()); setSynced(new Date()) }
    } catch { /* noop */ }
    try {
      const r = await fetch('/api/alerts?page=1&page_size=500')
      if (r.ok) {
        const data = await r.json()
        const hist: Alert[] = data.alerts ?? []
        if (hist.length) {
          setAlerts(prev => {
            const byId = new Map<string, Alert>()
            for (const a of hist) byId.set(a.alert_id, a)
            for (const a of prev) if (!byId.has(a.alert_id)) byId.set(a.alert_id, a)
            return Array.from(byId.values())
              .sort((x, y) => y.timestamp - x.timestamp)
              .slice(0, 5000)
          })
        }
      }
    } catch { /* noop */ }
  }, [])

  useEffect(() => {
    connect(); refresh()
    const id = setInterval(refresh, 4000)
    return () => {
      clearInterval(id)
      if (retry.current) clearTimeout(retry.current)
      ws.current?.close()
    }
  }, [connect, refresh])

  return { alerts, stats, live, synced, refresh }
}
