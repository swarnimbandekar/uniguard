/* ══════════════════════════════════════════════════════════════════
   useDemoSimulation — fires the /api/demo endpoint and polls
   /api/demo/status until the simulation is done.
   ════════════════════════════════════════════════════════════════════ */

import { useCallback, useEffect, useRef, useState } from 'react'

export type DemoPhase =
  | 'idle'
  | 'DDoS SYN flood'
  | 'Port scan reconnaissance'
  | 'DGA / DNS tunnelling'
  | 'C2 beaconing'
  | 'Data exfiltration'
  | 'Complete'

export interface DemoState {
  running: boolean
  phase: DemoPhase | string
  progress: number   // 0–100
  error: string | null
}

export function useDemoSimulation() {
  const [state, setState] = useState<DemoState>({
    running: false, phase: 'idle', progress: 0, error: null,
  })
  const pollRef = useRef<number | null>(null)

  const stopPolling = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null }
  }

  const startPolling = useCallback(() => {
    stopPolling()
    pollRef.current = window.setInterval(async () => {
      try {
        const r = await fetch('/api/demo/status')
        if (!r.ok) return
        const d = await r.json()
        setState({
          running: d.running,
          phase: d.phase || 'idle',
          progress: d.progress ?? 0,
          error: null,
        })
        if (!d.running) stopPolling()
      } catch { /* noop */ }
    }, 1000)
  }, [])

  const trigger = useCallback(async () => {
    setState({ running: true, phase: 'Starting…', progress: 0, error: null })
    try {
      const r = await fetch('/api/demo', { method: 'POST' })
      if (r.status === 409) {
        // already running — just start polling
        startPolling()
        return
      }
      if (!r.ok) {
        const e = await r.json().catch(() => ({}))
        setState(s => ({ ...s, running: false, error: e.detail ?? 'Failed to start simulation' }))
        return
      }
      startPolling()
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Network error'
      setState(s => ({ ...s, running: false, error: msg }))
    }
  }, [startPolling])

  useEffect(() => () => stopPolling(), [])

  return { state, trigger }
}
