import { useEffect, useState } from 'react'
import './theme.css'
import './chrome.css'
import './simple.css'
import './index.css' // advanced console styles

import { useUiPrefs } from './useUiPrefs'
import { useThreatFeed } from './useThreatFeed'
import { useDemoSimulation } from './useDemoSimulation'
import { fmtUptime } from './lib'
import { Header } from './components/Header'
import { Footer } from './components/Footer'
import { SimpleView } from './components/SimpleView'
import AdvancedConsole from './AdvancedConsole'

export default function App() {
  const prefs = useUiPrefs()
  const feed = useThreatFeed()
  // Single demo instance at app root — survives view switches
  const demo = useDemoSimulation()
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const uptime = feed.stats ? fmtUptime(feed.stats.uptime_seconds) : '—'

  if (prefs.mode === 'advanced') {
    return (
      <AdvancedConsole
        onBackToSimple={() => prefs.setMode('simple')}
        demoState={demo.state}
        onRunDemo={demo.trigger}
      />
    )
  }

  return (
    <div className="app-shell">
      <a href="#main" className="skip-link">Skip to main content</a>

      <Header
        mode={prefs.mode}
        onMode={prefs.setMode}
        fontScale={prefs.fontScale}
        onFont={prefs.bumpFont}
        contrast={prefs.contrast}
        onContrast={prefs.setContrast}
        live={feed.live}
        synced={feed.synced}
        onRefresh={feed.refresh}
      />

      <main id="main" className="app-main">
        <div className="container">
          <nav className="crumb" aria-label="Breadcrumb">
            <a href="#main">Home</a>
            <span className="sep" aria-hidden="true">&rsaquo;</span>
            <span className="here">Network Threat Monitor</span>
          </nav>

          <SimpleView
            alerts={feed.alerts}
            stats={feed.stats}
            now={now}
            demoState={demo.state}
            onRunDemo={demo.trigger}
          />
        </div>
      </main>

      <Footer uptime={uptime} />
    </div>
  )
}
