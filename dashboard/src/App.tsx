import { useEffect, useState } from 'react'
import './theme.css'
import './chrome.css'
import './simple.css'
import './index.css' // advanced console styles (retained until Task 6 redesign)

import { useUiPrefs } from './useUiPrefs'
import { useThreatFeed } from './useThreatFeed'
import { fmtUptime } from './lib'
import { Header } from './components/Header'
import { Footer } from './components/Footer'
import { SimpleView } from './components/SimpleView'
import AdvancedConsole from './AdvancedConsole'

export default function App() {
  const prefs = useUiPrefs()
  const feed = useThreatFeed()
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const uptime = feed.stats ? fmtUptime(feed.stats.uptime_seconds) : '—'

  /* Advanced mode: existing console with its own chrome, plus a floating
     button back to Simple. Redesigned into the govt language in a later step. */
  if (prefs.mode === 'advanced') {
    return (
      <>
        <button className="to-simple" onClick={() => prefs.setMode('simple')}>
          ‹ Simple view
        </button>
        <AdvancedConsole />
      </>
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
            <span className="sep" aria-hidden="true">›</span>
            <span className="here">Network Threat Monitor</span>
          </nav>

          <SimpleView alerts={feed.alerts} stats={feed.stats} now={now} />
        </div>
      </main>

      <Footer uptime={uptime} />
    </div>
  )
}
