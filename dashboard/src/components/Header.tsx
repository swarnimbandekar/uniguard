import { NtroLogo } from './NtroLogo'
import { IndiaFlag } from './IndiaFlag'
import type { FontScale, ViewMode, Contrast } from '../useUiPrefs'

interface HeaderProps {
  mode: ViewMode
  onMode: (m: ViewMode) => void
  fontScale: FontScale
  onFont: (dir: 1 | -1) => void
  contrast: Contrast
  onContrast: (c: Contrast) => void
  live: boolean
  synced: Date
  onRefresh: () => void
}

export function Header({
  mode, onMode, fontScale, onFont, contrast, onContrast, live, synced, onRefresh,
}: HeaderProps) {
  const timeStr = synced.toLocaleTimeString('en-GB', { hour12: false })

  return (
    <header className="gov-header">
      {/* Tricolour top strip */}
      <div className="tricolour" aria-hidden="true">
        <span style={{ background: 'var(--saffron)' }} />
        <span style={{ background: '#ffffff' }} />
        <span style={{ background: 'var(--india-green)' }} />
      </div>

      {/* Accessibility / utility bar */}
      <div className="util-bar">
        <div className="util-tools">
          <div className="a11y" role="group" aria-label="Text size">
            <button className="a11y-btn" onClick={() => onFont(-1)} aria-label="Decrease text size"
              disabled={fontScale === 'sm'}>A−</button>
            <button className="a11y-btn"
              onClick={() => onFont(fontScale === 'md' ? -1 : 1)} aria-label="Reset text size">A</button>
            <button className="a11y-btn" onClick={() => onFont(1)} aria-label="Increase text size"
              disabled={fontScale === 'xl'}>A+</button>
          </div>
          <button
            className={`a11y-btn contrast ${contrast === 'high' ? 'on' : ''}`}
            onClick={() => onContrast(contrast === 'high' ? 'normal' : 'high')}
            aria-pressed={contrast === 'high'}>
            ◑ High contrast
          </button>
        </div>

        {/* Government of India + national flag (top-right) */}
        <div className="util-gov">
          <div className="util-gov-txt">
            <span className="util-gov-hi">भारत सरकार</span>
            <span className="util-gov-en">Government of India</span>
          </div>
          <IndiaFlag height={22} />
        </div>
      </div>

      {/* Identity row */}
      <div className="id-row">
        <div className="id-mark">
          <NtroLogo size={44} />
          <div className="id-titles">
            <div className="id-org">National Technical Research Organisation</div>
            <div className="id-sub">राष्ट्रीय तकनीकी अनुसंधान संगठन</div>
          </div>
        </div>

        <div className="id-system">
          <div className="id-sysname">Network Threat Monitor</div>
          <div className="id-sysmeta">AI detection of cyber threats in unidirectional IP traffic</div>
        </div>

        <div className="id-right">
          <span className={`live-pill ${live ? 'up' : 'down'}`}>
            <span className={`live-dot ${live ? 'beat' : ''}`} />
            {live ? 'Live monitoring' : 'Reconnecting…'}
          </span>
          <button className="ghost-btn" onClick={onRefresh} title="Refresh now">
            <span className="mono" style={{ fontSize: '.72rem' }}>Updated {timeStr}</span> ↻
          </button>

          <div className="mode-switch" role="group" aria-label="View mode">
            <button className={mode === 'simple' ? 'on' : ''} onClick={() => onMode('simple')}
              aria-pressed={mode === 'simple'}>Simple</button>
            <button className={mode === 'advanced' ? 'on' : ''} onClick={() => onMode('advanced')}
              aria-pressed={mode === 'advanced'}>Advanced</button>
          </div>
        </div>
      </div>
    </header>
  )
}
