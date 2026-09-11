import { useState } from 'react'
import { Emblem } from './Emblem'

/* NTRO identity mark — uses the official logo at /ntro-logo.svg.
   Falls back to a built Ashoka crest if the file is missing or fails to load. */

const REAL_LOGO_SRC = '/ntro-logo.svg'

export function NtroLogo({ size = 46 }: { size?: number }) {
  const [ok, setOk] = useState(true)

  return (
    <div className="ntro-mark">
      {ok ? (
        <img
          src={REAL_LOGO_SRC}
          alt="National Technical Research Organisation logo"
          height={size}
          className="ntro-img"
          onError={() => setOk(false)}
        />
      ) : (
        <span className="ntro-crest" aria-hidden="true" style={{ width: size + 8, height: size + 8 }}>
          <Emblem size={size * 0.62} color="#fff" />
          <span className="ntro-crest-txt">NTRO</span>
        </span>
      )}
    </div>
  )
}
