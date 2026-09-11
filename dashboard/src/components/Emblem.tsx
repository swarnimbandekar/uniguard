/* State Emblem mark — a simplified, stylised Ashoka Lion Capital silhouette
   for use as a header identity mark. Decorative; labelled for screen readers. */

export function Emblem({ size = 40, color = 'currentColor' }: { size?: number; color?: string }) {
  return (
    <svg
      width={size} height={size * 1.35} viewBox="0 0 60 81"
      role="img" aria-label="State Emblem of India"
      fill={color} xmlns="http://www.w3.org/2000/svg"
    >
      {/* Three lion heads (front + two profiles) */}
      <g>
        {/* centre lion */}
        <path d="M30 4c-4 0-6.5 2.6-6.5 6 0 2 1 3.7 2.4 4.8-1.6.7-2.7 1.9-2.7 3.6 0 .9.4 1.6 1 2.1h11.6c.6-.5 1-1.2 1-2.1 0-1.7-1.1-2.9-2.7-3.6 1.4-1.1 2.4-2.8 2.4-4.8 0-3.4-2.5-6-6.5-6z" />
        <path d="M25.5 14.5c-1.2 1-3 1.4-4.7 1.1.6 1.3 2 2.2 3.5 2.3zM34.5 14.5c1.2 1 3 1.4 4.7 1.1-.6 1.3-2 2.2-3.5 2.3z" />
        {/* left profile lion */}
        <path d="M17 8.5c-3.2.6-5.2 3.1-4.9 6.3.2 1.8 1.2 3.2 2.6 4-1.5.9-2.4 2.2-2.2 3.8.1.9.6 1.5 1.2 1.9l7.4-1.3c-.3-1.7-1.6-2.7-3.3-3 1.2-1.3 1.9-3.1 1.6-5-.2-1.3-.8-2.4-1.7-3.2z" />
        {/* right profile lion */}
        <path d="M43 8.5c3.2.6 5.2 3.1 4.9 6.3-.2 1.8-1.2 3.2-2.6 4 1.5.9 2.4 2.2 2.2 3.8-.1.9-.6 1.5-1.2 1.9l-7.4-1.3c.3-1.7 1.6-2.7 3.3-3-1.2-1.3-1.9-3.1-1.6-5 .2-1.3.8-2.4 1.7-3.2z" />
      </g>

      {/* Abacus band */}
      <rect x="13" y="30" width="34" height="6" rx="1.5" />
      {/* Dharma Chakra (wheel) on the abacus */}
      <g transform="translate(30 33)">
        <circle r="7" fill="none" stroke={color} strokeWidth="1.6" />
        <circle r="1.4" />
        {Array.from({ length: 12 }).map((_, i) => {
          const a = (i * Math.PI) / 6
          return (
            <line key={i}
              x1={Math.cos(a) * 1.6} y1={Math.sin(a) * 1.6}
              x2={Math.cos(a) * 6.4} y2={Math.sin(a) * 6.4}
              stroke={color} strokeWidth="0.8" />
          )
        })}
      </g>
      {/* small flanking wheels */}
      <circle cx="16" cy="33" r="2.4" fill="none" stroke={color} strokeWidth="1.2" />
      <circle cx="44" cy="33" r="2.4" fill="none" stroke={color} strokeWidth="1.2" />

      {/* Bell base / pillar */}
      <path d="M22 36h16l-1.5 5h-13z" />
      <path d="M23 41h14c2 3 3 6 3 9H20c0-3 1-6 3-9z" />

      {/* Satyameva Jayate scroll suggestion */}
      <rect x="18" y="52" width="24" height="3.4" rx="1" />

      {/* Motto in Devanagari */}
      <text x="30" y="66" textAnchor="middle"
        fontFamily="'Noto Sans Devanagari', sans-serif" fontSize="7.5" fontWeight="700"
        fill={color}>सत्यमेव जयते</text>
    </svg>
  )
}
