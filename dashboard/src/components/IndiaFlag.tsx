/* Indian national flag — Tiranga with the 24-spoke Ashoka Chakra.
   Proportions follow the 3:2 flag ratio. Decorative + labelled. */

export function IndiaFlag({ height = 22 }: { height?: number }) {
  const w = height * 1.5 // 3:2 ratio

  return (
    <svg
      width={w} height={height} viewBox="0 0 90 60"
      role="img" aria-label="Flag of India"
      xmlns="http://www.w3.org/2000/svg"
      style={{ borderRadius: 2, boxShadow: '0 0 0 1px rgba(0,0,0,.12)' }}
    >
      <rect width="90" height="20" y="0" fill="#ff9933" />
      <rect width="90" height="20" y="20" fill="#ffffff" />
      <rect width="90" height="20" y="40" fill="#138808" />
      {/* Ashoka Chakra */}
      <g transform="translate(45 30)">
        <circle r="8.2" fill="none" stroke="#0b3d91" strokeWidth="1.1" />
        <circle r="1.6" fill="#0b3d91" />
        {Array.from({ length: 24 }).map((_, i) => {
          const a = (i * Math.PI) / 12
          return (
            <line key={i}
              x1={Math.cos(a) * 1.6} y1={Math.sin(a) * 1.6}
              x2={Math.cos(a) * 8} y2={Math.sin(a) * 8}
              stroke="#0b3d91" strokeWidth="0.55" />
          )
        })}
      </g>
    </svg>
  )
}
