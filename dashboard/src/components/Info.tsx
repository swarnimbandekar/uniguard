import { useState, useRef, useId } from 'react'

/* "What is this?" inline help — accessible tooltip toggled on hover/focus/click. */
export function Info({ text, label = 'What is this?' }: { text: string; label?: string }) {
  const [open, setOpen] = useState(false)
  const id = useId()
  const timer = useRef<number | null>(null)

  const show = () => { if (timer.current) clearTimeout(timer.current); setOpen(true) }
  const hide = () => { timer.current = window.setTimeout(() => setOpen(false), 120) }

  return (
    <span className="info-wrap" onMouseEnter={show} onMouseLeave={hide}>
      <button
        type="button" className="info-btn" aria-label={label}
        aria-describedby={open ? id : undefined}
        onFocusCapture={show} onBlur={hide}
        onClick={() => setOpen(o => !o)}>
        ?
      </button>
      {open && (
        <span role="tooltip" id={id} className="info-pop">{text}</span>
      )}
    </span>
  )
}
