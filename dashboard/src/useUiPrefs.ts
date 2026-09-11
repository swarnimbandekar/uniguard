/* Persisted UI preferences: view mode, font scale, contrast, advanced theme.
   Applies accessibility attributes to <html> so theme.css can react. */

import { useCallback, useEffect, useState } from 'react'

export type ViewMode = 'simple' | 'advanced'
export type FontScale = 'sm' | 'md' | 'lg' | 'xl'
export type Contrast = 'normal' | 'high'
export type AdvTheme = 'light' | 'dark'

const read = <T,>(k: string, fallback: T): T => {
  try { const v = localStorage.getItem(k); return v ? (v as unknown as T) : fallback }
  catch { return fallback }
}

/* Set the theme attributes synchronously before first paint so Simple view is
   guaranteed to render in light mode with no flash of the dark advanced theme. */
;(() => {
  try {
    const mode = read<ViewMode>('ntro-mode', 'simple')
    const advTheme = read<AdvTheme>('ntro-advtheme', 'light')
    const el = document.documentElement
    el.setAttribute('data-fontscale', read<FontScale>('ntro-fontscale', 'md'))
    el.setAttribute('data-contrast', read<Contrast>('ntro-contrast', 'normal'))
    el.setAttribute('data-adv-theme', mode === 'advanced' ? advTheme : 'light')
  } catch { /* noop */ }
})()

export function useUiPrefs() {
  const [mode, setMode] = useState<ViewMode>(() => read('ntro-mode', 'simple'))
  const [fontScale, setFontScale] = useState<FontScale>(() => read('ntro-fontscale', 'md'))
  const [contrast, setContrast] = useState<Contrast>(() => read('ntro-contrast', 'normal'))
  const [advTheme, setAdvTheme] = useState<AdvTheme>(() => read('ntro-advtheme', 'light'))

  useEffect(() => { localStorage.setItem('ntro-mode', mode) }, [mode])
  useEffect(() => {
    localStorage.setItem('ntro-fontscale', fontScale)
    document.documentElement.setAttribute('data-fontscale', fontScale)
  }, [fontScale])
  useEffect(() => {
    localStorage.setItem('ntro-contrast', contrast)
    document.documentElement.setAttribute('data-contrast', contrast)
  }, [contrast])
  useEffect(() => {
    localStorage.setItem('ntro-advtheme', advTheme)
    // Advanced dark theme only applies while in advanced mode
    document.documentElement.setAttribute('data-adv-theme', mode === 'advanced' ? advTheme : 'light')
  }, [advTheme, mode])

  const bumpFont = useCallback((dir: 1 | -1) => {
    const order: FontScale[] = ['sm', 'md', 'lg', 'xl']
    setFontScale(cur => {
      const i = Math.min(order.length - 1, Math.max(0, order.indexOf(cur) + dir))
      return order[i]
    })
  }, [])

  return {
    mode, setMode,
    fontScale, setFontScale, bumpFont,
    contrast, setContrast,
    advTheme, setAdvTheme,
  }
}
