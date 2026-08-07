import { useEffect, useState } from 'react'

export type Theme = 'dark' | 'macos'
/** ce a ales utilizatorul: o temă fixă sau „auto" (după setarea sistemului) */
export type ThemePref = Theme | 'auto'

const systemTheme = (): Theme =>
  window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'macos' : 'dark'

export function themePref(): ThemePref {
  const v = localStorage.getItem('wt_theme')
  return v === 'macos' || v === 'dark' || v === 'auto' ? v : 'dark'
}

export function currentTheme(): Theme {
  // Midnight (dark) e tema implicită — o singură paletă întunecată coerentă,
  // rail + workspace din aceeași familie. „auto" urmează sistemul.
  const p = themePref()
  return p === 'auto' ? systemTheme() : p
}

/** Aplică preferința (fixă sau „auto") și o persistă. */
export function applyTheme(pref: ThemePref): void {
  localStorage.setItem('wt_theme', pref)
  paintTheme(pref === 'auto' ? systemTheme() : pref)
  window.dispatchEvent(new Event('wt-theme'))
}

function paintTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme
  // bara de titlu a ferestrei PWA / cromul browserului mobil urmează tema —
  // altfel rămâne neagră (valoarea statică din index.html) peste UI-ul alb Aurora
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute('content', theme === 'macos' ? '#edf0f7' : '#0b0e14')
}

// „auto": urmărește schimbarea setării de sistem cât timp e activă preferința
window.matchMedia?.('(prefers-color-scheme: light)').addEventListener?.('change', () => {
  if (themePref() === 'auto') {
    paintTheme(systemTheme())
    window.dispatchEvent(new Event('wt-theme'))
  }
})

/** [preferința aleasă, tema efectivă, setter] */
export function useTheme(): [ThemePref, Theme, (t: ThemePref) => void] {
  const [pref, setPref] = useState<ThemePref>(themePref)
  const [theme, setTheme] = useState<Theme>(currentTheme)
  useEffect(() => {
    const onChange = () => { setPref(themePref()); setTheme(currentTheme()) }
    window.addEventListener('wt-theme', onChange)
    return () => window.removeEventListener('wt-theme', onChange)
  }, [])
  return [pref, theme, applyTheme]
}
