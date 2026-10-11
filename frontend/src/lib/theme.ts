import { useEffect, useState } from 'react'
import { lsGet, lsSet } from './storage'
import {
  isLight, parseThemePref, resolveVariant, serializeThemePref, THEME_KEY, VARIANTS,
  type ThemePref, type ThemeVariant,
} from './themeModel'

/* Aplicarea temei pe <html> (modelul — familie × mod — e în themeModel.ts).
   `data-theme` = varianta (tokenii din index.css), `data-family` = familia (raze, crom, efecte),
   `data-mode` = light/dark efectiv (regulile care depind doar de „deschis vs închis"). */

export type { ThemeFamily, ThemeMode, ThemePref, ThemeVariant } from './themeModel'
export { isLight } from './themeModel'
/** compat: „tema efectivă" = varianta */
export type Theme = ThemeVariant

const hasWindow = typeof window !== 'undefined'
const mq = hasWindow && typeof window.matchMedia === 'function'
  ? window.matchMedia('(prefers-color-scheme: light)') : null
const systemLight = (): boolean => !!mq?.matches

export function themePref(): ThemePref {
  return parseThemePref(lsGet(THEME_KEY))
}

export function currentTheme(): ThemeVariant {
  // Midnight (WebTerm dark) e tema implicită. „auto" urmează sistemul, în familia aleasă.
  return resolveVariant(themePref(), systemLight())
}

function paintTheme(v: ThemeVariant): void {
  const root = document.documentElement
  root.dataset.theme = v
  root.dataset.family = VARIANTS[v].family
  root.dataset.mode = isLight(v) ? 'light' : 'dark'
  // bara de titlu a ferestrei PWA / cromul browserului mobil urmează varianta — altfel rămâne
  // neagră (valoarea statică din index.html) peste un UI deschis
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', VARIANTS[v].themeColor)
}

function notify(): void {
  window.dispatchEvent(new Event('wt-theme'))
  // schema de terminal implicită urmează familia (termtheme.ts) → terminalele deschise se repictează
  window.dispatchEvent(new Event('wt-termscheme'))
}

/** La pornire: pictează preferinţa salvată FĂRĂ s-o rescrie. (Până în 3.6.3 pornirea scria tema
    efectivă înapoi în storage, deci „auto" devenea „dark"/„macos" la primul reload.) */
export function initTheme(): void {
  paintTheme(currentTheme())
}

/** Aplică preferinţa (familie + mod) şi o persistă. */
export function applyTheme(pref: ThemePref): void {
  lsSet(THEME_KEY, serializeThemePref(pref))
  paintTheme(resolveVariant(pref, systemLight()))
  notify()
}

// „auto": urmărește schimbarea setării de sistem cât timp e activă preferința
mq?.addEventListener?.('change', () => {
  if (themePref().mode === 'auto') {
    paintTheme(currentTheme())
    notify()
  }
})

/** [preferința aleasă, varianta efectivă, setter] */
export function useTheme(): [ThemePref, ThemeVariant, (p: ThemePref) => void] {
  const [pref, setPref] = useState<ThemePref>(themePref)
  const [theme, setTheme] = useState<ThemeVariant>(currentTheme)
  useEffect(() => {
    const onChange = () => { setPref(themePref()); setTheme(currentTheme()) }
    window.addEventListener('wt-theme', onChange)
    return () => window.removeEventListener('wt-theme', onChange)
  }, [])
  return [pref, theme, applyTheme]
}
