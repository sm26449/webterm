import { createContext, useCallback, useContext, useEffect, useState, ReactNode } from 'react'
import { LANGS, FALLBACK_LANG } from '../lang'

// i18n minimalist, fără librărie externă (se potrivește cu „totul inline"). Un catalog
// cheie→valoare per limbă (vezi src/lang/), un hook `useI18n().t('cheie', {var})`, fallback
// pe limba de referință (RO) apoi pe numele cheii dacă lipsește. Alegerea se persistă.
const STORAGE_KEY = 'wt_lang'

export function detectLang(): string {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && LANGS[saved]) return saved
  } catch { /* localStorage indisponibil */ }
  const nav = (navigator.language || '').toLowerCase()
  for (const code of Object.keys(LANGS)) {
    if (nav === code || nav.startsWith(code + '-')) return code
  }
  return FALLBACK_LANG
}

interface I18nCtx {
  lang: string
  setLang: (code: string) => void
  t: (key: string, vars?: Record<string, string | number>) => string
}

const Ctx = createContext<I18nCtx | null>(null)

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<string>(detectLang)

  // `<html lang>` se seta DOAR în `setLang`, adică doar dacă schimbai limba manual. Cine
  // deschidea UI-ul în engleză (detectat din browser sau din localStorage) rămânea pe
  // `lang="ro"` din index.html — deci cititoarele de ecran pronunţau engleza cu reguli
  // româneşti. Îl sincronizăm la montare şi la orice schimbare, nu doar la comutare.
  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  const setLang = useCallback((code: string) => {
    if (!LANGS[code]) return
    try { localStorage.setItem(STORAGE_KEY, code) } catch { /* ignoră */ }
    document.documentElement.lang = code
    setLangState(code)
  }, [])

  const t = useCallback((key: string, vars?: Record<string, string | number>) => {
    let s = LANGS[lang]?.strings[key] ?? LANGS[FALLBACK_LANG]?.strings[key] ?? key
    if (vars) {
      for (const [k, v] of Object.entries(vars)) s = s.split('{' + k + '}').join(String(v))
    }
    return s
  }, [lang])

  return <Ctx.Provider value={{ lang, setLang, t }}>{children}</Ctx.Provider>
}

export function useI18n(): I18nCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useI18n used outside <I18nProvider>')
  return c
}
