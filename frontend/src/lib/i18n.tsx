import { createContext, useCallback, useContext, useEffect, useState, ReactNode } from 'react'
import { LANG_META, FALLBACK_LANG, loadLang, loaded, isLoaded } from '../lang'

// i18n minimalist, fără librărie externă (se potrivește cu „totul inline"). Un catalog
// cheie→valoare per limbă (vezi src/lang/), un hook `useI18n().t('cheie', {var})`, fallback
// pe FALLBACK_LANG (= `en`, vezi src/lang/index.ts) apoi pe numele cheii. Alegerea se persistă.
//
// Referința e `en`, nu `ro`: o cheie care există doar în `ro.ts` NU cade pe română — cade pe
// numele cheii, adică utilizatorul englez vede `login.footer.greeting` în interfață. Trei
// comentarii susțineau invers, iar cine le urma introducea exact defectul ăsta.
// `tests/i18n_catalog_test.py` păzește acum simetria mecanic.
const STORAGE_KEY = 'wt_lang'

export function detectLang(): string {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && LANG_META[saved]) return saved
  } catch { /* localStorage indisponibil */ }
  // `navigator.languages`, nu doar `navigator.language`: al doilea e DOAR prima preferinţă,
  // deci un browser setat `de-DE, ro;q=0.9` — germană preferată, română acceptată — primea
  // engleză, deşi utilizatorul spusese limpede că înţelege româna. Parcurgem lista în ordinea
  // preferinţei şi luăm prima limbă pe care o avem.
  const prefs = (navigator.languages && navigator.languages.length
    ? navigator.languages
    : [navigator.language || '']).map((l) => (l || '').toLowerCase())
  for (const nav of prefs) {
    for (const code of Object.keys(LANG_META)) {
      if (nav === code || nav.startsWith(code + '-')) return code
    }
  }
  return FALLBACK_LANG
}

/** PF-11: încarcă leneș catalogul limbii detectate ÎNAINTE de primul render (main.tsx), ca un
    utilizator pe română să nu vadă o clipire de engleză. `en` se rezolvă imediat. Best-effort. */
export async function preloadLang(): Promise<void> {
  await loadLang(detectLang())
}

interface I18nCtx {
  lang: string
  setLang: (code: string) => void
  t: (key: string, vars?: Record<string, string | number>) => string
}

const Ctx = createContext<I18nCtx | null>(null)

/* Traducere in afara React: `duration()` si `humanUptime()` sunt functii de modul,
   fara acces la hook. Fara asta ramaneau cu abrevieri hardcodate — „z" romanesc
   scurs in interfata engleza. Citeste aceeasi limba ca `useI18n`, deci nu poate
   diverge de ea. */
export function tStatic(key: string): string {
  const lang = detectLang()
  return loaded(lang)?.strings[key] ?? loaded(FALLBACK_LANG)?.strings[key] ?? key
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<string>(detectLang)
  // PF-11: forţează un re-render când catalogul limbii active termină de încărcat (lazy)
  const [, bumpLoaded] = useState(0)

  // `<html lang>` se seta DOAR în `setLang`, adică doar dacă schimbai limba manual. Cine
  // deschidea UI-ul în engleză (detectat din browser sau din localStorage) rămânea pe
  // `lang="ro"` din index.html — deci cititoarele de ecran pronunţau engleza cu reguli
  // româneşti. Îl sincronizăm la montare şi la orice schimbare, nu doar la comutare.
  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  // PF-11: dacă limba activă încă nu e în memorie (preload-ul din main.tsx a fost sărit sau a
  // eşuat), o încarcă acum şi re-randează — până atunci `t` cade pe `en`. No-op dacă e deja acolo.
  useEffect(() => {
    if (isLoaded(lang)) return
    let live = true
    void loadLang(lang).then(() => { if (live) bumpLoaded((n) => n + 1) })
    return () => { live = false }
  }, [lang])

  const setLang = useCallback((code: string) => {
    if (!LANG_META[code]) return
    try { localStorage.setItem(STORAGE_KEY, code) } catch { /* ignoră */ }
    // încarcă catalogul ÎNAINTE de a comuta starea, ca interfaţa să nu clipească prin engleză la
    // schimbarea manuală; `en` şi o limbă deja încărcată se rezolvă imediat. La eşec comutăm oricum
    // (cade pe `en`), ca UI-ul să nu rămână blocat.
    void loadLang(code).finally(() => {
      document.documentElement.lang = code
      setLangState(code)
    })
  }, [])

  const t = useCallback((key: string, vars?: Record<string, string | number>) => {
    const pick = (k: string) => loaded(lang)?.strings[k] ?? loaded(FALLBACK_LANG)?.strings[k]
    let s: string | undefined
    // Plural. Codul folosea `n === 1 ? singular : plural`, ceea ce e corect în engleză şi
    // greşit în română, care are TREI forme: 1 / 2–19 / 20+ cu „de" — deci ieşea „20 host-uri"
    // în loc de „20 de host-uri", şi „1 fișiere". Cu `count`, căutăm întâi `cheie.one`/
    // `cheie.few`/`cheie.other` după regulile limbii, apoi cădem pe cheia simplă, ca să nu
    // fie nevoie de variante acolo unde textul nu depinde de număr.
    if (vars && typeof vars.count === 'number') {
      try {
        s = pick(key + '.' + new Intl.PluralRules(lang).select(vars.count))
      } catch { /* limbă necunoscută de Intl → cădem pe cheia simplă */ }
      s = s ?? pick(key + '.other')
    }
    s = s ?? pick(key) ?? key
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
