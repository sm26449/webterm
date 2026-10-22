// Registrul de limbi. Ca să adaugi una nouă: creează `xx.ts` (copiază `en.ts` — e catalogul
// de REFERINȚĂ, vezi FALLBACK_LANG mai jos), tradu valorile, apoi adaug-o în `LANG_META`,
// `LANG_ORDER` și `LOADERS` aici. Cheile trebuie să fie exact aceleași ca în `en.ts`;
// `tests/i18n_catalog_test.py` verifică asta.
//
// PF-11/UI-24: cataloagele sunt mari (~290–310 KB sursă fiecare) și se schimbă la fiecare release
// (deci cache-ul nu ajută). `en` e FALLBACK_LANG — îi trebuie SINCRON oricui (fallback pentru orice
// cheie lipsă și pentru `tStatic`), deci rămâne eager. Celelalte se încarcă LENEȘ (`import()`), doar
// limba activă, așa că un utilizator pe engleză nu mai descarcă româna. Meta-ul (flag + nume) stă
// static aici, ca meniul de limbă să-l arate fără a încărca tot catalogul.
import en from './en'

export interface Lang {
  meta: { code: string; name: string; flag: string }
  strings: Record<string, string>
}

export const FALLBACK_LANG = 'en'

// Doar metadatele (flag + nume) — statice și mici, pentru meniu și detecție, fără stringurile grele.
// A se păstra în sincron cu `meta` din fiecare catalog (`tests/i18n_catalog_test.py` nu-l verifică).
export const LANG_META: Record<string, Lang['meta']> = {
  en: en.meta,
  ro: { code: 'ro', name: 'Română', flag: '🇷🇴' },
}

// Ordinea din meniu (flag + nume). Adaugă codul limbii noi aici.
export const LANG_ORDER = ['ro', 'en']

// `en` e deja încărcat (eager, fallback); restul au un loader leneș.
const LOADED: Record<string, Lang> = { en }
const LOADERS: Record<string, () => Promise<{ default: Lang }>> = {
  ro: () => import('./ro'),
}

/** Catalogul deja în memorie pentru `code`, sau undefined dacă nu s-a încărcat încă. */
export function loaded(code: string): Lang | undefined {
  return LOADED[code]
}

export function isLoaded(code: string): boolean {
  return !!LOADED[code]
}

/** Încarcă (o singură dată) catalogul limbii. `en` și o limbă deja încărcată se rezolvă imediat;
    un cod necunoscut e un no-op (apelantul cade pe fallback). Best-effort: la eșec nu aruncă. */
export async function loadLang(code: string): Promise<void> {
  if (LOADED[code] || !LOADERS[code]) return
  try {
    LOADED[code] = (await LOADERS[code]()).default
  } catch { /* chunk indisponibil (rețea / deploy) → rămâne pe fallback-ul `en` */ }
}
