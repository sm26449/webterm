// Registrul de limbi. Ca să adaugi una nouă: creează `xx.ts` (copiază `en.ts` — e catalogul
// de REFERINȚĂ, vezi FALLBACK_LANG mai jos), tradu valorile, pune-ți flag-ul + numele în
// `meta`, și adaug-o în `LANGS` și `LANG_ORDER` aici. Cheile trebuie să fie exact aceleași
// ca în `en.ts`; `tests/i18n_catalog_test.py` verifică asta.
import ro from './ro'
import en from './en'

export interface Lang {
  meta: { code: string; name: string; flag: string }
  strings: Record<string, string>
}

export const LANGS: Record<string, Lang> = { ro, en }

// Ordinea din meniu (flag + nume). Adaugă codul limbii noi aici.
export const LANG_ORDER = ['ro', 'en']

export const FALLBACK_LANG = 'en'
