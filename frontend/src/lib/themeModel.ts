/* Modelul temelor (3.6.4) — logică PURĂ, fără DOM, ca să poată fi testată în vitest (mediu node).
   theme.ts o aplică pe <html>; termtheme.ts citeşte familia pentru schema de terminal implicită.

   O temă = FAMILIE × MOD:
     - familia: `webterm` (Midnight + Aurora, temele istorice), `mac` (stil macOS),
       `win` (stil Windows 11 / Fluent), `gnome` (stil GNOME / libadwaita);
     - modul: `light` / `dark` / `auto` (auto = urmează prefers-color-scheme ÎN familia aleasă).
   Rezultatul e o VARIANTĂ concretă, scrisă în `data-theme` pe <html>; index.css are un bloc de
   tokeni pentru fiecare variantă. Variantele WebTerm îşi păstrează id-urile istorice (`dark` =
   Midnight, `macos` = Aurora — numele „macos" e moştenit de dinainte de 3.6.4 şi NU înseamnă
   familia macOS), ca regulile CSS şi datele existente să rămână valabile.

   Stocare (localStorage `wt_theme`):
     - familia WebTerm se scrie în formatul VECHI (`dark` / `macos` / `auto`) → un downgrade la
       3.6.3 citeşte exact aceeaşi temă;
     - celelalte familii: `<familie>:<mod>` (ex. `win:dark`) — 3.6.3 nu le recunoaşte şi cade pe
       Midnight, adică pe default, fără să strice nimic;
     - orice valoare necunoscută → default (WebTerm, dark = Midnight). */

export type ThemeFamily = 'webterm' | 'mac' | 'win' | 'gnome'
export type ThemeMode = 'light' | 'dark' | 'auto'
export type ThemeVariant =
  | 'dark' | 'macos'                 // WebTerm: Midnight, Aurora (id-uri istorice)
  | 'mac-light' | 'mac-dark'
  | 'win-light' | 'win-dark'
  | 'gnome-light' | 'gnome-dark'

export interface ThemePref { family: ThemeFamily; mode: ThemeMode }

export const THEME_KEY = 'wt_theme'
export const DEFAULT_PREF: ThemePref = { family: 'webterm', mode: 'dark' }

/** Mostre pentru cardurile din Setări (doar ilustraţie: culorile reale sunt tokenii din index.css). */
export interface Swatch { bg: string; side: string; surface: string; line: string; accent: string; text: string }

export interface VariantInfo {
  family: ThemeFamily
  light: boolean
  /** <meta name="theme-color"> — bara de titlu PWA / cromul browserului mobil */
  themeColor: string
  swatch: Swatch
}

export const VARIANTS: Record<ThemeVariant, VariantInfo> = {
  dark: { family: 'webterm', light: false, themeColor: '#0b0e14',
    swatch: { bg: '#0c1017', side: '#151b29', surface: '#1a2030', line: '#252d42', accent: '#4f46e5', text: '#e2e8f0' } },
  macos: { family: 'webterm', light: true, themeColor: '#edf0f7',
    swatch: { bg: '#edf0f7', side: '#ffffff', surface: '#ffffff', line: '#dbe0eb', accent: '#4f46e5', text: '#1b1b1e' } },
  'mac-light': { family: 'mac', light: true, themeColor: '#ececee',
    swatch: { bg: '#ececee', side: '#f6f6f8', surface: '#ffffff', line: '#dedee2', accent: '#055dbe', text: '#1d1d1f' } },
  'mac-dark': { family: 'mac', light: false, themeColor: '#1e1e20',
    swatch: { bg: '#1e1e20', side: '#2a2a2c', surface: '#323235', line: '#424246', accent: '#055dbe', text: '#e5e5ea' } },
  'win-light': { family: 'win', light: true, themeColor: '#f3f3f3',
    swatch: { bg: '#f3f3f3', side: '#eeeeee', surface: '#ffffff', line: '#e5e5e5', accent: '#055fb5', text: '#1a1a1a' } },
  'win-dark': { family: 'win', light: false, themeColor: '#202020',
    swatch: { bg: '#202020', side: '#2b2b2b', surface: '#323232', line: '#3d3d3d', accent: '#055fb5', text: '#f0f0f0' } },
  'gnome-light': { family: 'gnome', light: true, themeColor: '#ebebed',
    swatch: { bg: '#fafafb', side: '#ebebed', surface: '#ffffff', line: '#dedee2', accent: '#185fb4', text: '#2e2e33' } },
  'gnome-dark': { family: 'gnome', light: false, themeColor: '#222226',
    swatch: { bg: '#222226', side: '#2e2e32', surface: '#38383c', line: '#48484d', accent: '#185fb4', text: '#eeeef0' } },
}

/** Ordinea din Setări; `light`/`dark` = varianta fiecărui mod. */
export const FAMILIES: readonly { id: ThemeFamily; light: ThemeVariant; dark: ThemeVariant }[] = [
  { id: 'webterm', light: 'macos', dark: 'dark' },
  { id: 'mac', light: 'mac-light', dark: 'mac-dark' },
  { id: 'win', light: 'win-light', dark: 'win-dark' },
  { id: 'gnome', light: 'gnome-light', dark: 'gnome-dark' },
]

const FAMILY_IDS = new Set<string>(FAMILIES.map((f) => f.id))
const MODES = new Set<string>(['light', 'dark', 'auto'])

/** Valoarea din `wt_theme` → preferinţă. Nu aruncă niciodată: necunoscut/gol → default. */
export function parseThemePref(raw: string | null | undefined): ThemePref {
  const v = (raw ?? '').trim()
  // formatul vechi (≤ 3.6.3) — trebuie să dea EXACT aceeaşi temă
  if (v === 'dark') return { family: 'webterm', mode: 'dark' }
  if (v === 'macos') return { family: 'webterm', mode: 'light' }
  if (v === 'auto') return { family: 'webterm', mode: 'auto' }
  const m = /^([a-z]+):([a-z]+)$/.exec(v)
  if (m && FAMILY_IDS.has(m[1]) && MODES.has(m[2])) return { family: m[1] as ThemeFamily, mode: m[2] as ThemeMode }
  return { ...DEFAULT_PREF }
}

/** Preferinţă → valoarea scrisă în `wt_theme` (WebTerm în formatul vechi, pentru downgrade). */
export function serializeThemePref(p: ThemePref): string {
  if (p.family === 'webterm') return p.mode === 'light' ? 'macos' : p.mode
  return `${p.family}:${p.mode}`
}

/** Varianta efectivă; `systemLight` = prefers-color-scheme: light (contează doar la `auto`). */
export function resolveVariant(p: ThemePref, systemLight: boolean): ThemeVariant {
  const fam = FAMILIES.find((f) => f.id === p.family) ?? FAMILIES[0]
  const light = p.mode === 'auto' ? systemLight : p.mode === 'light'
  return light ? fam.light : fam.dark
}

/** Temă deschisă? Singurul test permis în componente (nu `=== 'macos'`): orice variantă
    deschisă nouă trebuie să primească automat editorul `vs`, watermark-ul închis etc. */
export function isLight(v: ThemeVariant): boolean {
  return VARIANTS[v]?.light ?? false
}

export function familyOf(v: ThemeVariant): ThemeFamily {
  return VARIANTS[v]?.family ?? 'webterm'
}

/** Numele afişat al unei variante: Midnight/Aurora rămân nume proprii; restul = „familie · mod". */
export function variantName(v: ThemeVariant, t: (key: string) => string): string {
  if (v === 'dark') return 'Midnight'
  if (v === 'macos') return 'Aurora'
  return `${t(`theme.family.${familyOf(v)}`)} · ${t(isLight(v) ? 'theme.mode.light' : 'theme.mode.dark')}`
}

/** Comutarea rapidă din paleta de comenzi: rămâi în familie, treci pe modul opus celui afişat. */
export function toggledPref(p: ThemePref, current: ThemeVariant): ThemePref {
  return { family: p.family, mode: isLight(current) ? 'dark' : 'light' }
}
