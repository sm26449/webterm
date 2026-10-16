/* Navigarea din panoul de fişiere (3.6.14) — logica PURĂ, fără React, testată în filesNav.test.ts:
   firimiturile căii, istoricul înapoi/înainte al unui panou, „tastează ca să sari" (type-to-jump),
   completarea cu Tab a ultimului segment din câmpul de cale şi comanda `cd` tastată în terminal.
   Panoul doar ţine starea şi o redă. */
import { isSafeToType } from './transfers'

// ── firimituri ───────────────────────────────────────────────────────────────────────────────
export interface Crumb { label: string; path: string }

/** `/var/log/nginx` → `/`, `var`, `log`, `nginx` (fiecare cu calea lui absolută). O cale relativă la
    home (`~`, `~/x`) — doar înainte de prima listare — porneşte de la `~`. Slash-urile duble / finale
    nu produc segmente goale. */
export function crumbs(path: string): Crumb[] {
  const p = path.trim()
  if (!p) return []
  if (p === '~' || p.startsWith('~/')) {
    const out: Crumb[] = [{ label: '~', path: '~' }]
    let acc = '~'
    for (const seg of p.slice(1).split('/').filter(Boolean)) {
      acc += '/' + seg
      out.push({ label: seg, path: acc })
    }
    return out
  }
  const out: Crumb[] = [{ label: '/', path: '/' }]
  let acc = ''
  for (const seg of p.split('/').filter(Boolean)) {
    acc += '/' + seg
    out.push({ label: seg, path: acc })
  }
  return out
}

/** Directorul-părinte al unei căi absolute (`/a/b` → `/a`, `/a` → `/`, `/` → `/`). */
export function parentOf(path: string): string {
  const p = path.replace(/\/+$/, '')
  if (!p) return '/'
  const i = p.lastIndexOf('/')
  return i <= 0 ? '/' : p.slice(0, i)
}

/** Numele ultimului segment (`/a/b/` → `b`); `/` → ''. */
export function baseName(path: string): string {
  const p = path.replace(/\/+$/, '')
  return p.slice(p.lastIndexOf('/') + 1)
}

// ── istoric înapoi / înainte (per instanţă de panou) ─────────────────────────────────────────
export interface NavHistory { readonly stack: readonly string[]; readonly idx: number }
export const EMPTY_HISTORY: NavHistory = { stack: [], idx: -1 }
/** plafon: un panou ţinut deschis o zi întreagă cu „follow cwd" nu creşte la nesfârşit */
export const HISTORY_MAX = 50

/** Un director nou vizitat: taie „înainte"-ul (ca în browser) şi îl adaugă. Acelaşi director ca cel
    curent (reload, follow pe acelaşi cwd) nu adaugă nimic. */
export function histPush(h: NavHistory, path: string): NavHistory {
  if (h.idx >= 0 && h.stack[h.idx] === path) return h
  const stack = [...h.stack.slice(0, h.idx + 1), path]
  const drop = Math.max(0, stack.length - HISTORY_MAX)
  return { stack: stack.slice(drop), idx: stack.length - 1 - drop }
}
export const canBack = (h: NavHistory): boolean => h.idx > 0
export const canForward = (h: NavHistory): boolean => h.idx >= 0 && h.idx < h.stack.length - 1
/** Pasul înapoi (-1) sau înainte (+1): noul istoric + calea de încărcat, sau null la capăt. */
export function histStep(h: NavHistory, d: -1 | 1): { hist: NavHistory; path: string } | null {
  const idx = h.idx + d
  if (idx < 0 || idx >= h.stack.length) return null
  return { hist: { stack: h.stack, idx }, path: h.stack[idx] }
}

// ── tastează ca să sari ──────────────────────────────────────────────────────────────────────
/** pauza după care bufferul de litere se goleşte (ca în orice manager de fişiere) */
export const TYPE_JUMP_MS = 1000

/** Rândul spre care sare „tastează ca să sari": primul nume care ÎNCEPE cu `buffer` (fără să ţină
    cont de majuscule), căutând de la `from` şi dând ocol listei. Bufferul format din aceeaşi literă
    repetată („aaa") trece la URMĂTORUL nume cu acea literă — apăsări repetate pe `a` ciclează prin
    `a*`, nu caută „aaa". `from` = rândul curent; la o literă nouă căutarea îl include (rândul
    curent poate deja să se potrivească), la ciclare începe după el. -1 = nicio potrivire. */
export function typeJump(names: readonly string[], buffer: string, from: number): number {
  const n = names.length
  if (!n || !buffer) return -1
  const b = buffer.toLowerCase()
  const cycle = b.length > 1 && [...b].every((c) => c === b[0])
  const needle = cycle ? b[0] : b
  // o singură literă = şi ea ciclează (apăsarea repetată după pauză merge la următorul)
  const startAfter = cycle || b.length === 1
  const start = Math.max(0, Math.min(n - 1, from))
  for (let k = 0; k < n; k++) {
    const i = (start + (startAfter ? k + 1 : k)) % n
    if (names[i].toLowerCase().startsWith(needle)) return i
  }
  return -1
}

// ── completarea cu Tab în câmpul de cale ─────────────────────────────────────────────────────
/** Împarte textul tastat în directorul de listat şi prefixul ultimului segment:
    `/var/lo` → { dir: '/var', prefix: 'lo' }; `/var/` → { dir: '/var', prefix: '' };
    `lo` (relativ) → { dir: base, prefix: 'lo' }; `~/Do` → { dir: '~', prefix: 'Do' }. */
export function splitForCompletion(input: string, base: string): { dir: string; prefix: string } {
  const slash = input.lastIndexOf('/')
  if (slash < 0) {
    if (input === '~') return { dir: '~', prefix: '' }
    return { dir: base, prefix: input }
  }
  const head = input.slice(0, slash)
  return { dir: head === '' ? '/' : head, prefix: input.slice(slash + 1) }
}

/** cel mai lung prefix comun al unor nume */
export function commonPrefix(names: readonly string[]): string {
  if (!names.length) return ''
  let p = names[0]
  for (const s of names) {
    let i = 0
    while (i < p.length && i < s.length && p[i] === s[i]) i++
    p = p.slice(0, i)
    if (!p) break
  }
  return p
}

/** plafonul candidaţilor arătaţi sub câmp (restul: „…şi încă N") */
export const COMPLETE_SHOW = 8

/** Completarea ultimului segment din `dirs` (numele SUBDIRECTOARELOR listate ale lui `dir`):
    potrivire exactă de majuscule întâi, apoi fără (dacă prima nu găseşte nimic). Un singur candidat
    → îl completează + `/` (gata de următorul segment). Mai mulţi → completează cât au în comun şi
    întoarce candidaţii (plafonaţi) ca să-i arate. `value` = noul text al câmpului. */
export function completePath(input: string, base: string, dirs: readonly string[]):
  { value: string; candidates: string[]; more: number } {
  const { prefix } = splitForCompletion(input, base)
  let hits = dirs.filter((d) => d.startsWith(prefix))
  if (!hits.length) {
    const lp = prefix.toLowerCase()
    hits = dirs.filter((d) => d.toLowerCase().startsWith(lp))
  }
  // fişierele ascunse doar dacă prefixul le cere (ca în shell)
  if (!prefix.startsWith('.')) hits = hits.filter((d) => !d.startsWith('.'))
  hits = [...hits].sort((a, b) => a.localeCompare(b))
  // ce rămâne neschimbat înaintea segmentului completat; un nume relativ devine cale absolută
  const slash = input.lastIndexOf('/')
  const head = slash >= 0 ? input.slice(0, slash + 1) : input === '~' ? '~/' : joinDir(base, '')
  if (!hits.length) return { value: input, candidates: [], more: 0 }
  if (hits.length === 1) return { value: head + hits[0] + '/', candidates: [], more: 0 }
  const cp = commonPrefix(hits)
  const value = cp.length > prefix.length ? head + cp : input
  return { value, candidates: hits.slice(0, COMPLETE_SHOW), more: Math.max(0, hits.length - COMPLETE_SHOW) }
}

function joinDir(dir: string, name: string): string {
  return `${dir.replace(/\/$/, '')}/${name}`
}

// ── ţinte legate de directorul în care au fost alese (review 3.6.15, M2) ──────────────────────
/** Calea unei acţiuni pe un rând ales în directorul `at`, DOAR dacă panoul încă listează acel
    director. Altfel null: între timp follow-cwd (OSC 7) / „deschide aici" / navigarea au schimbat
    directorul, iar un nume reconstruit din directorul NOU ar ţinti alt fişier (acelaşi nume, alt loc). */
export function targetPath(at: string, current: string | null | undefined, name: string): string | null {
  if (!at || !name || current == null || current !== at) return null
  return `${at.replace(/\/$/, '')}/${name}`
}

// ── „cd aici" în terminal ────────────────────────────────────────────────────────────────────
/** `cd -- '<cale>'` de tastat la prompt (FĂRĂ Enter — ca „insert path" şi comanda de mutare ca
    root: omul vede comanda şi apasă el Enter). Mereu între apostrofuri (şi `~` sau `-` rămân
    literale; `--` opreşte oricum opţiunile). Apostroful din nume → `'\''`; backslash-ul se scrie ÎN
    AFARA apostrofului, ca `\\` (în fish `\'` şi `\\` sunt escape-uri şi între apostrofuri — vezi
    shellQuote din lib/transfers.ts). Caracterele de control / bidi / zero-width / separatorii de
    linie NU se curăţă (ar schimba directorul ţintă), ci refuză: null. */
export function cdCommand(path: string): string | null {
  if (!path || !isSafeToType(path)) return null
  const q = `'${path.replace(/['\\]/g, (ch) => (ch === "'" ? `'\\''` : `'\\\\'`))}'`
  return `cd -- ${q}`
}
