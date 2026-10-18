/* Navigarea din panoul de fişiere (3.6.14) — logica PURĂ, fără React, testată în filesNav.test.ts:
   firimiturile căii, istoricul înapoi/înainte al unui panou, „tastează ca să sari" (type-to-jump),
   completarea cu Tab a ultimului segment din câmpul de cale şi comanda `cd` tastată în terminal.
   Din audit 2026-10-17 P1 şi: gating-ul cosmetic pe permisiuni (FL-09), clasificarea unui `mkdir`
   refuzat la upload de folder (FS-04) şi indiciul de cale fizică pentru merged-usr (FS-02).
   Panoul doar ţine starea şi o redă. */
import { isSafeToType } from './transfers'
import { anyHost, canOn, type MyPerms } from './perms'
import { errIsWriteDenied } from './rootmove'

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

// ── gating cosmetic pe permisiuni (FL-09, audit 2026-10-17) ───────────────────────────────────
/** `ok` = acţiunea e oferită; `disabled` = contul are permisiunea pe ALT host, nu pe ăsta → buton
    dezactivat cu motivul în tooltip; `hidden` = n-o are nicăieri → controlul nu se arată deloc
    (docs/design/DESIGN-SYSTEM.md „Hide vs disable"). Permisiuni necunoscute încă (`null`) = `ok` —
    serverul refuză oricum (lib/perms.ts). */
export type GateState = 'ok' | 'disabled' | 'hidden'
export interface FilesGate { write: GateState; del: GateState }
export function filesGate(p: MyPerms | null, hostId: number): FilesGate {
  const one = (perm: string): GateState => (canOn(p, hostId, perm) ? 'ok' : anyHost(p, perm) ? 'disabled' : 'hidden')
  return { write: one('files.write'), del: one('files.delete') }
}
/** cheile din meniul contextual / foaie care cer `files.write`, respectiv `files.delete` */
export const WRITE_ACTIONS: ReadonlySet<string> = new Set(['newfile', 'newfolder', 'upload', 'rename', 'duplicate'])
export const DELETE_ACTIONS: ReadonlySet<string> = new Set(['delete'])
/** Aplică gating-ul pe itemele unui meniu: cele `hidden` dispar (separatorul lor trece pe itemul
    următor), cele `disabled` rămân vizibile, dezactivate, cu motivul; restul neatinse. */
export function gateMenuItems<T extends { key: string; disabled?: boolean; reason?: string; sep?: boolean }>(
  items: readonly T[], gate: FilesGate, reason: { write: string; del: string }): T[] {
  const out: T[] = []
  let carrySep = false
  for (const it of items) {
    const isWrite = WRITE_ACTIONS.has(it.key), isDel = DELETE_ACTIONS.has(it.key)
    const g: GateState = isWrite ? gate.write : isDel ? gate.del : 'ok'
    if (g === 'hidden') { carrySep ||= !!it.sep; continue }
    // niciun separator deasupra primului item vizibil (ar fi o linie goală în capul meniului)
    const sep = (carrySep || !!it.sep) && out.length > 0
    const base = sep !== !!it.sep ? { ...it, sep } : it
    carrySep = false
    out.push(g === 'ok' ? base : { ...base, disabled: true, reason: isWrite ? reason.write : reason.del })
  }
  return out
}

// ── upload de folder: un `mkdir` refuzat (FS-04, audit 2026-10-17) ────────────────────────────
/** O creare de subdosar refuzată pentru că userul agentului NU poate scrie acolo. Întoarce de unde
    în jos nu mai merită încercat nimic (altfel fiecare fişier ar primi „the folder does not exist",
    adevărat literal şi fals ca explicaţie) şi dosarul absolut de arătat în banner:
    - prima componentă a căii relative NU exista în listarea lui `base` → `base` însuşi nu e scriibil:
      `prefix: ''` = tot ce e imbricat (fişierele simple se încearcă totuşi: ele intră în oferta
      „move as root");
    - exista deja → acea componentă e cea nescriibilă: `prefix: <ea>`.
    Orice altă eroare (dosarul există deja, agent vechi) → null: comportamentul vechi. */
export interface MkdirRefusal { prefix: string; at: string }
export function mkdirRefusal(e: unknown, base: string, rel: string, existing: ReadonlySet<string>): MkdirRefusal | null {
  if (!errIsWriteDenied(e)) return null
  const first = rel.split('/')[0]
  if (!first) return null
  const b = base.replace(/\/$/, '')
  return existing.has(first) ? { prefix: first, at: `${b}/${first}` } : { prefix: '', at: base }
}
/** `rel` cade sub un prefix refuzat? (`''` = orice cale imbricată) */
export const underRefused = (rel: string, prefixes: readonly string[]): boolean =>
  prefixes.some((p) => (p === '' ? rel.includes('/') : rel === p || rel.startsWith(p + '/')))

// ── merged-usr: calea fizică a unui dosar atins printr-un symlink (FS-02, audit 2026-10-17) ───
/** Comanda „move as root" intră cu `cd -P` şi cere ca `pwd -P` să fie exact dosarul numit; sub
    merged-usr (`/bin → /usr/bin` pe Debian ≥ 12, Ubuntu ≥ 21.10, Fedora, Arch) şi `/var/run → /run`
    calea LOGICĂ din Files (OSC 7 / abspath în agent) pică acea verificare. Până când agentul (v59)
    va raporta realpath-ul, ghicim calea fizică doar pentru prefixele ştiute; altfel null. */
const MERGED_USR: readonly (readonly [string, string])[] = [
  ['/bin', '/usr/bin'], ['/sbin', '/usr/sbin'], ['/lib', '/usr/lib'], ['/lib32', '/usr/lib32'],
  ['/lib64', '/usr/lib64'], ['/libx32', '/usr/libx32'], ['/var/run', '/run'], ['/var/lock', '/run/lock'],
]
export function physicalPathHint(dir: string): string | null {
  for (const [logical, physical] of MERGED_USR) {
    if (dir === logical || dir.startsWith(logical + '/')) return physical + dir.slice(logical.length)
  }
  return null
}
