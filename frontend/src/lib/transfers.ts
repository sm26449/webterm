/* Transferuri „din terminal": drop pe terminal → upload în cwd-ul sesiunii; paste de imagine /
   fişier → upload în inbox-ul hostului + calea tastată la prompt.

   De ce există: un CLI cu AI (Claude Code, aider, …) rulat printr-un terminal web NU poate citi
   clipboardul browserului — „lipeşte un screenshot" nu are cum să ajungă la el. WebTerm
   materializează fişierul pe host (`~/.webterm/inbox/<timestamp>.<ext>`) şi îi dă unealtei
   CALEA, singurul lucru pe care îl înţelege. Funcţiile pure de aici (nume, citare, retenţie)
   sunt testate în transfers.test.ts; registrul de inserare şi preferinţele stau tot aici ca să
   nu depindă de nicio componentă (job-ul se poate termina după ce tab-ul s-a închis). */
import { api } from './api'
import { lsGet, lsSet } from './storage'

// ── convenţia inbox-ului ──────────────────────────────────────────────────────────────────
/** relativ la home-ul hostului; agentul face `expanduser` pe orice cale fs, deci `~` merge
    direct în mkdir/upload — pentru calea INSERATĂ în terminal rezolvăm însă home-ul absolut */
export const INBOX_REL = '.webterm/inbox'

/** MIME → extensie. Doar tipurile pe care un paste le produce realist; necunoscut → `bin`,
    ca fişierul să fie totuşi scris (un CLI îl poate inspecta), nu refuzat. */
const MIME_EXT: Record<string, string> = {
  'image/png': 'png', 'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp',
  'image/svg+xml': 'svg', 'image/bmp': 'bmp', 'image/tiff': 'tiff', 'image/avif': 'avif', 'image/heic': 'heic',
  'application/pdf': 'pdf', 'text/plain': 'txt', 'text/markdown': 'md', 'text/csv': 'csv', 'text/html': 'html',
  'application/json': 'json', 'application/zip': 'zip', 'application/gzip': 'gz', 'application/x-tar': 'tar',
}
export function extFromMime(mime: string): string {
  const m = (mime || '').toLowerCase().split(';')[0].trim()
  if (MIME_EXT[m]) return MIME_EXT[m]
  // `image/x-foo` → `foo`, dacă arată a extensie
  const sub = m.split('/')[1] ?? ''
  const guess = sub.replace(/^x-/, '')
  return /^[a-z0-9]{1,8}$/.test(guess) ? guess : 'bin'
}

/** `YYYY-MM-DD_HH-mm-ss` în ora LOCALĂ a browserului (aşa citeşte omul lista: „cel de la
    14:03"). Fără `:` — cale sigură pe orice sistem de fişiere. */
export function stampFor(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}-${p(d.getMinutes())}-${p(d.getSeconds())}`
}

/** Un item lipit e „fără nume" când browserul i-a dat numele generic al unei capturi
    (Chrome/Firefox: `image.png`; Safari: `Pasted Graphic`) sau niciunul. */
export const isGenericName = (name: string): boolean =>
  !name || /^image(\.[a-z0-9]+)?$/i.test(name) || /^pasted graphic/i.test(name)

/** Regula de nume din inbox:
    - fără nume:  `<stamp>[-n].<ext>`          (ext din MIME)
    - cu nume:    `<stamp>[-n]_<nume>`          (numele original, curăţat de `/` şi spaţii de capăt)
    `n` (≥2) e contorul de coliziune pentru mai multe fişiere în aceeaşi secundă. */
export function inboxName(file: { name: string; type: string }, when: Date, n = 1): string {
  const stamp = stampFor(when) + (n > 1 ? `-${n}` : '')
  if (isGenericName(file.name)) return `${stamp}.${extFromMime(file.type)}`
  // Octeţii de control (`\r \n \x1b \x00-\x1f \x7f`) ies PRIMII: numele devine parte dintr-o cale
  // care se tastează apoi la prompt (vezi shellQuote). Citarea cu apostrof opreşte shell-ul, dar
  // NU line discipline-ul PTY-ului — un `\r` în nume ar trimite linia, `\x1b` ar începe o secvenţă
  // escape. Un nume de fişier legitim nu are de ce să conţină aşa ceva.
  const clean = file.name.replace(/[\x00-\x1f\x7f]/g, '').replace(/[/\\]/g, '_').replace(/^\s+|\s+$/g, '').replace(/^\.+/, '') || `file.${extFromMime(file.type)}`
  return `${stamp}_${clean}`
}

// ── citare shell ──────────────────────────────────────────────────────────────────────────
/** Calea se tastează la prompt ca argument: citată DOAR dacă e nevoie (altfel `ls /tmp/a`
    ar apărea ca `ls '/tmp/a'`, urât şi inutil). Apostrof simplu — `$`, `` ` `` şi `!` sunt inerte
    în el în sh/bash/zsh/fish; apostroful din interior devine `'\''`.
    Backslash-ul NU e inert în fish (3.6.9 re-review M2): acolo `\'` şi `\\` sunt escape-uri şi
    ÎN apostrof, deci `'a\'` nu se închide, iar un nume `a\` + `x;id>pwn;#` ar ieşi din citare
    şi ar rula. Îl scriem deci ÎN AFARA apostrofului, ca `\\` — un backslash literal în sh, bash,
    zsh, fish (nu csh/tcsh: acolo `!` se expandează şi între apostrofuri): `a\b` → `'a'\\'b'`. Niciun backslash nu rămâne între apostrofuri. */
export function shellQuote(p: string): string {
  // Scoatem întâi octeţii de control (`\x00-\x1f \x7f`, adică `\r \n \x1b \x00` …): apostroful
  // inertizează `$`/`` ` ``/`!` pentru PARSER-ul shell-ului, dar octeţii de control ajung
  // nefiltraţi la LINE DISCIPLINE-ul PTY-ului — un `\r` trimite linia (execuţie fără Enter de la
  // om), `\x1b` deschide o secvenţă escape. O cale inserată nu are motiv legitim să-i conţină.
  const safe = p.replace(/[\x00-\x1f\x7f]/g, '')
  if (safe && /^[A-Za-z0-9_\-./~:@%+=,]+$/.test(safe)) return safe
  // o singură trecere: `'` → `'\''`, `\` → `'\\'` (închide citarea, pune caracterul escape-uit ÎN
  // AFARA ei, o redeschide); ce introduce o înlocuire nu mai e atins de cealaltă
  return `'${safe.replace(/['\\]/g, (ch) => (ch === "'" ? `'\\''` : `'\\\\'`))}'`
}

// ── retenţie ──────────────────────────────────────────────────────────────────────────────
export interface InboxEntry { name: string; dir: boolean; mtime: number }
export const RETENTION_BATCH = 50
/** Ce se şterge dintr-o listare a inbox-ului: fişiere (nu directoare) mai vechi de `days` zile
    faţă de `nowSec`, niciodată `keep` (cel tocmai urcat), cel mult RETENTION_BATCH pe rulare —
    best effort, cele mai vechi primele. `days <= 0` = nu se şterge nimic. */
export function selectExpired(entries: InboxEntry[], nowSec: number, days: number, keep?: string): string[] {
  if (!(days > 0)) return []
  const cutoff = nowSec - days * 86400
  return entries
    .filter((e) => !e.dir && e.name !== keep && e.mtime > 0 && e.mtime < cutoff)
    .sort((a, b) => a.mtime - b.mtime)
    .slice(0, RETENTION_BATCH)
    .map((e) => e.name)
}

// ── preferinţe (Settings → Preferences) ──────────────────────────────────────────────────
export const PASTE_DEST_KEY = 'wt_paste_dest'     // 'inbox' | 'cwd'
export const INBOX_DAYS_KEY = 'wt_inbox_days'     // număr întreg ≥ 0; 0 = păstrează
export type PasteDest = 'inbox' | 'cwd'
export const pasteDest = (): PasteDest => (lsGet(PASTE_DEST_KEY) === 'cwd' ? 'cwd' : 'inbox')
export const setPasteDest = (d: PasteDest) => lsSet(PASTE_DEST_KEY, d)
export function inboxDays(): number {
  const raw = lsGet(INBOX_DAYS_KEY)
  if (raw == null || raw === '') return 7
  const n = Number(raw)
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 7
}
export const setInboxDays = (n: number) => lsSet(INBOX_DAYS_KEY, String(Math.max(0, Math.floor(n) || 0)))

// ── feedback de paste/drop (toast-uri care EXPLICĂ ce s-a întâmplat) ────────────────────────
// Problema de UX pe care o rezolvă: singurul semn al unui paste era calea apărută la prompt, deci
// omul nu înţelegea că screenshot-ul lui a fost urcat în inbox. Logica de ALEGERE a mesajului
// (captură vs nume vs N fişiere; inbox vs directorul sesiunii; pornire vs final) stă aici, pură şi
// testată — componenta doar traduce şi afişează; textele propriu-zise trăiesc în catalog (i18n).

/** Ce „lucru lipit/tras" descriem într-un toast:
    - 1 fişier cu nume generic (captură de ecran) → `screenshot` (fără nume util de arătat);
    - 1 fişier cu nume                             → `file` (numele original, prietenos de citit);
    - N fişiere                                    → `files` (numărul). */
export interface PasteSubject { kind: 'screenshot' | 'file' | 'files'; name: string; count: number }
export function pasteSubject(files: { name: string }[]): PasteSubject {
  if (files.length === 1) {
    const name = files[0].name
    return { kind: isGenericName(name) ? 'screenshot' : 'file', name, count: 1 }
  }
  return { kind: 'files', name: files[0]?.name ?? '', count: files.length }
}

/** Cheia i18n a toastului, din fază + destinaţie + fel. Pură (testată); NU construieşte textul
    (ăla cere `t` şi pluralul subiectului) — doar alege formularea. La `done` separăm singular de
    plural fiindcă partea cu „calea/căile … Enter" nu se acordă altfel corect în română. */
export function pasteToastKey(phase: 'start' | 'done', dest: PasteDest, kind: PasteSubject['kind']): string {
  const d = dest === 'cwd' ? 'Cwd' : 'Inbox'
  if (phase === 'start') return `transfers.pasteStart${d}`
  return `transfers.pasteDone${d}${kind === 'files' ? 'Many' : 'One'}`
}

/** Fragmentul tradus care umple `{subject}`: captura → cuvântul tradus, un fişier → numele lui,
    N fişiere → „N fişiere" (cu pluralul corect al limbii). */
export function pasteSubjectText(s: PasteSubject, t: (k: string, v?: Record<string, string | number>) => string): string {
  if (s.kind === 'screenshot') return t('transfers.pasteSubjShot')
  if (s.kind === 'files') return t('transfers.pasteSubjMany', { count: s.count })
  return s.name
}

// Educaţie „o singură dată": la PRIMUL paste de captură, toastul de final capătă o propoziţie în
// plus care spune la ce foloseşte (predai un screenshot unui CLI). Memorat în localStorage.
export const PASTE_HINT_KEY = 'wt_paste_hint_seen'
export const pasteHintSeen = (): boolean => lsGet(PASTE_HINT_KEY) === '1'
export const markPasteHintSeen = (): void => lsSet(PASTE_HINT_KEY, '1')

// ── registrul ţintelor de inserare (sid → tastează în terminal) ───────────────────────────
// Job-ul trăieşte în motor, nu în componentă: când se termină, tab-ul care l-a pornit poate
// fi închis. Atunci NU tastăm nicăieri (ar ateriza în alt terminal, poate pe alt host) — rândul
// oferă „Copy path" în loc. SessionView se înscrie la montare şi se retrage la demontare.
export interface InsertTarget {
  /** trimite textul pe drumul unei taste; false = n-a trimis (doar-citire / mut / socket închis) */
  send: (text: string) => boolean | void
  /** aplicaţia din prim-plan a cerut bracketed paste (DECSET 2004) — xterm `modes.bracketedPasteMode` */
  bracketedPaste: () => boolean
  /** shell integration (OSC 133) spune că shell-ul aşteaptă la prompt (CommandTracker.atPrompt) */
  atPrompt?: () => boolean
  /** terminalul are focusul tastaturii (textarea-ul xterm) */
  hasFocus?: () => boolean
  /** ecranul alternativ e activ (nano, vim, emacs, mc, less, htop…) — 3.6.15 */
  altScreen?: () => boolean
}
const targets = new Map<string, InsertTarget>()
export function registerInsertTarget(sid: string, target: InsertTarget | null): void {
  if (target) targets.set(sid, target); else targets.delete(sid)
}
export const hasInsertTarget = (sid: string | undefined): boolean => !!sid && targets.has(sid)
/** Terminalul cu focus rulează o aplicaţie pe ecranul alternativ (review 3.6.15, L4)? Atunci o
    scurtătură globală pe Alt+literă (Alt+E) NU se declanşează: tasta e a aplicaţiei (nano M-E,
    emacs M-e…). La promptul shell-ului (ecranul normal) scurtătura rămâne. */
export function focusedTerminalInAltScreen(): boolean {
  for (const tg of targets.values()) {
    try { if (tg.hasFocus?.() && tg.altScreen?.()) return true } catch { /* terminal în demontare */ }
  }
  return false
}

/** Caractere care n-au ce căuta într-un text TASTAT în terminal: C0/C1, DEL, separatori de
    linie/paragraf, controale bidi şi zero-width. ESC lipseşte deci şi el: textul nu poate ieşi
    din parantezele de bracketed paste (`ESC[201~`). */
const UNSAFE_TYPED = new RegExp('[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u200b-\\u200f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]')
export const isSafeToType = (text: string): boolean => !!text && text.length <= 32768 && !UNSAFE_TYPED.test(text)

export type TypeOutcome = 'typed' | 'noTarget' | 'unsafe' | 'notPrompt' | 'refused'
const PASTE_START = '\x1b[200~'
const PASTE_END = '\x1b[201~'

/** Tastează `text` (FĂRĂ Enter) în terminalul `sid` prin ACELAŞI drum ca o tastă — deci aceleaşi
    porţi (doar-citire, mut, accesul la sesiune verificat din nou pe server).

    Doar la un PROMPT (3.6.9 review L2): ca taste simple, într-un program în mod raw (mc, vim,
    less, htop) fiecare literă ar fi o comandă a lui. Ştim că suntem la un prompt dacă:
      - programul din prim-plan a cerut bracketed paste (DECSET 2004 — bash, zsh, fish, readline
        o fac implicit): atunci tastăm ÎMPACHETAT în ESC[200~ … ESC[201~;
      - sau shell integration (OSC 133) arată shell-ul la prompt, fără comandă pornită (sub tmux
        DECSET 2004 nu ajunge la xterm, marcajele OSC 133 da): atunci tastăm textul simplu, ca o
        tastare la prompt.
    Altfel (program necunoscut în prim-plan) → 'notPrompt' şi apelantul oferă „Copy". Textul nu are
    caractere de control (deci nici ESC): nu poate închide parantezele mai devreme. */
export function typeIntoOutcome(sid: string | undefined, text: string): TypeOutcome {
  const t = sid ? targets.get(sid) : undefined
  if (!t) return 'noTarget'
  if (!isSafeToType(text)) return 'unsafe'
  let bracketed = false
  let prompt = false
  try { bracketed = t.bracketedPaste() === true } catch { bracketed = false }
  try { prompt = t.atPrompt?.() === true } catch { prompt = false }
  if (!bracketed && !prompt) return 'notPrompt'
  return t.send(bracketed ? PASTE_START + text + PASTE_END : text) === false ? 'refused' : 'typed'
}
export const typeInto = (sid: string | undefined, text: string): boolean => typeIntoOutcome(sid, text) === 'typed'
/** tastează `<cale citată> ` (spaţiu, FĂRĂ Enter) în terminalul `sid`; false dacă n-a tastat */
export function insertPathInto(sid: string | undefined, path: string): boolean {
  return typeInto(sid, shellQuote(path) + ' ')
}

// ── home-ul şi inbox-ul hostului ──────────────────────────────────────────────────────────
interface Listing { path: string; entries: InboxEntry[] }
const homes = new Map<number, string>()
/** home-ul absolut al userului agentului: listarea lui `~` întoarce calea rezolvată. Memorat
    per host pe durata paginii (nu se schimbă). */
export async function resolveHome(hostId: number): Promise<string> {
  const c = homes.get(hostId)
  if (c) return c
  const l = await api<Listing>(`/api/hosts/${hostId}/fs?path=${encodeURIComponent('~')}`)
  const home = l.path || '~'
  homes.set(hostId, home)
  return home
}

const inboxReady = new Set<number>()
/** `mkdir -p ~/.webterm/inbox` o singură dată per host per sesiune de pagină; întoarce calea
    ABSOLUTĂ a inbox-ului (cea care se inserează în terminal). */
export async function ensureInbox(hostId: number): Promise<string> {
  const home = await resolveHome(hostId)
  const dir = `${home.replace(/\/$/, '')}/${INBOX_REL}`
  if (!inboxReady.has(hostId)) {
    await api(`/api/hosts/${hostId}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: dir, parents: true }) })
    inboxReady.add(hostId)
  }
  return dir
}

/** Retenţia, aplicată oportunist după un upload reuşit în inbox: listăm, ştergem ce a expirat
    (plafon RETENTION_BATCH), ignorăm orice eroare — e curăţenie, nu o garanţie. Nu există
    cron pe host pentru asta (fără schimbări în agent), deci rulează doar cât foloseşti funcţia. */
export async function pruneInbox(hostId: number, dir: string, keepName: string): Promise<number> {
  const days = inboxDays()
  if (days <= 0) return 0
  try {
    const l = await api<Listing>(`/api/hosts/${hostId}/fs?path=${encodeURIComponent(dir)}`)
    const names = selectExpired(l.entries ?? [], Date.now() / 1000, days, keepName)
    let n = 0
    for (const name of names) {
      try {
        await api(`/api/hosts/${hostId}/fs/delete`, { method: 'POST', body: JSON.stringify({ path: `${dir}/${name}`, recursive: false }) })
        n++
      } catch { /* altcineva l-a şters / permisiuni: mergem mai departe */ }
    }
    return n
  } catch { return 0 }
}
