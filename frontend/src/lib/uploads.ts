/* Motorul de upload resumabil — INDEPENDENT de orice componentă React.

   Protocolul (neschimbat faţă de FilePanel, de unde a fost extras): felii de 8 MiB trimise cu
   `POST /api/hosts/{id}/fs/upload?upload_id&offset` (gateway → agent `fs_write` adaugă în
   `<dest>.wtpart.<upload_id>`), `GET …/upload/status` întoarce offset-ul aterizat, `POST …/commit`
   face rename-ul atomic (cu CRC-32 când tot fişierul a trecut prin sesiunea asta), `DELETE` şterge
   temp-ul. 409 = offset desincronizat, 403 = fereastra de step-up a expirat — ambele re-sincronizează
   prin sonda de status (care redeschide prompt-ul de passkey prin `withStepup`).

   De ce a ieşit din componentă (incidentul din 2026-10-04): un drop de 17 GB a mers ~24 MB/s până
   la felia 1579, apoi browserul a încetat să trimită (uplink / sleep) — gateway şi agent sănătoşi.
   XHR-ul avea timeout de 300 s şi 5 reîncercări cu backoff, deci o conexiune atârnată stătea tăcută
   minute în şir; singurul feedback era rândul din panoul de fişiere (închizibil) şi un toast de 6 s.
   Acum: watchdog pe octeţi (20 s → `stalled` vizibil, 60 s → abort + reîncercare), reîncercări
   limitate cu backoff, `Retry` manual care reintră de la offset-ul real, reluare automată la
   `online`/`visibilitychange`, metadate în localStorage ca un reload să arate job-ul ca „orfan"
   (re-tragi fişierul şi continuă), şi o bară globală (JobsBar) vizibilă pe orice ecran. */
import { api, ApiError, apiErrorFrom, errText, withStepup } from './api'
import { crc32 } from './crc'
import { tStatic } from './i18n'
import { lsGet, lsRemove, lsSet } from './storage'
import { insertPathOutcome, type PasteContext } from './transfers'
import { UploadJob, isActive, uploadStore } from './uploadStore'

// ── parametri ─────────────────────────────────────────────────────────────────────────────
/** Felie de PORNIRE: 8 MiB. Mărimea se ADAPTEAZĂ apoi între UP_CHUNK_MIN şi UP_CHUNK_MAX (vezi
    nextChunkSize). Serverul verifică offset-ul; dacă e desincronizat (retry care a aterizat deja,
    două tab-uri) răspunde 409, iar clientul reia bucla de la offset-ul real. */
export const UP_CHUNK = 8 * 1024 * 1024
/** Felie adaptivă: 2–16 MiB. Pe o legătură rapidă felii mari = mai puţine round-trip-uri; pe una
    instabilă felii mici = retry-uri ieftine. Gateway-ul re-taie oricum fiecare felie în blocuri de
    1 MiB spre agent, deci mărimea HTTP a feliei NU e mărginită de plafonul de frame (16 MiB) — e
    mărginită doar de memoria ferestrei de reordonare de pe gateway (UP_WINDOW × max). */
export const UP_CHUNK_MIN = 2 * 1024 * 1024
export const UP_CHUNK_MAX = 16 * 1024 * 1024
/** Câte felii trimite clientul CONCURENT (pipelining peste HTTP, ca să ascundă RTT-ul pe legături
    cu latenţă mare). Aliniat cu WINDOW_K de pe gateway: cele K corpuri urcă în paralel, iar
    gateway-ul le aplică la agent STRICT în ordinea offset-ului (fereastră de reordonare). */
export const UP_WINDOW = 3
/** Ţinta de durată per felie (ms): sub LO creştem felia, peste HI (sau la instabilitate) o scădem. */
const CHUNK_TARGET_LO_MS = 2500
const CHUNK_TARGET_HI_MS = 9000

/** Mărimea feliei URMĂTOARE, din durata măsurată a celei curente şi dacă legătura a fost instabilă
    (stall/retry în timpul ei). Pură (testată în uploads.test.ts). */
export function nextChunkSize(current: number, lastMs: number, unstable: boolean): number {
  const clamp = (n: number) => Math.max(UP_CHUNK_MIN, Math.min(UP_CHUNK_MAX, Math.round(n)))
  if (unstable || lastMs > CHUNK_TARGET_HI_MS) return clamp(current / 2)
  if (lastMs > 0 && lastMs < CHUNK_TARGET_LO_MS) return clamp(current * 2)
  return clamp(current)
}
/** fără octeţi noi timp de 20 s → `stalled` (doar vizibil; XHR-ul rămâne în zbor) */
export const STALL_WARN_MS = 20_000
/** 60 s fără octeţi → abort + reîncercare IMEDIATĂ a feliei (se numără ca încercare) */
export const STALL_ABORT_MS = 60_000
/** încercări per felie înainte de `err` (controlerul şi File-ul rămân pentru Retry manual) */
export const MAX_ATTEMPTS = 8
/** backoff exponenţial 1,2,4,8,15,15… s — plafonat: după al 5-lea eşec nu mai câştigi nimic
    aşteptând mai mult, doar pierzi fereastra în care legătura şi-a revenit */
export const BACKOFF_CAP_MS = 15_000
export const backoffMs = (attempt: number) => Math.min(BACKOFF_CAP_MS, 1000 * 2 ** (Math.max(1, attempt) - 1))
/** rândul „done" dispare singur după un timp — store-ul e global, altfel s-ar aduna la infinit */
const DONE_LINGER_MS = 20_000
const UID_RE = /^[0-9a-f]{16,64}$/

// ── semnale interne ───────────────────────────────────────────────────────────────────────
class ResyncSignal { constructor(readonly offset: number) {} }
/** XHR-ul a fost oprit de watchdog (sau de un `kick` manual): se reia fără backoff */
class StallAbort extends Error { constructor() { super('stall') } }
/** Gateway-ul a răspuns 429: fereastra de reordonare e plină (am trimis prea multe felii înaintea
    rândului lor). Nu e eroare — backpressure: aşteptăm scurt şi reîncercăm ACEEAŞI felie. */
class BusySignal extends Error { constructor() { super('busy') } }
/** Pauză manuală: bucla iese curat, păstrând File-ul + offset-ul; Resume reintră din `status`. */
class PausedSignal extends Error { constructor() { super('paused') } }
/** 401 generic: sesiunea web a expirat. Nu se reîncearcă singur — după login, omul apasă Retry. */
class AuthLost extends Error { constructor() { super('unauth') } }

// ── CRC-32 ────────────────────────────────────────────────────────────────────────────────
// CRC-32 (IEEE), incremental — IDENTIC cu `zlib.crc32(bytes, prev)` din agent. Trăieşte în
// ./crc.ts ca să-l poată importa şi crcWorker.ts fără tot motorul; re-exportat aici fiindcă
// uploads.test.ts (şi alţi importatori) îl iau din `./uploads`.
export { crc32 }

// FS-09: CRC-ul feliei (2–16 MiB, buclă byte-cu-byte) se mută de pe firul principal într-un Web
// Worker. Worker-ul e fără stare — CRC-ul cumulativ rămâne aici şi se dă ca `prev`, deci ordinea
// feliilor e păstrată de apelant (aşteaptă fiecare răspuns). Buffer-ul e TRANSFERAT dus-întors
// (zero-copy): după CRC se întoarce ca să poată fi trimis la upload. Un singur worker, leneş,
// reutilizat; dacă Worker lipseşte (vitest/node, browser fără suport) sau crearea eşuează, cădem
// pe CRC sincron pe firul principal — corectitudinea e aceeaşi peste tot.
let crcWorker: Worker | null = null
let crcWorkerDead = false
let crcSeq = 0
const crcPending = new Map<number, (crc: { crc: number; buf: ArrayBuffer }) => void>()

function ensureCrcWorker(): Worker | null {
  if (crcWorker || crcWorkerDead) return crcWorker
  if (typeof Worker === 'undefined') { crcWorkerDead = true; return null }
  try {
    const w = new Worker(new URL('./crcWorker.ts', import.meta.url), { type: 'module' })
    w.onmessage = (e: MessageEvent<{ id: number; crc: number; buf: ArrayBuffer }>) => {
      const cb = crcPending.get(e.data.id)
      if (cb) { crcPending.delete(e.data.id); cb({ crc: e.data.crc, buf: e.data.buf }) }
    }
    w.onerror = () => {            // worker rupt (CSP, build) → sincron de aici înainte
      crcWorkerDead = true
      try { w.terminate() } catch { /* ignore */ }
      crcWorker = null
    }
    crcWorker = w
    return w
  } catch { crcWorkerDead = true; return null }
}

/** CRC-ul cumulativ după felia `buf`, calculat în worker când se poate; întoarce ŞI buffer-ul
    (transferat înapoi) ca apelantul să-l trimită mai departe la upload. */
async function crcChunk(prev: number, buf: ArrayBuffer): Promise<{ crc: number; buf: ArrayBuffer }> {
  const w = ensureCrcWorker()
  if (!w) return { crc: crc32(prev, new Uint8Array(buf)), buf }
  const id = ++crcSeq
  try {
    return await new Promise<{ crc: number; buf: ArrayBuffer }>((resolve, reject) => {
      crcPending.set(id, resolve)
      try { w.postMessage({ id, prev, buf }, [buf]) }
      catch (e) { crcPending.delete(id); reject(e) }
    })
  } catch {                       // transfer/worker eşuat: buffer-ul e încă al nostru → sincron
    crcWorkerDead = true
    return { crc: crc32(prev, new Uint8Array(buf)), buf }
  }
}

// ── funcţii pure (testate în uploads.test.ts) ─────────────────────────────────────────────

/** Decizia după un 409/403 re-sincronizat: serverul spune că are `offset` octeţi.
    - `landed`: felia a aterizat, doar răspunsul s-a pierdut → mergem mai departe;
    - `retry`: nimic nou aterizat → refacem ACEEAŞI felie, CRC-ul incremental rămâne valid;
    - `jump`: aterizare parţială / alt scriitor → sărim la offset-ul real; CRC-ul nu mai poate
      fi corect (prefixul n-a trecut prin noi) → commit fără verificare. */
export function resolveResync(pos: number, end: number, offset: number):
  { action: 'landed' | 'retry' | 'jump'; pos: number } {
  if (offset === end) return { action: 'landed', pos: end }
  if (offset === pos) return { action: 'retry', pos }
  return { action: 'jump', pos: offset }
}

/** Viteză netezită (EWMA pe eşantioane de ≥1 s) + ETA. Pe o legătură cu rafale, viteza
    instantanee a unui tick `onprogress` sare între 0 şi 100 MB/s; o medie exponenţială (70/30)
    dă un număr pe care îl poţi citi fără să clipească. */
export function speedTracker(alpha = 0.3) {
  // `anchored` explicit, nu `lastAt === 0`: un timestamp 0 e legitim (testele, performance.now)
  let anchored = false, lastAt = 0, lastBytes = 0, rate = 0
  return {
    /** întoarce viteza curentă (B/s) după ce înregistrează `bytes` totali la momentul `now` */
    sample(bytes: number, now: number): number {
      if (!anchored || bytes < lastBytes) { anchored = true; lastAt = now; lastBytes = bytes; return rate }
      const dt = now - lastAt
      if (dt < 1000) return rate
      const inst = ((bytes - lastBytes) * 1000) / dt
      rate = rate ? rate * (1 - alpha) + inst * alpha : inst
      lastAt = now; lastBytes = bytes
      return rate
    },
    /** nimic nu s-a mişcat (stalled): viteza cade la 0, iar următorul eşantion porneşte curat */
    reset(): void { anchored = false; lastAt = 0; lastBytes = 0; rate = 0 },
    get rate(): number { return rate },
  }
}
export const etaSec = (size: number, pos: number, bytesPerSec: number): number | null =>
  bytesPerSec > 0 ? Math.max(0, Math.round((size - pos) / bytesPerSec)) : null

// ── metadate persistate ───────────────────────────────────────────────────────────────────
/** Ce rămâne în localStorage despre un upload neterminat. Înainte valoarea era doar upload_id-ul
    (string hex) — suficient ca un re-drop să reia, dar insuficient ca după un reload să ŞTIM că
    există un transfer neterminat (fără File nu putem relua, dar putem arăta). */
export interface UploadMeta {
  uid: string
  hostId: number
  hostName: string
  dest: string
  name: string
  size: number
  lastModified: number
  pos: number
  updated: number
}

export const LS_PREFIX = 'wt_up_'
// upload_id STABIL per (cont, host, cale, fișier): persistat în localStorage, ca un reload de pagină
// să poată relua același upload (browserul nu re-citește fișierul singur — re-selectezi același
// fișier și reia de unde a rămas, exact ca protocolul tus).
// 3.5.18: cheia poartă user id-ul (`wt_up_u<uid>_…`), ca la download-uri (dlresume.ts): alt cont în
// acelaşi browser nu vede (şi nu poate „relua" peste) upload-urile altcuiva, iar logout-ul explicit
// le uită. Cheile VECHI, fără cont (`wt_up_<host>_…`), nu au proprietar sigur → se şterg la pornire.
export const upLsKey = (userId: number, hostId: number, dest: string, size: number, lastModified: number) =>
  `${LS_PREFIX}u${userId}_${hostId}_${dest}_${size}_${lastModified}`

/** Inversa lui `upLsKey`. `dest` poate conţine `_`, de aceea tăiem de la capete, nu cu split.
    O cheie în formatul vechi (fără `u<uid>_`) → null (vezi isLegacyUpKey). */
export function parseUpLsKey(key: string): { userId: number; hostId: number; dest: string; size: number; lastModified: number } | null {
  if (!key.startsWith(LS_PREFIX)) return null
  const rest = key.slice(LS_PREFIX.length)
  const m = rest.match(/^u(\d+)_(\d+)_(.*)_(\d+)_(\d+)$/)
  if (!m) return null
  return { userId: Number(m[1]), hostId: Number(m[2]), dest: m[3], size: Number(m[4]), lastModified: Number(m[5]) }
}

/** Cheie `wt_up_*` care NU e în formatul cheiat pe cont (dinainte de 3.5.18, sau stricată). */
export const isLegacyUpKey = (key: string): boolean => key.startsWith(LS_PREFIX) && parseUpLsKey(key) == null

/** Împarte cheile `wt_up_*` după proprietar: ale contului curent (de arătat), vechi/fără cont (de
    şters), ale altor conturi (neatinse — revin la login-ul lor). */
export function classifyUpKeys(keys: string[], userId: number): { mine: string[]; legacy: string[]; others: string[] } {
  const out = { mine: [] as string[], legacy: [] as string[], others: [] as string[] }
  for (const k of keys) {
    if (!k.startsWith(LS_PREFIX)) continue
    const p = parseUpLsKey(k)
    if (!p) out.legacy.push(k)
    else if (p.userId === userId) out.mine.push(k)
    else out.others.push(k)
  }
  return out
}

function lsKeysWithPrefix(prefix: string): string[] {
  const keys: string[] = []
  try {
    const ls = window.localStorage
    for (let i = 0; i < ls.length; i++) {
      const k = ls.key(i)
      if (k && k.startsWith(prefix)) keys.push(k)
    }
  } catch { return [] }
  return keys
}

/** Valoarea din localStorage → metadate. Compatibil înapoi: un uid simplu (format vechi) devine
    metadate reconstruite din cheie, cu `pos` necunoscut (0) şi fără nume de host. */
export function parseUploadMeta(raw: string | null, key: string): UploadMeta | null {
  if (!raw) return null
  if (UID_RE.test(raw)) {
    const k = parseUpLsKey(key)
    if (!k) return null
    return { uid: raw, hostId: k.hostId, hostName: '', dest: k.dest, size: k.size,
             lastModified: k.lastModified, name: baseName(k.dest), pos: 0, updated: 0 }
  }
  try {
    const m = JSON.parse(raw)
    if (!m || typeof m !== 'object' || !UID_RE.test(String(m.uid))) return null
    return {
      uid: String(m.uid), hostId: Number(m.hostId) || 0, hostName: String(m.hostName ?? ''),
      dest: String(m.dest ?? ''), name: String(m.name ?? '') || baseName(String(m.dest ?? '')),
      size: Number(m.size) || 0, lastModified: Number(m.lastModified) || 0,
      pos: Number(m.pos) || 0, updated: Number(m.updated) || 0,
    }
  } catch { return null }
}

export const baseName = (p: string) => p.slice(p.lastIndexOf('/') + 1) || p
export const dirName = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) || '/' : '.')

// ── formatare ─────────────────────────────────────────────────────────────────────────────
export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}
export const fmtRate = (bps: number) => `${fmtBytes(Math.max(0, bps))}/s`
/** ETA compact cu unităţile din catalog (`time.s/m/h`), ca restul duratelor din UI */
export function fmtEta(sec: number | null, t: (k: string) => string): string {
  if (sec == null) return '—'
  if (sec < 60) return `${sec}${t('time.s')}`
  if (sec < 3600) return `${Math.round(sec / 60)}${t('time.m')}`
  return `${Math.floor(sec / 3600)}${t('time.h')} ${Math.round((sec % 3600) / 60)}${t('time.m')}`
}

// ── controlere (în memorie; File-ul NU se poate persista) ─────────────────────────────────
interface Ctl {
  id: string
  hostId: number
  hostName: string
  dest: string
  name: string
  /** cheia din localStorage; null = contul nu e (încă) cunoscut → nu persistăm nimic */
  lsKey: string | null
  /** contul care a pornit upload-ul (null = necunoscut) */
  owner: number | null
  file: File | null            // null = orfan (după reload): ştim că există, nu-l putem relua
  xhrs: Set<XMLHttpRequest>    // feliile în zbor (pipelining: până la UP_WINDOW concurente)
  cancelled: boolean
  paused: boolean              // pauză manuală: bucla iese păstrând File-ul; Resume reintră
  running: boolean             // bucla e în execuţie — a doua intrare e refuzată
  authLost: boolean            // ultima eroare a fost 401: nu se reia automat
  size: number
  lastModified: number
  /** ce se întâmplă după commit (drop pe terminal / paste): calea se tastează în terminalul
      `sid`, dacă acel tab mai e deschis — vezi lib/transfers.ts */
  then?: 'insert-path'
  sid?: string
  /** 3.6.16: upload pornit de un paste / drop pe terminal — calea se tastează ca un paste cât
      contextul gestului e acelaşi (transfers.ts typeIntoPasted); altfel regulile vechi */
  pasteCtx?: PasteContext
}
const ctls = new Map<string, Ctl>()

const tr = (k: string, vars?: Record<string, string | number>) => {
  let s = tStatic(k)
  if (vars) for (const [kk, v] of Object.entries(vars)) s = s.split('{' + kk + '}').join(String(v))
  return s
}

function newUid(): string {
  // exact 32 hex lowercase — formatul pe care GC-ul de pe server îl recunoaşte strict
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('')
}

// ── contul curent ─────────────────────────────────────────────────────────────────────────
let currentUser: number | null = null
/** App-ul o setează din `/api/state.user_id` (acelaşi tipar ca setDownloadUser). Rândurile din
    memorie ale ALTUI cont (err/done/paused rămase de la o sesiune expirată pe acelaşi browser) se
    uită aici, nu doar la logout-ul explicit — altfel contul următor le vedea, cu `Retry` activ sub
    cookie-ul lui (audit 2026-10-17, FL-06). Cheile lor din localStorage rămân (sunt per cont). */
export function setUploadUser(id: number | null): void {
  currentUser = id
  dropRows(id)
}

/** Scoate din memorie (controlere + rânduri din store) upload-urile care NU sunt ale contului
    `keep` (null = toate): feliile în zbor se taie, File-ul se eliberează. NU atinge localStorage
    (cheile revin la login-ul proprietarului, ca orfani) şi NU cere ştergerea temp-urilor de pe host
    (sesiunea proprietarului nu mai e; le ia GC-ul de pe server). Rândurile de download/copy sunt
    ale altor module (downloads.ts, copyjobs.ts) şi rămân. */
function dropRows(keep: number | null): void {
  for (const [id, c] of ctls) {
    if (keep != null && c.owner === keep) continue
    c.cancelled = true
    abortInflight(c, 'cancel')
    ctls.delete(id)
    uploadStore.remove(id)
  }
  for (const j of uploadStore.snapshot().values()) {
    if (j.dir && j.dir !== 'up') continue
    if (keep != null && j.owner === keep) continue
    uploadStore.remove(j.id)
  }
}

function writeMeta(c: Ctl, pos: number) {
  if (!c.lsKey || c.owner == null || c.owner !== currentUser) return
  const m: UploadMeta = { uid: c.id, hostId: c.hostId, hostName: c.hostName, dest: c.dest, name: c.name,
                          size: c.size, lastModified: c.lastModified, pos, updated: Date.now() }
  lsSet(c.lsKey, JSON.stringify(m))
}

/** un rând terminat dispare singur după DONE_LINGER_MS (dacă e tot `done`) — şi după un
    „Type into terminal" reuşit (review hotfix 3.6.13, L4) */
export function lingerDone(id: string): void {
  window.setTimeout(() => {
    if (uploadStore.get(id)?.state === 'done') uploadStore.remove(id)
  }, DONE_LINGER_MS)
}

function publish(c: Ctl, p: Partial<UploadJob>) {
  const cur = uploadStore.get(c.id)
  if (cur) { uploadStore.patch(c.id, p); return }
  // rândul lipseşte pentru că a fost SCOS (cancel / dropRows la schimbarea contului) cât un await
  // fără XHR (sonda de status, commit-ul) era în zbor: nu-l re-creăm — ar rămâne o „fantomă" a
  // contului A în faţa contului B. Pe calea `done` controlerul e încă în hartă, iar `cancelled`
  // e fals, deci rândul final se publică normal.
  if (c.cancelled || !ctls.has(c.id)) return
  uploadStore.set({
    id: c.id, hostId: c.hostId, hostName: c.hostName, dest: c.dest, name: c.name, size: c.size,
    pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running', attempts: 1, then: c.then, sid: c.sid,
    owner: c.owner, ...p,
  })
}

/** Coduri de eroare pe care o reîncercare NU le schimbă (gateway: _file_api_error/_fs_write_error). */
export const DEFINITIVE_CODES = new Set([
  'files.writeDenied', 'files.writeDeniedMode', 'files.permissionDenied', 'files.readOnly',
  'files.readOnlyAt', 'files.noSpace', 'files.noSpaceAt', 'files.dirMissing', 'files.notFound',
  'files.isDirectory', 'files.notDirectory', 'files.agentInternal', 'files.notRegular',
])
export const isDefinitiveError = (e: unknown): boolean =>
  e instanceof ApiError && e.status >= 400 && e.status < 500 && DEFINITIVE_CODES.has(e.code)
/** Dintre refuzurile definitive, singurele după care pe host RĂMÂNE un temp parţial care merită
    reluat (după ce se face loc): disc plin. La permisiuni / dosar lipsă / FS doar-citire nu s-a
    scris nimic şi un re-drop ar primi acelaşi răspuns. */
export const KEEP_TEMP_CODES = new Set(['files.noSpace', 'files.noSpaceAt'])
export const keepsTempOnError = (e: unknown): boolean => e instanceof ApiError && KEEP_TEMP_CODES.has(e.code)

/** Decizia DOAR pentru cheia din localStorage (FS-01): după eroarea `e` mai are rost să ţinem cheia
    (= să înviem rândul după reload ca orfan, ca un re-drop să reia temp-ul)?
    - refuz definitiv al hostului FĂRĂ nimic aterizat (`landed` = 0) → nu (excepţie: disc plin,
      temp-ul parţial merită reluat). Dacă au aterizat deja felii (`landed` > 0) şi refuzul a venit
      după ele — `files.agentInternal` la o felie târzie, `files.readOnlyAt` după un remount —, pe
      host EXISTĂ un temp care merită reluat: cheia rămâne (audit 2026-10-17 P1, critica FS-01);
    - 403 / 404 cu un cod care NU e în lista definitivă (rolul a pierdut `files.write` pe host în
      timpul sesiunii, hostul a dispărut): reîncercările rămân cum sunt, dar dacă NU a aterizat nimic
      — nici în trecerea asta (`landed` = 0), nici într-una anterioară (pos-ul din cheie = 0) — nu
      există temp de reluat şi cheia ar învia doar un „orfan 0 %". Un temp parţial din altă sesiune
      (pos > 0 în cheie) rămâne reluabil chiar dacă sonda de status a picat şi am pornit de la 0.
    401 (sesiune expirată), 409 (resync) şi 429 (backpressure) nu ajung aici ca refuz. */
export function refusedForGood(e: unknown, landed: number, lsKey: string): boolean {
  if (isDefinitiveError(e)) return !keepsTempOnError(e) && landed === 0
  if (!(e instanceof ApiError) || !(e.status === 403 || e.status === 404)) return false
  if (landed > 0) return false
  const m = parseUploadMeta(lsGet(lsKey), lsKey)
  return (m?.pos ?? 0) === 0
}

const isAuthErr = (e: unknown) => e instanceof AuthLost || (e instanceof ApiError && e.status === 401)

function errorText(e: unknown): string {
  if (isAuthErr(e)) return tr('jobs.signInAgain')
  if (e instanceof StallAbort) return tr('jobs.errStall')
  if (e instanceof Error) {
    if (e.message === 'network') return tr('jobs.errNetwork')
    if (e.message === 'timeout') return tr('jobs.errTimeout')
    if (e.message === 'resync') return tr('jobs.errResync')
    if (/^\d{3}$/.test(e.message)) return tr('jobs.errHttp', { code: e.message })
  }
  return errText(e, tr) || tr('files.genericErr')
}

// ── bucla propriu-zisă ────────────────────────────────────────────────────────────────────
// Un fișier, resumabil + verificat, PIPELINED: taie în felii ADAPTIVE (2–16 MiB) şi trimite până la
// UP_WINDOW (3) felii CONCURENT, ca să ascundă RTT-ul pe legături cu latenţă mare (corpurile urcă în
// paralel browser→gateway). Gateway-ul le aplică la agent STRICT în ordinea offset-ului (fereastră de
// reordonare), deci agentul vede tot o secvenţă append-only şi CRC-ul lui incremental rămâne corect.
// CRC-ul CLIENTULUI se acumulează în ORDINEA fişierului, o singură dată per felie, la DISPATCH (citirea
// e secvenţială) — un retry re-trimite aceiaşi octeţi, dar gateway-ul tratează o felie deja aterizată
// idempotent (nu o rescrie), deci nu se dublează nimic. La cădere reia de la octetul aterizat
// (retry+backoff per felie; 409 = re-sincronizare din status; 429 = backpressure, aşteptăm scurt).
// Pauză: se opreşte trimiterea, File-ul + offset-ul rămân; Resume reintră din status.
async function runLoop(c: Ctl): Promise<void> {
  const file = c.file
  if (!file || c.running) return
  c.running = true
  c.cancelled = false
  c.paused = false
  c.authLost = false
  const hid = c.hostId
  const q = `path=${encodeURIComponent(c.dest)}&upload_id=${c.id}`
  const speed = speedTracker()

  // Progresul e stare GLOBALĂ (uploadStore) şi re-randează la fiecare scriere; cu pipelining mai
  // multe felii raportează `onprogress` deodată → publicăm cel mult ~10/s şi doar la schimbare de
  // procent (sau o dată pe secundă, ca viteza/ETA să respire). `pos` = offset-ul contiguu aterizat
  // (`landedMax`) + octeţii în zbor ai feliilor curente, ca bara să urce lin, nu în trepte de felie.
  let landedMax = 0
  const inflightLoaded = new Map<number, number>()
  let lastPos = 0, shownPct = -1, shownAt = 0
  const curPos = () => landedMax + [...inflightLoaded.values()].reduce((a, b) => a + b, 0)
  const setPos = (force = false, state: UploadJob['state'] = 'running') => {
    const bytes = Math.min(file.size, curPos())
    lastPos = bytes
    const pct = file.size ? Math.round((bytes / file.size) * 100) : 100
    const now = Date.now()
    const bps = speed.sample(bytes, now)
    if (!force && ((pct === shownPct && now - shownAt < 1000) || now - shownAt < 100)) return
    shownPct = pct; shownAt = now
    publish(c, { pos: bytes, pct, bytesPerSec: bps, etaSec: etaSec(file.size, bytes, bps), state })
  }

  // O felie, cu retry/backoff/stall/429 ÎN INTERIOR. Întoarce { offset: offsetul contiguu raportat de
  // server, unstable: a avut stall/retry }. Aruncă AuthLost / ResyncSignal / Error la eşec definitiv.
  const sendOneChunk = (off: number, body: ArrayBuffer): Promise<{ offset: number; unstable: boolean }> =>
    new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      c.xhrs.add(xhr)
      let lastByteAt = Date.now()
      let stalled = false
      const reason = { why: '' as '' | 'stall' | 'pause' | 'cancel' }
      ;(xhr as unknown as { _wt: typeof reason })._wt = reason
      const tick = window.setInterval(() => {
        const idle = Date.now() - lastByteAt
        if (idle >= STALL_ABORT_MS) { window.clearInterval(tick); reason.why = 'stall'; xhr.abort() }
        else if (idle >= STALL_WARN_MS && !stalled) {
          stalled = true; speed.reset()
          publish(c, { state: 'stalled', bytesPerSec: 0, etaSec: null })
        }
      }, 5000)
      const done = () => { window.clearInterval(tick); c.xhrs.delete(xhr); inflightLoaded.delete(off) }
      xhr.open('POST', `/api/hosts/${hid}/fs/upload?${q}&offset=${off}`)
      xhr.upload.onprogress = (ev) => {
        if (!ev.lengthComputable) return
        lastByteAt = Date.now()
        inflightLoaded.set(off, ev.loaded)
        if (stalled) { stalled = false; setPos(true) } else setPos()
      }
      xhr.onload = async () => {
        done()
        if (xhr.status >= 200 && xhr.status < 300) {
          let srvOff = off + body.byteLength
          try { const r = JSON.parse(xhr.responseText); if (typeof r.offset === 'number') srvOff = r.offset } catch { /* corp ne-JSON */ }
          resolve({ offset: srvOff, unstable: stalled }); return
        }
        if (xhr.status === 401) { reject(new AuthLost()); return }
        if (xhr.status === 429) { reject(new BusySignal()); return }   // fereastra de reordonare plină
        // 409: offset desincronizat. 403: fereastra de step-up a expirat în mijlocul unui upload lung.
        // Sonda de status prin withStepup redeschide prompt-ul de passkey, apoi reluăm de la offset-ul real.
        if (xhr.status === 409 || xhr.status === 403) {
          try {
            const st = await withStepup(hid, () => api<{ offset: number }>(`/api/hosts/${hid}/fs/upload/status?${q}`))
            reject(new ResyncSignal(Math.min(st.offset || 0, file.size)))
          } catch (e) { reject(e) }
          return
        }
        // corp JSON cu cod (gateway/app/errors.py): eroarea reală, tradusă — „agentul rulează ca
        // webterm şi nu poate scrie în /srv/bin/lists" —, nu „Server answered 400" (3.6.9)
        const ae = apiErrorFrom(xhr.status, xhr.responseText || '', xhr.getResponseHeader('X-WebTerm-Error'))
        reject(ae.code ? ae : new Error(String(xhr.status)))
      }
      xhr.onerror = () => { done(); reject(new Error('network')) }
      xhr.ontimeout = () => { done(); reject(new Error('timeout')) }
      xhr.onabort = () => {
        done()
        if (reason.why === 'stall') reject(new StallAbort())
        else if (c.cancelled || reason.why === 'cancel') reject(new Error('abort'))
        else reject(new PausedSignal())           // pauză (sau abort la pauză): iese curat
      }
      xhr.timeout = 300_000
      // Pauza/anularea apăsate cât citeam felia (arrayBuffer + CRC) nu prindeau XHR-ul ăsta în
      // `c.xhrs`: abortInflight rula înainte să existe, deci felia pleca oricum şi pauza se aplica
      // abia după ce rafala se termina. Pe un runner lent (CI) fereastra era destul de mare ca
      // pauza să întârzie zeci de secunde (3.5.3). Verificăm chiar înainte de trimitere.
      if (c.paused || c.cancelled) {
        done()
        reject(c.cancelled ? new Error('abort') : new PausedSignal())
        return
      }
      xhr.send(body)
    })

  // retry per felie: întoarce rezultatul, sau aruncă definitiv (după MAX_ATTEMPTS) / semnalele speciale
  const sendWithRetry = async (off: number, body: ArrayBuffer): Promise<{ offset: number; unstable: boolean }> => {
    let tries = 0, unstable = false
    for (;;) {
      try { const r = await sendOneChunk(off, body); return { offset: r.offset, unstable: unstable || r.unstable } }
      catch (e) {
        if (c.cancelled || c.paused) throw e
        if (isAuthErr(e) || e instanceof ResyncSignal) throw e
        // refuz DEFINITIV de pe host (permisiuni, FS doar-citire, disc plin, dosar inexistent): o
        // reîncercare dă acelaşi răspuns — 8 încercări cu backoff însemnau un minut de „retrying"
        // înainte de eroare. Ieşim imediat, cu mesajul clar.
        if (isDefinitiveError(e)) throw e
        unstable = true
        if (e instanceof BusySignal) {   // backpressure: aşteptăm scurt, NU numărăm ca eşec dur
          await new Promise((r) => setTimeout(r, 500))
          if (c.cancelled || c.paused) throw e
          continue
        }
        if (++tries >= MAX_ATTEMPTS) throw e
        publish(c, { state: 'retrying', attempts: tries + 1, bytesPerSec: 0, etaSec: null })
        speed.reset()
        if (!(e instanceof StallAbort)) await new Promise((r) => setTimeout(r, backoffMs(tries)))
        if (c.cancelled || c.paused) throw e
        publish(c, { state: 'running' })
      }
    }
  }

  try {
    // Seed din status: offset aterizat + CRC-ul octeţilor deja pe disc (agent v55). Cu CRC-ul putem
    // continua verificarea şi după un resume; fără el (agent vechi) cădem pe regula veche (doar din 0).
    let offset = 0
    let resumeCrc: number | undefined
    try {
      const st = await withStepup(hid, () => api<{ offset: number; crc32?: number }>(`/api/hosts/${hid}/fs/upload/status?${q}`))
      offset = Math.min(st.offset || 0, file.size)
      if (typeof st.crc32 === 'number') resumeCrc = st.crc32 >>> 0
    } catch (e) {
      if (isAuthErr(e)) throw e
      offset = 0
    }
    // sonda poate sta pe un prompt de passkey: între timp rândul a putut fi scos (cancel, cont
    // schimbat) — nu-l re-publicăm ca „running" pentru un controler care nu mai există
    if (c.cancelled) return
    let doCrc = offset === 0 || resumeCrc !== undefined
    let crc = offset === 0 ? 0 : (resumeCrc ?? 0)
    let dispatchPos = offset
    landedMax = offset
    let chunkSize = UP_CHUNK
    let resyncs = 0
    publish(c, { state: 'running', attempts: 1, error: undefined })
    setPos(true)

    // fişier de 0 octeţi: o felie goală la offset 0 (creează temp-ul gol), fără pipelining
    if (file.size === 0) {
      if (offset === 0) await sendWithRetry(0, new ArrayBuffer(0))
    }

    while (dispatchPos < file.size) {
      if (c.cancelled) return
      if (c.paused) throw new PausedSignal()
      // construim o rafală de până la UP_WINDOW felii concurente (citirea e secvenţială → CRC în ordine)
      const burst: Array<{ start: number; end: number; buf: ArrayBuffer }> = []
      for (let k = 0; k < UP_WINDOW && dispatchPos < file.size; k++) {
        const start = dispatchPos
        const end = Math.min(start + chunkSize, file.size)
        let buf = await file.slice(start, end).arrayBuffer()
        // ordinea fişierului, o singură dată per felie; CRC-ul pleacă în worker (FS-09), care dă
        // buffer-ul înapoi ca să-l putem trimite la upload
        if (doCrc) { const r = await crcChunk(crc, buf); crc = r.crc; buf = r.buf }
        dispatchPos = end
        burst.push({ start, end, buf })
        if (c.paused || c.cancelled) break      // pauză în timp ce citeam: nu mai construim rafala
      }
      if (c.cancelled) return
      if (c.paused) throw new PausedSignal()
      const t0 = (typeof performance !== 'undefined' ? performance.now() : Date.now())
      const results = await Promise.allSettled(burst.map((b) => sendWithRetry(b.start, b.buf)))
      if (c.cancelled) return
      if (c.paused) throw new PausedSignal()

      let authErr: unknown = null, resync: ResyncSignal | null = null, hard: unknown = null
      let anyUnstable = false
      for (const r of results) {
        if (r.status === 'fulfilled') { landedMax = Math.max(landedMax, r.value.offset); anyUnstable ||= r.value.unstable }
        else {
          const e = r.reason
          if (e instanceof PausedSignal) throw e
          if (isAuthErr(e)) authErr = e
          else if (e instanceof ResyncSignal) resync = resync ?? e
          else hard = hard ?? e
        }
      }
      if (authErr) throw authErr
      if (hard && !resync) throw hard
      if (resync) {
        // re-sincronizare: reluăm din status. Dacă prefixul a divergat (offset ≠ landedMax contiguu),
        // CRC-ul incremental nu mai poate fi corect → îl dezactivăm (commit fără verificare).
        if (++resyncs > 20) throw new Error('resync')
        const st = await withStepup(hid, () => api<{ offset: number; crc32?: number }>(`/api/hosts/${hid}/fs/upload/status?${q}`))
        const real = Math.min(st.offset || 0, file.size)
        if (real !== landedMax) doCrc = false
        dispatchPos = real; landedMax = real
        inflightLoaded.clear()
        publish(c, { state: 'running' })
        setPos(true)
        continue
      }
      // rafală reuşită: adaptăm mărimea feliei după durata medie şi stabilitate
      const ms = ((typeof performance !== 'undefined' ? performance.now() : Date.now()) - t0) / Math.max(1, burst.length)
      chunkSize = nextChunkSize(chunkSize, ms, anyUnstable)
      writeMeta(c, landedMax)
      setPos(true)
    }

    if (c.cancelled) return
    const crcQ = doCrc ? `&crc32=${crc >>> 0}` : ''
    await withStepup(hid, () => api(`/api/hosts/${hid}/fs/upload/commit?${q}${crcQ}`, { method: 'POST' }))
    if (c.lsKey) lsRemove(c.lsKey)
    // scos cât commit-ul era în zbor (sesiune pierdută / alt cont): fişierul e pe host, dar nu mai
    // publicăm rândul şi nu tastăm calea într-un terminal al sesiunii vechi
    if (c.cancelled) return
    // paste / drop pe terminal (3.6.16): calea NU se tastează aici — SessionView aşteaptă toate
    // upload-urile gestului şi le tastează în ordinea selecţiei, ca un paste, cât contextul e acelaşi
    // (lib/transfers.ts typePastedPaths). Un retry ulterior (contextul deja închis) şi orice alt upload
    // cu `then` → regulile vechi (doar la un prompt).
    const deferred = c.then === 'insert-path' && !!c.pasteCtx && c.pasteCtx.sid === c.sid && !c.pasteCtx.closed
    const insertOutcome = c.then !== 'insert-path' || deferred ? undefined : insertPathOutcome(c.sid, c.dest)
    const inserted = insertOutcome === undefined ? undefined : insertOutcome === 'typed'
    publish(c, { pos: file.size, pct: 100, bytesPerSec: 0, etaSec: 0, state: 'done', inserted, insertOutcome })
    ctls.delete(c.id)        // eliberăm File-ul; rândul rămâne în store până la dismiss/expirare
    if (inserted !== false && !deferred) lingerDone(c.id)   // amânat: SessionView decide
  } catch (e) {
    if (c.cancelled) return
    if (e instanceof PausedSignal || c.paused) {
      // pauză manuală: păstrăm File-ul + offset-ul (temp-ul rămâne pe host). Resume reintră din status.
      writeMeta(c, landedMax)
      publish(c, { pos: Math.min(file.size, landedMax), state: 'paused', bytesPerSec: 0, etaSec: null })
      return
    }
    // temp-ul RĂMÂNE pe host, File-ul rămâne în controler → Retry reia de la offset-ul real
    c.authLost = isAuthErr(e)
    // Refuz DEFINITIV al hostului (permisiuni, dosar lipsă, FS doar-citire…): nu există temp de
    // reluat, iar cheia din localStorage — scrisă în startUpload ÎNAINTE de prima felie — ar învia
    // rândul după reload ca „orfan 0 %" şi ar deschide singură widgetul de transferuri, pentru un
    // fişier refuzat (sau deja instalat ca root prin fluxul 3.6.9). O ştergem (audit 2026-10-17,
    // FS-01); rândul `err` rămâne, cu motivul, iar Retry/re-drop reiau din controler. Excepţiile:
    // disc plin — temp-ul parţial există şi merită reluat după ce se face loc — şi orice refuz venit
    // DUPĂ felii aterizate (`landedMax` > 0): temp-ul de pe host e real. Acelaşi tratament pentru un
    // 403/404 cu alt cod când n-a aterizat nimic (vezi refusedForGood).
    if (c.lsKey && refusedForGood(e, landedMax, c.lsKey)) lsRemove(c.lsKey)
    // cheia rămâne şi au aterizat felii: notăm offset-ul real, ca orfanul de după reload să arate
    // progresul adevărat (nu „0 %"); fără nimic aterizat lăsăm pos-ul din cheie (temp dintr-o
    // sesiune anterioară) neatins
    else if (c.lsKey && landedMax > 0) writeMeta(c, landedMax)
    publish(c, { pos: lastPos, state: 'err', error: errorText(e), bytesPerSec: 0, etaSec: null,
                 errorCode: e instanceof ApiError ? e.code : undefined,
                 errorVars: e instanceof ApiError ? e.vars : undefined })
  } finally {
    c.running = false
    c.xhrs.clear()
  }
}

// ── API public ────────────────────────────────────────────────────────────────────────────
export interface StartUploadOpts {
  hostId: number; hostName: string; dest: string; name?: string; file: File
  /** după commit: tastează calea în terminalul `sid` (drop pe terminal / paste de imagine) */
  then?: 'insert-path'
  sid?: string
  /** contextul paste-ului / drop-ului pe terminal (capturePasteContext) — vezi Ctl.pasteCtx */
  pasteCtx?: PasteContext
}

/** Un upload (cu `name` = eticheta relativă din drop). Dacă ACELAŞI fişier spre aceeaşi ţintă e
    deja în mers, nu porneşte un al doilea scriitor (cele două bucle şi-ar suprascrie reciproc
    controlerul şi şi-ar fura offset-ul prin resync-uri 409); dacă era `err`/`orphan`, re-drop-ul
    ESTE reluarea. Promisiunea se rezolvă la finalul primei treceri (done/err/cancelled) cu
    id-ul job-ului, ca apelantul să poată citi starea finală din store (ex. retenţia inbox-ului
    rulează doar după un `done`). */
export async function startUpload(o: StartUploadOpts): Promise<string> {
  ensureGlobalListeners()
  const owner = currentUser
  const lsKey = owner == null ? null : upLsKey(owner, o.hostId, o.dest, o.file.size, o.file.lastModified)
  const meta = lsKey ? parseUploadMeta(lsGet(lsKey), lsKey) : null
  // fără cheie (refuz definitiv: cheia a fost ştearsă, FS-01) re-drop-ul aceluiaşi fişier regăseşte
  // tot controlerul `err` existent, nu porneşte un al doilea rând pentru acelaşi transfer
  const id = meta?.uid ?? findIdleCtl(owner, o)?.id ?? newUid()
  let c = ctls.get(id)
  if (c && c.running) return id
  if (!c) {
    c = { id, hostId: o.hostId, hostName: o.hostName, dest: o.dest, name: o.name ?? o.file.name, lsKey, owner,
          file: o.file, xhrs: new Set(), cancelled: false, paused: false, running: false, authLost: false,
          size: o.file.size, lastModified: o.file.lastModified, then: o.then, sid: o.sid, pasteCtx: o.pasteCtx }
    ctls.set(id, c)
  } else {
    c.file = o.file                                // orfan sau err: acum avem din nou octeţii
    c.hostName = o.hostName || c.hostName
    if (o.name) c.name = o.name
    if (o.then) { c.then = o.then; c.sid = o.sid; c.pasteCtx = o.pasteCtx }
  }
  // rândul „orphan" (dacă exista) devine rândul viu al aceluiaşi job — acelaşi id, deci acelaşi rând
  uploadStore.remove(id)
  writeMeta(c, meta?.pos ?? 0)
  await runLoop(c)
  return id
}

/** controlerul NEpornit (err/orphan/paused) al aceluiaşi fişier spre aceeaşi ţintă, al aceluiaşi cont */
function findIdleCtl(owner: number | null, o: StartUploadOpts): Ctl | undefined {
  for (const c of ctls.values()) {
    if (!c.running && c.owner === owner && c.hostId === o.hostId && c.dest === o.dest
        && c.size === o.file.size && c.lastModified === o.file.lastModified) return c
  }
  return undefined
}

/** taie toate feliile în zbor ale unui ctl, cu un motiv (ca onabort să ştie de ce) */
function abortInflight(c: Ctl, why: 'stall' | 'pause' | 'cancel'): void {
  for (const xhr of c.xhrs) {
    const w = (xhr as unknown as { _wt?: { why: string } })._wt
    if (w) w.why = why                    // motivul, ca onabort să ştie de ce (stall/pause/cancel)
    try { xhr.abort() } catch { /* deja terminat */ }
  }
}

/** Reintră în buclă de la offset-ul real (`status`) pentru un job `err`/`paused`; pentru `stalled`
    taie feliile atârnate acum, fără să mai aştepte cele 60 s ale watchdog-ului. */
export function retryUpload(id: string): void {
  const c = ctls.get(id)
  if (!c) return
  if (c.running) {
    if (c.xhrs.size && uploadStore.get(id)?.state === 'stalled') abortInflight(c, 'stall')
    return
  }
  if (c.file) void runLoop(c)
}

/** Pauză manuală: opreşte trimiterea feliilor noi şi taie cele în zbor; File-ul + offset-ul rămân în
    memorie, temp-ul rămâne pe host. Resume reintră din offset-ul real (`status`). */
export function pauseUpload(id: string): void {
  const c = ctls.get(id)
  if (!c || !c.running || c.paused) return
  c.paused = true
  abortInflight(c, 'pause')
}

/** Reluare după o pauză manuală: reintră în buclă (status → offset real). No-op dacă nu e în pauză
    sau dacă e orfan (fără File — după un reload nu avem octeţii). */
export function resumeUpload(id: string): void {
  const c = ctls.get(id)
  if (!c || c.running || !c.file) return
  c.paused = false
  void runLoop(c)
}

/** anulare: opreşte feliile în zbor şi şterge temp-ul de pe host (nu mai e resumabil) */
export function cancelUpload(id: string): void {
  const c = ctls.get(id)
  if (c) {
    c.cancelled = true
    abortInflight(c, 'cancel')
    fetch(`/api/hosts/${c.hostId}/fs/upload?path=${encodeURIComponent(c.dest)}&upload_id=${c.id}`,
      { method: 'DELETE', credentials: 'same-origin' }).catch(() => {})
    if (c.lsKey) lsRemove(c.lsKey)
    ctls.delete(id)
  }
  uploadStore.remove(id)
}

/** scoate rândul (done/err/cancelled). Pe `err` temp-ul RĂMÂNE şi, dacă eroarea nu a fost un refuz
    definitiv (FS-01), şi cheia: re-drop-ul reia. */
export function dismissUpload(id: string): void {
  const c = ctls.get(id)
  if (c && !c.running) ctls.delete(id)
  uploadStore.remove(id)
}

/** orfan: şterge temp-ul de pe host + cheia locală; nu mai e nimic de reluat */
export const discardUpload = cancelUpload

/** există deja un transfer în mers (sau în reîncercare) spre această ţintă? */
export function isUploadBusy(hostId: number, dest: string): boolean {
  for (const c of ctls.values()) {
    if (c.hostId === hostId && c.dest === dest && c.running) return true
  }
  return false
}

/** La pornirea aplicaţiei (autentificat, cont cunoscut): cheile `wt_up_u<uid>_*` ale CONTULUI
    CURENT rămase = transferuri neterminate într-o sesiune anterioară. Fără File nu le putem relua,
    dar le ARĂTĂM (altfel omul nu ştie că pe host zace un `.wtpart` de 12 GB şi că un re-drop ar
    continua de acolo, nu de la zero). Cheile vechi fără cont se şterg (nu ştim al cui e temp-ul —
    GC-ul de pe server îl curăţă); cele ale altor conturi rămân neatinse. */
export function restoreOrphans(userId: number | null = currentUser): void {
  if (userId == null) return
  ensureGlobalListeners()
  const { mine, legacy } = classifyUpKeys(lsKeysWithPrefix(LS_PREFIX), userId)
  for (const k of legacy) lsRemove(k)
  for (const k of mine) {
    const m = parseUploadMeta(lsGet(k), k)
    if (!m) { lsRemove(k); continue }          // valoare coruptă: nu are cum să reia nimic
    if (ctls.has(m.uid) || uploadStore.get(m.uid)) continue
    const c: Ctl = { id: m.uid, hostId: m.hostId, hostName: m.hostName, dest: m.dest, name: m.name, lsKey: k,
                     owner: userId, file: null, xhrs: new Set(), cancelled: false, paused: false, running: false,
                     authLost: false, size: m.size, lastModified: m.lastModified }
    ctls.set(m.uid, c)
    publish(c, { pos: m.pos, pct: m.size ? Math.round((m.pos / m.size) * 100) : 0, state: 'orphan', attempts: 0 })
  }
}

/** Sesiunea web s-a terminat FĂRĂ logout explicit (expirare, 401, cont dezactivat): uităm TOATE
    rândurile din memorie — nu doar orfanii; un rând `err`/`done`/`paused` cu File-ul în controler
    ar fi apărut contului următor pe acelaşi browser, cu `Retry` activ sub cookie-ul lui (audit
    2026-10-17, FL-06). Cheile din localStorage rămân (revin la următorul login al ACELUIAŞI cont, ca
    orfani: re-drop-ul reia de la offset-ul real) şi nu mai persistăm nimic. */
export function hideUploads(): void {
  currentUser = null
  dropRows(null)
}

/** Logout explicit: uită upload-urile neterminate ale contului — cheile din localStorage, rândurile
    şi controlerele (feliile în zbor se taie; oricum ar pica cu 401). Temp-urile de pe host se cer
    şterse best-effort cât sesiunea mai e validă (altfel le ia GC-ul de pe server). */
export function forgetUploads(): void {
  const uid = currentUser
  currentUser = null
  for (const [id, c] of ctls) {
    if (c.owner !== uid && uid != null) continue
    c.cancelled = true
    abortInflight(c, 'cancel')
    fetch(`/api/hosts/${c.hostId}/fs/upload?path=${encodeURIComponent(c.dest)}&upload_id=${c.id}`,
      { method: 'DELETE', credentials: 'same-origin', keepalive: true }).catch(() => {})
    ctls.delete(id)
    uploadStore.remove(id)
  }
  if (uid != null) for (const k of lsKeysWithPrefix(`${LS_PREFIX}u${uid}_`)) lsRemove(k)
}

// ── navigare: „deschide panoul de fişiere al hostului în directorul ţintei" ──────────────
// Butonul din bară nu poate deschide panoul direct (e componentă pe pagina hostului, montată
// lazy). Lăsăm cererea aici; HostOverview o VEDE (ca să aleagă tab-ul Files), FilePanel o
// CONSUMĂ (ca să încarce directorul în loc de cwd-ul sesiunii).
let pendingDir: { hostId: number; dir: string } | null = null
export function openFilesAt(hostId: number, dir: string): void {
  pendingDir = { hostId, dir }
  window.location.hash = `/h/${hostId}`
  window.dispatchEvent(new CustomEvent('wt-open-files', { detail: { hostId, dir } }))
}
export const peekFilesDir = (hostId: number): string | null =>
  pendingDir && pendingDir.hostId === hostId ? pendingDir.dir : null
export function takeFilesDir(hostId: number): string | null {
  const d = peekFilesDir(hostId)
  if (d != null) pendingDir = null
  return d
}

// ── ascultători globali (o singură dată) ──────────────────────────────────────────────────
let listenersOn = false
function ensureGlobalListeners() {
  if (listenersOn || typeof window === 'undefined') return
  listenersOn = true
  // Închiderea tab-ului cu un transfer în mers = transfer pierdut (temp-ul rămâne, dar File-ul
  // nu). Browserul arată propriul text; noi doar cerem confirmarea.
  window.addEventListener('beforeunload', (e) => {
    for (const j of uploadStore.snapshot().values()) {
      // o copiere host → host rulează pe SERVER: închiderea tab-ului n-o opreşte, nu cerem confirmare
      if (isActive(j) && j.dir !== 'copy') { e.preventDefault(); return }
    }
  })
  // Legătura a revenit / tab-ul a redevenit vizibil: reluăm ce a picat (nu şi 401 — acela cere
  // login, iar o reîncercare automată ar eşua iar) şi tăiem acum XHR-urile atârnate.
  const resume = () => {
    for (const j of uploadStore.snapshot().values()) {
      const c = ctls.get(j.id)
      if (!c) continue
      if (j.state === 'err' && !c.authLost && c.file && !c.running) void runLoop(c)
      else if (j.state === 'stalled') retryUpload(j.id)
    }
  }
  window.addEventListener('online', resume)
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') resume() })
}

// Hook pentru e2e (acelaşi tipar ca `window.__wtTerms` pentru terminale): dă testului controlul
// pauză/reluare şi citirea stării, ca să NU depindă de deschiderea popover-ului de transferuri cât
// chip-ul se re-randează (progres/viteză) — Playwright consideră un element care se animă „instabil".
// Expus necondiţionat; e un self-hosted tool, iar funcţiile sunt exact cele din UI.
if (typeof window !== 'undefined') {
  ;(window as unknown as { __wtTransfers?: object }).__wtTransfers = {
    pauseUpload, resumeUpload, retryUpload, cancelUpload, store: uploadStore,
  }
}
