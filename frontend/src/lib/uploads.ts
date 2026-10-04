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
import { api, ApiError, errText, withStepup } from './api'
import { tStatic } from './i18n'
import { lsGet, lsRemove, lsSet } from './storage'
import { insertPathInto } from './transfers'
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
// CRC-32 (IEEE), incremental — IDENTIC cu `zlib.crc32(bytes, prev)` din agent (poly reflectat
// 0xEDB88320, init/xor 0xFFFFFFFF). Verificare de integritate la commit: prinde coruperea
// accidentală (disc, trunchiere, offset). `prev` începe de la 0.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1)
    t[n] = c >>> 0
  }
  return t
})()
export function crc32(prev: number, bytes: Uint8Array): number {
  let c = (prev ^ 0xFFFFFFFF) >>> 0
  for (let i = 0; i < bytes.length; i++) c = (CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8)) >>> 0
  return (c ^ 0xFFFFFFFF) >>> 0
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
// upload_id STABIL per (host, cale, fișier): persistat în localStorage, ca un reload de pagină
// să poată relua același upload (browserul nu re-citește fișierul singur — re-selectezi același
// fișier și reia de unde a rămas, exact ca protocolul tus).
export const upLsKey = (hostId: number, dest: string, size: number, lastModified: number) =>
  `${LS_PREFIX}${hostId}_${dest}_${size}_${lastModified}`

/** Inversa lui `upLsKey` — necesară DOAR pentru valorile vechi (uid simplu), unde cheia e singura
    sursă de host/cale. `dest` poate conţine `_`, de aceea tăiem de la capete, nu cu split. */
export function parseUpLsKey(key: string): { hostId: number; dest: string; size: number; lastModified: number } | null {
  if (!key.startsWith(LS_PREFIX)) return null
  const rest = key.slice(LS_PREFIX.length)
  const m = rest.match(/^(\d+)_(.*)_(\d+)_(\d+)$/)
  if (!m) return null
  return { hostId: Number(m[1]), dest: m[2], size: Number(m[3]), lastModified: Number(m[4]) }
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
  lsKey: string
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

function writeMeta(c: Ctl, pos: number) {
  const m: UploadMeta = { uid: c.id, hostId: c.hostId, hostName: c.hostName, dest: c.dest, name: c.name,
                          size: c.size, lastModified: c.lastModified, pos, updated: Date.now() }
  lsSet(c.lsKey, JSON.stringify(m))
}

function publish(c: Ctl, p: Partial<UploadJob>) {
  const cur = uploadStore.get(c.id)
  if (cur) { uploadStore.patch(c.id, p); return }
  uploadStore.set({
    id: c.id, hostId: c.hostId, hostName: c.hostName, dest: c.dest, name: c.name, size: c.size,
    pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running', attempts: 1, then: c.then, sid: c.sid, ...p,
  })
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
        reject(new Error(String(xhr.status)))
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
        const buf = await file.slice(start, end).arrayBuffer()
        if (doCrc) crc = crc32(crc, new Uint8Array(buf))   // ordinea fişierului, o singură dată per felie
        dispatchPos = end
        burst.push({ start, end, buf })
      }
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
    lsRemove(c.lsKey)
    const inserted = c.then === 'insert-path' ? insertPathInto(c.sid, c.dest) : undefined
    publish(c, { pos: file.size, pct: 100, bytesPerSec: 0, etaSec: 0, state: 'done', inserted })
    ctls.delete(c.id)        // eliberăm File-ul; rândul rămâne în store până la dismiss/expirare
    if (inserted !== false) {
      window.setTimeout(() => {
        if (uploadStore.get(c.id)?.state === 'done') uploadStore.remove(c.id)
      }, DONE_LINGER_MS)
    }
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
    publish(c, { pos: lastPos, state: 'err', error: errorText(e), bytesPerSec: 0, etaSec: null })
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
}

/** Un upload (cu `name` = eticheta relativă din drop). Dacă ACELAŞI fişier spre aceeaşi ţintă e
    deja în mers, nu porneşte un al doilea scriitor (cele două bucle şi-ar suprascrie reciproc
    controlerul şi şi-ar fura offset-ul prin resync-uri 409); dacă era `err`/`orphan`, re-drop-ul
    ESTE reluarea. Promisiunea se rezolvă la finalul primei treceri (done/err/cancelled) cu
    id-ul job-ului, ca apelantul să poată citi starea finală din store (ex. retenţia inbox-ului
    rulează doar după un `done`). */
export async function startUpload(o: StartUploadOpts): Promise<string> {
  ensureGlobalListeners()
  const lsKey = upLsKey(o.hostId, o.dest, o.file.size, o.file.lastModified)
  const meta = parseUploadMeta(lsGet(lsKey), lsKey)
  const id = meta?.uid ?? newUid()
  let c = ctls.get(id)
  if (c && c.running) return id
  if (!c) {
    c = { id, hostId: o.hostId, hostName: o.hostName, dest: o.dest, name: o.name ?? o.file.name, lsKey,
          file: o.file, xhrs: new Set(), cancelled: false, paused: false, running: false, authLost: false,
          size: o.file.size, lastModified: o.file.lastModified, then: o.then, sid: o.sid }
    ctls.set(id, c)
  } else {
    c.file = o.file                                // orfan sau err: acum avem din nou octeţii
    c.hostName = o.hostName || c.hostName
    if (o.name) c.name = o.name
    if (o.then) { c.then = o.then; c.sid = o.sid }
  }
  // rândul „orphan" (dacă exista) devine rândul viu al aceluiaşi job — acelaşi id, deci acelaşi rând
  uploadStore.remove(id)
  writeMeta(c, meta?.pos ?? 0)
  await runLoop(c)
  return id
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
    lsRemove(c.lsKey)
    ctls.delete(id)
  }
  uploadStore.remove(id)
}

/** scoate rândul (done/err/cancelled). Pe `err` temp-ul şi cheia RĂMÂN: re-drop-ul reia. */
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

/** La pornirea aplicaţiei: cheile `wt_up_*` rămase = transferuri neterminate într-o sesiune
    anterioară. Fără File nu le putem relua, dar le ARĂTĂM (altfel omul nu ştie că pe host zace
    un `.wtpart` de 12 GB şi că un re-drop ar continua de acolo, nu de la zero). */
export function restoreOrphans(): void {
  ensureGlobalListeners()
  let keys: string[] = []
  try {
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i)
      if (k && k.startsWith(LS_PREFIX)) keys.push(k)
    }
  } catch { keys = [] }
  for (const k of keys) {
    const m = parseUploadMeta(lsGet(k), k)
    if (!m) { lsRemove(k); continue }          // valoare coruptă: nu are cum să reia nimic
    if (ctls.has(m.uid) || uploadStore.get(m.uid)) continue
    const c: Ctl = { id: m.uid, hostId: m.hostId, hostName: m.hostName, dest: m.dest, name: m.name, lsKey: k,
                     file: null, xhrs: new Set(), cancelled: false, paused: false, running: false,
                     authLost: false, size: m.size, lastModified: m.lastModified }
    ctls.set(m.uid, c)
    publish(c, { pos: m.pos, pct: m.size ? Math.round((m.pos / m.size) * 100) : 0, state: 'orphan', attempts: 0 })
  }
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
      if (isActive(j)) { e.preventDefault(); return }
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
