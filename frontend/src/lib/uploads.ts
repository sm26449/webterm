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
import { UploadJob, isActive, uploadStore } from './uploadStore'

// ── parametri ─────────────────────────────────────────────────────────────────────────────
/** Felie de 8 MiB. Serverul verifică offset-ul; dacă e desincronizat (retry care a aterizat deja,
    două tab-uri) răspunde 409, iar clientul reia bucla de la offset-ul real. */
export const UP_CHUNK = 8 * 1024 * 1024
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
  xhr: XMLHttpRequest | null
  cancelled: boolean
  running: boolean             // bucla e în execuţie — a doua intrare e refuzată
  abortReason: 'stall' | null  // setat ÎNAINTE de xhr.abort() ca onabort să ştie de ce
  authLost: boolean            // ultima eroare a fost 401: nu se reia automat
  size: number
  lastModified: number
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
    pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running', attempts: 1, ...p,
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
// Un fișier, resumabil + verificat: taie în felii, trimite cu offset (XHR → progres byte-level),
// calculează CRC-32 în timp ce citește, iar commit-ul verifică integritatea pe host. La cădere reia
// de la octetul aterizat (retry+backoff; 409 = re-sincronizare). CRC-ul se verifică DOAR la un
// upload dintr-o singură sesiune (offset 0): la reluare, prefixul a fost urcat înainte și nu-l mai
// putem re-hash-ui — atunci ne bazăm pe guard-ul de offset + rename-ul atomic + TLS.
async function runLoop(c: Ctl): Promise<void> {
  const file = c.file
  if (!file || c.running) return
  c.running = true
  c.cancelled = false
  c.authLost = false
  const hid = c.hostId
  const q = `path=${encodeURIComponent(c.dest)}&upload_id=${c.id}`
  const speed = speedTracker()
  // Progresul e stare GLOBALĂ (uploadStore) şi re-randează panoul + bara la fiecare scriere; XHR
  // `onprogress` bate de zeci de ori pe secundă pe o legătură rapidă → furtună de randări
  // (audit frontend F-05). Publicăm cel mult ~10/s şi doar când procentul s-a schimbat (sau o
  // dată pe secundă, ca viteza/ETA să respire); graniţele de felie şi finalul trec mereu (`force`).
  let lastPos = 0, shownPct = -1, shownAt = 0
  const setPos = (bytes: number, force = false) => {
    lastPos = bytes
    const pct = file.size ? Math.round((bytes / file.size) * 100) : 100
    const now = Date.now()
    const bps = speed.sample(bytes, now)
    if (!force && ((pct === shownPct && now - shownAt < 1000) || now - shownAt < 100)) return
    shownPct = pct; shownAt = now
    publish(c, { pos: bytes, pct, bytesPerSec: bps, etaSec: etaSec(file.size, bytes, bps), state: 'running' })
  }

  publish(c, { state: 'running', attempts: 1, error: undefined })

  // XHR (nu fetch) ca să avem progres pe octeți în timpul feliei + cancel
  const sendChunk = (off: number, body: ArrayBuffer): Promise<void> =>
    new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      c.xhr = xhr
      c.abortReason = null
      let lastByteAt = Date.now()
      let stalled = false
      // Watchdog-ul: `ontimeout` prinde doar o conexiune moartă de 300 s; un uplink care picură
      // 0 octeţi (laptop în sleep, Wi-Fi care s-a reasociat) nu-l atinge niciodată. Numărăm
      // octeţii, nu timpul total: 20 s → vizibil `stalled`, 60 s → abort şi felia se reia.
      const tick = window.setInterval(() => {
        const idle = Date.now() - lastByteAt
        if (idle >= STALL_ABORT_MS) {
          window.clearInterval(tick)
          c.abortReason = 'stall'
          xhr.abort()
        } else if (idle >= STALL_WARN_MS && !stalled) {
          stalled = true
          speed.reset()
          publish(c, { state: 'stalled', bytesPerSec: 0, etaSec: null })
        }
      }, 5000)
      const done = () => { window.clearInterval(tick); c.xhr = null }
      xhr.open('POST', `/api/hosts/${hid}/fs/upload?${q}&offset=${off}`)
      xhr.upload.onprogress = (ev) => {
        if (!ev.lengthComputable) return
        lastByteAt = Date.now()
        if (stalled) { stalled = false; setPos(off + ev.loaded, true) } else setPos(off + ev.loaded)
      }
      xhr.onload = async () => {
        done()
        if (xhr.status >= 200 && xhr.status < 300) { resolve(); return }
        if (xhr.status === 401) { reject(new AuthLost()); return }
        // 409: offset desincronizat. 403: fereastra de step-up a expirat în mijlocul unui
        // upload lung (multi-GB pe host cu require_2fa) — fără asta, chunk-urile picau 5
        // retry-uri şi eroarea finală era un opac „403", fără re-prompt. Sonda de status prin
        // withStepup redeschide prompt-ul de passkey, apoi reluăm de la offset-ul real.
        if (xhr.status === 409 || xhr.status === 403) {
          try {
            const st = await withStepup(hid, () =>
              api<{ offset: number }>(`/api/hosts/${hid}/fs/upload/status?${q}`))
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
        const why = c.abortReason
        c.abortReason = null
        reject(why === 'stall' ? new StallAbort() : new Error('abort'))
      }
      // fără timeout explicit, `ontimeout` era cod mort (default 0 = niciodată): o conexiune
      // TCP atârnată (switch care nu trimite RST) îngheţa upload-ul la nesfârşit, fără retry
      xhr.timeout = 300_000
      xhr.send(body)
    })

  try {
    let offset = 0
    try {
      const st = await withStepup(hid, () => api<{ offset: number }>(`/api/hosts/${hid}/fs/upload/status?${q}`))
      offset = Math.min(st.offset || 0, file.size)
    } catch (e) {
      if (isAuthErr(e)) throw e
      offset = 0
    }
    let doCrc = offset === 0
    let crc = 0
    setPos(offset, true)
    let pos = offset, resyncs = 0
    do {   // do/while: acoperă și fișierul de 0 octeți (o felie goală la offset 0)
      if (c.cancelled) return
      const end = Math.min(pos + UP_CHUNK, file.size)
      const buf = await file.slice(pos, end).arrayBuffer()
      let landed = false, tries = 0
      publish(c, { attempts: 1 })
      for (;;) {
        try { await sendChunk(pos, buf); landed = true; break }
        catch (e) {
          if (c.cancelled) return
          if (isAuthErr(e)) throw e
          if (e instanceof ResyncSignal) {
            if (++resyncs > 20) throw new Error('resync')
            const r = resolveResync(pos, end, e.offset)
            if (r.action === 'landed') { landed = true; break }  // felia a aterizat, doar răspunsul s-a pierdut
            if (r.action === 'jump') { doCrc = false; pos = r.pos } // aterizare parţială / alt scriitor:
            break            // CRC-ul incremental nu mai poate fi corect. `retry` = nimic
          }                  // aterizat → refacem aceeaşi felie, cu CRC-ul încă valid.
          if (++tries >= MAX_ATTEMPTS) throw e
          // stall: legătura a tăcut 60 s şi am tăiat-o noi → reluăm imediat, nu mai aşteptăm;
          // orice altceva (network/5xx/timeout) → backoff exponenţial plafonat
          publish(c, { state: 'retrying', attempts: tries + 1, bytesPerSec: 0, etaSec: null })
          speed.reset()
          if (!(e instanceof StallAbort)) await new Promise((r) => setTimeout(r, backoffMs(tries)))
          if (c.cancelled) return
          publish(c, { state: 'running' })
        }
      }
      if (landed) {
        // CRC-ul se acumulează DOAR după ce felia a aterizat confirmat. Acumulat la citire (cum
        // era), orice felie re-trimisă după un resync se număra de DOUĂ ori: commit-ul pica fals
        // la integritate şi ştergea temp-ul bun — tot progresul pierdut pe o legătură instabilă.
        if (doCrc) crc = crc32(crc, new Uint8Array(buf))
        pos = end
      }
      writeMeta(c, pos)      // după fiecare felie, nu la fiecare tick: ieftin şi suficient
      setPos(pos, true)
    } while (pos < file.size)

    if (c.cancelled) return
    const crcQ = doCrc ? `&crc32=${crc >>> 0}` : ''
    await withStepup(hid, () => api(`/api/hosts/${hid}/fs/upload/commit?${q}${crcQ}`, { method: 'POST' }))
    lsRemove(c.lsKey)
    publish(c, { pos: file.size, pct: 100, bytesPerSec: 0, etaSec: 0, state: 'done' })
    ctls.delete(c.id)        // eliberăm File-ul; rândul rămâne în store până la dismiss/expirare
    window.setTimeout(() => {
      if (uploadStore.get(c.id)?.state === 'done') uploadStore.remove(c.id)
    }, DONE_LINGER_MS)
  } catch (e) {
    if (c.cancelled) return
    // temp-ul RĂMÂNE pe host, File-ul rămâne în controler → Retry reia de la offset-ul real
    c.authLost = isAuthErr(e)
    publish(c, { pos: lastPos, state: 'err', error: errorText(e), bytesPerSec: 0, etaSec: null })
  } finally {
    c.running = false
    c.xhr = null
  }
}

// ── API public ────────────────────────────────────────────────────────────────────────────
export interface StartUploadOpts { hostId: number; hostName: string; dest: string; name?: string; file: File }

/** Un upload (cu `name` = eticheta relativă din drop). Dacă ACELAŞI fişier spre aceeaşi ţintă e
    deja în mers, nu porneşte un al doilea scriitor (cele două bucle şi-ar suprascrie reciproc
    controlerul şi şi-ar fura offset-ul prin resync-uri 409); dacă era `err`/`orphan`, re-drop-ul
    ESTE reluarea. Promisiunea se rezolvă la finalul primei treceri (done/err/cancelled). */
export async function startUpload(o: StartUploadOpts): Promise<void> {
  ensureGlobalListeners()
  const lsKey = upLsKey(o.hostId, o.dest, o.file.size, o.file.lastModified)
  const meta = parseUploadMeta(lsGet(lsKey), lsKey)
  const id = meta?.uid ?? newUid()
  let c = ctls.get(id)
  if (c && c.running) return
  if (!c) {
    c = { id, hostId: o.hostId, hostName: o.hostName, dest: o.dest, name: o.name ?? o.file.name, lsKey,
          file: o.file, xhr: null, cancelled: false, running: false, abortReason: null, authLost: false,
          size: o.file.size, lastModified: o.file.lastModified }
    ctls.set(id, c)
  } else {
    c.file = o.file                                // orfan sau err: acum avem din nou octeţii
    c.hostName = o.hostName || c.hostName
    if (o.name) c.name = o.name
  }
  // rândul „orphan" (dacă exista) devine rândul viu al aceluiaşi job — acelaşi id, deci acelaşi rând
  uploadStore.remove(id)
  writeMeta(c, meta?.pos ?? 0)
  await runLoop(c)
}

/** Reintră în buclă de la offset-ul real (`status`) pentru un job `err`; pentru `stalled` taie
    XHR-ul atârnat acum, fără să mai aştepte cele 60 s ale watchdog-ului. */
export function retryUpload(id: string): void {
  const c = ctls.get(id)
  if (!c) return
  if (c.running) {
    if (c.xhr && uploadStore.get(id)?.state === 'stalled') { c.abortReason = 'stall'; c.xhr.abort() }
    return
  }
  if (c.file) void runLoop(c)
}

/** anulare: opreşte felia în zbor şi şterge temp-ul de pe host (nu mai e resumabil) */
export function cancelUpload(id: string): void {
  const c = ctls.get(id)
  if (c) {
    c.cancelled = true
    c.xhr?.abort()
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
                     file: null, xhr: null, cancelled: false, running: false, abortReason: null,
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
