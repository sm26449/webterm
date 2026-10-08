/* Motorul de DOWNLOAD host→browser (transfers phase 2) — simetric cu lib/uploads.ts, prin acelaşi
   store global (uploadStore) şi aceeaşi bară/chip, dar în sens invers (`dir: 'down'`).

   De ce prin motor, nu un simplu `<a download>`: un link clasic nu are progres, nu se poate pune pe
   pauză, iar o cădere de reţea la 90% dintr-un fişier de 40 GB îl aruncă de la zero, fără niciun
   feedback. Aici: felii cu `Range`, watchdog pe octeţi (stall vizibil + abort), retry cu backoff,
   pauză/reluare, şi salvare prin File System Access API (streaming pe disc, fişiere uriaşe) când e
   disponibilă — altfel un Blob în memorie (cost de RAM: cerem FS Access pentru fişiere foarte mari).

   Agentul NU se atinge: gateway-ul serveşte deja `GET /fs/download` şi răspunde la `Range` (HTTP
   206) peste `fs_read` (care citeşte de la orice offset), cu un validator `ETag: W/"size-mtime"` din
   `fs_stat`-ul pe care oricum îl face.

   Reluare DUPĂ RELOAD (3.5.13) — doar pe calea File System Access (Chrome/Edge), unde avem un
   FileSystemFileHandle: job-ul (handle, host, cale, mărime, ETag, checkpoint) stă în IndexedDB
   (lib/dlresume.ts), cheiat pe user id. Chromium scrie într-un fişier swap şi comite abia la
   `close()`, deci motorul face CHECKPOINT-uri: închide writable-ul (octeţii devin ai fişierului),
   persistă offset-ul, şi redeschide cu `keepExistingData` + `seek`. Cadenţa e geometrică (vezi
   shouldCheckpoint) pentru că fiecare redeschidere copiază fişierul existent; pauza şi eroarea
   finală fac şi ele checkpoint, deci un job pus pe pauză nu pierde nimic la reload. La pornire,
   job-urile rămase apar în Transferuri ca „Întrerupt — Resume / Discard"; Resume cere permisiunea
   de scriere (gest al omului), reia de la min(checkpoint, mărimea reală de pe disc) şi refuză să
   lipească octeţi dacă ETag-ul s-a schimbat pe host (→ „Start over", de la zero, în acelaşi fişier).
   Blob-ul (Firefox/Safari, fişiere mici) şi arhivele .tgz (generate din mers, fără validator
   stabil) NU se reiau după reload — doar în sesiune (Blob) sau deloc (arhivă: Retry de la zero). */
import { ApiError, ensureStepup, errText } from './api'
import { tStatic } from './i18n'
import { backoffMs, baseName, etaSec, MAX_ATTEMPTS, speedTracker, STALL_ABORT_MS, STALL_WARN_MS } from './uploads'
import { UploadJob, uploadStore } from './uploadStore'
import {
  DlRecStore, FileHandleLike, WritableLike, contentRangeTotal, defaultStore, dlRecKey, forgetUser,
  lastModifiedSec, loadForUser, resumeOffset, shouldCheckpoint, validatorMatches,
} from './dlresume'

const tr = (k: string, vars?: Record<string, string | number>) => {
  let s = tStatic(k)
  if (vars) for (const [kk, v] of Object.entries(vars)) s = s.split('{' + kk + '}').join(String(v))
  return s
}

const DONE_LINGER_MS = 20_000
/** Peste atât FĂRĂ File System Access API refuzăm (Blob-ul ar umple RAM-ul): cerem un browser capabil. */
export const DL_BLOB_MAX = 1024 * 1024 * 1024
/** Peste atât, dacă avem FS Access, o preferăm Blob-ului (streaming pe disc, nu în memorie). */
export const DL_FSA_PREFER = 64 * 1024 * 1024

// Minimul din File System Access API de care avem nevoie (tipurile lipsesc în lib.dom mai vechi).
type SaveHandle = FileHandleLike
type DirHandle = { getFileHandle(name: string, o?: { create?: boolean }): Promise<SaveHandle> }
type PickerWin = Window & {
  showSaveFilePicker?: (o?: { suggestedName?: string }) => Promise<SaveHandle>
  showDirectoryPicker?: (o?: { mode?: 'read' | 'readwrite' }) => Promise<DirHandle>
}

export const canFsa = (): boolean =>
  typeof window !== 'undefined' && typeof (window as PickerWin).showSaveFilePicker === 'function'

class AuthLost extends Error { constructor() { super('unauth') } }
class StallAbort extends Error { constructor() { super('stall') } }
class PausedSignal extends Error { constructor() { super('paused') } }
/** ETag-ul răspunsului diferă de cel de la începutul descărcării: fişierul s-a schimbat pe host */
class ChangedSignal extends Error { constructor() { super('changed') } }
/** 403 de step-up (host cu 2FA, fereastra a expirat): deschidem ceremonia şi reîncercăm */
class StepupNeeded extends Error { constructor(readonly code: string) { super('stepup') } }

interface DlCtl {
  id: string
  hostId: number
  hostName: string
  path: string              // calea pe host
  name: string              // numele de salvat / eticheta
  size: number
  cancelled: boolean
  paused: boolean
  running: boolean
  abort: AbortController | null
  abortWhy: 'stall' | 'pause' | 'cancel' | null
  writable: WritableLike | null    // FS Access: stream deschis pe disc (ţinut între retry-uri)
  parts: Uint8Array[] | null       // Blob fallback: feliile adunate în memorie
  written: number                  // octeţi deja scrişi în writable / Blob (punctul de reluare în sesiune)
  // ── reluare după reload (doar cu handle) ──
  handle: SaveHandle | null        // fişierul ales: se poate redeschide (checkpoint, Start over)
  committed: number                // octeţi COMIŞI pe disc (după close) = punctul de reluare după reload
  ckAt: number                     // momentul ultimului checkpoint
  etag: string | null              // validatorul de la primul răspuns
  mtime: number | null
  owner: number | null             // user id-ul care a pornit job-ul (cheia înregistrării)
  recKey: string | null            // != null ⇒ job-ul are înregistrare în IndexedDB
  created: number
  touchedDisk: boolean             // am comis măcar un checkpoint (fişierul e al nostru, parţial)
  handleSaved: boolean             // handle-ul e deja în IndexedDB (se scrie o singură dată)
}
const ctls = new Map<string, DlCtl>()

/** id stabil per (host, cale): un re-download al aceluiaşi fişier regăseşte rândul (nu se dublează) */
const dlId = (hostId: number, path: string) => `dl_${hostId}_${path}`

// ── persistenţa (IndexedDB, lib/dlresume.ts) ──────────────────────────────────────────────
let recStore: DlRecStore | null = null
const store = () => (recStore ??= defaultStore())
/** doar pentru teste: un stoc în memorie în locul IndexedDB */
export function _setDownloadStore(s: DlRecStore | null): void { recStore = s }
/** politica de checkpoint (lib/dlresume.ts); testele o înlocuiesc cu un prag la scara lor */
let ckPolicy: (committed: number, written: number, sinceMs: number) => boolean = shouldCheckpoint
export function _setCheckpointPolicy(f: typeof ckPolicy | null): void { ckPolicy = f ?? shouldCheckpoint }
let currentUser: number | null = null
/** App: contul autentificat (null la logout/expirare — nimic nu se mai persistă pe numele nimănui) */
export function setDownloadUser(id: number | null): void { currentUser = id }

async function saveRec(c: DlCtl): Promise<void> {
  if (!c.recKey || !c.handle || !c.etag || c.cancelled || c.owner == null || c.owner !== currentUser) return
  const withHandle = !c.handleSaved
  await store().put({
    key: c.recKey, v: 1, userId: c.owner, hostId: c.hostId, hostName: c.hostName, path: c.path, name: c.name,
    size: c.size, etag: c.etag, mtime: c.mtime, checkpoint: c.committed, created: c.created,
    updated: Date.now(),
  }, withHandle ? c.handle : undefined)
    .then(() => { if (withHandle) c.handleSaved = true })
    .catch(() => { /* IDB indisponibil: doar reluarea după reload lipseşte */ })
}
function dropRec(c: DlCtl): void {
  const k = c.recKey
  c.recKey = null
  c.handleSaved = false
  if (k) void store().del(k).catch(() => {})
}

function publish(c: DlCtl, p: Partial<UploadJob>) {
  if (uploadStore.get(c.id)) { uploadStore.patch(c.id, p); return }
  uploadStore.set({
    id: c.id, dir: 'down', hostId: c.hostId, hostName: c.hostName, dest: c.path, name: c.name, size: c.size,
    pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running', attempts: 1, ...p,
  })
}
const pctOf = (c: DlCtl, bytes: number) => (c.size ? Math.min(100, Math.round((bytes / c.size) * 100)) : 0)

const isAuthErr = (e: unknown) => e instanceof AuthLost
function errorText(e: unknown): string {
  if (isAuthErr(e)) return tr('jobs.signInAgain')
  if (e instanceof StallAbort) return tr('jobs.errStall')
  if (e instanceof ChangedSignal) return tr('transfers.dlChanged')
  if (e instanceof ApiError) return errText(e, tr) || tr('jobs.errHttp', { code: e.status })
  if (e instanceof DOMException && e.name === 'NotAllowedError') return tr('transfers.dlPermDenied')
  if (e instanceof DOMException && e.name === 'NotFoundError') return tr('transfers.dlFileGone')
  if (e instanceof DOMException) return e.message || tr('files.genericErr')   // disc plin, blocat de Safe Browsing…
  if (e instanceof Error) {
    if (e.message === 'network') return tr('jobs.errNetwork')
    if (/^\d{3}$/.test(e.message)) return tr('jobs.errHttp', { code: e.message })
  }
  return tr('files.genericErr')
}
/** 4xx definitive: reîncercarea n-ar schimba nimic (fişier lipsă, cerere greşită, acces refuzat).
    409 (host offline) şi 408/429 rămân reîncercabile. */
const isFinalHttp = (e: unknown) =>
  e instanceof ApiError && e.status >= 400 && e.status < 500 && ![408, 409, 429].includes(e.status)

/** fişierul local: permisiune retrasă / fişier mutat sau şters / seek nesuportat — reîncercarea nu ajută */
const isFinalFs = (e: unknown) =>
  (e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'NotFoundError'
                                 || e.name === 'NoModificationAllowedError' || e.name === 'QuotaExceededError'))
  || (e instanceof Error && e.message === tr('transfers.dlNoSeek'))

/** Comite pe disc ce s-a scris: `close()` (swap → fişier), persistă offset-ul. Writable-ul rămâne
    închis; următoarea felie îl redeschide (`reopen`). */
async function checkpoint(c: DlCtl): Promise<void> {
  const w = c.writable
  if (!w || !c.handle) return
  c.writable = null
  publish(c, { detail: tr('transfers.dlSaving') })
  try {
    await w.close()
  } finally {
    publish(c, { detail: undefined })
  }
  c.committed = c.written
  c.ckAt = Date.now()
  c.touchedDisk = true
  await saveRec(c)
}

/** Redeschide fişierul la `at`: copia existentă (keepExistingData) trunchiată la `at`, cursorul la
    `at`. Fără `seek` (implementare veche/parţială) nu putem poziţiona → eroare, nu octeţi greşiţi. */
async function reopen(c: DlCtl, at: number): Promise<void> {
  const h = c.handle!
  publish(c, { detail: at > 0 ? tr('transfers.dlPreparing') : undefined })
  try {
    const w = await h.createWritable({ keepExistingData: at > 0 })
    if (at > 0) {
      if (!w.seek || !w.truncate) { try { await w.abort?.() } catch { /* noop */ } throw new Error(tr('transfers.dlNoSeek')) }
      await w.truncate(at)        // ce e dincolo de checkpoint pe disc nu e de încredere
      await w.seek(at)            // truncate NU mută cursorul (rămâne la 0)
    }
    if (c.cancelled) { try { await w.abort?.() } catch { /* noop */ } return }
    c.writable = w
    c.written = at
    c.committed = at
    c.ckAt = Date.now()
  } finally {
    publish(c, { detail: undefined })
  }
}

async function runLoop(c: DlCtl): Promise<void> {
  if (c.running) return
  c.running = true
  c.cancelled = false
  c.paused = false
  const speed = speedTracker()
  let shownPct = -1, shownAt = 0
  const setPos = (force = false, state: UploadJob['state'] = 'running') => {
    const bytes = Math.min(c.size || c.written, c.written)
    const pct = c.size ? Math.round((bytes / c.size) * 100) : (c.written ? 100 : 0)
    const now = Date.now()
    const bps = speed.sample(bytes, now)
    if (!force && ((pct === shownPct && now - shownAt < 1000) || now - shownAt < 100)) return
    shownPct = pct; shownAt = now
    publish(c, { pos: bytes, pct, bytesPerSec: bps, etaSec: etaSec(c.size, bytes, bps), state })
  }

  // o felie (de la c.written în sus), cu watchdog pe octeţi + abort. Scrie direct pe măsură ce curge.
  // 'done' = fişierul s-a terminat; 'more' = conexiunea s-a închis devreme; 'ck' = e timpul unui
  // checkpoint (conexiunea e închisă de noi: close/reopen poate dura, nu ţinem un socket mut deschis).
  const fetchFrom = async (): Promise<'done' | 'more' | 'ck'> => {
    const ac = new AbortController()
    c.abort = ac
    c.abortWhy = null
    let lastByteAt = Date.now()
    let stalled = false
    const tick = window.setInterval(() => {
      const idle = Date.now() - lastByteAt
      if (idle >= STALL_ABORT_MS) { window.clearInterval(tick); c.abortWhy = 'stall'; ac.abort() }
      else if (idle >= STALL_WARN_MS && !stalled) { stalled = true; speed.reset(); publish(c, { state: 'stalled', bytesPerSec: 0, etaSec: null }) }
    }, 5000)
    try {
      const resp = await fetch(
        `/api/hosts/${c.hostId}/fs/download?path=${encodeURIComponent(c.path)}`,
        { headers: { Range: `bytes=${c.written}-` }, credentials: 'same-origin', signal: ac.signal })
      if (resp.status === 401) throw new AuthLost()
      if (resp.status === 416) return 'done'               // nimic de citit = deja complet
      if (!(resp.status === 206 || resp.status === 200)) {
        const code = resp.headers.get('X-WebTerm-Error') ?? ''
        if (resp.status === 403 && code.startsWith('stepup.')) throw new StepupNeeded(code)
        let detail = resp.statusText
        try { detail = (await resp.json()).detail ?? detail } catch { /* corp ne-JSON */ }
        throw new ApiError(resp.status, detail, code)
      }
      // validatorul: primul răspuns îl fixează; fiecare răspuns ulterior (retry, reluare după
      // reload) trebuie să-l repete — altfel fişierul de pe host s-a schimbat şi NU lipim octeţi noi
      // peste cei vechi.
      const etag = resp.headers.get('ETag')
      const total = resp.status === 206 ? contentRangeTotal(resp.headers.get('Content-Range'))
        : (Number(resp.headers.get('Content-Length')) || null)
      if (c.etag) {
        if (!validatorMatches({ etag: c.etag, size: c.size }, { etag, total })) {
          void resp.body?.cancel().catch(() => {})
          throw new ChangedSignal()
        }
      } else if (etag && c.written === 0) {
        c.etag = etag
        c.mtime = lastModifiedSec(resp.headers.get('Last-Modified'))
        if (total != null) c.size = total
        if (c.handle && c.owner != null && c.owner === currentUser) {
          c.recKey ??= dlRecKey(c.owner, c.hostId, c.path)
          c.created = Date.now()
          await saveRec(c)
        }
      }
      // Serverul a ignorat Range-ul (200, nu 206) deşi am cerut de la >0: fără suport de Range nu
      // putem relua — repornim de la zero (truncăm ce-am scris). Rar (doar agenţi fără fs_stat).
      if (c.written > 0 && resp.status === 200) {
        if (c.handle && c.recKey) {          // o reluare persistată fără Range: fişierul nu mai e acelaşi
          void resp.body?.cancel().catch(() => {})
          throw new ChangedSignal()
        }
        c.written = 0
        if (c.parts) c.parts = []
        setPos(true)
      }
      const reader = resp.body?.getReader()
      if (!reader) throw new Error('network')
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        if (value && value.length) {
          lastByteAt = Date.now()
          if (stalled) { stalled = false }
          if (c.writable) await c.writable.write(value)
          else if (c.parts) c.parts.push(value)
          c.written += value.length
          setPos()
          if (c.recKey && c.writable && !(c.size && c.written >= c.size)
              && ckPolicy(c.committed, c.written, Date.now() - c.ckAt)) {
            void reader.cancel().catch(() => {})
            return 'ck'
          }
        }
      }
      return (c.size ? c.written >= c.size : true) ? 'done' : 'more'
    } catch (e) {
      if (ac.signal.aborted) {
        if (c.abortWhy === 'stall') throw new StallAbort()
        if (c.cancelled || c.abortWhy === 'cancel') throw new Error('abort')
        throw new PausedSignal()                           // pauză
      }
      if (e instanceof AuthLost || e instanceof ChangedSignal || e instanceof StepupNeeded || e instanceof ApiError) throw e
      if (e instanceof TypeError) throw new Error('network')   // fetch de reţea
      throw e
    } finally {
      window.clearInterval(tick)
      c.abort = null
    }
  }

  try {
    publish(c, { state: 'running', attempts: 1, error: undefined, restartable: undefined })
    setPos(true)
    let tries = 0
    let stepups = 0
    for (;;) {
      if (c.cancelled) return
      if (c.paused) throw new PausedSignal()
      try {
        // FS Access cu handle şi writable închis (checkpoint, pauză, eroare, reluare după reload, un
        // close eşuat): îl redeschidem la offset-ul COMIS înainte de orice felie — altfel octeţii
        // n-ar avea unde ateriza
        if (c.handle && !c.writable && !c.parts) {
          await reopen(c, c.committed)
          if (c.cancelled) return
          setPos(true)
        }
        const r = await fetchFrom()
        if (r === 'done') break
        if (r === 'ck') await checkpoint(c)
        tries = 0                                          // progres bun: resetăm contorul de eşec
      } catch (e) {
        if (c.cancelled) return
        if (c.paused || e instanceof PausedSignal) throw new PausedSignal()
        if (isAuthErr(e) || e instanceof ChangedSignal || isFinalHttp(e) || isFinalFs(e)) throw e
        if (e instanceof StepupNeeded) {
          // fereastra de step-up a expirat (sau, după un reload, nu fusese deschisă): ceremonia
          // (passkey / parolă / TOTP) şi o nouă încercare; refuzat → eroare clară, nu 8 retry-uri
          if (++stepups <= 2 && (await ensureStepup(c.hostId, e.code))) continue
          throw new ApiError(403, tr('transfers.dlStepup'), e.code)
        }
        if (c.size && c.written >= c.size) break           // ultima felie a aterizat, doar finalul s-a rupt
        if (++tries >= MAX_ATTEMPTS) throw e
        publish(c, { state: 'retrying', attempts: tries + 1, bytesPerSec: 0, etaSec: null })
        speed.reset()
        if (!(e instanceof StallAbort)) await new Promise((r) => setTimeout(r, backoffMs(tries)))
        if (c.cancelled) return
        if (c.paused) throw new PausedSignal()
        publish(c, { state: 'running' })
      }
    }

    // finalizare: închidem stream-ul de disc sau declanşăm salvarea Blob-ului
    if (c.writable) { await c.writable.close(); c.writable = null; c.committed = c.written }
    else if (c.parts) {
      const blob = new Blob(c.parts as BlobPart[], { type: 'application/octet-stream' })
      c.parts = null
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = c.name; a.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
    }
    dropRec(c)
    publish(c, { pos: c.size || c.written, pct: 100, bytesPerSec: 0, etaSec: 0, state: 'done', detail: undefined })
    ctls.delete(c.id)
    window.setTimeout(() => { if (uploadStore.get(c.id)?.state === 'done') uploadStore.remove(c.id) }, DONE_LINGER_MS)
  } catch (e) {
    if (c.cancelled) return
    // pauză / eroare finală: comitem ce s-a scris, ca un reload (sau un laptop închis) să nu piardă
    // nimic din ce e deja aici. Eşecul checkpoint-ului nu ascunde eroarea originală.
    if (c.handle && c.writable) { try { await checkpoint(c) } catch { c.writable = null } }
    const pos = c.handle ? c.committed : c.written
    if (e instanceof PausedSignal || c.paused) {
      publish(c, { pos, pct: pctOf(c, pos), state: 'paused', bytesPerSec: 0, etaSec: null })
      return
    }
    publish(c, { pos, pct: pctOf(c, pos), state: 'err', error: errorText(e), bytesPerSec: 0, etaSec: null,
                 restartable: e instanceof ChangedSignal && (!!c.handle || !!c.parts) })
  } finally {
    c.running = false
    c.abort = null
  }
}

export interface StartDownloadOpts {
  hostId: number; hostName: string; path: string; name?: string; size?: number
  /** descărcare în bloc (3.5.5): destinaţia e deja deschisă (fişier în folderul ales o dată cu
      showDirectoryPicker) — fără selector per fişier */
  writable?: WritableLike | null
  /** handle-ul fişierului din `writable` (bloc cu folder ales): permite checkpoint-uri şi reluarea
      după reload; fără el, writable-ul e de unică folosinţă (doar reluare în sesiune) */
  handle?: SaveHandle | null
  /** în bloc FĂRĂ selector de folder: Blob direct (un al doilea showSaveFilePicker n-ar mai avea
      gestul click-ului şi ar eşua oricum) */
  noPicker?: boolean
}

/** Porneşte (sau reia) un download prin motor. `showSaveFilePicker` TREBUIE chemat primul (cât încă
    avem activarea de gest a click-ului), înainte de orice await care ar consuma-o. Întoarce id-ul
    job-ului, sau null dacă omul a anulat selectorul de fişier. */
export async function startDownload(o: StartDownloadOpts): Promise<string | null> {
  const name = o.name ?? baseName(o.path)
  const size = o.size ?? 0
  const id = dlId(o.hostId, o.path)
  const existing = ctls.get(id)
  if (existing && existing.running) return id

  // alegerea destinaţiei: File System Access pentru fişiere mari (streaming pe disc), altfel Blob.
  let writable: WritableLike | null = o.writable ?? null
  let handle: SaveHandle | null = o.writable ? (o.handle ?? null) : null
  const wantFsa = !writable && !o.noPicker && canFsa() && (size === 0 || size > DL_FSA_PREFER || size > DL_BLOB_MAX)
  if (!writable && (!canFsa() || o.noPicker) && size > DL_BLOB_MAX) {
    throw new Error(tr('transfers.dlTooBig', { name }))
  }
  if (wantFsa) {
    try {
      handle = await (window as PickerWin).showSaveFilePicker!({ suggestedName: name })
      writable = await handle.createWritable()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return null   // omul a închis selectorul
      writable = null; handle = null                                         // alt eşec: cădem pe Blob
    }
  }

  // un rând rămas (întrerupt dintr-o sesiune anterioară, sau eşuat) pentru acelaşi fişier: descărcarea
  // nouă îl înlocuieşte — înregistrarea veche (alt handle) nu mai are ce relua
  if (existing) dropRec(existing)
  const c: DlCtl = existing ?? {
    id, hostId: o.hostId, hostName: o.hostName, path: o.path, name, size,
    cancelled: false, paused: false, running: false, abort: null, abortWhy: null,
    writable: null, parts: null, written: 0,
    handle: null, committed: 0, ckAt: 0, etag: null, mtime: null, owner: null, recKey: null, created: 0,
    touchedDisk: false, handleSaved: false,
  }
  c.hostName = o.hostName || c.hostName
  c.name = name
  c.size = size
  c.writable = writable
  c.handle = writable ? handle : null
  c.parts = writable ? null : []
  c.written = 0
  c.committed = 0
  c.ckAt = Date.now()
  c.etag = null
  c.mtime = null
  c.owner = currentUser
  c.touchedDisk = false
  c.handleSaved = false
  ctls.set(id, c)
  uploadStore.remove(id)
  await runLoop(c)
  return id
}

export function pauseDownload(id: string): void {
  const c = ctls.get(id)
  if (!c || !c.running || c.paused) return
  c.paused = true
  c.abortWhy = 'pause'
  c.abort?.abort()
}

/** Cere permisiunea de scriere pe handle — SINCRON din click (requestPermission vrea gestul omului,
    deci e primul apel, înaintea oricărui await), apoi rulează `then`. Fără handle: direct. */
function withWritePermission(c: DlCtl, then: () => Promise<void>): void {
  const h = c.handle
  const req: Promise<PermissionState> = h?.requestPermission
    ? h.requestPermission({ mode: 'readwrite' }).catch(() => 'denied' as PermissionState)
    : Promise.resolve('granted')
  void (async () => {
    if ((await req) !== 'granted') {
      // rămâne reluabil: un nou click pe Resume întreabă din nou
      publish(c, { detail: tr('transfers.dlPermDenied') })
      return
    }
    await then()
  })()
}

export function resumeDownload(id: string): void {
  const c = ctls.get(id)
  if (!c || c.running) return
  // Blob: avem feliile în memorie, continuăm de la c.written. FS Access: writable-ul s-a comis la
  // pauză; runLoop îl redeschide la checkpoint (permisiunea o re-confirmăm din click).
  c.paused = false
  withWritePermission(c, () => runLoop(c))
}

/** Handle-ul unui job restaurat se citeşte din IndexedDB abia acum (click pe Resume / Start over).
    requestPermission vine DUPĂ această citire: activarea tranzitorie a click-ului ţine ~5 s în
    Chromium, iar o citire IDB durează milisecunde. Fără handle → explicaţia pe rând. */
function withHandle(c: DlCtl, then: () => void): void {
  if (c.handle) { then(); return }
  const k = c.recKey
  if (!k) { publish(c, { detail: tr('transfers.dlFileGone') }); return }
  void store().handle(k).then((h) => {
    if (!h) { publish(c, { detail: tr('transfers.dlFileGone') }); return }
    c.handle = h
    then()
  }).catch(() => publish(c, { detail: tr('transfers.dlFileGone') }))
}

/** Reluarea unui download ÎNTRERUPT într-o sesiune anterioară (rândul „Întrerupt"). Din click:
    handle → permisiune → mărimea reală de pe disc → reluare de la min(checkpoint, mărime). */
export function resumeInterrupted(id: string): void {
  const c = ctls.get(id)
  if (!c || c.running) return
  withHandle(c, () => withWritePermission(c, async () => {
    let actual: number
    try {
      const f = c.handle!.getFile ? await c.handle!.getFile() : null
      actual = f ? f.size : c.committed
    } catch {
      // fişierul parţial a fost mutat/şters: nu mai avem ce continua (şi nici unde rescrie)
      publish(c, { detail: tr('transfers.dlFileGone') })
      return
    }
    c.committed = resumeOffset(c.committed, actual)
    c.written = c.committed
    publish(c, { pos: c.committed, pct: pctOf(c, c.committed), detail: undefined })
    await runLoop(c)
  }))
}

/** „Start over": de la ZERO, în ACELAŞI fişier (trunchiat), cu validatorul re-învăţat — pentru un
    fişier schimbat pe host. Blob: feliile din memorie se aruncă. */
export function restartDownload(id: string): void {
  const c = ctls.get(id)
  if (!c || c.running) return
  const go = () => withWritePermission(c, async () => {
    c.etag = null
    c.mtime = null
    c.committed = 0
    c.written = 0
    c.paused = false
    if (c.handle) c.writable = null          // runLoop redeschide la 0: fişier nou, gol
    else if (c.parts) c.parts = []
    else return                              // writable de unică folosinţă: nu se poate rescrie
    c.owner = currentUser
    publish(c, { pos: 0, pct: 0, detail: undefined, restartable: undefined, error: undefined })
    await runLoop(c)
  })
  if (c.parts) go(); else withHandle(c, go)
}

export function retryDownload(id: string): void {
  if (arCtls.has(id)) { retryArchive(id); return }
  const c = ctls.get(id)
  if (!c) return
  if (c.running) { if (uploadStore.get(id)?.state === 'stalled') { c.abortWhy = 'stall'; c.abort?.abort() } return }
  withWritePermission(c, () => runLoop(c))
}

/** Şterge fişierul parţial pe care l-am scris noi (doar dacă am comis măcar un checkpoint — altfel
    fişierul ales e încă cel vechi al omului şi nu-l atingem). */
async function removePartial(h: SaveHandle): Promise<void> {
  try {
    if (h.remove) await h.remove()
    else await (await h.createWritable()).close()       // fallback: trunchiat la 0
  } catch { /* fără permisiune / deja şters: rămâne pe disc */ }
}

export function cancelDownload(id: string): void {
  if (arCtls.has(id)) { cancelArchive(id); return }
  const c = ctls.get(id)
  if (c) {
    c.cancelled = true
    c.abortWhy = 'cancel'
    c.abort?.abort()
    // închidem/abandonăm destinaţia ca să nu rămână un fişier parţial pe disc
    try { void c.writable?.abort?.() } catch { /* noop */ }
    if (c.handle && c.touchedDisk) void removePartial(c.handle)
    dropRec(c)
    c.writable = null; c.parts = null
    ctls.delete(id)
  }
  uploadStore.remove(id)
}

export const dismissDownload = (id: string): void => {
  const ar = arCtls.get(id)
  if (ar) { if (!ar.running) arCtls.delete(id); uploadStore.remove(id); return }
  const c = ctls.get(id)
  // dismiss explicit = nu mai vrem reluarea: înregistrarea din IndexedDB pleacă (fişierul parţial
  // rămâne pe disc, unde l-a ales omul)
  if (c && !c.running) { dropRec(c); ctls.delete(id) }
  uploadStore.remove(id)
}

/** „Discard" pe un rând întrerupt: uită job-ul; fişierul parţial se şterge doar dacă avem deja
    permisiunea (fără un prompt doar ca să ştergem) — altfel rămâne pe disc. */
export function discardDownload(id: string): void {
  const c = ctls.get(id)
  if (c && !c.running) {
    const h = c.handle
    if (h && c.committed > 0 && h.queryPermission) {
      void h.queryPermission({ mode: 'readwrite' }).then((p) => { if (p === 'granted') void removePartial(h) }).catch(() => {})
    }
    dropRec(c)
    ctls.delete(id)
  }
  uploadStore.remove(id)
}

/** La pornire (autentificat): job-urile FS Access rămase neterminate ale contului curent apar ca
    „Întrerupt" — Resume / Discard. Expiratele (7 zile) şi cele stricate se şterg. */
export async function restoreInterruptedDownloads(now = Date.now()): Promise<void> {
  const uid = currentUser
  if (uid == null) return
  const recs = await loadForUser(store(), uid, now)
  if (currentUser !== uid) return                    // logout între timp
  for (const r of recs) {
    const id = dlId(r.hostId, r.path)
    if (ctls.has(id) || uploadStore.get(id)) continue
    const c: DlCtl = {
      id, hostId: r.hostId, hostName: r.hostName, path: r.path, name: r.name, size: r.size,
      cancelled: false, paused: false, running: false, abort: null, abortWhy: null,
      writable: null, parts: null, written: r.checkpoint,
      // handle-ul NU se citeşte aici: abia la Resume (vezi DlRecStore — un handle deserializat într-un
      // profil off-the-record a oprit browserul în teste; nu riscăm asta la fiecare încărcare)
      handle: null, committed: r.checkpoint, ckAt: now, etag: r.etag, mtime: r.mtime, owner: r.userId,
      recKey: r.key, created: r.created, touchedDisk: r.checkpoint > 0, handleSaved: true,
    }
    ctls.set(id, c)
    publish(c, { pos: r.checkpoint, pct: pctOf(c, r.checkpoint), state: 'orphan', attempts: 0 })
  }
}

/** Sesiunea web s-a terminat (expirare): ascundem rândurile întrerupte (înregistrările rămân —
    revin la următorul login al ACELUIAŞI cont) şi nu mai persistăm nimic. */
export function hideInterruptedDownloads(): void {
  currentUser = null
  for (const [id, c] of ctls) {
    if (!c.running && uploadStore.get(id)?.state === 'orphan') { ctls.delete(id); uploadStore.remove(id) }
  }
}

/** Logout explicit: uită descărcările întrerupte ale contului (IndexedDB + rânduri). */
export async function forgetDownloads(): Promise<void> {
  const uid = currentUser
  hideInterruptedDownloads()
  for (const c of ctls.values()) if (c.owner === uid) c.recKey = null
  if (uid != null) await forgetUser(store(), uid)
}

// ── folder ca .tgz prin motor (3.5.5) ─────────────────────────────────────────────────────
// Înainte, un `<a download>` simplu spre /fs/archive: fără progres, fără Cancel, iar o eroare a
// tar-ului (folder prea mare, permisiuni) apărea ca un download „eşuat" fără niciun motiv. Acum e
// un rând în Transferuri: „se pregăteşte arhiva pe host…" cât rulează tar-ul (până la 5 min — de
// aceea watchdog-ul pe octeţi porneşte abia după antete), apoi octeţii primiţi (mărimea arhivei
// nu se ştie dinainte, deci nu există %), Cancel, şi eroarea SERVERULUI (cod tradus) la eşec.
// O arhivă generată din mers NU se poate relua (fiecare cerere produce alt tar.gz) — rândul o
// spune, iar Retry o reporneşte de la zero (trunchiem destinaţia).
interface ArCtl {
  id: string; hostId: number; hostName: string; path: string; name: string
  handle: SaveHandle | null          // FS Access: re-deschis (trunchiat) la Retry
  writable: WritableLike | null
  parts: Uint8Array[] | null         // Blob (plafon DL_BLOB_MAX)
  written: number
  running: boolean
  cancelled: boolean
  abort: AbortController | null
  abortWhy: 'stall' | 'cancel' | null
}
const arCtls = new Map<string, ArCtl>()
const arId = (hostId: number, path: string) => `ar_${hostId}_${path}`

function arPublish(c: ArCtl, p: Partial<UploadJob>) {
  if (uploadStore.get(c.id)) { uploadStore.patch(c.id, p); return }
  uploadStore.set({
    id: c.id, dir: 'down', kind: 'archive', hostId: c.hostId, hostName: c.hostName, dest: c.path, name: c.name,
    size: 0, pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running', attempts: 1, ...p,
  })
}

async function runArchive(c: ArCtl): Promise<void> {
  if (c.running) return
  c.running = true
  c.cancelled = false
  const speed = speedTracker()
  let shownAt = 0
  const ac = new AbortController()
  c.abort = ac
  c.abortWhy = null
  let lastByteAt = Date.now()
  let headers = false
  let stalled = false
  const tick = window.setInterval(() => {
    if (!headers) return                     // tar-ul încă rulează pe host: tăcerea e normală
    const idle = Date.now() - lastByteAt
    if (idle >= STALL_ABORT_MS) { c.abortWhy = 'stall'; ac.abort() }
    else if (idle >= STALL_WARN_MS && !stalled) { stalled = true; speed.reset(); arPublish(c, { state: 'stalled', bytesPerSec: 0 }) }
  }, 5000)
  try {
    arPublish(c, { state: 'running', pos: 0, pct: 0, error: undefined, detail: tr('transfers.arPreparing') })
    const resp = await fetch(`/api/hosts/${c.hostId}/fs/archive?path=${encodeURIComponent(c.path)}`,
      { credentials: 'same-origin', signal: ac.signal })
    if (resp.status === 401) throw new Error(tr('jobs.signInAgain'))
    if (!resp.ok) {
      // eroarea SERVERULUI (tar eşuat, folder prea mare, permisiuni), cu codul ei tradus
      let detail = resp.statusText
      try { detail = (await resp.json()).detail ?? detail } catch { /* corp ne-JSON */ }
      throw new Error(errText(new ApiError(resp.status, detail, resp.headers.get('X-WebTerm-Error') ?? ''), tr))
    }
    headers = true
    lastByteAt = Date.now()
    arPublish(c, { detail: tr('transfers.arNoResume') })
    const reader = resp.body?.getReader()
    if (!reader) throw new Error(tr('jobs.errNetwork'))
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      if (!value || !value.length) continue
      lastByteAt = Date.now()
      if (stalled) { stalled = false; arPublish(c, { state: 'running' }) }
      if (c.writable) await c.writable.write(value)
      else if (c.parts) {
        if (c.written + value.length > DL_BLOB_MAX) throw new Error(tr('transfers.dlTooBig', { name: c.name }))
        c.parts.push(value)
      }
      c.written += value.length
      const now = Date.now()
      const bps = speed.sample(c.written, now)
      if (now - shownAt >= 250) { shownAt = now; arPublish(c, { pos: c.written, bytesPerSec: bps }) }
    }
    if (c.writable) { await c.writable.close(); c.writable = null }
    else if (c.parts) {
      const url = URL.createObjectURL(new Blob(c.parts as BlobPart[], { type: 'application/gzip' }))
      c.parts = null
      const a = document.createElement('a')
      a.href = url; a.download = c.name; a.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
    }
    arPublish(c, { pos: c.written, size: c.written, pct: 100, bytesPerSec: 0, etaSec: 0, state: 'done', detail: undefined })
    arCtls.delete(c.id)
    window.setTimeout(() => { if (uploadStore.get(c.id)?.state === 'done') uploadStore.remove(c.id) }, DONE_LINGER_MS)
  } catch (e) {
    if (c.cancelled) return
    let msg = e instanceof Error ? e.message : String(e)
    if (ac.signal.aborted && c.abortWhy === 'stall') msg = tr('jobs.errStall')
    else if (e instanceof TypeError) msg = tr('jobs.errNetwork')
    arPublish(c, { pos: c.written, state: 'err', error: msg, bytesPerSec: 0, detail: tr('transfers.arNoResume') })
  } finally {
    window.clearInterval(tick)
    c.running = false
    c.abort = null
  }
}

export interface StartArchiveOpts {
  hostId: number; hostName: string; path: string; name?: string
  writable?: WritableLike | null
  noPicker?: boolean
}

/** Folder → .tgz prin motor. Selectorul de fişier (FS Access) se cere PRIMUL, cât încă avem gestul
    click-ului; fără FS Access → Blob în memorie (plafon DL_BLOB_MAX, verificat pe măsură ce curge).
    Întoarce id-ul rândului, sau null dacă omul a închis selectorul. */
export async function startArchiveDownload(o: StartArchiveOpts): Promise<string | null> {
  const name = o.name ?? `${baseName(o.path.replace(/\/+$/, ''))}.tgz`
  const id = arId(o.hostId, o.path)
  const existing = arCtls.get(id)
  if (existing?.running) return id
  let handle: SaveHandle | null = null
  let writable: WritableLike | null = o.writable ?? null
  if (!writable && !o.noPicker && canFsa()) {
    try {
      handle = await (window as PickerWin).showSaveFilePicker!({ suggestedName: name })
      writable = await handle.createWritable()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return null
      handle = null; writable = null                     // alt eşec: Blob
    }
  }
  const c: ArCtl = {
    id, hostId: o.hostId, hostName: o.hostName, path: o.path, name, handle, writable,
    parts: writable ? null : [], written: 0, running: false, cancelled: false, abort: null, abortWhy: null,
  }
  arCtls.set(id, c)
  uploadStore.remove(id)
  await runArchive(c)
  return id
}

/** Retry = de la ZERO (o arhivă din mers nu are offset-uri stabile): trunchiem destinaţia.
    Un writable deschis din folderul ales în bloc (fără handle) nu se poate redeschide: Blob. */
export function retryArchive(id: string): void {
  const c = arCtls.get(id)
  if (!c || c.running) return
  void (async () => {
    c.written = 0
    c.writable = null
    c.parts = []
    if (c.handle) {
      try { c.writable = await c.handle.createWritable(); c.parts = null } catch { /* Blob */ }
    }
    await runArchive(c)
  })()
}

export function cancelArchive(id: string): void {
  const c = arCtls.get(id)
  if (c) {
    c.cancelled = true
    c.abortWhy = 'cancel'
    c.abort?.abort()                 // conexiunea închisă → gateway-ul şterge temp-ul .wtarch de pe host
    try { void c.writable?.abort?.() } catch { /* noop */ }
    c.writable = null; c.parts = null
    arCtls.delete(id)
  }
  uploadStore.remove(id)
}

// ── descărcare în BLOC (selecţie multiplă, 3.5.5) ───────────────────────────────────────────
/** `nume (n).ext` — aceeaşi regulă ca `fscopy.rename_candidate` de pe gateway: extensiile compuse
    rămân întregi (`a.tar.gz` → `a (1).tar.gz`), dotfile-urile primesc sufixul la coadă. */
export function numberedName(name: string, n: number): string {
  const m = name.match(/^(.+?)(\.tar\.(?:gz|bz2|xz|zst))$/i)
  if (m) return `${m[1]} (${n})${m[2]}`
  const dot = name.lastIndexOf('.')
  return dot > 0 ? `${name.slice(0, dot)} (${n})${name.slice(dot)}` : `${name} (${n})`
}

export interface BulkItem { hostId: number; hostName: string; path: string; name: string; size: number; dir: boolean }
export const BULK_PARALLEL = 3

/** Un job de transfer PER element: fişierele prin motorul de download (Range, pauză, retry),
    folderele prin motorul de arhivă. Cu showDirectoryPicker (Chrome/Edge) folderul de destinaţie
    se alege O DATĂ şi fiecare fişier curge direct pe disc (nume ocupat → `nume (1).ext`, nu
    suprascriere tăcută); fără el, Blob per element (plafon DL_BLOB_MAX — ce e mai mare se
    raportează, nu porneşte). Cel mult BULK_PARALLEL în zbor. Întoarce erorile de pornire (deja
    traduse); null = omul a anulat selectorul de folder. */
export async function startDownloads(items: BulkItem[]): Promise<string[] | null> {
  if (items.length === 1) {
    // un singur element: exact calea obişnuită (selector de fişier când e cazul)
    const it = items[0]
    try {
      if (it.dir) await startArchiveDownload({ hostId: it.hostId, hostName: it.hostName, path: it.path })
      else await startDownload({ hostId: it.hostId, hostName: it.hostName, path: it.path, name: it.name, size: it.size })
      return []
    } catch (e) { return [`${it.name}: ${e instanceof Error ? e.message : String(e)}`] }
  }
  let dir: DirHandle | null = null
  const w = window as PickerWin
  if (typeof w.showDirectoryPicker === 'function') {
    try { dir = await w.showDirectoryPicker({ mode: 'readwrite' }) } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return null
      dir = null
    }
  }
  const errors: string[] = []
  const used = new Set<string>()
  const free = async (d: DirHandle, name: string): Promise<string> => {
    for (let i = 0; i < 1000; i++) {
      const cand = i === 0 ? name : numberedName(name, i)
      if (used.has(cand)) continue
      try { await d.getFileHandle(cand) } catch { used.add(cand); return cand }   // NotFound = liber
    }
    throw new Error(tr('files.genericErr'))
  }
  const queue = [...items]
  const worker = async () => {
    for (let it = queue.shift(); it; it = queue.shift()) {
      try {
        let name = it.dir ? `${it.name}.tgz` : it.name
        let writable: WritableLike | null = null
        let handle: SaveHandle | null = null
        if (dir) {
          name = await free(dir, name)
          handle = await dir.getFileHandle(name, { create: true })
          writable = await handle.createWritable()
        }
        if (it.dir) await startArchiveDownload({ hostId: it.hostId, hostName: it.hostName, path: it.path, name, writable, noPicker: true })
        // handle-ul fişierului: checkpoint-uri + reluare după reload şi pentru descărcarea în bloc
        else await startDownload({ hostId: it.hostId, hostName: it.hostName, path: it.path, name, size: it.size, writable, handle, noPicker: true })
      } catch (e) {
        errors.push(`${it.name}: ${e instanceof Error ? e.message : String(e)}`)
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(BULK_PARALLEL, items.length) }, worker))
  return errors
}
