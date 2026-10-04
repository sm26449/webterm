/* Motorul de DOWNLOAD host→browser (transfers phase 2) — simetric cu lib/uploads.ts, prin acelaşi
   store global (uploadStore) şi aceeaşi bară/chip, dar în sens invers (`dir: 'down'`).

   De ce prin motor, nu un simplu `<a download>`: un link clasic nu are progres, nu se poate pune pe
   pauză, iar o cădere de reţea la 90% dintr-un fişier de 40 GB îl aruncă de la zero, fără niciun
   feedback. Aici: felii cu `Range`, watchdog pe octeţi (stall vizibil + abort), retry cu backoff,
   pauză/reluare, şi salvare prin File System Access API (streaming pe disc, fişiere uriaşe) când e
   disponibilă — altfel un Blob în memorie (cost de RAM: cerem FS Access pentru fişiere foarte mari).

   Agentul NU se atinge: gateway-ul serveşte deja `GET /fs/download` şi acum răspunde la `Range`
   (HTTP 206) peste `fs_read` (care citeşte de la orice offset). Reluarea e ÎN SESIUNE (continuă de la
   octeţii deja scrişi); după un reload nu putem relua (nu persistăm handle-ul de fişier) — rândul
   dispare, ca la un download de browser întrerupt. */
import { tStatic } from './i18n'
import { backoffMs, baseName, etaSec, MAX_ATTEMPTS, speedTracker, STALL_ABORT_MS, STALL_WARN_MS } from './uploads'
import { UploadJob, uploadStore } from './uploadStore'

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
type WritableLike = { write(d: BufferSource): Promise<void>; close(): Promise<void>; abort?(): Promise<void> }
type SaveHandle = { createWritable(): Promise<WritableLike> }
type PickerWin = Window & { showSaveFilePicker?: (o?: { suggestedName?: string }) => Promise<SaveHandle> }

export const canFsa = (): boolean =>
  typeof window !== 'undefined' && typeof (window as PickerWin).showSaveFilePicker === 'function'

class AuthLost extends Error { constructor() { super('unauth') } }
class StallAbort extends Error { constructor() { super('stall') } }
class PausedSignal extends Error { constructor() { super('paused') } }

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
  written: number                  // octeţi deja salvaţi (punctul de reluare în sesiune)
}
const ctls = new Map<string, DlCtl>()

/** id stabil per (host, cale): un re-download al aceluiaşi fişier regăseşte rândul (nu se dublează) */
const dlId = (hostId: number, path: string) => `dl_${hostId}_${path}`

function publish(c: DlCtl, p: Partial<UploadJob>) {
  if (uploadStore.get(c.id)) { uploadStore.patch(c.id, p); return }
  uploadStore.set({
    id: c.id, dir: 'down', hostId: c.hostId, hostName: c.hostName, dest: c.path, name: c.name, size: c.size,
    pos: 0, pct: 0, bytesPerSec: 0, etaSec: null, state: 'running', attempts: 1, ...p,
  })
}

const isAuthErr = (e: unknown) => e instanceof AuthLost
function errorText(e: unknown): string {
  if (isAuthErr(e)) return tr('jobs.signInAgain')
  if (e instanceof StallAbort) return tr('jobs.errStall')
  if (e instanceof Error) {
    if (e.message === 'network') return tr('jobs.errNetwork')
    if (/^\d{3}$/.test(e.message)) return tr('jobs.errHttp', { code: e.message })
  }
  return tr('files.genericErr')
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
  const fetchFrom = async (): Promise<boolean> => {   // true = s-a terminat fişierul
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
      if (resp.status === 416) return true                 // nimic de citit = deja complet
      if (!(resp.status === 206 || resp.status === 200)) throw new Error(String(resp.status))
      // Serverul a ignorat Range-ul (200, nu 206) deşi am cerut de la >0: fără suport de Range nu
      // putem relua — repornim de la zero (truncăm ce-am scris). Rar (doar agenţi fără fs_stat).
      if (c.written > 0 && resp.status === 200) {
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
        }
      }
      return c.size ? c.written >= c.size : true
    } catch (e) {
      if (ac.signal.aborted) {
        if (c.abortWhy === 'stall') throw new StallAbort()
        if (c.cancelled || c.abortWhy === 'cancel') throw new Error('abort')
        throw new PausedSignal()                           // pauză
      }
      if (e instanceof AuthLost) throw e
      if (e instanceof TypeError) throw new Error('network')   // fetch de reţea
      throw e
    } finally {
      window.clearInterval(tick)
      c.abort = null
    }
  }

  try {
    publish(c, { state: 'running', attempts: 1, error: undefined })
    setPos(true)
    let tries = 0
    for (;;) {
      if (c.cancelled) return
      if (c.paused) throw new PausedSignal()
      try {
        const finished = await fetchFrom()
        if (finished) break
        tries = 0                                          // progres bun: resetăm contorul de eşec
      } catch (e) {
        if (c.cancelled) return
        if (c.paused || e instanceof PausedSignal) throw new PausedSignal()
        if (isAuthErr(e)) throw e
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
    if (c.writable) { await c.writable.close(); c.writable = null }
    else if (c.parts) {
      const blob = new Blob(c.parts as BlobPart[], { type: 'application/octet-stream' })
      c.parts = null
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = c.name; a.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
    }
    publish(c, { pos: c.size || c.written, pct: 100, bytesPerSec: 0, etaSec: 0, state: 'done' })
    ctls.delete(c.id)
    window.setTimeout(() => { if (uploadStore.get(c.id)?.state === 'done') uploadStore.remove(c.id) }, DONE_LINGER_MS)
  } catch (e) {
    if (c.cancelled) return
    if (e instanceof PausedSignal || c.paused) {
      publish(c, { pos: c.written, state: 'paused', bytesPerSec: 0, etaSec: null })
      return
    }
    publish(c, { pos: c.written, state: 'err', error: errorText(e), bytesPerSec: 0, etaSec: null })
  } finally {
    c.running = false
    c.abort = null
  }
}

export interface StartDownloadOpts { hostId: number; hostName: string; path: string; name?: string; size?: number }

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
  let writable: WritableLike | null = null
  const wantFsa = canFsa() && (size === 0 || size > DL_FSA_PREFER || size > DL_BLOB_MAX)
  if (!canFsa() && size > DL_BLOB_MAX) {
    throw new Error(tr('transfers.dlTooBig', { name }))
  }
  if (wantFsa) {
    try {
      const handle = await (window as PickerWin).showSaveFilePicker!({ suggestedName: name })
      writable = await handle.createWritable()
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return null   // omul a închis selectorul
      writable = null                                                        // alt eşec: cădem pe Blob
    }
  }

  const c: DlCtl = existing ?? {
    id, hostId: o.hostId, hostName: o.hostName, path: o.path, name, size,
    cancelled: false, paused: false, running: false, abort: null, abortWhy: null,
    writable: null, parts: null, written: 0,
  }
  c.hostName = o.hostName || c.hostName
  c.writable = writable
  c.parts = writable ? null : []
  c.written = 0
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

export function resumeDownload(id: string): void {
  const c = ctls.get(id)
  if (!c || c.running) return
  // Blob: avem feliile în memorie, continuăm de la c.written. FS Access: stream-ul e încă deschis.
  c.paused = false
  void runLoop(c)
}

export function retryDownload(id: string): void {
  const c = ctls.get(id)
  if (!c) return
  if (c.running) { if (uploadStore.get(id)?.state === 'stalled') { c.abortWhy = 'stall'; c.abort?.abort() } return }
  void runLoop(c)
}

export function cancelDownload(id: string): void {
  const c = ctls.get(id)
  if (c) {
    c.cancelled = true
    c.abortWhy = 'cancel'
    c.abort?.abort()
    // închidem/abandonăm destinaţia ca să nu rămână un fişier parţial pe disc
    try { void c.writable?.abort?.() } catch { /* noop */ }
    c.writable = null; c.parts = null
    ctls.delete(id)
  }
  uploadStore.remove(id)
}

export const dismissDownload = (id: string): void => {
  const c = ctls.get(id)
  if (c && !c.running) ctls.delete(id)
  uploadStore.remove(id)
}
