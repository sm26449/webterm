/* Copiere host → host (3.5.5) în widgetul de Transferuri. Copierea propriu-zisă rulează pe
   GATEWAY (`POST /api/fs/copy`, vezi gateway/app/fscopy.py) — octeţii nu trec prin browser. Aici
   doar o pornim, îi oglindim starea în uploadStore (polling `GET /api/fs/copy/{id}`, ~1 s) şi
   dăm Cancel (`DELETE`) / Retry (job nou pe server cu ce a eşuat, aceleaşi opţiuni).

   Foldere (3.6, agent 58): serverul copiază tot arborele; rândul arată fişierul în lucru, iar la
   final un rezumat (foldere, sărite, link-uri/fişiere speciale necopiate, permisiuni păstrate sau
   nu — destinaţie cu agent < 58). Retry-ul e pe SERVER (`POST /api/fs/copy/{id}/retry`): un folder
   se îmbină în exact folderul de data trecută, deci nu re-trimitem căi din browser.

   Rândul e `dir: 'copy'`: fără pauză (serverul nu are), fără „Insert path". Un reload al paginii
   pierde rândul, dar NU job-ul: copierea continuă pe server (n-o legăm de tab). Partea pură
   (`copyPatch`: starea serverului → câmpurile rândului) e testată în copyjobs.test.ts. */
import { api, ApiError, errText, isStepupError } from './api'
import { tStatic } from './i18n'
import { UploadJob, uploadStore } from './uploadStore'

type T = (k: string, v?: Record<string, string | number>) => string
const tr: T = (k, vars) => {
  let s = tStatic(k)
  if (vars) for (const [kk, v] of Object.entries(vars)) s = s.split('{' + kk + '}').join(String(v))
  return s
}

export type Conflict = 'skip' | 'overwrite' | 'rename'

export interface CopyFileRow {
  src: string; name: string; dst: string; size: number; done: number; state: string; error?: string; code?: string
  kind?: 'file' | 'dir' | 'link'; note?: string; note_code?: string
}
export interface CopyNote { code: string; msg: string }
export interface CopyStatus {
  job_id: string
  state: 'running' | 'done' | 'failed' | 'cancelled'
  src_host: number; src_host_name: string
  dst_host: number; dst_host_name: string
  dst_dir: string
  on_conflict: Conflict
  total_bytes: number; done_bytes: number
  files_total: number; files_done: number; files_skipped: number; files_failed: number
  errors: CopyFileRow[]
  // 3.6 (lipsesc pe un gateway mai vechi — tratate opţional)
  folders_total?: number; folders_done?: number
  modes?: boolean | null
  notes?: CopyNote[]
  current?: string[]
  noted?: CopyFileRow[]; noted_total?: number
}

export interface StartCopyOpts {
  srcHost: number; srcName: string
  dstHost: number; dstName: string
  paths: string[]
  dstDir: string
  onConflict: Conflict
}

const POLL_MS = 1000
const DONE_LINGER_MS = 20_000
export const copyRowId = (jobId: string) => `cp_${jobId}`

/** Textul unei erori per fişier: codul serverului tradus (`err.<code>`), altfel mesajul brut. */
export function fileErrText(e: CopyFileRow, t: T): string {
  if (e.code) {
    const k = 'err.' + e.code
    const s = t(k)
    if (s !== k) return s
  }
  return e.error || t('files.genericErr')
}

/** Rezumatul notelor: link-uri / fişiere speciale necopiate, permisiuni neaplicate, destinaţie
    fără păstrarea permisiunilor (agent < 58). `noted` vine plafonat la 50 de rânduri de server —
    numărăm ce vedem, iar restul (noted_total) intră la „necopiate". */
/** câte rânduri au fost lăsate deliberat necopiate (link-uri / fişiere speciale) — tot „sărite"
    pentru server (`files_skipped`), dar numărate o singură dată în rezumat */
export function notCopiedCount(s: CopyStatus): number {
  const noted = s.noted ?? []
  const modeFailed = noted.filter((n) => n.note_code === 'copy.modeFailed').length
  return Math.max(0, (s.noted_total ?? noted.length) - modeFailed)
}

export function copyNotes(s: CopyStatus, t: T): string[] {
  const out: string[] = []
  const noted = s.noted ?? []
  const modeFailed = noted.filter((n) => n.note_code === 'copy.modeFailed').length
  const notCopied = notCopiedCount(s)
  if (notCopied) out.push(t('transfers.copyNotCopied', { n: notCopied }))
  if (modeFailed) out.push(t('transfers.copyModeFailed', { n: modeFailed }))
  if ((s.notes ?? []).some((n) => n.code === 'copy.noModes')) out.push(t('transfers.copyNoModes'))
  return out
}

/** Starea serverului → câmpurile rândului din widget. Pur (testat):
    - running → running, % pe octeţi (0 până se ştie totalul), cu fişierul în lucru („→ nume");
    - done → done (100%), cu „N sărite" + notele (necopiate, permisiuni) în detaliu;
    - failed → err, cu prima eroare (numele fişierului + motivul tradus) şi câte au eşuat;
    - cancelled → cancelled. */
export function copyPatch(s: CopyStatus, t: T): Partial<UploadJob> {
  const pct = s.total_bytes > 0 ? Math.min(100, Math.round((s.done_bytes / s.total_bytes) * 100))
    : (s.state === 'done' ? 100 : 0)
  const parts = [t('transfers.copyFiles', { done: s.files_done, total: s.files_total })]
  if (s.folders_total) parts.push(t('transfers.copyFolders', { done: s.folders_done ?? 0, total: s.folders_total }))
  // un symlink dintr-un folder e şi „sărit" (files_skipped) şi „necopiat" (nota): în capturile 3.5.18
  // un singur link apărea ca „skipped: 1 · not copied: 1" — două lucruri. „Sărite" = doar cele care
  // existau deja pe destinaţie (regula Skip).
  const skipped = Math.max(0, s.files_skipped - (s.state === 'running' ? 0 : notCopiedCount(s)))
  if (skipped) parts.push(t('transfers.copySkipped', { n: skipped }))
  if (s.files_failed) parts.push(t('transfers.copyFailed', { n: s.files_failed }))
  if (s.state === 'running' && s.current?.length) parts.unshift(`→ ${s.current.join(', ')}`)
  else parts.push(...copyNotes(s, t))
  const base: Partial<UploadJob> = {
    size: s.total_bytes, pos: s.done_bytes, pct, detail: parts.join(' · '), dest: s.dst_dir,
  }
  if (s.state === 'running') return { ...base, state: 'running' }
  if (s.state === 'cancelled') return { ...base, state: 'cancelled', bytesPerSec: 0, etaSec: null }
  if (s.state === 'failed') {
    const e = s.errors[0]
    const why = e ? `${e.name}: ${fileErrText(e, t)}` : t('files.genericErr')
    return { ...base, state: 'err', bytesPerSec: 0, etaSec: null, error: why }
  }
  return { ...base, state: 'done', pct: 100, bytesPerSec: 0, etaSec: 0 }
}

/** Eticheta rândului: o cale → numele ei (fişier sau folder); mai multe → „N elemente". */
export function copyLabel(paths: string[], t: T): string {
  if (paths.length === 1) {
    const p = paths[0].replace(/\/+$/, '')
    return p.slice(p.lastIndexOf('/') + 1)
  }
  return t('transfers.copyNFiles', { n: paths.length })
}

interface CopyCtl { opts: StartCopyOpts; jobId: string; timer: number | null; lastPos: number; lastAt: number; label: string }
const ctls = new Map<string, CopyCtl>()          // rowId → controller

function poll(rowId: string): void {
  const c = ctls.get(rowId)
  if (!c) return
  c.timer = window.setTimeout(async () => {
    c.timer = null
    if (!ctls.has(rowId)) return
    try {
      const s = await api<CopyStatus>(`/api/fs/copy/${c.jobId}`)
      const p = copyPatch(s, tr)
      // viteza: din diferenţa de octeţi între două poll-uri (serverul nu o raportează)
      const now = Date.now()
      if (p.state === 'running' && c.lastAt) {
        const bps = Math.max(0, ((s.done_bytes - c.lastPos) * 1000) / Math.max(1, now - c.lastAt))
        p.bytesPerSec = bps
        p.etaSec = bps > 0 && s.total_bytes > s.done_bytes ? Math.round((s.total_bytes - s.done_bytes) / bps) : null
      }
      c.lastPos = s.done_bytes; c.lastAt = now
      uploadStore.patch(rowId, p)
      if (s.state === 'running') { poll(rowId); return }
      if (s.state === 'done') {
        window.setTimeout(() => { if (uploadStore.get(rowId)?.state === 'done') dismissCopy(rowId) }, DONE_LINGER_MS)
      }
      if (s.state !== 'failed') ctls.delete(rowId)   // failed: păstrăm opţiunile pentru Retry
    } catch (e) {
      // 404 = job-ul a expirat / gateway repornit (job-urile trăiesc în memorie): spunem asta
      if (e instanceof ApiError && e.status === 404) {
        uploadStore.patch(rowId, { state: 'err', error: tr('transfers.copyLost'), bytesPerSec: 0, etaSec: null })
        return
      }
      poll(rowId)                                     // reţea căzută: încercăm iar
    }
  }, POLL_MS)
}

/** Porneşte copierea pe server şi adaugă rândul în Transferuri. Pasul de step-up: dacă oricare
    host cere 2FA şi fereastra a expirat, serverul dă 403 stepup.* fără să spună care — re-listăm
    ambele capete prin `api()` (care rulează ceremonia doar pentru cel care o cere) şi reîncercăm
    O DATĂ. Ridică eroarea serverului (validare, offline, plafon) — dialogul o arată. */
export async function startCopy(o: StartCopyOpts): Promise<string> {
  const body = JSON.stringify({ src_host: o.srcHost, paths: o.paths, dst_host: o.dstHost, dst_dir: o.dstDir, on_conflict: o.onConflict })
  const post = () => api<{ job_id: string; dst_dir: string }>('/api/fs/copy', { method: 'POST', body })
  let r: { job_id: string; dst_dir: string }
  try { r = await post() } catch (e) {
    if (!isStepupError(e)) throw e
    await api(`/api/hosts/${o.srcHost}/fs?path=${encodeURIComponent('~')}`)
    await api(`/api/hosts/${o.dstHost}/fs?path=${encodeURIComponent(o.dstDir)}`)
    r = await post()
  }
  return track(r, o, copyLabel(o.paths, tr), 1)
}

/** Rândul din Transferuri pentru un job pornit (start sau retry) + polling-ul lui. */
function track(r: { job_id: string; dst_dir: string }, o: StartCopyOpts, label: string, attempts: number): string {
  const rowId = copyRowId(r.job_id)
  uploadStore.set({
    id: rowId, dir: 'copy', hostId: o.srcHost, hostName: `${o.srcName} → ${o.dstName}`,
    dest: r.dst_dir, name: label, size: 0, pos: 0, pct: 0, bytesPerSec: 0, etaSec: null,
    state: 'running', attempts, detail: tr('transfers.copyFiles', { done: 0, total: o.paths.length }),
  })
  ctls.set(rowId, { opts: { ...o, dstDir: r.dst_dir }, jobId: r.job_id, timer: null, lastPos: 0, lastAt: 0, label })
  poll(rowId)
  return rowId
}

/** Cancel: serverul opreşte fişierul în zbor şi îi şterge temp-ul de pe destinaţie; ce s-a copiat rămâne. */
export async function cancelCopy(rowId: string): Promise<void> {
  const c = ctls.get(rowId)
  const jobId = c?.jobId ?? rowId.replace(/^cp_/, '')
  if (c?.timer) window.clearTimeout(c.timer)
  ctls.delete(rowId)
  try {
    const s = await api<CopyStatus>(`/api/fs/copy/${jobId}`, { method: 'DELETE' })
    uploadStore.patch(rowId, copyPatch(s, tr))
  } catch { uploadStore.patch(rowId, { state: 'cancelled', bytesPerSec: 0, etaSec: null }) }
}

/** Retry: un job NOU pe server cu ce a eşuat, aceleaşi opţiuni (`POST /api/fs/copy/{id}/retry`).
    Serverul ştie arborele: un fişier dintr-un folder ajunge înapoi în ACELAŞI folder (şi la
    „păstrează-le pe amândouă", unde folderul are alt nume pe destinaţie). Step-up ca la start. */
export async function retryCopy(rowId: string): Promise<void> {
  const c = ctls.get(rowId)
  if (!c) return
  const post = () => api<{ job_id: string; dst_dir: string }>(`/api/fs/copy/${c.jobId}/retry`, { method: 'POST' })
  try {
    let r: { job_id: string; dst_dir: string }
    try { r = await post() } catch (e) {
      if (!isStepupError(e)) throw e
      await api(`/api/hosts/${c.opts.srcHost}/fs?path=${encodeURIComponent('~')}`)
      await api(`/api/hosts/${c.opts.dstHost}/fs?path=${encodeURIComponent(c.opts.dstDir)}`)
      r = await post()
    }
    const attempts = (uploadStore.get(rowId)?.attempts ?? 1) + 1
    ctls.delete(rowId)
    uploadStore.remove(rowId)
    track(r, c.opts, c.label, attempts)
  } catch (e) {
    uploadStore.patch(rowId, { state: 'err', error: errText(e, tr) })
  }
}

export function dismissCopy(rowId: string): void {
  const c = ctls.get(rowId)
  if (c?.timer) window.clearTimeout(c.timer)
  ctls.delete(rowId)
  uploadStore.remove(rowId)
}

/** Retry are sens doar cât ţinem opţiunile job-ului eşuat (în memoria paginii). */
export const canRetryCopy = (rowId: string): boolean => ctls.has(rowId)
