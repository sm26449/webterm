// Starea upload-urilor trăieşte în AFARA componentelor. Închiderea panoului de fişiere nu
// opreşte transferul (bucla din lib/uploads.ts rulează mai departe în closure-ul ei), dar
// înainte îl făcea INVIZIBIL şi neanulabil: redeschiderea găsea o listă goală, iar re-drop-ul
// aceluiaşi fişier pornea un al doilea scriitor pe acelaşi upload_id. Un store la nivel de
// modul (consumat cu useSyncExternalStore) păstrează progresul — panoul de fişiere şi bara
// globală de transferuri (JobsBar) citesc AMÂNDOUĂ de aici; controlul (File, XHR, anulare)
// stă în motor (lib/uploads.ts), singurul care scrie.
//
// Incidentul care a dat forma de acum (2026-10-04): un upload de 17 GB s-a oprit la felia
// 1579 fără niciun semnal — singura urmă era rândul din panoul de fişiere, iar acela putea fi
// închis. De aceea un job are stări VIZIBILE (`stalled`, `retrying`, `orphan`), viteză şi ETA,
// nu doar un procent.

export type JobState = 'running' | 'stalled' | 'retrying' | 'err' | 'done' | 'cancelled' | 'orphan'

export interface UploadJob {
  /** = upload_id (32 hex): stabil per (host, cale, mărime, mtime) → un re-drop al aceluiaşi
      fişier regăseşte ACELAŞI job, inclusiv unul rămas „orfan" după un reload. */
  id: string
  hostId: number
  hostName: string
  dest: string            // calea absolută a ţintei pe host
  name: string            // eticheta afişată (calea relativă din drop: `sub/dir/fişier`)
  size: number
  pos: number             // octeţi aterizaţi (confirmaţi sau în zbor)
  pct: number
  bytesPerSec: number     // 0 când nu se mişcă nimic
  etaSec: number | null   // null = necunoscut (încă fără viteză)
  state: JobState
  error?: string          // text deja tradus, pentru `err`
  /** încercarea curentă pe felia curentă (1 = prima); se resetează la fiecare felie */
  attempts: number
}

/** Stări în care transferul chiar se mişcă (sau încearcă) — ţin `beforeunload` şi apar în sumar. */
export const ACTIVE_STATES: ReadonlySet<JobState> = new Set(['running', 'stalled', 'retrying'])
export const isActive = (j: UploadJob) => ACTIVE_STATES.has(j.state)

const state = new Map<string, UploadJob>()
const subs = new Set<() => void>()
let snap: ReadonlyMap<string, UploadJob> = new Map()

function emit() {
  snap = new Map(state)              // snapshot imuabil: useSyncExternalStore compară referinţe
  subs.forEach((f) => f())
}

export const uploadStore = {
  subscribe(f: () => void): () => void {
    subs.add(f)
    return () => { subs.delete(f) }
  },
  snapshot(): ReadonlyMap<string, UploadJob> { return snap },
  get: (id: string): UploadJob | undefined => state.get(id),
  set(job: UploadJob): void { state.set(job.id, job); emit() },
  /** actualizare parţială; no-op dacă job-ul nu (mai) există (ex. dismiss în timpul unui tick) */
  patch(id: string, p: Partial<UploadJob>): void {
    const cur = state.get(id)
    if (!cur) return
    state.set(id, { ...cur, ...p })
    emit()
  },
  remove(id: string): void { if (state.delete(id)) emit() },
}
