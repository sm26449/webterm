/* Statistici per container pentru panoul Docker: tipul răspunsului de la
   `GET /api/hosts/{id}/docker/stats`, potrivirea cu rândurile din `docker ps`, formatarea şi
   bucla de sondare. Gateway-ul trimite NUMERE (octeţi, procente) — aici doar le afişăm.

   Sondarea: ~5 s cât panoul e deschis ŞI tabul browserului e vizibil. Pe `document.hidden` se
   opreşte (nu ardem `docker stats` pe host pentru un tab din fundal) şi reia imediat la revenire.
   Un timeout pe host („indisponibil") răreşte sondarea la 30 s; o eroare o OPREŞTE (lista însăşi
   arată deja eroarea docker — nu vrem o furtună de cereri eşuate la fiecare 5 s). */
import { fmtBytes } from './uploads'

export interface DockerStat {
  id: string
  name: string
  cpu_pct: number | null
  mem_used: number | null
  mem_limit: number | null
  mem_pct: number | null
  net_rx: number | null
  net_tx: number | null
  block_read: number | null
  block_write: number | null
  pids: number | null
}

export interface DockerStatsResponse {
  available: boolean
  reason?: string
  rows: DockerStat[]
  /** nucleele hostului (din snapshot-ul de diagnostic al agentului); null/lipsă = necunoscut */
  host_cpus?: number | null
}

export const STATS_INTERVAL = 5000
export const STATS_SLOW_INTERVAL = 30000

/** `docker stats` dă id-ul SCURT (12 caractere), `docker ps --no-trunc` pe cel lung: potrivim pe
    prefix, cu numele ca rezervă (Names din ps poate fi o listă separată prin virgulă). */
export function matchStats(stats: DockerStat[] | null | undefined, id: string, names?: string): DockerStat | undefined {
  if (!stats || !stats.length) return undefined
  const byId = id ? stats.find((s) => s.id && (id.startsWith(s.id) || s.id.startsWith(id))) : undefined
  if (byId) return byId
  const list = (names || '').split(',').map((n) => n.trim()).filter(Boolean)
  return list.length ? stats.find((s) => s.name && list.includes(s.name)) : undefined
}

/** procent compact: „0.4%", „12%", „250%" (CPU poate trece de 100 pe mai multe nuclee) */
export function fmtPct(p: number | null | undefined): string | null {
  if (p == null || !Number.isFinite(p)) return null
  return p < 10 ? `${p.toFixed(1)}%` : `${Math.round(p)}%`
}

/** CPU-ul unui container RELATIV la host (3.5.15).

    `docker stats` raportează procentul pe UN nucleu: 400% = patru nuclee pline, deci pe o maşină
    de 8 nuclee „96%" nu e „aproape plin", e 12% din host — iar pragurile de culoare (gândite pe
    0–100% din capacitate) colorau roşu un container care folosea un singur nucleu. Împărţim la
    numărul de nuclee când îl ştim; altfel rămânem pe valoarea brută, marcată „per nucleu".
    `pressure` = valoarea pe care se aplică pragurile de culoare. */
export interface CpuShare {
  /** % din capacitatea hostului (null dacă nucleele sunt necunoscute) */
  hostPct: number | null
  /** % dintr-un nucleu, exact cum îl dă docker */
  corePct: number | null
  /** procentul folosit pentru culoarea de prag */
  pressure: number
}

export function cpuShare(raw: number | null | undefined, hostCpus: number | null | undefined): CpuShare {
  const core = raw != null && Number.isFinite(raw) && raw >= 0 ? raw : null
  const n = typeof hostCpus === 'number' && Number.isInteger(hostCpus) && hostCpus > 0 ? hostCpus : null
  if (core == null) return { hostPct: null, corePct: null, pressure: 0 }
  if (n == null) return { hostPct: null, corePct: core, pressure: core }
  // docker poate depăşi uşor N×100 între eşantioane; „din host" nu trece de 100%
  const host = Math.min(100, core / n)
  return { hostPct: host, corePct: core, pressure: host }
}

/** „120.5 MB / 1.94 GB" sau doar „120.5 MB" când limita lipseşte */
export function fmtMem(used: number | null | undefined, limit: number | null | undefined): string | null {
  if (used == null || !Number.isFinite(used)) return null
  return limit != null && Number.isFinite(limit) && limit > 0 ? `${fmtBytes(used)} / ${fmtBytes(limit)}` : fmtBytes(used)
}

/** următoarea sondare după un rezultat: ok → 5 s, timeout pe host → 30 s, eroare → stop (null) */
export function nextStatsDelay(outcome: 'ok' | 'unavailable' | 'error'): number | null {
  return outcome === 'ok' ? STATS_INTERVAL : outcome === 'unavailable' ? STATS_SLOW_INTERVAL : null
}

/** ce ştie bucla despre document: injectabil, ca testele să ruleze în node fără DOM */
export interface VisibilitySource {
  hidden: boolean
  addEventListener(type: 'visibilitychange', fn: () => void): void
  removeEventListener(type: 'visibilitychange', fn: () => void): void
}

/** Rulează `tick` acum şi apoi după întârzierea pe care o întoarce (null = stop). Se suspendă
    cât `doc.hidden` e adevărat şi reia imediat la revenire. Întoarce funcţia de oprire
    (apelată la închiderea panoului / unmount). Un tick nu se suprapune niciodată cu altul. */
export function startPolling(tick: () => Promise<number | null>, doc: VisibilitySource): () => void {
  let timer: ReturnType<typeof setTimeout> | null = null
  let stopped = false
  let running = false
  let ended = false         // tick-ul a cerut stop (eroare): nu repornim nici la vizibilitate

  const clear = () => { if (timer !== null) { clearTimeout(timer); timer = null } }
  const run = async () => {
    clear()
    if (stopped || ended || doc.hidden) return
    if (running) return     // revenire la vizibil în timpul unui tick: el programează următorul
    running = true
    let delay: number | null = null
    try { delay = await tick() } catch { delay = null }
    running = false
    if (stopped) return
    if (delay === null) { ended = true; return }
    if (!doc.hidden) timer = setTimeout(run, delay)
  }
  const onVis = () => { if (doc.hidden) clear(); else if (timer === null) run() }

  doc.addEventListener('visibilitychange', onVis)
  run()
  return () => {
    stopped = true
    clear()
    doc.removeEventListener('visibilitychange', onVis)
  }
}
