import { useEffect, useRef } from 'react'
import { Host } from './api'

/** Istoric de metrice, client-side: poll-ul global (5s) alimentează un ring
    buffer per host, deci obținem tendința fără nicio schimbare de backend și
    fără retenție pe disc. 60 de mostre ≈ 5 minute — exact fereastra în care
    întrebi „urcă sau coboară?" în timpul unui incident.

    Se pierde la reload (e o unealtă de context, nu un sistem de monitorizare —
    pentru istoric persistent ar trebui serie temporală în SQLite). */
export const HISTORY_LEN = 60

export interface HostHistory {
  cpu: number[]
  mem: number[]
}

const history = new Map<number, HostHistory>()

const memPct = (h: Host): number | null => {
  const m = h.metrics
  if (!m?.mem_total || !m.mem_used) return null
  return (m.mem_used / m.mem_total) * 100
}

/** Împinge o mostră per host la fiecare poll cu date noi. */
export function recordMetrics(hosts: Host[]): void {
  for (const h of hosts) {
    if (!h.online) continue
    const cpu = h.metrics?.cpu_pct
    const mem = memPct(h)
    if (cpu == null && mem == null) continue
    let hist = history.get(h.id)
    if (!hist) {
      hist = { cpu: [], mem: [] }
      history.set(h.id, hist)
    }
    // NaN ca „gaură" ar complica graficul; repetăm ultima valoare cunoscută
    hist.cpu.push(cpu ?? hist.cpu[hist.cpu.length - 1] ?? 0)
    hist.mem.push(mem ?? hist.mem[hist.mem.length - 1] ?? 0)
    if (hist.cpu.length > HISTORY_LEN) hist.cpu.shift()
    if (hist.mem.length > HISTORY_LEN) hist.mem.shift()
  }
}

export const hostHistory = (id: number): HostHistory | null => history.get(id) ?? null

/** Re-randează la fiecare poll (istoricul e mutabil, în afara stării React). */
export function useMetricsTick(hosts: Host[]): void {
  const prev = useRef('')
  useEffect(() => {
    const key = hosts.map((h) => `${h.id}:${h.metrics?.cpu_pct ?? ''}:${h.metrics?.mem_used ?? ''}`).join('|')
    if (key === prev.current) return
    prev.current = key
    recordMetrics(hosts)
  }, [hosts])
}
