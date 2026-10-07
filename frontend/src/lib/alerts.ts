import { api } from './api'
import type { BadgeTone } from '../components/ui'

/* Istoricul de alerte în aplicaţie (3.5.11) — partea fără React: tipuri, maparea severitate →
   ton/etichetă, gruparea preferinţelor şi STORE-ul contorului de necitite.

   Contorul are un singur poll pe pagină, indiferent câte clopoţei sunt montaţi (Sidebar îşi
   randează corpul de două ori: desktop + drawer-ul de mobil). 60 s, oprit cât tab-ul e ascuns
   (document.hidden), cu un refresh imediat la revenire — acelaşi tipar ca poll-ul de hosturi din
   App, doar mai rar: o alertă nu e o metrică live, iar contorul costă o interogare pe index. */

export type Severity = 'critical' | 'warning' | 'info' | 'ok'

export interface AlertItem {
  id: number
  ts: number
  kind: string
  severity: Severity
  title: string
  details: string
  host_id: number | null
  read: boolean
}

export interface AlertPage { alerts: AlertItem[]; unread: number; next_before: number | null }

export interface AlertPref {
  kind: string
  group: 'account' | 'security' | 'hosts' | 'gateway'
  scope: 'account' | 'fleet'
  security: boolean
  email: boolean
  inapp: boolean
}

export const ALERT_GROUPS: readonly AlertPref['group'][] = ['account', 'security', 'hosts', 'gateway']

/** ton de Badge pentru severitate; culoarea nu e singurul semnal — insigna poartă şi textul */
export function severityTone(sev: string): BadgeTone {
  switch (sev) {
    case 'critical': return 'danger'
    case 'warning': return 'warn'
    case 'ok': return 'ok'
    default: return 'info'
  }
}

/** severitate necunoscută (server mai nou) → „info", ca UI-ul să nu randeze o cheie lipsă */
export function normSeverity(sev: string): Severity {
  return sev === 'critical' || sev === 'warning' || sev === 'ok' ? sev : 'info'
}

/** textul insignei de pe clopoţel: 0 → nimic, peste 99 → „99+" (lăţime fixă, lizibil) */
export function badgeText(n: number): string {
  if (!n || n < 0) return ''
  return n > 99 ? '99+' : String(n)
}

/** preferinţele grupate în ordinea din UI; grupurile goale dispar */
export function groupPrefs(prefs: AlertPref[]): { group: AlertPref['group']; items: AlertPref[] }[] {
  return ALERT_GROUPS
    .map((group) => ({ group, items: prefs.filter((p) => p.group === group) }))
    .filter((g) => g.items.length > 0)
}

/** un toggle schimbat: tipurile de securitate rămân mereu în aplicaţie (serverul o impune oricum) */
export function applyPref(prefs: AlertPref[], kind: string, field: 'email' | 'inapp', value: boolean): AlertPref[] {
  return prefs.map((p) => {
    if (p.kind !== kind) return p
    if (field === 'inapp' && p.security) return { ...p, inapp: true }
    return { ...p, [field]: value }
  })
}

/** combină o pagină nouă (paginare „încarcă mai multe") fără duplicate, newest-first */
export function mergePage(cur: AlertItem[], next: AlertItem[]): AlertItem[] {
  const seen = new Set(cur.map((a) => a.id))
  return [...cur, ...next.filter((a) => !seen.has(a.id))].sort((a, b) => b.id - a.id)
}

// ── store-ul contorului de necitite ───────────────────────────────────────────────────────
const POLL_MS = 60_000
let unread = 0
let users = 0
let timer: ReturnType<typeof setInterval> | null = null
const listeners = new Set<() => void>()

function emit(n: number) {
  if (n === unread) return
  unread = n
  for (const l of listeners) l()
}

export function setUnread(n: number) { emit(Math.max(0, n | 0)) }

export async function refreshUnread(): Promise<void> {
  try {
    const r = await api<{ unread: number }>('/api/alerts/unread')
    setUnread(r.unread)
  } catch { /* offline / sesiune expirată: păstrăm ultima valoare, App tratează 401-ul */ }
}

const onVis = () => { if (!document.hidden) refreshUnread() }

export const unreadStore = {
  /** useSyncExternalStore: primul abonat porneşte poll-ul, ultimul îl opreşte */
  subscribe(cb: () => void) {
    listeners.add(cb)
    if (users++ === 0) {
      refreshUnread()
      timer = setInterval(() => { if (!document.hidden) refreshUnread() }, POLL_MS)
      document.addEventListener('visibilitychange', onVis)
    }
    return () => {
      listeners.delete(cb)
      if (--users === 0) {
        if (timer) clearInterval(timer)
        timer = null
        document.removeEventListener('visibilitychange', onVis)
      }
    }
  },
  snapshot: () => unread,
}
