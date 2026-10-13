/* System health (3.6.8) — the pure part of Settings → System health.

   The gateway runs the checks, decides severities, and builds every command from a server-side
   allow-list (gateway/app/healthcmd.py). This file only decides how to show a result and which
   action is on offer. It never builds, edits or sends a command: "Open in terminal" names the
   CHECK and the index of its command, and the server re-derives the command itself. */

export type Severity = 'ok' | 'info' | 'warning' | 'critical'

export interface HealthCommand {
  template: string
  text: string
  requires_root: boolean
}

export interface HealthCheck {
  id: string
  severity: Severity
  message_key: string
  params: Record<string, string | number | boolean>
  why_key: string
  recommendation_key: string
  commands: HealthCommand[]
  command_where: string
  requires_root: boolean
  action: string
  source: 'gateway' | 'host_helper'
  doc: string
  hosts: { id: number; name: string }[]
  hosts_hidden: number
  checked_at: number | null
  first_failed_at: number | null
  changed_at: number | null
  muted: boolean
  muted_until: number
  message: string
}

export interface HealthStatus {
  checks: HealthCheck[]
  attention: { count: number; severity: Severity }
  checked_at: number | null
  can_manage: boolean
  can_terminal: boolean
  terminal_host: { id: number; name: string } | null
  retry_after: number
}

export const RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

export type Tone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral'

export function severityTone(s: Severity, muted = false): Tone {
  if (muted) return 'neutral'
  return s === 'critical' ? 'danger' : s === 'warning' ? 'warn' : s === 'info' ? 'info' : 'ok'
}

/** Needs attention = warning/critical and not muted (the badge counts exactly these). */
export function needsAttention(c: Pick<HealthCheck, 'severity' | 'muted'>): boolean {
  return RANK[c.severity] >= RANK.warning && !c.muted
}

/** Problems first (critical → warning → info), muted after them, passing checks last. */
export function sortChecks(list: HealthCheck[]): HealthCheck[] {
  return [...list].sort((a, b) => {
    const ga = a.severity === 'ok' ? 2 : a.muted ? 1 : 0
    const gb = b.severity === 'ok' ? 2 : b.muted ? 1 : 0
    if (ga !== gb) return ga - gb
    if (RANK[a.severity] !== RANK[b.severity]) return RANK[b.severity] - RANK[a.severity]
    return a.id.localeCompare(b.id)
  })
}

/** Splits the sorted list into what is shown open and the "N checks pass" fold. */
export function splitChecks(list: HealthCheck[]): { open: HealthCheck[]; passing: HealthCheck[] } {
  const sorted = sortChecks(list)
  return { open: sorted.filter((c) => c.severity !== 'ok'), passing: sorted.filter((c) => c.severity === 'ok') }
}

type T = (key: string, vars?: Record<string, string | number>) => string

/** The message in the UI language; an unknown key (newer server) falls back to the server's
    English text, which React renders as plain text. */
export function checkText(c: Pick<HealthCheck, 'message_key' | 'params' | 'message'>, t: T): string {
  const key = 'health.msg.' + c.message_key
  const vars: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(c.params || {})) vars[k] = typeof v === 'boolean' ? String(v) : v
  const s = t(key, vars)
  return s === key ? c.message : s
}

/** Optional catalog text (why / recommendation / check title): '' when the key is unknown. */
export function optText(prefix: string, key: string, t: T): string {
  if (!key) return ''
  const k = prefix + key
  const s = t(k)
  return s === k ? '' : s
}

/** What the "Open in terminal" button can do for a command:
    `terminal` — Owner with a gateway host picked → server types it (not run);
    `pick`     — Owner without a host picked → say where to pick one;
    `copy`     — everyone else who can see commands: copy only. */
export function fixMode(st: Pick<HealthStatus, 'can_terminal' | 'terminal_host'>): 'terminal' | 'pick' | 'copy' {
  if (!st.can_terminal) return 'copy'
  return st.terminal_host ? 'terminal' : 'pick'
}

/** Where a UI action leads inside Settings (tab + section), or null when it is not a jump. */
export function actionTarget(action: string): { cat: string; section?: string } | null {
  switch (action) {
    case 'settings:notifications': return { cat: 'notificari', section: 'smtp' }
    case 'settings:backup': return { cat: 'backup', section: 'backupAuto' }
    case 'settings:signing': return { cat: 'infrastructura', section: 'signingKey' }
    case 'settings:certificates': return { cat: 'infrastructura', section: 'certificates' }
    case 'settings:forward': return { cat: 'infrastructura', section: 'forwardDomain' }
    case 'about:update': return { cat: 'preferinte', section: 'appUpdate' }
    default: return null
  }
}

/** A docs path from the server → the repository URL (only paths under docs/, nothing else). */
export function docUrl(doc: string): string | null {
  if (!/^docs\/[A-Za-z0-9._/-]+(#[a-z0-9-]+)?$/.test(doc) || doc.includes('..')) return null
  return 'https://github.com/sm26449/webterm/blob/main/' + doc
}

/** Mute choices offered in the UI (the server validates the same set). */
export const MUTE_MODES = ['7d', '30d', 'change'] as const
export type MuteMode = typeof MUTE_MODES[number] | 'off'
