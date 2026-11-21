/* System health (3.6.8) — the pure part of Settings → System health.

   The gateway runs the checks, decides severities, and builds every command from a server-side
   allow-list (gateway/app/healthcmd.py). This file only decides how to show a result and which
   action is on offer. It never builds, edits or sends a command: "Open in terminal" names the
   CHECK and the index of its command, and the server re-derives the command itself. */

import { catOfSection, type SettingsCat } from './settingsIndex'

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
  /** who muted it (shown while it is muted) */
  muted_by?: string
  /** true: only the Owner may mute it — it is, or can become, critical (security review 3.6.8) */
  mute_owner_only?: boolean
  message: string
}

export interface HealthStatus {
  checks: HealthCheck[]
  attention: { count: number; severity: Severity }
  checked_at: number | null
  can_manage: boolean
  can_terminal: boolean
  /** the viewer may mute checks that can become critical (certs.renew, the Owner) */
  can_mute_critical?: boolean
  terminal_host: { id: number; name: string } | null
  retry_after: number
  /** 3.6.38: refused agent handshakes (edgeguard.py) */
  edge?: EdgeState
}

/** One episode of refused agent handshakes. `proxy` = a Traefik limit (authentication never ran:
    result unknown); `gateway` = an authentication refusal recorded by the gateway. */
export interface EdgeEpisode {
  id: number
  source: 'proxy' | 'gateway' | 'web'
  rule: 'ip' | 'global' | 'deny' | 'bad_token' | 'instance_conflict' | 'bad_path' | 'blocked'
    | 'login_failed' | 'login_locked' | 'api_token_bad' | 'ws_refused'
  started: number
  last_seen: number
  ended: number | null
  active: boolean
  duration: number
  count: number
  auth: 'unknown' | 'refused'
  /** most frequent sources: address (IPv6 per /64), for WebSockets with the first two path segments */
  sources?: [string, number][]
}

export interface EdgeState {
  episodes: EdgeEpisode[]
  telemetry: { configured: boolean; available: boolean; last_ok: number; error: string; error_since: number }
  quiet: number
  interval: number
  /** addresses blocked right now by the gateway's in-memory gate (agentgate.py) */
  blocked_now?: number
  /** the allow/deny lists the gateway writes for Traefik (edgelists.py) */
  lists?: { enabled: boolean; supported?: boolean; off_reason?: string; allow: number; deny: number; last_write: number; error: string }
}

/** i18n key of the rule that refused (health.edge.rule.*). */
export function edgeRuleKey(e: Pick<EdgeEpisode, 'rule'>): string {
  return 'health.edge.rule.' + e.rule
}

/** "1 h 5 min", "3 min", "40 s": an episode's length, rounded to what the scrape interval can tell. */
export function edgeDuration(seconds: number, t: (k: string, v?: Record<string, string | number>) => string): string {
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return t('health.edge.dur.s', { n: s })
  const m = Math.round(s / 60)
  if (m < 60) return t('health.edge.dur.m', { n: m })
  return t('health.edge.dur.hm', { h: Math.floor(m / 60), m: m % 60 })
}

/** Which telemetry line to show: the proxy counts can be missing without the limits being off. */
export function edgeTelemetryKey(tm: EdgeState['telemetry']): string {
  if (!tm.configured) return 'health.edge.telemetry.off'
  if (tm.error_since) return 'health.edge.telemetry.down'
  if (!tm.last_ok) return 'health.edge.telemetry.pending'
  return 'health.edge.telemetry.ok'
}

export const RANK: Record<Severity, number> = { ok: 0, info: 1, warning: 2, critical: 3 }

export type Tone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral'

export function severityTone(s: Severity, muted = false): Tone {
  if (muted) return 'neutral'
  return s === 'critical' ? 'danger' : s === 'warning' ? 'warn' : s === 'info' ? 'info' : 'ok'
}

/** May this viewer mute (not only unmute) this check? Mirrors the server rule: settings.manage, and
    for a check that is or can become critical, the Owner. The server enforces it either way. */
export function canMute(c: Pick<HealthCheck, 'mute_owner_only'>,
  st: Pick<HealthStatus, 'can_manage' | 'can_mute_critical'>): boolean {
  if (!st.can_manage) return false
  return !c.mute_owner_only || !!st.can_mute_critical
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

/** The Settings section a server action opens. Only the section is named here: its tab comes from
    lib/settingsIndex (`catOfSection`), so moving a section between tabs (3.7.1) cannot leave a
    stale tab id behind in a second list. */
const ACTION_SECTION: Readonly<Record<string, string>> = {
  'settings:notifications': 'smtp',
  'settings:backup': 'backupAuto',
  'settings:signing': 'signingKey',
  'settings:certificates': 'certificates',
  'settings:forward': 'forwardDomain',
  'settings:enroll': 'enrollGroups',
  'about:update': 'appUpdate',
}

/** Where a UI action leads inside Settings (tab + section), or null when it is not a jump. */
export function actionTarget(action: string): { cat: SettingsCat; section: string } | null {
  const section = Object.prototype.hasOwnProperty.call(ACTION_SECTION, action) ? ACTION_SECTION[action] : undefined
  const cat = section ? catOfSection(section) : undefined
  return section && cat ? { cat, section } : null
}

/** A docs path from the server → the repository URL (only paths under docs/, nothing else). */
export function docUrl(doc: string): string | null {
  if (!/^docs\/[A-Za-z0-9._/-]+(#[a-z0-9-]+)?$/.test(doc) || doc.includes('..')) return null
  return 'https://github.com/sm26449/webterm/blob/main/' + doc
}

/** Mute choices offered in the UI (the server validates the same set). */
export const MUTE_MODES = ['7d', '30d', 'change'] as const
export type MuteMode = typeof MUTE_MODES[number] | 'off'

/** "203.0.113.5 ×40, 198.51.100.0/24 ×3, +2 more": the top sources of an episode, short. */
export function edgeSources(src: [string, number][] | undefined, max = 3,
  t?: (k: string, v?: Record<string, string | number>) => string): string {
  if (!src || src.length === 0) return ''
  const named = src.filter(([k]) => k !== 'other')
  const shown = named.slice(0, max).map(([k, n]) => `${k} ×${n}`)
  const rest = named.length - shown.length + (src.some(([k]) => k === 'other') ? 1 : 0)
  return shown.join(', ') + (rest > 0 ? (t ? ' ' + t('health.edge.more', { count: rest }) : ` +${rest}`) : '')
}
