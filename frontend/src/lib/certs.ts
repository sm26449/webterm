/* TLS certificate status (3.6.7) — the pure part of Settings → Infrastructure → Certificates.

   The gateway reads the certificate Traefik SERVES for each name (main domain, a forward subdomain,
   Authentik) and says how it stands; this file only decides how to show it and which renewal
   action is on offer. The server is the authority: `renew_command` is built there from validated
   names, `can_renew` is the Owner-only `certs.renew` permission, and the terminal route re-checks
   everything (permission, picked host, allow-listed name, fresh second factor). */

export type CertState = 'ok' | 'expiring' | 'expiring_soon' | 'expired' | 'default' | 'mismatch' | 'error'
export type CertRole = 'main' | 'forward' | 'authentik'

export interface CertItem {
  name: string
  role: CertRole
  state: CertState
  level: number
  days_left?: number
  not_after?: number
  issuer?: string
  subject_cn?: string
  sans?: string[]
  via?: 'traefik' | 'public'
  error?: string
  checked_at?: number
  renew_domain?: string
  renew_command?: string
  wildcard_hint?: boolean
}

export interface CertStatus {
  enabled: boolean
  checked_at: number | null
  running: boolean
  items: CertItem[]
  warn_days: number
  crit_days: number
  resolver: string
  can_renew: boolean
  renew_host: { id: number; name: string } | null
  retry_after: number
}

export type Tone = 'good' | 'warn' | 'danger' | 'muted'

export function certTone(state: CertState): Tone {
  switch (state) {
    case 'ok': return 'good'
    case 'expiring': case 'expiring_soon': return 'warn'
    case 'expired': case 'default': case 'mismatch': return 'danger'
    default: return 'muted'
  }
}

type T = (key: string, vars?: Record<string, string | number>) => string

/** „Valid, 62 days left" / „Expires in 2 days" / „Expired 3 days ago" / „Traefik default cert"… */
export function certStateText(item: CertItem, t: T): string {
  const d = item.days_left ?? 0
  switch (item.state) {
    case 'ok': return t('settings.certs.state.ok', { count: Math.floor(d) })
    case 'expiring':
    case 'expiring_soon': return t('settings.certs.state.expiring', { count: Math.max(0, Math.floor(d)) })
    case 'expired': return t('settings.certs.state.expired', { count: Math.max(0, Math.ceil(-d)) })
    case 'default': return t('settings.certs.state.default')
    case 'mismatch': return t('settings.certs.state.mismatch')
    default: return t('settings.certs.state.error')
  }
}

/** A certificate that needs a human: expiring, expired, the default one, or the wrong one. */
export function needsRenew(item: CertItem): boolean {
  return item.level > 0
}

/** What the Renew action does for this row:
    `terminal` — Owner, a gateway host picked, a command the server built → open a terminal with it
                 typed (not run);
    `copy`     — Owner, no host picked → show the command to copy;
    `none`     — healthy, not an Owner, or the server did not give a command (fail closed). */
export function renewMode(st: Pick<CertStatus, 'can_renew' | 'renew_host'>, item: CertItem): 'terminal' | 'copy' | 'none' {
  if (!st.can_renew || !needsRenew(item) || !item.renew_command || !item.renew_domain) return 'none'
  return st.renew_host ? 'terminal' : 'copy'
}

/** The roles in the order the section lists them. */
export function sortCerts(items: CertItem[]): CertItem[] {
  const order: Record<string, number> = { main: 0, forward: 1, authentik: 2 }
  return [...items].sort((a, b) => (order[a.role] ?? 9) - (order[b.role] ?? 9) || a.name.localeCompare(b.name))
}
