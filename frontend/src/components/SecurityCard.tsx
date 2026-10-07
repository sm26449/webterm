import { useCallback, useEffect, useId, useState } from 'react'
import { api, errText, SecurityCheck, SecurityStatus, timeAgo } from '../lib/api'
import { useI18n } from '../lib/i18n'
import HelpTip from './HelpTip'
import LoadFailed from './LoadFailed'
import { CheckIcon, CloseIcon } from './Icons'

/* Cardul „Securitate" de pe Dashboard: „e totul în regulă acum?" la o privire. Înainte răspunsul
   cerea patru drumuri (Setări → Securitate, fiecare sesiune partajată, guardrail-ul, cheia de
   semnare). Serverul agregă starea (GET /api/security/summary) şi trimite DOAR {id, status, value};
   textul îl compunem aici, din catalog — aşa rămâne în limba omului.

   Strâns pe un singur rând când totul e ok; deschis singur când ceva cere atenţie. Starea NU e
   doar culoare (WCAG 1.4.1): fiecare rând are un glif distinct (✓ ! ✕ i) şi cuvântul stării,
   vizibil pentru cititorul de ecran. Fiecare rând duce acolo unde se repară. */

export type SecurityTarget =
  | { kind: 'settings'; cat: 'securitate' | 'backup' | 'notificari' }
  | { kind: 'shares' }
  | { kind: 'status' }

const TARGET: Record<string, SecurityTarget | undefined> = {
  account2fa: { kind: 'settings', cat: 'securitate' },
  shares: { kind: 'shares' },
  guardrail: { kind: 'settings', cat: 'securitate' },
  signingKey: { kind: 'settings', cat: 'securitate' },
  backup: { kind: 'settings', cat: 'backup' },
  alerts: { kind: 'settings', cat: 'notificari' },
  agents: { kind: 'status' },
  // hosts2fa: informativ — alegerea e per host (Editează hostul), nu un loc unic de reparat
}

// pictograme SVG (erau glifele ✓ ! ✕ i): aceeaşi formă distinctă per stare, fără font
const GLYPH: Record<SecurityStatus, React.ReactNode> = {
  ok: <CheckIcon size={12} />, warn: <span className="font-bold">!</span>, bad: <CloseIcon size={12} />, info: <span className="font-bold">i</span>,
}
const TONE: Record<SecurityStatus, string> = {
  ok: 'wt-good bg-emerald-500/15', warn: 'wt-warn bg-amber-500/15',
  bad: 'wt-danger bg-rose-500/15', info: 'text-slate-400 bg-ink-700/60',
}
const POLL_MS = 60_000

const num = (v: unknown): number => (typeof v === 'number' ? v : 0)

export default function SecurityCard(props: {
  onNavigate: (target: SecurityTarget) => void
  /** schimbat de părinte după o acţiune care schimbă starea (ex. „Revocă tot") → reîncărcăm */
  refreshSignal?: number
}) {
  const { t } = useI18n()
  const [checks, setChecks] = useState<SecurityCheck[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  // null = „decide singur" (deschis dacă ceva cere atenţie); un click al omului fixează alegerea
  const [expanded, setExpanded] = useState<boolean | null>(null)
  const listId = useId()

  const load = useCallback(() => {
    api<{ checks: SecurityCheck[] }>('/api/security/summary')
      .then((r) => { setChecks(r.checks); setError(null) })
      .catch((e) => setError(errText(e, t) || t('common.loadFailed')))
  }, [t])

  // la afişarea dashboard-ului (montare) + la 60 s, doar cât tab-ul e vizibil (ca restul poll-urilor)
  useEffect(() => {
    load()
    const timer = setInterval(() => { if (!document.hidden) load() }, POLL_MS)
    return () => clearInterval(timer)
  }, [load])
  useEffect(() => { if (props.refreshSignal) load() }, [props.refreshSignal, load])

  const ago = (ts: unknown) => {
    const s = num(ts)
    return Date.now() / 1000 - s < 60 ? t('time.now') : t('secsum.ago', { time: timeAgo(s, t) })
  }

  // textul unei verificări, din `id` + `value`. null = verificare necunoscută → sărită.
  const describe = (c: SecurityCheck): { label: string; value: string } | null => {
    const v = c.value
    switch (c.id) {
      case 'account2fa': {
        if (v.sso && !num(v.passkeys) && !v.totp) return { label: t('secsum.account2fa'), value: t('secsum.account2fa.sso') }
        return { label: t('secsum.account2fa'),
          value: `${t('secsum.passkeys', { count: num(v.passkeys) })} · ${v.totp ? t('secsum.totpOn') : t('secsum.totpOff')}` }
      }
      case 'shares': {
        const active = num(v.active), writable = num(v.writable)
        return { label: t('secsum.shares'),
          value: active === 0 ? t('secsum.shares.none')
            : t('secsum.shares.active', { count: active })
              + (writable ? ` · ${t('secsum.shares.writable', { count: writable })}` : '') }
      }
      case 'guardrail':
        return { label: t('secsum.guardrail'),
          value: v.enabled ? t('secsum.guardrail.rules', { count: num(v.rules) }) : t('secsum.guardrail.off') }
      case 'signingKey':
        return { label: t('secsum.signingKey'),
          value: v.state === 'locked' ? t('secsum.signingKey.locked')
            : v.state === 'missing' ? t('secsum.signingKey.missing') : t('secsum.signingKey.ok') }
      case 'hosts2fa':
        return { label: t('secsum.hosts2fa'), value: t('secsum.hosts2fa.value', { on: num(v.on), total: num(v.total) }) }
      case 'backup': {
        const where = v.encrypted ? t('secsum.backup.offsiteEncrypted')
          : v.offsite ? t('secsum.backup.offsite') : t('secsum.backup.localOnly')
        const value = v.failed_at ? t('secsum.backup.failed', { time: ago(v.failed_at) })
          : !v.last_ok ? t('secsum.backup.never')
          : t('secsum.backup.last', { time: ago(v.last_ok) })
        return { label: t('secsum.backup'), value: v.last_ok || v.offsite ? `${value} · ${where}` : value }
      }
      case 'alerts':
        return { label: t('secsum.alerts'),
          value: v.smtp && v.webhook ? t('secsum.alerts.both') : v.smtp ? t('secsum.alerts.email')
            : v.webhook ? t('secsum.alerts.webhook') : t('secsum.alerts.none') }
      case 'agents': {
        const online = num(v.online), outdated = num(v.outdated), offline = num(v.offline)
        if (online + offline === 0) return { label: t('secsum.agents'), value: t('secsum.agents.none') }
        const head = outdated
          ? t('secsum.agents.outdated', { count: outdated, version: num(v.expected) })
          : t('secsum.agents.current', { count: online, version: num(v.expected) })
        return { label: t('secsum.agents'),
          value: offline ? `${head} · ${t('secsum.agents.offline', { count: offline })}` : head }
      }
      default:
        return null
    }
  }

  const rows = (checks ?? []).map((c) => ({ c, d: describe(c) })).filter((r) => r.d !== null)
  const issues = rows.filter((r) => r.c.status === 'bad' || r.c.status === 'warn').length
  const open = expanded ?? issues > 0
  const worst: SecurityStatus = rows.some((r) => r.c.status === 'bad') ? 'bad' : issues ? 'warn' : 'ok'
  const statusWord = (s: SecurityStatus) => t(`secsum.status.${s}`)

  return (
    <section data-testid="security-card" aria-labelledby={`${listId}-h`} className="mt-7">
      <div className="mb-2.5 flex items-center gap-2">
        <h2 id={`${listId}-h`} className="text-xs font-semibold uppercase tracking-wide text-slate-500">{t('secsum.title')}</h2>
        <HelpTip id="securitySummary" />
      </div>
      <div className="rounded-xl border border-ink-700 bg-ink-900/40">
        {error && !checks ? (
          <LoadFailed compact message={error} onRetry={load} />
        ) : !checks ? (
          <p className="px-4 py-3 text-sm text-slate-500" aria-live="polite">{t('secsum.loading')}</p>
        ) : (
          <>
            <button
              type="button"
              onClick={() => setExpanded(!open)}
              aria-expanded={open}
              aria-controls={listId}
              className="flex w-full items-center gap-3 rounded-xl px-4 py-3 text-left hover:bg-ink-800/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
            >
              <span aria-hidden="true" className={`grid h-6 w-6 shrink-0 place-items-center rounded-full text-xs font-bold ${TONE[worst]}`}>{GLYPH[worst]}</span>
              <span className="min-w-0 flex-1 text-sm text-slate-200">
                {issues === 0
                  ? t('secsum.allGood', { count: rows.length })
                  : t('secsum.needAttention', { count: issues })}
              </span>
              <span className="shrink-0 text-xs text-slate-500">{open ? t('secsum.hide') : t('secsum.show')}</span>
            </button>
            {/* lista rămâne în DOM şi când e strânsă (`hidden`), ca aria-controls să ţintească ceva real */}
            <ul id={listId} hidden={!open} className="border-t border-ink-800 px-2 py-1.5">
              {rows.map(({ c, d }) => {
                const target = TARGET[c.id]
                const body = (
                  <>
                    <span aria-hidden="true" className={`grid h-5 w-5 shrink-0 place-items-center rounded-full text-[11px] font-bold ${TONE[c.status]}`}>{GLYPH[c.status]}</span>
                    <span className="sr-only">{statusWord(c.status)}:</span>
                    <span className="w-40 shrink-0 truncate text-sm text-slate-300 max-sm:w-auto">{d!.label}</span>
                    <span className="min-w-0 flex-1 truncate text-xs text-slate-400">{d!.value}</span>
                    {target && <span aria-hidden="true" className="shrink-0 text-slate-600">›</span>}
                  </>
                )
                return (
                  <li key={c.id} data-check={c.id} data-status={c.status}>
                    {target ? (
                      <button type="button" onClick={() => props.onNavigate(target)}
                        className="flex min-h-9 w-full flex-wrap items-center gap-x-3 gap-y-0.5 rounded-lg px-2 py-1.5 text-left hover:bg-ink-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 sm:flex-nowrap">
                        {body}
                      </button>
                    ) : (
                      <div className="flex min-h-9 w-full flex-wrap items-center gap-x-3 gap-y-0.5 px-2 py-1.5 sm:flex-nowrap">{body}</div>
                    )}
                  </li>
                )
              })}
            </ul>
          </>
        )}
      </div>
    </section>
  )
}
