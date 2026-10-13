import { useEffect, useState } from 'react'
import { api, ApiError, ensureStepup, errText, isStepupError, type Host } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { fmtTs, getTimezone } from '../../lib/tz'
import { copyText } from '../../lib/clipboard'
import { askSecret } from '../../lib/secretPrompt'
import { certStateText, certTone, renewMode, sortCerts, type CertItem, type CertStatus } from '../../lib/certs'
import { field, heading } from './ui'
import { Badge, Button } from '../ui'
import type { LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'

// TLS certificates (3.6.7): what Traefik actually serves for the main domain, a forward subdomain
// and Authentik — days left, issuer, names — with "Check now" and, for an Owner, "Renew". Renewal
// is a HOST action (scripts/cert-renew.sh under sudo); the gateway never touches the ACME store.
// "Renew" opens a terminal on the gateway host with the command TYPED, not run (Owner + fresh
// second factor, re-checked by the server), or shows it to copy when no host is picked.
const TONE_BADGE = { good: 'ok', warn: 'warn', danger: 'danger', muted: 'neutral' } as const

export default function CertificatesSection() {
  const { t } = useI18n()
  const vis = useSectionVisible()
  const [st, setSt] = useState<CertStatus | null>(null)
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [copied, setCopied] = useState('')
  const [hosts, setHosts] = useState<Host[] | null>(null)
  const [pick, setPick] = useState('')
  const [renewing, setRenewing] = useState('')

  const reload = () => {
    setLoad({ status: 'loading' })
    return api<CertStatus>('/api/certs')
      .then((s) => { setSt(s); setLoad({ status: 'ok' }) })
      .catch((e) => setLoad({ status: 'error', error: errText(e, t) }))
  }
  useEffect(() => { if (vis('certificates')) void reload() }, [])   // eslint-disable-line react-hooks/exhaustive-deps
  // the host picker is only for an Owner, and only loaded when there is no pick yet
  useEffect(() => {
    if (st?.can_renew && !st.renew_host && hosts === null) {
      api<Host[]>('/api/hosts').then((h) => setHosts(h.filter((x) => (x.connection_type ?? 'agent') === 'agent')))
        .catch(() => setHosts([]))
    }
  }, [st?.can_renew, st?.renew_host, hosts])

  async function checkNow() {
    setBusy(true); setMsg(''); setErr('')
    try {
      setSt(await api<CertStatus>('/api/certs/check', { method: 'POST' }))
      setMsg(t('settings.certs.checked'))
    } catch (e) {
      setErr(errText(e, t))
    } finally { setBusy(false) }
  }

  async function saveHost(hostId: number) {
    setErr(''); setMsg('')
    try {
      setSt(await api<CertStatus>('/api/certs/renew-host', { method: 'PUT', body: JSON.stringify({ host_id: hostId }) }))
      if (!hostId) setHosts(null)
      setMsg(t('settings.saved'))
    } catch (e) { setErr(errText(e, t)) }
  }

  async function copy(cmd: string) {
    if (await copyText(cmd)) { setCopied(cmd); setTimeout(() => setCopied(''), 1500) }
  }

  // Renew in a terminal. The request skips api()'s automatic step-up retry (`true`): this route
  // wants a FRESH factor, and a TOTP code must travel in the request itself (the /stepup window
  // route does not take one on a host without require_2fa) — so the ceremony is handled here.
  async function renew(item: CertItem) {
    const host = st?.renew_host
    if (!host || !item.renew_domain) return
    setErr(''); setMsg(''); setRenewing(item.name)
    const url = `/api/hosts/${host.id}/cert-renew`
    const send = (extra: Record<string, string> = {}) => api<{ id: string; command: string }>(url, {
      method: 'POST', body: JSON.stringify({ domain: item.renew_domain, tz: getTimezone(), ...extra }),
    }, true)
    try {
      let r: { id: string; command: string } | null = null
      try {
        r = await send()
      } catch (e) {
        if (e instanceof ApiError && e.code === 'stepup.totp') {
          const otp = await askSecret(t('stepup.totpTitle'), {
            masked: false, otp: true, label: t('stepup.totpLabel'), hint: t('stepup.totpHint'),
          })
          if (otp === null) return
          r = await send({ stepup_totp: otp.trim() })
        } else if (isStepupError(e) && await ensureStepup(host.id, e instanceof ApiError ? e.code : '')) {
          r = await send()
        } else {
          throw e
        }
      }
      if (r?.id) window.dispatchEvent(new CustomEvent('wt-open-session', { detail: { sid: r.id } }))
    } catch (e) {
      setErr(errText(e, t))
    } finally { setRenewing('') }
  }

  const items = st ? sortCerts(st.items) : []
  return (
    <>
      <h3 className={heading}>{t('settings.certs.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">{t('settings.certs.hint', { warn: st?.warn_days ?? 14, crit: st?.crit_days ?? 3 })}</p>
      <NotLoaded state={load} onRetry={() => { void reload() }} />
      {st && (
        <div className="mt-2 flex flex-col gap-2">
          {!st.enabled && <p className="text-xs text-slate-500">{t('settings.certs.disabled')}</p>}
          {st.enabled && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <Button variant="secondary" size="sm" type="button" loading={busy} onClick={checkNow}>
                {t('settings.certs.checkNow')}
              </Button>
              <span>{st.checked_at ? t('settings.certs.lastCheck', { when: fmtTs(st.checked_at) }) : t('settings.certs.notChecked')}</span>
            </div>
          )}
          <span role="status" className={msg ? 'text-sm wt-good' : 'sr-only'}>{msg}</span>
          <span role="alert" className={err ? 'text-sm wt-danger' : 'sr-only'}>{err}</span>
          <ul className="flex flex-col gap-2">
            {items.map((it) => {
              const mode = renewMode(st, it)
              return (
                <li key={it.name} data-cert={it.name} className="rounded-md border border-ink-700 bg-ink-800/40 p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-slate-200 break-all">{it.name}</span>
                    <Badge tone="neutral">{t('settings.certs.role.' + it.role)}</Badge>
                    <Badge tone={TONE_BADGE[certTone(it.state)]} size="md">{certStateText(it, t)}</Badge>
                  </div>
                  {it.not_after != null && (
                    <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-slate-400">
                      <dt>{t('settings.certs.expires')}</dt><dd>{fmtTs(it.not_after)}</dd>
                      <dt>{t('settings.certs.issuer')}</dt><dd className="break-all">{it.issuer || '?'}</dd>
                      {!!it.sans?.length && (<><dt>{t('settings.certs.names')}</dt>
                        <dd className="font-mono break-all">{it.sans.slice(0, 6).join(', ')}{it.sans.length > 6 ? ' …' : ''}</dd></>)}
                      {it.via && (<><dt>{t('settings.certs.via')}</dt><dd>{t('settings.certs.via.' + it.via)}</dd></>)}
                    </dl>
                  )}
                  {it.error && <p className="mt-1.5 wt-warn break-all">{t('settings.certs.lastError', { error: it.error })}</p>}
                  {it.wildcard_hint && <p className="mt-1.5 text-slate-400">{t('settings.certs.wildcardHint')}</p>}
                  {mode === 'terminal' && (
                    <div className="mt-2 flex flex-wrap items-center gap-2">
                      <Button variant="primary" size="sm" type="button" loading={renewing === it.name}
                        disabled={!!renewing} onClick={() => { void renew(it) }}>
                        {t('settings.certs.renew')}
                      </Button>
                      <span className="text-slate-500">{t('settings.certs.renewTerminalHint', { host: st.renew_host?.name ?? '' })}</span>
                    </div>
                  )}
                  {(mode === 'terminal' || mode === 'copy') && it.renew_command && (
                    <div className="mt-2 flex items-center gap-2">
                      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded-md bg-ink-900 px-2 py-1 font-mono text-slate-300">{it.renew_command}</code>
                      <Button variant="ghost" size="sm" type="button" onClick={() => { void copy(it.renew_command!) }}
                        aria-label={t('settings.certs.copyCommand')}>
                        {copied === it.renew_command ? t('fleet.copied') : t('settings.certs.copy')}
                      </Button>
                    </div>
                  )}
                  {mode === 'copy' && <p className="mt-1 text-slate-500">{t('settings.certs.renewCopyHint')}</p>}
                  {mode === 'none' && it.level > 0 && !st.can_renew && (
                    <p className="mt-1.5 text-slate-500">{t('settings.certs.ownerOnly')}</p>
                  )}
                </li>
              )
            })}
          </ul>
          {st.can_renew && st.enabled && (
            <div className="mt-1 flex flex-col gap-1 text-xs text-slate-400">
              <span className="font-medium text-slate-300">{t('settings.certs.hostTitle')}</span>
              <span className="text-slate-500">{t('settings.certs.hostHint')}</span>
              {st.renew_host ? (
                <div className="flex flex-wrap items-center gap-2">
                  <span>{t('settings.certs.hostPicked', { host: st.renew_host.name })}</span>
                  <Button variant="ghost" size="sm" type="button" onClick={() => { void saveHost(0) }}>{t('settings.certs.hostChange')}</Button>
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  <select value={pick} onChange={(e) => setPick(e.target.value)} aria-label={t('settings.certs.hostTitle')}
                    className={`${field} max-w-xs`}>
                    <option value="">{t('settings.certs.hostNone')}</option>
                    {(hosts ?? []).map((h) => <option key={h.id} value={String(h.id)}>{h.name}</option>)}
                  </select>
                  <Button variant="secondary" size="sm" type="button" disabled={!pick}
                    onClick={() => { void saveHost(Number(pick)) }}>{t('settings.save')}</Button>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </>
  )
}
