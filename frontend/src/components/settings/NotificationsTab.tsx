import { useEffect, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { field, heading } from './ui'

// Notificări: domeniul de port-forwarding, alerte pe email (SMTP) + webhook, praguri de resurse.
// Extras din SettingsModal ca tab de sine stătător (îşi ţine starea, se încarcă la montare).
type FwdCfg = {
  domain: string; app_domain: string; is_custom: boolean
  server_ip: string; dns_ip: string; dns_ok: boolean; cert_ok: boolean
}

export default function NotificationsTab() {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)

  // praguri de alertă pe resurse
  const [thresholds, setThresholds] = useState({ cpu: 90, mem: 90, disk: 90 })
  const [alertMsg, setAlertMsg] = useState('')
  const loadThresholds = () =>
    api<{ cpu: number; mem: number; disk: number }>('/api/settings/alerts').then(setThresholds).catch(() => {})
  async function saveThresholds() {
    setAlertMsg(''); setSmtpErr(''); setBusy(true)
    try {
      await api('/api/settings/alerts', { method: 'POST', body: JSON.stringify(thresholds) })
      setAlertMsg(t('settings.thresholdsSaved'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setBusy(false) }
  }

  // SMTP (alerte pe email) + webhook
  const [smtp, setSmtp] = useState({
    host: '', port: 587, user: '', password: '', from_addr: '', to_addr: '', starttls: true, webhook: '',
  })
  const [smtpHasPw, setSmtpHasPw] = useState(false)
  const [smtpMsg, setSmtpMsg] = useState('')
  const [smtpErr, setSmtpErr] = useState('')
  const [smtpTesting, setSmtpTesting] = useState(false)
  const loadSmtp = () =>
    api<{ host?: string; port?: number; user?: string; from_addr?: string; to_addr?: string
          starttls: boolean; webhook?: string; has_password: boolean }>('/api/settings/smtp').then((c) => {
      setSmtp({ host: c.host || '', port: c.port || 587, user: c.user || '', password: '',
        from_addr: c.from_addr || '', to_addr: c.to_addr || '', starttls: c.starttls, webhook: c.webhook || '' })
      setSmtpHasPw(c.has_password)
    }).catch(() => {})
  async function saveSmtp() {
    setSmtpMsg(''); setSmtpErr(''); setBusy(true)
    try {
      await api('/api/settings/smtp', { method: 'POST', body: JSON.stringify(smtp) })
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp()
      setSmtpMsg(t('settings.smtp.saved'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setBusy(false) }
  }
  async function testSmtp() {
    setSmtpMsg(''); setSmtpErr(''); setSmtpTesting(true)
    try {
      // salvează ÎNTÂI ce e în formular: altfel testul rulează pe configurația veche şi fluxul
      // natural „completez → testez" testează altceva
      await api('/api/settings/smtp', { method: 'POST', body: JSON.stringify(smtp) })
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp()
      await api('/api/settings/smtp/test', { method: 'POST' })
      setSmtpMsg(t('settings.smtp.testSent'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setSmtpTesting(false) }
  }

  // Port forwarding: domeniu configurabil
  const [fwd, setFwd] = useState<FwdCfg | null>(null)
  const [fwdDomain, setFwdDomain] = useState('')
  const [fwdMsg, setFwdMsg] = useState('')
  const [fwdErr, setFwdErr] = useState('')
  const [fwdBusy, setFwdBusy] = useState(false)
  const loadFwd = () =>
    api<FwdCfg>('/api/settings/forward').then((c) => { setFwd(c); setFwdDomain(c.domain) }).catch(() => {})
  async function saveFwd() {
    setFwdBusy(true); setFwdMsg(''); setFwdErr('')
    try {
      const c = await api<FwdCfg>('/api/settings/forward', {
        method: 'POST', body: JSON.stringify({ domain: fwdDomain.trim() }),
      })
      setFwd(c); setFwdDomain(c.domain); setFwdMsg(t('settings.forward.saved'))
    } catch (e) {
      setFwdErr(errText(e, t) || t('settings.error'))
    } finally { setFwdBusy(false) }
  }

  useEffect(() => { loadSmtp(); loadThresholds(); loadFwd() }, [])

  return (
    <div>
      {/* ── Port forwarding (domeniu) ── */}
      <h3 className={heading}>{t('settings.forward.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.forward.hintA')} <span className="font-mono">{t('settings.forward.subdomain')}</span>{t('settings.forward.hintB')} <span className="font-mono">{t('settings.forward.exampleDomain')}</span>{t('settings.forward.hintC')} <span className="font-mono">.env</span>{t('settings.forward.hintD')}
      </p>
      <div className="mt-2 flex flex-col gap-2">
        <div className="flex gap-2">
          <input value={fwdDomain} onChange={(e) => setFwdDomain(e.target.value)}
            placeholder={t('settings.forward.inputPlaceholder')} aria-label={t('settings.forward.ariaLabel')} spellCheck={false}
            className={`${field} font-mono`} />
          <button disabled={fwdBusy} onClick={saveFwd}
            className="shrink-0 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
            {t('settings.save')}
          </button>
          <button disabled={fwdBusy} onClick={() => { setFwdMsg(''); setFwdErr(''); loadFwd() }}
            className="shrink-0 rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-50">
            {t('settings.recheck')}
          </button>
        </div>
        {fwdMsg && <span className="text-sm wt-good">{fwdMsg}</span>}
        {fwdErr && <span className="text-sm wt-danger">{fwdErr}</span>}
        {fwd && (
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
            <span className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${fwd.dns_ok ? 'bg-emerald-500' : 'bg-rose-500'}`} />
              {t('settings.forward.dnsWildcard')} {fwd.dns_ok
                ? <span className="font-mono text-slate-400">*.{fwd.domain} → {fwd.dns_ip}</span>
                : <span className="text-slate-500">{t('settings.forward.notResolving')}</span>}
            </span>
            <span className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${fwd.cert_ok ? 'bg-emerald-500' : 'bg-amber-500'}`} />
              {t('settings.forward.certificate')} {fwd.cert_ok ? <span className="text-slate-400">{t('settings.forward.certActive')}</span> : <span className="text-slate-500">{t('settings.forward.certPending')}</span>}
            </span>
          </div>
        )}
        {fwd && fwd.is_custom && !(fwd.dns_ok && fwd.cert_ok) && (
          <div className="rounded-lg border border-ink-700 bg-ink-800/50 p-3 text-xs text-slate-400">
            <p className="mb-1.5 font-medium text-slate-300">{t('settings.forward.toActivateA')} <span className="font-mono">{fwd.domain}</span> {t('settings.forward.toActivateB')}</p>
            <ol className="ml-4 list-decimal space-y-1">
              <li>{t('settings.forward.step1Label')} <span className="font-mono wt-link">*.{fwd.domain}</span> → <span className="font-mono">A {fwd.server_ip || t('settings.forward.ipServerPlaceholder')}</span> (DNS-only)</li>
              <li>{t('settings.forward.step2In')} <span className="font-mono">/opt/webterm/.env</span>: <span className="font-mono wt-link">FORWARD_DOMAIN={fwd.domain}</span> {t('settings.forward.step2TokenA')} <span className="font-mono">.env</span> {t('settings.forward.step2TokenB')}</li>
              <li>Redeploy: <span className="font-mono">cd /opt/webterm &amp;&amp; ./deploy.sh</span> {t('settings.forward.step3Desc')}</li>
            </ol>
          </div>
        )}
      </div>

      {/* ── Alerte pe email (SMTP) ── */}
      <h3 className={heading}>{t('settings.smtp.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">{t('settings.smtp.hint')}</p>
      <div className="mt-2 flex flex-col gap-2">
        <div className="flex gap-2">
          <input value={smtp.host} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })}
            placeholder={t('settings.smtp.hostPlaceholder')} aria-label={t('settings.smtp.host')} className={field} />
          <input type="number" value={smtp.port} onChange={(e) => setSmtp({ ...smtp, port: +e.target.value })}
            placeholder={t('settings.smtp.portPlaceholder')} aria-label={t('settings.smtp.port')} className={`${field} w-24`} />
        </div>
        <input value={smtp.user} onChange={(e) => setSmtp({ ...smtp, user: e.target.value })}
          placeholder={t('settings.smtp.user')} aria-label={t('settings.smtp.user')} autoComplete="off" className={field} />
        <input type="password" value={smtp.password}
          onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
          placeholder={smtpHasPw ? t('settings.smtp.passwordSetPlaceholder') : t('settings.smtp.passwordPlaceholder')}
          aria-label={t('settings.smtp.password')} autoComplete="off" className={field} />
        <input value={smtp.from_addr} onChange={(e) => setSmtp({ ...smtp, from_addr: e.target.value })}
          placeholder={t('settings.smtp.from')} aria-label={t('settings.smtp.from')} className={field} />
        <input value={smtp.to_addr} onChange={(e) => setSmtp({ ...smtp, to_addr: e.target.value })}
          placeholder={t('settings.smtp.toPlaceholder')} aria-label={t('settings.smtp.to')} className={field} />
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input type="checkbox" checked={smtp.starttls}
            onChange={(e) => setSmtp({ ...smtp, starttls: e.target.checked })} />
          {t('settings.smtp.starttls')}
        </label>
        {/* webhook: aceleaşi alerte, dar unde le vezi imediat. Independent de SMTP. */}
        <input value={smtp.webhook} onChange={(e) => setSmtp({ ...smtp, webhook: e.target.value })}
          placeholder={t('settings.smtp.webhookPlaceholder')} aria-label={t('settings.smtp.webhook')}
          spellCheck={false} className={field} />
        <p className="text-xs text-slate-500">{t('settings.smtp.webhookHint')}</p>
        <div className="flex items-center gap-2">
          <button disabled={busy} onClick={saveSmtp}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
            {t('settings.save')}
          </button>
          <button disabled={smtpTesting} onClick={testSmtp}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-50">
            {smtpTesting ? t('settings.smtp.sending') : t('settings.smtp.sendTest')}
          </button>
          {smtpMsg && <span className="text-sm wt-good">{smtpMsg}</span>}
          {smtpErr && <span className="text-sm wt-danger">{smtpErr}</span>}
        </div>
      </div>

      {/* ── Alerte pe resurse ── */}
      <h3 className={heading}>{t('settings.alerts.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">{t('settings.alerts.hint')}</p>
      <div className="mt-2 flex flex-wrap items-center gap-3">
        {([['cpu', 'CPU'], ['mem', 'RAM'], ['disk', t('settings.alerts.disk')]] as const).map(([k, label]) => (
          <label key={k} className="flex items-center gap-2 text-sm text-slate-300">
            <span className="w-10 text-slate-400">{label}</span>
            <input type="number" min={0} max={100} value={thresholds[k]}
              aria-label={t('settings.alerts.thresholdAria', { label })}
              onChange={(e) => setThresholds({ ...thresholds, [k]: Math.max(0, Math.min(100, +e.target.value)) })}
              className={`${field} w-20`} />
            <span className="text-slate-500">%</span>
          </label>
        ))}
        <button disabled={busy} onClick={saveThresholds}
          className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
          {t('settings.alerts.saveThresholds')}
        </button>
        {alertMsg && <span className="text-sm wt-good">{alertMsg}</span>}
      </div>
    </div>
  )
}
