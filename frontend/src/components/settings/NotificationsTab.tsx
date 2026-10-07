import { useEffect, useState } from 'react'
import { api, ApiError, errText } from '../../lib/api'
import { askSecret } from '../../lib/secretPrompt'
import { useI18n } from '../../lib/i18n'
import { field, heading } from './ui'
import { Button, ErrorState } from '../ui'
import { fmtTs } from '../../lib/tz'
import { AlertPref, applyPref, groupPrefs } from '../../lib/alerts'
import HelpTip from '../HelpTip'

// Notificări: domeniul de port-forwarding, alerte pe email (SMTP) + webhook, praguri de resurse.
// Extras din SettingsModal ca tab de sine stătător (îşi ţine starea, se încarcă la montare).
type FwdCfg = {
  domain: string; app_domain: string; is_custom: boolean
  server_ip: string; dns_ip: string; dns_ok: boolean; cert_ok: boolean
}

// Ultima livrare reuşită / eşuată pe fiecare canal, persistată de gateway (email_alerts._record).
// Fără ea, un SMTP care picase de luni de zile era invizibil: eroarea mergea doar în log.
type Delivery = { ts: number; subject: string; error?: string } | null
type AlertStatus = {
  alert_email_last_sent: Delivery; alert_email_last_failed: Delivery
  alert_webhook_last_sent: Delivery; alert_webhook_last_failed: Delivery
}

export default function NotificationsTab() {
  const { t } = useI18n()
  const [busy, setBusy] = useState(false)

  // praguri de alertă pe resurse
  const [thresholds, setThresholds] = useState({ cpu: 90, mem: 90, disk: 90 })
  const [alertMsg, setAlertMsg] = useState('')
  const [alertErr, setAlertErr] = useState('')
  const loadThresholds = () =>
    api<{ cpu: number; mem: number; disk: number }>('/api/settings/alerts').then(setThresholds).catch(() => {})
  async function saveThresholds() {
    // eroarea lângă butonul ei: setSmtpErr o afişa cu DOUĂ secţiuni mai sus, lângă butoanele
    // SMTP — apăsai „salvează praguri" şi eroarea apărea în altă parte (sau în afara ecranului)
    setAlertMsg(''); setAlertErr(''); setBusy(true)
    try {
      await api('/api/settings/alerts', { method: 'POST', body: JSON.stringify(thresholds) })
      setAlertMsg(t('settings.thresholdsSaved'))
    } catch (err) {
      setAlertErr(errText(err, t) || t('settings.error'))
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
  const [alertStatus, setAlertStatus] = useState<AlertStatus | null>(null)
  const loadSmtp = () =>
    api<{ host?: string; port?: number; user?: string; from_addr?: string; to_addr?: string
          starttls: boolean; webhook?: string; has_password: boolean; status?: AlertStatus }>('/api/settings/smtp').then((c) => {
      setSmtp({ host: c.host || '', port: c.port || 587, user: c.user || '', password: '',
        from_addr: c.from_addr || '', to_addr: c.to_addr || '', starttls: c.starttls, webhook: c.webhook || '' })
      setSmtpHasPw(c.has_password)
      setAlertStatus(c.status ?? null)
    }).catch(() => {})
  // Orice schimbare SMTP/webhook cere parola contului (vezi save_smtp în gateway — SMTP-ul
  // poartă codurile de email, deci e destinaţie de exfiltrare). Încercăm întâi fără: o salvare
  // fără schimbări trece tăcut; la 401 cerem parola şi repetăm o dată.
  async function postSmtp() {
    try {
      await api('/api/settings/smtp', { method: 'POST', body: JSON.stringify(smtp) })
    } catch (err) {
      if (!(err instanceof ApiError) || err.status !== 401) throw err
      const acct = await askSecret(t('settings.reauthPrompt'))
      if (acct === null) throw err          // anulat: eroarea originală rămâne vizibilă
      await api('/api/settings/smtp', { method: 'POST',
        body: JSON.stringify({ ...smtp, current_password: acct }) })
    }
  }
  async function saveSmtp() {
    setSmtpMsg(''); setSmtpErr(''); setBusy(true)
    try {
      await postSmtp()
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
      await postSmtp()
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp()
      await api('/api/settings/smtp/test', { method: 'POST' })
      setSmtpMsg(t('settings.smtp.testSent'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setSmtpTesting(false) }
  }

  // Test pe webhook: acelaşi tipar ca testul SMTP (salvează întâi formularul), dar posteaza pe canalul
  // de chat — înainte singurul test trimitea email, deci un webhook greşit se vedea abia la o alertă pierdută
  async function testWebhook() {
    setSmtpMsg(''); setSmtpErr(''); setSmtpTesting(true)
    try {
      await postSmtp()
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp()
      await api('/api/settings/webhook/test', { method: 'POST' })
      setSmtpMsg(t('settings.smtp.webhookTestSent'))
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

  // Evenimente de alertă (3.5.11): per tip, email (+ webhook) şi istoric în aplicaţie. Fiecare
  // bifă se salvează imediat (un singur tip pe cerere); la eroare revenim la starea serverului.
  const [prefs, setPrefs] = useState<AlertPref[] | null>(null)
  const [prefsErr, setPrefsErr] = useState('')
  const [prefsLoadErr, setPrefsLoadErr] = useState(false)
  const [prefsMsg, setPrefsMsg] = useState('')
  const loadPrefs = () => {
    setPrefsLoadErr(false)
    api<{ prefs: AlertPref[] }>('/api/alerts/prefs').then((r) => setPrefs(r.prefs)).catch(() => setPrefsLoadErr(true))
  }
  async function togglePref(kind: string, field: 'email' | 'inapp', value: boolean) {
    if (!prefs) return
    const next = applyPref(prefs, kind, field, value)
    setPrefs(next); setPrefsErr(''); setPrefsMsg('')
    const p = next.find((x) => x.kind === kind)!
    try {
      const r = await api<{ prefs: AlertPref[] }>('/api/alerts/prefs', {
        method: 'POST', body: JSON.stringify({ prefs: { [kind]: { email: p.email, inapp: p.inapp } } }),
      })
      setPrefs(r.prefs); setPrefsMsg(t('settings.alertPrefs.saved'))
    } catch (err) {
      setPrefsErr(errText(err, t) || t('settings.error'))
      loadPrefs()
    }
  }

  useEffect(() => { loadSmtp(); loadThresholds(); loadFwd(); loadPrefs() }, [])

  return (
    <div>
      <section data-setting-id="forwardDomain">
        {/* ── Port forwarding (domeniu) ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.forward.title')}<HelpTip id="forwardDomain" /></h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.forward.hintA')} <span className="font-mono">{t('settings.forward.subdomain')}</span>{t('settings.forward.hintB')} <span className="font-mono">{t('settings.forward.exampleDomain')}</span>{t('settings.forward.hintC')} <span className="font-mono">.env</span>{t('settings.forward.hintD')}
        </p>
        <div className="mt-2 flex flex-col gap-2">
          <div className="flex gap-2">
            <input value={fwdDomain} onChange={(e) => setFwdDomain(e.target.value)}
              placeholder={t('settings.forward.inputPlaceholder')} aria-label={t('settings.forward.ariaLabel')} spellCheck={false}
              aria-invalid={fwdErr ? true : undefined} aria-describedby={fwdErr ? 'fwd-error' : undefined}
              className={`${field} font-mono`} />
            <Button variant="primary" disabled={fwdBusy} onClick={saveFwd} className="shrink-0">
              {t('settings.save')}
            </Button>
            <Button variant="secondary" disabled={fwdBusy} onClick={() => { setFwdMsg(''); setFwdErr(''); loadFwd() }} className="shrink-0">
              {t('settings.recheck')}
            </Button>
          </div>
          {/* regiuni live montate permanent: confirmarea e `status`, eroarea `alert` (WCAG 4.1.3) */}
          <span role="status" className={fwdMsg ? 'text-sm wt-good' : 'sr-only'}>{fwdMsg}</span>
          <span id="fwd-error" role="alert" className={fwdErr ? 'text-sm wt-danger' : 'sr-only'}>{fwdErr}</span>
          {fwd && (
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
              <span className="flex items-center gap-1.5">
                <span aria-hidden="true" className={`h-2 w-2 rounded-full ${fwd.dns_ok ? 'bg-emerald-500' : 'bg-rose-500'}`} />
                {t('settings.forward.dnsWildcard')} {fwd.dns_ok
                  ? <span className="font-mono text-slate-400">*.{fwd.domain} → {fwd.dns_ip}</span>
                  : <span className="text-slate-500">{t('settings.forward.notResolving')}</span>}
              </span>
              <span className="flex items-center gap-1.5">
                <span aria-hidden="true" className={`h-2 w-2 rounded-full ${fwd.cert_ok ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                {t('settings.forward.certificate')} {fwd.cert_ok ? <span className="text-slate-400">{t('settings.forward.certActive')}</span> : <span className="text-slate-500">{t('settings.forward.certPending')}</span>}
              </span>
            </div>
          )}
          {fwd && fwd.is_custom && !(fwd.dns_ok && fwd.cert_ok) && (
            <div className="rounded-md border border-ink-700 bg-ink-800/50 p-3 text-xs text-slate-400">
              <p className="mb-1.5 font-medium text-slate-300">{t('settings.forward.toActivateA')} <span className="font-mono">{fwd.domain}</span> {t('settings.forward.toActivateB')}</p>
              <ol className="ml-4 list-decimal space-y-1">
                <li>{t('settings.forward.step1Label')} <span className="font-mono wt-link">*.{fwd.domain}</span> → <span className="font-mono">A {fwd.server_ip || t('settings.forward.ipServerPlaceholder')}</span> (DNS-only)</li>
                <li>{t('settings.forward.step2In')} <span className="font-mono">/opt/webterm/.env</span>: <span className="font-mono wt-link">FORWARD_DOMAIN={fwd.domain}</span> {t('settings.forward.step2TokenA')} <span className="font-mono">.env</span> {t('settings.forward.step2TokenB')}</li>
                <li>Redeploy: <span className="font-mono">cd /opt/webterm &amp;&amp; ./deploy.sh</span> {t('settings.forward.step3Desc')}</li>
              </ol>
            </div>
          )}
        </div>
      </section>

      <section data-setting-id="smtp">
        {/* ── Alerte pe email (SMTP) ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.smtp.title')}<HelpTip id="smtp" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.smtp.hint')}</p>
        <div className="mt-2 flex flex-col gap-2">
          <div className="flex gap-2">
            <input value={smtp.host} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })}
              placeholder={t('settings.smtp.hostPlaceholder')} aria-label={t('settings.smtp.host')}
              aria-invalid={smtpErr ? true : undefined} aria-describedby={smtpErr ? 'smtp-error' : undefined} className={field} />
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
          {/* webhook: aceleaşi alerte, dar unde le vezi imediat. Independent de SMTP. Are id-ul
              lui de secţiune (căutarea din Setări duce aici, nu la începutul blocului SMTP). */}
          <div data-setting-id="webhook" className="flex flex-col gap-2">
            <input value={smtp.webhook} onChange={(e) => setSmtp({ ...smtp, webhook: e.target.value })}
              placeholder={t('settings.smtp.webhookPlaceholder')} aria-label={t('settings.smtp.webhook')}
              spellCheck={false} className={field} />
            <p className="flex items-start gap-2 text-xs text-slate-500"><span>{t('settings.smtp.webhookHint')}</span><HelpTip id="webhook" /></p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="primary" disabled={busy} onClick={saveSmtp}>
              {t('settings.save')}
            </Button>
            <Button variant="secondary" disabled={smtpTesting} onClick={testSmtp}>
              {smtpTesting ? t('settings.smtp.sending') : t('settings.smtp.sendTest')}
            </Button>
            {smtp.webhook.trim() && (
              <Button variant="secondary" disabled={smtpTesting} onClick={testWebhook}>
                {t('settings.smtp.testWebhook')}
              </Button>
            )}
            <span role="status" className={smtpMsg ? 'text-sm wt-good' : 'sr-only'}>{smtpMsg}</span>
            <span id="smtp-error" role="alert" className={smtpErr ? 'text-sm wt-danger' : 'sr-only'}>{smtpErr}</span>
          </div>
          {/* „au plecat alertele?" — ultimul email/webhook trimis şi ultimul eşuat; un eşec mai
              recent decât ultimul succes e roşu, altfel e doar istoric */}
          {alertStatus && (
            <div className="flex flex-col gap-0.5 text-xs" data-testid="alert-delivery-status">
              {([['email', alertStatus.alert_email_last_sent, alertStatus.alert_email_last_failed],
                 ['webhook', alertStatus.alert_webhook_last_sent, alertStatus.alert_webhook_last_failed]] as const)
                .map(([ch, sent, failed]) => {
                  if (!sent && !failed) {
                    return ch === 'email'
                      ? <span key={ch} className="text-slate-500">{t('settings.smtp.neverSent')}</span>
                      : null
                  }
                  const failedRecent = !!failed && (!sent || failed.ts > sent.ts)
                  return (
                    <span key={ch} className={failedRecent ? 'wt-danger break-words' : 'text-slate-500'}>
                      {sent && t(ch === 'email' ? 'settings.smtp.lastSent' : 'settings.smtp.webhookLastSent',
                        { when: fmtTs(sent.ts), subject: sent.subject })}
                      {sent && failed ? ' · ' : ''}
                      {failed && t(ch === 'email' ? 'settings.smtp.lastFailed' : 'settings.smtp.webhookLastFailed',
                        { when: fmtTs(failed.ts), error: failed.error || '' })}
                    </span>
                  )
                })}
            </div>
          )}
        </div>
      </section>

      <section data-setting-id="resourceAlerts">
        {/* ── Alerte pe resurse ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.alerts.title')}<HelpTip id="resourceAlerts" /></h3>
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
          <Button variant="primary" disabled={busy} onClick={saveThresholds}>
            {t('settings.alerts.saveThresholds')}
          </Button>
          <span role="status" className={alertMsg ? 'text-sm wt-good' : 'sr-only'}>{alertMsg}</span>
          <span role="alert" className={alertErr ? 'text-sm wt-danger' : 'sr-only'}>{alertErr}</span>
        </div>
      </section>

      <section data-setting-id="alertPrefs">
        {/* ── Evenimente de alertă: email / în aplicaţie, per tip ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.alertPrefs.title')}<HelpTip id="alertPrefs" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.alertPrefs.hint')}</p>
        <p className="mt-1 text-xs text-slate-500">{t('settings.alertPrefs.fleetNote')}</p>
        {prefsLoadErr && <ErrorState compact title={t('settings.alertPrefs.loadFailed')} onRetry={loadPrefs} />}
        {prefs && (
          <div className="mt-2 flex flex-col gap-3" data-testid="alert-prefs">
            {groupPrefs(prefs).map(({ group, items }) => (
              <table key={group} className="w-full table-fixed text-sm">
                <caption className="pb-1 text-left text-xs font-semibold text-slate-400">{t(`alerts.group.${group}`)}</caption>
                <thead className="sr-only">
                  <tr>
                    <th scope="col">{t('settings.alertPrefs.colEvent')}</th>
                    <th scope="col">{t('settings.alertPrefs.colEmail')}</th>
                    <th scope="col">{t('settings.alertPrefs.colInapp')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-800">
                  {items.map((p) => {
                    const label = t(`alerts.kind.${p.kind}`)
                    return (
                      <tr key={p.kind} data-alert-kind={p.kind}>
                        <td className="py-1.5 pr-2 align-top text-slate-300">
                          <span className="break-words">{label}</span>
                          {p.security && (
                            <span className="mt-0.5 block text-2xs text-slate-500">{t('settings.alertPrefs.alwaysRecorded')}</span>
                          )}
                          {p.security && !p.email && (
                            <span className="mt-0.5 block text-2xs wt-warn" role="note">{t('settings.alertPrefs.securityEmailOff')}</span>
                          )}
                        </td>
                        <td className="w-20 py-1.5 align-top">
                          <label className="wt-touch inline-flex items-center gap-1.5 text-xs text-slate-400">
                            <input type="checkbox" checked={p.email}
                              aria-label={t('settings.alertPrefs.emailAria', { event: label })}
                              onChange={(e) => togglePref(p.kind, 'email', e.target.checked)} />
                            <span aria-hidden="true">{t('settings.alertPrefs.colEmail')}</span>
                          </label>
                        </td>
                        <td className="w-28 py-1.5 align-top">
                          <label className="wt-touch inline-flex items-center gap-1.5 text-xs text-slate-400">
                            <input type="checkbox" checked={p.inapp} disabled={p.security}
                              aria-label={t('settings.alertPrefs.inappAria', { event: label })}
                              onChange={(e) => togglePref(p.kind, 'inapp', e.target.checked)} />
                            <span aria-hidden="true">{t('settings.alertPrefs.colInapp')}</span>
                          </label>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            ))}
          </div>
        )}
        <span role="status" className={prefsMsg ? 'text-sm wt-good' : 'sr-only'}>{prefsMsg}</span>
        <span role="alert" className={prefsErr ? 'text-sm wt-danger' : 'sr-only'}>{prefsErr}</span>
      </section>
    </div>
  )
}
