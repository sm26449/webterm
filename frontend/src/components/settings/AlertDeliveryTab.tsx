import { useEffect, useState } from 'react'
import { api, ApiError, errText } from '../../lib/api'
import { askSecret } from '../../lib/secretPrompt'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { field } from './ui'
import { Badge, Button, eyebrow, Field, SettingsSection, Switch } from '../ui'
import { fmtTs } from '../../lib/tz'
import { canSave, type LoadState } from '../../lib/loadable'
import HelpTip from '../HelpTip'
import NotLoaded from './NotLoaded'

// Livrarea alertelor (instanţă): alerte pe email (SMTP) + webhook, praguri de resurse. Fostul tab
// „Notifications"; extras din SettingsModal ca tab de sine stătător (îşi ţine starea, se încarcă la montare).
// 3.7.1 (audit UX Setări #3): Canalele instanţei (Email, Webhook: fiecare cu starea, Save-ul şi
// testul lui) şi Regulile instanţei (praguri). Notificările MELE (per cont, „Alert events") au plecat
// în 3.7.1 în MyNotificationsTab, în grupul Personal: cine căuta în preferinţele lui nu mai dă peste
// SMTP-ul comun, iar un Viewer nu mai vede un tab „Notifications" cu alt conţinut decât un Owner.

// Ultima livrare reuşită / eşuată pe fiecare canal, persistată de gateway (email_alerts._record).
// Fără ea, un SMTP care picase de luni de zile era invizibil: eroarea mergea doar în log.
type Delivery = { ts: number; subject: string; error?: string } | null
type AlertStatus = {
  alert_email_last_sent: Delivery; alert_email_last_failed: Delivery
  alert_webhook_last_sent: Delivery; alert_webhook_last_failed: Delivery
}

// 3.7.1 (audit UX Setări C3/#6): pe telefon cele ~40 de checkbox-uri din Alert events aveau sub
// 24 px. Acelaşi tipar ca în Users/Roles (24 px sub `pointer: coarse`), iar eticheta `.wt-touch`
// umple celula, deci toată celula (≥ 44 px) e ţinta atingerii.
// (3.7.1, pasul 2: bifele au devenit <Switch>, cu ţintă de 44 px prin .wt-touch.)
type SmtpForm = { host: string; port: number; user: string; password: string; from_addr: string; to_addr: string; starttls: boolean; webhook: string }
type Channel = 'email' | 'webhook'

export default function AlertDeliveryTab() {
  const { t } = useI18n()
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  const [busy, setBusy] = useState(false)

  // praguri de alertă pe resurse
  // U04 — contractul „eroare ≠ gol" pe formulare: valorile de mai jos sunt doar IMPLICITE. Dacă
  // încărcarea pică, ele NU sunt setările de pe server — afişate ca atare păreau salvate, iar un
  // Save le scria peste configuraţia reală (praguri 90/90/90, SMTP gol = alerte pe email oprite).
  // Fiecare secţiune are starea ei; Save e blocat până când secţiunea s-a încărcat.
  const [thresholds, setThresholds] = useState({ cpu: 90, mem: 90, disk: 90 })
  const [thrState, setThrState] = useState<LoadState>({ status: 'loading' })
  // ultima valoare de pe server: „Unsaved changes" = formularul diferă de ea
  const [thrSaved, setThrSaved] = useState({ cpu: 90, mem: 90, disk: 90 })
  const [alertMsg, setAlertMsg] = useState('')
  const [alertErr, setAlertErr] = useState('')
  const loadThresholds = () => {
    setThrState({ status: 'loading' })
    return api<{ cpu: number; mem: number; disk: number }>('/api/settings/alerts')
      .then((r) => { setThresholds(r); setThrSaved(r); setThrState({ status: 'ok' }) })
      .catch((e) => setThrState({ status: 'error', error: errText(e, t) }))
  }
  async function saveThresholds() {
    if (!canSave(thrState)) return
    // eroarea lângă butonul ei: setSmtpErr o afişa cu DOUĂ secţiuni mai sus, lângă butoanele
    // SMTP — apăsai „salvează praguri" şi eroarea apărea în altă parte (sau în afara ecranului)
    setAlertMsg(''); setAlertErr(''); setBusy(true)
    try {
      await api('/api/settings/alerts', { method: 'POST', body: JSON.stringify(thresholds) })
      setThrSaved(thresholds)
      setAlertMsg(t('settings.thresholdsSaved'))
    } catch (err) {
      setAlertErr(errText(err, t) || t('settings.error'))
    } finally { setBusy(false) }
  }

  // SMTP (alerte pe email) + webhook
  const [smtp, setSmtp] = useState<SmtpForm>({
    host: '', port: 587, user: '', password: '', from_addr: '', to_addr: '', starttls: true, webhook: '',
  })
  const [smtpSaved, setSmtpSaved] = useState<SmtpForm | null>(null)
  const [smtpHasPw, setSmtpHasPw] = useState(false)
  // mesajul stă în cardul canalului care l-a produs (Email sau Webhook). Ambele carduri trimit
  // ACELAŞI POST /api/settings/smtp, cu tot formularul — exact ca înainte de împărţire.
  const [chan, setChan] = useState<Channel>('email')
  const [smtpMsg, setSmtpMsg] = useState('')
  const [smtpErr, setSmtpErr] = useState('')
  const [smtpTesting, setSmtpTesting] = useState(false)
  const [alertStatus, setAlertStatus] = useState<AlertStatus | null>(null)
  const [smtpState, setSmtpState] = useState<LoadState>({ status: 'loading' })
  // `quiet`: reîncărcarea de după un save reuşit nu ascunde formularul cât aşteaptă
  const loadSmtp = (quiet = false) => {
    if (!quiet) setSmtpState({ status: 'loading' })
    return api<{ host?: string; port?: number; user?: string; from_addr?: string; to_addr?: string
          starttls: boolean; webhook?: string; has_password: boolean; status?: AlertStatus }>('/api/settings/smtp').then((c) => {
      const loaded = { host: c.host || '', port: c.port || 587, user: c.user || '', password: '',
        from_addr: c.from_addr || '', to_addr: c.to_addr || '', starttls: c.starttls, webhook: c.webhook || '' }
      setSmtp(loaded); setSmtpSaved(loaded)
      setSmtpHasPw(c.has_password)
      setAlertStatus(c.status ?? null)
      setSmtpState({ status: 'ok' })
    }).catch((e) => setSmtpState({ status: 'error', error: errText(e, t) }))
  }
  // Orice schimbare SMTP/webhook cere parola contului (vezi save_smtp în gateway — SMTP-ul
  // poartă codurile de email, deci e destinaţie de exfiltrare). Încercăm întâi fără: o salvare
  // fără schimbări trece tăcut; la 401 cerem parola şi repetăm o dată.
  async function postSmtp() {
    // peste un formular neîncărcat (valori implicite) NU trimitem nimic — ar şterge SMTP-ul real
    if (!canSave(smtpState)) throw new Error(t('settings.notLoadedNoSave'))
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
  async function saveSmtp(which: Channel) {
    setChan(which); setSmtpMsg(''); setSmtpErr(''); setBusy(true)
    try {
      await postSmtp()
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp(true)
      setSmtpMsg(t('settings.smtp.saved'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setBusy(false) }
  }
  async function testSmtp() {
    setChan('email'); setSmtpMsg(''); setSmtpErr(''); setSmtpTesting(true)
    try {
      // salvează ÎNTÂI ce e în formular: altfel testul rulează pe configurația veche şi fluxul
      // natural „completez → testez" testează altceva
      await postSmtp()
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp(true)
      await api('/api/settings/smtp/test', { method: 'POST' })
      setSmtpMsg(t('settings.smtp.testSent'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setSmtpTesting(false) }
  }

  // Test pe webhook: acelaşi tipar ca testul SMTP (salvează întâi formularul), dar posteaza pe canalul
  // de chat — înainte singurul test trimitea email, deci un webhook greşit se vedea abia la o alertă pierdută
  async function testWebhook() {
    setChan('webhook'); setSmtpMsg(''); setSmtpErr(''); setSmtpTesting(true)
    try {
      await postSmtp()
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp(true)
      await api('/api/settings/webhook/test', { method: 'POST' })
      setSmtpMsg(t('settings.smtp.webhookTestSent'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setSmtpTesting(false) }
  }


  useEffect(() => { void loadSmtp(); void loadThresholds() }, [])

  const emailDirty = !!smtpSaved && (smtp.password !== '' || (['host', 'port', 'user', 'from_addr', 'to_addr', 'starttls'] as const)
    .some((k) => smtp[k] !== smtpSaved[k]))
  const webhookDirty = !!smtpSaved && smtp.webhook !== smtpSaved.webhook
  const thrDirty = (['cpu', 'mem', 'disk'] as const).some((k) => thresholds[k] !== thrSaved[k])
  // „au plecat alertele?" — ultimul trimis şi ultimul eşuat pe un canal; un eşec mai recent decât
  // ultimul succes e roşu, altfel e doar istoric
  const delivery = (ch: Channel) => {
    if (!alertStatus) return null
    const sent = ch === 'email' ? alertStatus.alert_email_last_sent : alertStatus.alert_webhook_last_sent
    const failed = ch === 'email' ? alertStatus.alert_email_last_failed : alertStatus.alert_webhook_last_failed
    if (!sent && !failed) {
      return ch === 'email' ? <p className="text-xs text-slate-500">{t('settings.smtp.neverSent')}</p> : null
    }
    const failedRecent = !!failed && (!sent || failed.ts > sent.ts)
    return (
      <p className={`text-xs ${failedRecent ? 'wt-danger break-words' : 'text-slate-500'}`}>
        {sent && t(ch === 'email' ? 'settings.smtp.lastSent' : 'settings.smtp.webhookLastSent',
          { when: fmtTs(sent.ts), subject: sent.subject })}
        {sent && failed ? ' · ' : ''}
        {failed && t(ch === 'email' ? 'settings.smtp.lastFailed' : 'settings.smtp.webhookLastFailed',
          { when: fmtTs(failed.ts), error: failed.error || '' })}
      </p>
    )
  }
  const chanStatus = (ch: Channel) => (
    <>
      <span role="status" className={chan === ch && smtpMsg ? 'text-sm wt-good' : 'sr-only'}>{chan === ch ? smtpMsg : ''}</span>
      <span id={`${ch}-error`} role="alert" className={chan === ch && smtpErr ? 'text-sm wt-danger' : 'sr-only'}>{chan === ch ? smtpErr : ''}</span>
    </>
  )
  const configured = (on: boolean) => (
    <Badge tone={on ? 'ok' : 'neutral'} size="md">{on ? t('settings.channel.on') : t('settings.channel.off')}</Badge>
  )

  return (
    <div className="space-y-4">
      {/* ── Canale (instanţă): pe unde pleacă alertele ── */}
      {(vis('smtp') || vis('webhook')) && <h3 className={eyebrow}>{t('settings.notif.channels')}</h3>}
      <SettingsSection data-setting-id="smtp" hidden={!vis('smtp')} headingLevel={4} instanceWide
        title={t('settings.smtp.title')} titleExtra={<>{smtpSaved && configured(!!smtpSaved.host)}<HelpTip id="smtp" /></>}
        description={t('settings.smtp.hint')}
        dirty={canSave(smtpState) && emailDirty}
        footer={canSave(smtpState) ? <>
          <Button variant="primary" type="button" disabled={busy} onClick={() => { void saveSmtp('email') }}>
            {t('settings.save')}
          </Button>
          <Button variant="secondary" type="button" disabled={smtpTesting} onClick={() => { void testSmtp() }}>
            {smtpTesting && chan === 'email' ? t('settings.smtp.sending') : t('settings.smtp.sendTest')}
          </Button>
          {chanStatus('email')}
        </> : undefined}>
        <NotLoaded state={smtpState} onRetry={() => { void loadSmtp() }} />
        {canSave(smtpState) && (<div className="flex flex-col gap-3">
          <div className="flex flex-col gap-3 sm:flex-row">
            <Field label={t('settings.smtp.host')} className="min-w-0 flex-1">
              <input value={smtp.host} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })}
                placeholder={t('settings.smtp.hostPlaceholder')} spellCheck={false}
                aria-invalid={chan === 'email' && smtpErr ? true : undefined}
                aria-describedby={chan === 'email' && smtpErr ? 'email-error' : undefined} className={field} />
            </Field>
            <Field label={t('settings.smtp.port')} className="sm:w-28 sm:shrink-0">
              <input type="number" value={smtp.port} onChange={(e) => setSmtp({ ...smtp, port: +e.target.value })} className={field} />
            </Field>
          </div>
          <Field label={t('settings.smtp.user')}>
            <input value={smtp.user} onChange={(e) => setSmtp({ ...smtp, user: e.target.value })} autoComplete="off" className={field} />
          </Field>
          <Field label={t('settings.smtp.password')} hint={smtpHasPw ? t('settings.backup.keepStoredHint') : undefined}>
            <input type="password" value={smtp.password} onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
              autoComplete="off" className={field} />
          </Field>
          <Field label={t('settings.smtp.from')}>
            <input value={smtp.from_addr} onChange={(e) => setSmtp({ ...smtp, from_addr: e.target.value })}
              placeholder={t('settings.smtp.fromPlaceholder')} className={field} />
          </Field>
          <Field label={t('settings.smtp.to')}>
            <input value={smtp.to_addr} onChange={(e) => setSmtp({ ...smtp, to_addr: e.target.value })}
              placeholder={t('settings.smtp.toPlaceholder')} className={field} />
          </Field>
          <Switch checked={smtp.starttls} onChange={(v) => setSmtp({ ...smtp, starttls: v })} label={t('settings.smtp.starttls')} />
          {delivery('email')}
        </div>)}
      </SettingsSection>

      {/* webhook: aceleaşi alerte, dar unde le vezi imediat. Independent de SMTP; propriul card, cu
          id-ul lui de secţiune (căutarea din Setări duce aici) */}
      <SettingsSection data-setting-id="webhook" hidden={!vis('webhook')} headingLevel={4} instanceWide
        title={t('settings.smtp.webhook')} titleExtra={<>{smtpSaved && configured(!!smtpSaved.webhook.trim())}<HelpTip id="webhook" /></>}
        description={t('settings.smtp.webhookHint')}
        dirty={canSave(smtpState) && webhookDirty}
        footer={canSave(smtpState) ? <>
          <Button variant="primary" type="button" disabled={busy} onClick={() => { void saveSmtp('webhook') }}>
            {t('settings.save')}
          </Button>
          <Button variant="secondary" type="button" disabled={smtpTesting || !smtp.webhook.trim()}
            aria-describedby={!smtp.webhook.trim() ? 'webhook-test-why' : undefined} onClick={() => { void testWebhook() }}>
            {smtpTesting && chan === 'webhook' ? t('settings.smtp.sending') : t('settings.smtp.testWebhook')}
          </Button>
          {!smtp.webhook.trim() && <span id="webhook-test-why" className="text-xs text-slate-500">{t('settings.smtp.whyWebhookTest')}</span>}
          {chanStatus('webhook')}
        </> : undefined}>
        {/* fără încărcare reuşită nu arătăm formularul: un Save ar scrie valori implicite (U04) */}
        {!vis('smtp') && <NotLoaded state={smtpState} onRetry={() => { void loadSmtp() }} />}
        {canSave(smtpState) && (<div className="flex flex-col gap-3">
          <Field label={t('settings.smtp.webhookUrl')}>
            <input value={smtp.webhook} onChange={(e) => setSmtp({ ...smtp, webhook: e.target.value })}
              placeholder={t('settings.smtp.webhookPlaceholder')} spellCheck={false} className={field} />
          </Field>
          {delivery('webhook')}
        </div>)}
      </SettingsSection>

      {/* ── Reguli (instanţă): când se declanşează o alertă ── */}
      {vis('resourceAlerts') && <h3 className={`${eyebrow} pt-2`}>{t('settings.notif.rules')}</h3>}
      <SettingsSection data-setting-id="resourceAlerts" hidden={!vis('resourceAlerts')} headingLevel={4} instanceWide
        title={t('settings.alerts.title')} titleExtra={<HelpTip id="resourceAlerts" />}
        description={t('settings.alerts.hint')}
        dirty={canSave(thrState) && thrDirty}
        footer={canSave(thrState) ? <>
          <Button variant="primary" type="button" disabled={busy} onClick={() => { void saveThresholds() }}>
            {t('settings.alerts.saveThresholds')}
          </Button>
          <span role="status" className={alertMsg ? 'text-sm wt-good' : 'sr-only'}>{alertMsg}</span>
          <span role="alert" className={alertErr ? 'text-sm wt-danger' : 'sr-only'}>{alertErr}</span>
        </> : undefined}>
        <NotLoaded state={thrState} onRetry={() => { void loadThresholds() }} />
        {canSave(thrState) && (<div className="flex flex-wrap items-center gap-x-5 gap-y-3">
          {([['cpu', 'CPU'], ['mem', 'RAM'], ['disk', t('settings.alerts.disk')]] as const).map(([k, label]) => (
            <div key={k} className="flex items-center gap-1.5">
              <Field inline label={label}>
                <input type="number" min={0} max={100} value={thresholds[k]}
                  aria-label={t('settings.alerts.thresholdAria', { label })}
                  onChange={(e) => setThresholds({ ...thresholds, [k]: Math.max(0, Math.min(100, +e.target.value)) })}
                  className={`${field} w-20`} />
              </Field>
              <span className="text-sm text-slate-500" aria-hidden="true">%</span>
            </div>
          ))}
        </div>)}
      </SettingsSection>

    </div>
  )
}
