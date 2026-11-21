import { useEffect, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { field, heading } from './ui'
import { Button, ErrorState, SettingsSection, Switch } from '../ui'
import { AlertPref, applyPref, groupPrefs } from '../../lib/alerts'
import { ensureNotificationPermission } from '../../lib/notify'
import { setTaskNotifyEnabled, setTaskNotifySeconds, taskNotifyEnabled, taskNotifySeconds } from '../../lib/taskNotify'
import { pushStatus, pushSupported, setPushPrefs, subscribeThisDevice, testPush, thisDeviceSubscribed, unsubscribeThisDevice, type PushStatus } from '../../lib/push'
import HelpTip from '../HelpTip'

// Notificările mele (3.7.1, auditul UX Setări M3): tot ce primeşte CONTUL tău — evenimentele de
// alertă (email / în aplicaţie, per cont) şi notificările de task (per browser, + push pe acest
// dispozitiv). Erau în două tab-uri (Notifications şi Preferences); secţiunile sunt mutate ca atare
// din fostul NotificationsTab (acum AlertDeliveryTab, livrarea instanţei) şi din PreferencesTab.
export default function MyNotificationsTab() {
  const { t, lang } = useI18n()

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
  async function togglePref(kind: string, which: 'email' | 'inapp', value: boolean) {
    if (!prefs) return
    const next = applyPref(prefs, kind, which, value)
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

  // notificări de task (Faza 1): preferinţă per-browser (ca rendererul). Toggle + prag în secunde.
  const [taskNotif, setTaskNotif] = useState(() => taskNotifyEnabled())
  const [taskSec, setTaskSec] = useState(() => String(taskNotifySeconds()))
  // push pe acest dispozitiv (Faza 2): telefon cu aplicația închisă. `pushSt` = starea contului +
  // disponibilitatea server-side; `pushHere` = e abonat DISPOZITIVUL ăsta.
  const [pushSt, setPushSt] = useState<PushStatus | null>(null)
  const [pushHere, setPushHere] = useState(false)
  const [pushBusy, setPushBusy] = useState(false)
  const [pushErr, setPushErr] = useState('')
  const [pushMsg, setPushMsg] = useState('')
  useEffect(() => {
    if (!pushSupported()) return
    pushStatus().then(setPushSt).catch(() => { /* push nedisponibil pe server */ })
    void thisDeviceSubscribed().then(setPushHere)
  }, [])
  async function togglePush(on: boolean) {
    setPushErr(''); setPushMsg(''); setPushBusy(true)
    try {
      if (on) {
        const st = await subscribeThisDevice(lang)
        await setPushPrefs(true, taskNotifySeconds())   // o singură valoare de prag (cea de deasupra)
        setPushSt(st); setPushHere(true)
      } else {
        setPushSt(await unsubscribeThisDevice()); setPushHere(false)
      }
    } catch (e) {
      setPushErr(e instanceof Error && e.message === 'denied' ? t('push.denied') : (errText(e, t) || t('push.failed')))
      setPushHere(await thisDeviceSubscribed())
    } finally { setPushBusy(false) }
  }
  async function doPushTest() {
    setPushErr(''); setPushMsg('')
    try { const r = await testPush(); setPushMsg(t('push.testSent', { n: r.sent })) } catch (e) { setPushErr(errText(e, t) || t('push.failed')) }
  }

  useEffect(() => { loadPrefs() }, [])   // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-4">
      {/* ce primesc eu, pe email şi în aplicaţie (orice cont) */}
      <SettingsSection data-setting-id="alertPrefs" headingLevel={3}
        title={t('settings.alertPrefs.title')} titleExtra={<HelpTip id="alertPrefs" />}
        description={t('settings.alertPrefs.hint')}>
        <p className="text-xs text-slate-500">{t('settings.alertPrefs.fleetNote')}</p>
        {prefsLoadErr && <ErrorState compact title={t('settings.alertPrefs.loadFailed')} onRetry={loadPrefs} />}
        {prefs && (
          <div className="mt-3 flex flex-col gap-4" data-testid="alert-prefs">
            {groupPrefs(prefs).map(({ group, items }) => {
              const gid = `alert-group-${group}`
              return (
                <div key={group} role="group" aria-labelledby={gid}>
                  {/* antet: numele grupului + (de la sm în sus) coloanele vizibile „Email · In app";
                      pe telefon fiecare comutator îşi poartă eticheta lângă el */}
                  <div className="grid grid-cols-[minmax(0,1fr)] items-end gap-2 border-b border-ink-700/70 pb-1 sm:grid-cols-[minmax(0,1fr)_5.5rem_8.5rem]">
                    <p id={gid} className="text-xs font-semibold text-slate-300">{t(`alerts.group.${group}`)}</p>
                    <span aria-hidden="true" className="hidden text-xs text-slate-500 sm:block">{t('settings.alertPrefs.colEmail')}</span>
                    <span aria-hidden="true" className="hidden text-xs text-slate-500 sm:block">{t('settings.alertPrefs.colInapp')}</span>
                  </div>
                  <ul className="divide-y divide-ink-800">
                    {items.map((p) => {
                      const label = t(`alerts.kind.${p.kind}`)
                      return (
                        <li key={p.kind} data-alert-kind={p.kind}
                          className="grid grid-cols-[minmax(0,1fr)] gap-x-2 gap-y-1 py-2 sm:grid-cols-[minmax(0,1fr)_5.5rem_8.5rem] sm:items-center">
                          <div className="min-w-0 text-sm text-slate-300">
                            <span className="break-words">{label}</span>
                            {p.security && !p.email && (
                              <span className="mt-0.5 block text-2xs wt-warn" role="note">{t('settings.alertPrefs.securityEmailOff')}</span>
                            )}
                          </div>
                          <Switch checked={p.email} label={t('settings.alertPrefs.colEmail')} labelVisibility="mobile"
                            ariaLabel={t('settings.alertPrefs.emailAria', { event: label })}
                            onChange={(v) => { void togglePref(p.kind, 'email', v) }} />
                          {p.security ? (
                            // istoricul în aplicaţie al unui eveniment de securitate nu se poate opri:
                            // stare de citire, cu motivul lângă ea (audit Me4 / #11), nu o bifă gri
                            <p className="text-xs text-slate-400">
                              <span className="sm:hidden">{t('settings.alertPrefs.colInapp')}: </span>
                              {t('settings.alertPrefs.inappAlways')}
                            </p>
                          ) : (
                            <Switch checked={p.inapp} label={t('settings.alertPrefs.colInapp')} labelVisibility="mobile"
                              ariaLabel={t('settings.alertPrefs.inappAria', { event: label })}
                              onChange={(v) => { void togglePref(p.kind, 'inapp', v) }} />
                          )}
                        </li>
                      )
                    })}
                  </ul>
                </div>
              )
            })}
          </div>
        )}
        <span role="status" className={prefsMsg ? 'text-sm wt-good' : 'sr-only'}>{prefsMsg}</span>
        <span role="alert" className={prefsErr ? 'text-sm wt-danger' : 'sr-only'}>{prefsErr}</span>
      </SettingsSection>

      <section data-setting-id="taskNotify">
        {/* ── Notificări de task (Faza 1, local) ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.taskNotify')}<HelpTip id="taskNotify" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.taskNotifyHint')}</p>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={taskNotif}
            onChange={(e) => {
              const on = e.target.checked
              setTaskNotif(on)
              setTaskNotifyEnabled(on)
              if (on) void ensureNotificationPermission()   // cere permisiunea DIN gestul de utilizator (cerut pe iOS)
            }}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
          />
          <span>
            {t('settings.taskNotifyEnable')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.taskNotifyEnableHint')}</span>
          </span>
        </label>
        <label className="mt-3 block text-sm text-slate-300">
          <span className="mb-1 block text-xs text-slate-400">{t('settings.taskNotifySeconds')}</span>
          <input type="number" min={1} max={3600} step={1} value={taskSec} disabled={!taskNotif}
            onChange={(e) => { setTaskSec(e.target.value); const n = Number(e.target.value); if (Number.isFinite(n)) setTaskNotifySeconds(n) }}
            onBlur={() => setTaskSec(String(taskNotifySeconds()))}
            className={field + ' max-w-[8rem]'} />
          <span className="mt-0.5 block text-xs text-slate-500">{t('settings.taskNotifySecondsHint')}</span>
        </label>
        {/* Faza 2 — push pe acest dispozitiv (telefon cu aplicația închisă); apare doar dacă e
            suportat de browser ȘI configurat pe server (cheie VAPID). */}
        {pushSupported() && pushSt?.available && (
          <div className="mt-3 border-t border-ink-800 pt-3">
            <label className="flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
              <input type="checkbox" checked={pushHere} disabled={pushBusy}
                onChange={(e) => { void togglePush(e.target.checked) }}
                className="mt-0.5 h-4 w-4 rounded-md accent-sky-600" />
              <span>
                {t('settings.pushEnable')}
                <span className="mt-0.5 block text-xs text-slate-500">{t('settings.pushEnableHint')}</span>
              </span>
            </label>
            {pushHere && (
              <div className="mt-2">
                <Button variant="secondary" disabled={pushBusy} onClick={() => { void doPushTest() }}>
                  {t('push.test')}
                </Button>
              </div>
            )}
            <span role="status" className={pushMsg ? 'mt-1 block text-xs wt-good' : 'sr-only'}>{pushMsg}</span>
            <span role="alert" className={pushErr ? 'mt-1 block text-xs wt-danger' : 'sr-only'}>{pushErr}</span>
          </div>
        )}
      </section>
    </div>
  )
}
