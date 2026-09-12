import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { allTimezones, browserTimezone, getTimezone, setTimezone, timeInZone } from '../../lib/tz'
import UpdateCommand from '../UpdateCommand'
import { field, heading } from './ui'

// Preferinţe: fus orar, accesibilitate (mod screen-reader), verificarea de versiune. Extras din
// SettingsModal ca tab de sine stătător (îşi ţine starea, se încarcă la montare).
type UpdateInfo = {
  current: string; enabled: boolean; latest?: string
  update_available?: boolean; configurable?: boolean; error?: string
  update_command?: string
}

export default function PreferencesTab() {
  const { t } = useI18n()
  const [tz, setTz] = useState(getTimezone())
  const [clock, setClock] = useState(timeInZone(getTimezone()))
  const [srMode, setSrMode] = useState(() => localStorage.getItem('wt_sr') === '1')
  const [upd, setUpd] = useState<UpdateInfo | null>(null)
  const [updBusy, setUpdBusy] = useState(false)

  useEffect(() => {
    const iv = setInterval(() => setClock(timeInZone(tz)), 1000)
    return () => clearInterval(iv)
  }, [tz])

  // singura conexiune iniţiată de gateway spre exterior; o citim la deschiderea tab-ului
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (upd === null) api<UpdateInfo>('/api/version').then(setUpd).catch(() => {}) }, [])

  function chooseTz(value: string) {
    setTz(value)
    setTimezone(value)
    setClock(timeInZone(value))
  }

  return (
    <div>
      {/* ── Fus orar ── */}
      <h3 className={heading + ' !mt-0'}>{t('settings.timezone')}</h3>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.timezoneHintA')} <code className="font-mono text-slate-400">TZ</code>{t('settings.timezoneHintB')}
      </p>
      <div className="mt-2 flex items-center gap-2">
        <select value={tz} onChange={(e) => chooseTz(e.target.value)} aria-label={t('settings.timezone')} className={field}>
          {allTimezones().map((z) => (
            <option key={z} value={z}>{z}</option>
          ))}
        </select>
      </div>
      <div className="mt-2 flex items-center justify-between text-sm">
        <span className="font-mono tabular-nums text-slate-300">{clock}</span>
        <button onClick={() => chooseTz(browserTimezone())} className="wt-link text-xs">
          {t('settings.useDeviceTimezone', { tz: browserTimezone() })}
        </button>
      </div>

      {/* ── Accesibilitate ── */}
      <h3 className={heading}>{t('settings.accessibility')}</h3>
      <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
        <input
          type="checkbox"
          checked={srMode}
          onChange={(e) => {
            setSrMode(e.target.checked)
            localStorage.setItem('wt_sr', e.target.checked ? '1' : '0')
          }}
          className="mt-0.5 h-4 w-4 rounded accent-sky-600"
        />
        <span>
          {t('settings.screenReaderMode')}
          <span className="mt-0.5 block text-xs text-slate-500">
            {t('settings.screenReaderHintA')} <code className="font-mono">Ctrl+M</code> {t('settings.screenReaderHintB')}
          </span>
        </span>
      </label>

      {/* ── Verificare de versiune ── */}
      <h3 className={heading}>{t('settings.update.title')}</h3>
      {upd?.configurable === false ? (
        <p className="mt-2 text-xs text-slate-500">{t('settings.update.disabledByEnv')}</p>
      ) : (
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={!!upd?.enabled}
            disabled={upd === null}
            onChange={async (e) => {
              const enabled = e.target.checked
              setUpd((u) => (u ? { ...u, enabled } : u))
              try {
                setUpd(await api<UpdateInfo>('/api/version/check',
                  { method: 'POST', body: JSON.stringify({ enabled }) }))
              } catch { /* rămâne starea optimistă; reîncercarea e o re-deschidere */ }
            }}
            className="mt-0.5 h-4 w-4 rounded accent-sky-600"
          />
          <span>
            {t('settings.update.label')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.update.hint')}</span>
            {upd?.enabled && upd.update_available && (
              <span className="mt-1 block text-xs wt-warn">
                {t('status.updateAvailable', { version: upd.latest ?? '' })}
              </span>
            )}
            {upd?.enabled && upd.update_available === false && (
              <span className="mt-1 block text-xs wt-good">{t('status.upToDate')}</span>
            )}
            {upd?.enabled && upd.error && (
              <span className="mt-1 block text-xs text-slate-500">{t('settings.update.unreachable')}</span>
            )}
          </span>
        </label>
      )}
      {upd?.enabled && (
        <button
          type="button"
          onClick={async () => {
            setUpdBusy(true)
            try { setUpd(await api<UpdateInfo>('/api/version/refresh', { method: 'POST' })) }
            catch { /* mesajul de eroare vine din câmpul `error` al răspunsului următor */ }
            finally { setUpdBusy(false) }
          }}
          disabled={updBusy}
          className="mt-2 rounded-lg border border-ink-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800 disabled:opacity-50"
        >
          {updBusy ? t('settings.update.checking') : t('settings.update.checkNow')}
        </button>
      )}
      {upd?.update_command && (
        <div className="mt-3">
          <p className="text-xs text-slate-500">{t('settings.update.howTo')}</p>
          <UpdateCommand command={upd.update_command} />
        </div>
      )}
    </div>
  )
}
