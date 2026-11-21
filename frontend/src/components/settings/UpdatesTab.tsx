import { useEffect, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import UpdateCommand from '../UpdateCommand'
import { heading } from './ui'
import { ErrorState } from '../ui'

// Actualizări (3.7.1, auditul UX Setări M2): verificarea de versiune a instanţei şi comanda de upgrade.
// Stătea în Preferences, lângă fusul orar personal; acum are tab-ul ei în Administrare (`settings.manage`).
// Secţiunea e mutată ca atare din PreferencesTab.
type UpdateInfo = {
  current: string; enabled: boolean; latest?: string
  update_available?: boolean; configurable?: boolean; error?: string
  update_command?: string
  release_url?: string
}

export default function UpdatesTab() {
  const { t } = useI18n()
  const vis = useSectionVisible()   // tab-ul apare doar cu settings.manage; un link adânc nu ocoleşte asta
  const [upd, setUpd] = useState<UpdateInfo | null>(null)
  const [updBusy, setUpdBusy] = useState(false)
  // singura conexiune iniţiată de gateway spre exterior; o citim la deschiderea tab-ului
  // U04: un fetch picat lăsa bifa dezactivată fără explicaţie — acum eroarea + Reîncearcă
  const [updLoadErr, setUpdLoadErr] = useState<string | null>(null)
  const loadUpd = () => { setUpdLoadErr(null); api<UpdateInfo>('/api/version').then(setUpd).catch((e) => setUpdLoadErr(errText(e, t))) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { if (upd === null) loadUpd() }, [])

  return (
    <div>
      <section data-setting-id="appUpdate" hidden={!vis('appUpdate')}>
        {/* ── Verificare de versiune ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.update.title')}</h3>
        {upd === null && updLoadErr !== null && (
          <div className="mt-2 rounded-md ring-1 ring-ink-700"><ErrorState compact title={t('settings.notLoaded')} message={updLoadErr} onRetry={loadUpd} /></div>
        )}
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
              className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
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
              catch (e) {
                // cererea însăşi a picat (reţea, 5xx): fără asta rămânea afişată starea VECHE
                // („la zi" de acum o săptămână) — exact ce nu vrem de la un check de update
                setUpd((u) => (u ? { ...u, error: e instanceof Error ? e.message : String(e) } : u))
              }
              finally { setUpdBusy(false) }
            }}
            disabled={updBusy}
            className="mt-2 rounded-md border border-ink-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800 disabled:opacity-50"
          >
            {updBusy ? t('settings.update.checking') : t('settings.update.checkNow')}
          </button>
        )}
        {upd?.update_command && (
          <div className="mt-3">
            <p className="text-xs text-slate-500">{t('settings.update.howTo')}</p>
            <UpdateCommand command={upd.update_command}
              status={{ error: upd.error, checking: updBusy,
                        onRetry: () => { setUpdBusy(true); api<UpdateInfo>('/api/version/refresh', { method: 'POST' }).then(setUpd).catch((e) => setUpd((u) => (u ? { ...u, error: errText(e, t) || t('common.loadFailed') } : u))).finally(() => setUpdBusy(false)) } }} />
            {upd.release_url && (
              <a href={upd.release_url} target="_blank" rel="noopener noreferrer"
                className="wt-link mt-2 inline-block text-xs hover:underline">
                {t('settings.update.releaseNotes', { version: upd.latest ?? '' })}
              </a>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
