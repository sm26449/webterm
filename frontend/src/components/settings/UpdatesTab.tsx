import { useEffect, useState } from 'react'
import { api, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import UpdateCommand from '../UpdateCommand'
import { Button, ErrorState, SettingsSection, Switch } from '../ui'
import HelpTip from '../HelpTip'
import SectionLoading from './SectionLoading'

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

  async function toggleCheck(enabled: boolean) {
    setUpd((u) => (u ? { ...u, enabled } : u))
    try {
      setUpd(await api<UpdateInfo>('/api/version/check',
        { method: 'POST', body: JSON.stringify({ enabled }) }))
    } catch { /* rămâne starea optimistă; reîncercarea e o re-deschidere */ }
  }
  async function checkNow() {
    setUpdBusy(true)
    try { setUpd(await api<UpdateInfo>('/api/version/refresh', { method: 'POST' })) }
    catch (e) {
      // cererea însăşi a picat (reţea, 5xx): fără asta rămânea afişată starea VECHE
      // („la zi" de acum o săptămână) — exact ce nu vrem de la un check de update
      setUpd((u) => (u ? { ...u, error: e instanceof Error ? e.message : String(e) } : u))
    }
    finally { setUpdBusy(false) }
  }

  // 3.7.1: comutatorul se aplică imediat (ca înainte, bifa); secţiune-card cu „?" (audit UX Setări)
  return (
    <div>
      <SettingsSection data-setting-id="appUpdate" hidden={!vis('appUpdate')} instanceWide
        title={t('settings.update.title')} titleExtra={<HelpTip id="versionCheck" />}
        description={t('settings.update.desc')}>
        {upd === null && updLoadErr !== null && (
          <div className="rounded-md ring-1 ring-ink-700"><ErrorState compact title={t('settings.notLoaded')} message={updLoadErr} onRetry={loadUpd} /></div>
        )}
        {upd === null && updLoadErr === null && <SectionLoading rows={2} />}
        {upd?.configurable === false ? (
          <p className="text-xs text-slate-500">{t('settings.update.disabledByEnv')}</p>
        ) : upd !== null && (
          <Switch checked={!!upd.enabled} label={t('settings.update.label')} hint={t('settings.update.hint')}
            onChange={(v) => { void toggleCheck(v) }} />
        )}
        {upd?.enabled && (
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs" role="status">
            {upd.update_available && <span className="wt-warn">{t('status.updateAvailable', { version: upd.latest ?? '' })}</span>}
            {upd.update_available === false && <span className="wt-good">{t('status.upToDate')}</span>}
            {upd.error && <span className="text-slate-500">{t('settings.update.unreachable')}</span>}
          </div>
        )}
        {upd?.enabled && (
          <Button type="button" variant="secondary" size="sm" className="mt-2" loading={updBusy} onClick={() => { void checkNow() }}>
            {updBusy ? t('settings.update.checking') : t('settings.update.checkNow')}
          </Button>
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
      </SettingsSection>
    </div>
  )
}
