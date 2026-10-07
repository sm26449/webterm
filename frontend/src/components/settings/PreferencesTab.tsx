import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { allTimezones, browserTimezone, getTimezone, setTimezone, timeInZone } from '../../lib/tz'
import UpdateCommand from '../UpdateCommand'
import { lsGet, lsSet } from '../../lib/storage'
import { isWalkthroughDone, markWalkthroughDone, resetWalkthrough } from '../../lib/walkthrough'
import { resetAllTips } from '../../lib/coachtips'
import { INBOX_REL, PasteDest, inboxDays, pasteDest, setInboxDays, setPasteDest } from '../../lib/transfers'
import { UpdatesMode, setUpdatesMode, unmuteAllHosts, useUpdatesPref } from '../../lib/updatesPref'
import { field, heading } from './ui'
import HelpTip from '../HelpTip'

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
  const [srMode, setSrMode] = useState(() => lsGet('wt_sr') === '1')
  // „arată turul pentru sesiuni noi" = inversul lui `wt_walkthrough_done` (toggle-ul doar
  // setează/şterge cheaia; bifat = se redeschide automat la prima rulare următoare)
  const [showWalk, setShowWalk] = useState(() => !isWalkthroughDone())
  // confirmare după „arată din nou sfaturile": sfaturile reapar pe măsură ce ajungi la UI-ul lor
  const [tipsReset, setTipsReset] = useState(false)
  const [unicode11, setUnicode11] = useState(() => lsGet('wt_unicode11') === '1')
  const [upd, setUpd] = useState<UpdateInfo | null>(null)
  const [updBusy, setUpdBusy] = useState(false)
  // transferuri: unde ajung fişierele lipite în terminal + retenţia inbox-ului (lib/transfers.ts)
  const [dest, setDest] = useState<PasteDest>(pasteDest)
  const [days, setDays] = useState<string>(() => String(inboxDays()))
  const updPref = useUpdatesPref()

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
      <section data-setting-id="timezone">
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
      </section>

      <section data-setting-id="accessibility">
        {/* ── Accesibilitate ── */}
        <h3 className={heading}>{t('settings.accessibility')}</h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={srMode}
            onChange={(e) => {
              setSrMode(e.target.checked)
              lsSet('wt_sr', e.target.checked ? '1' : '0')
            }}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
          />
          <span>
            {t('settings.screenReaderMode')}
            <span className="mt-0.5 block text-xs text-slate-500">
              {t('settings.screenReaderHintA')} <code className="font-mono">Ctrl+M</code> {t('settings.screenReaderHintB')}
            </span>
          </span>
        </label>
      </section>

      <section data-setting-id="walkthrough">
        {/* ── Turul de bun venit ── */}
        <h3 className={heading}>{t('walkthrough.settingsTitle')}</h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={showWalk}
            onChange={(e) => {
              setShowWalk(e.target.checked)
              // bifat → ştergem cheia (reapare la prima rulare); debifat → marcăm gata (nu mai apare)
              if (e.target.checked) resetWalkthrough()
              else markWalkthroughDone()
            }}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
          />
          <span>{t('walkthrough.settingsToggle')}</span>
        </label>
        {/* Redeschidere imediată: App ţine starea modalului, deci o cerem printr-un eveniment
            global (acelaşi tipar ca wt-focus-search/wt-session-insert) — nu atinge `wt_walkthrough_done`. */}
        <button
          type="button"
          onClick={() => window.dispatchEvent(new Event('wt-open-walkthrough'))}
          className="mt-2 rounded-md border border-ink-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800"
        >
          {t('walkthrough.replayButton')}
        </button>
      </section>

      <section data-setting-id="tips">
        {/* ── Sfaturi contextuale ── */}
        {/* Complementare walkthrough-ului: hint-uri de o singură dată, lângă UI-ul concret. „Arată
            din nou" şterge toate cheile wt_tip_* (resetAllTips), deci reapar pe măsură ce ajungi
            la funcţiile lor — fără să redeschidă nimic acum (spre deosebire de „reia turul"). */}
        <h3 className={heading}>{t('tips.resetTitle')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('tips.resetDesc')}</p>
        <button
          type="button"
          onClick={() => { resetAllTips(); setTipsReset(true) }}
          className="mt-2 rounded-md border border-ink-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800"
        >
          {t('tips.resetButton')}
        </button>
        {/* `role="status"`: resetarea e anunţată, nu doar colorată în verde */}
        <span role="status" className={tipsReset ? 'mt-2 block text-xs wt-good' : 'sr-only'}>
          {tipsReset ? t('tips.resetDone') : ''}
        </span>
      </section>

      <section data-setting-id="terminal">
        {/* ── Terminal ── */}
        <h3 className={heading}>{t('settings.terminal')}</h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={unicode11}
            onChange={(e) => {
              setUnicode11(e.target.checked)
              lsSet('wt_unicode11', e.target.checked ? '1' : '0')
            }}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
          />
          <span>
            {t('settings.unicode11')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.unicode11Hint')}</span>
          </span>
        </label>
        <p className="mt-2 text-xs text-slate-500">{t('settings.termReloadHint')}</p>
      </section>

      <section data-setting-id="transfers">
        {/* ── Transferuri ── */}
        <h3 className={heading}>{t('transfers.settingsTitle')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('transfers.pasteDestHint')}</p>
        <label className="mt-2 block text-sm text-slate-300">
          <span className="mb-1 block text-xs text-slate-400">{t('transfers.pasteDest')}</span>
          <select value={dest} onChange={(e) => { const d = e.target.value === 'cwd' ? 'cwd' : 'inbox'; setDest(d); setPasteDest(d) }} className={field}>
            <option value="inbox">{t('transfers.pasteDestInbox', { dir: `~/${INBOX_REL}` })}</option>
            <option value="cwd">{t('transfers.pasteDestCwd')}</option>
          </select>
        </label>
        <label className="mt-2 block text-sm text-slate-300">
          <span className="mb-1 block text-xs text-slate-400">{t('transfers.inboxDays')}</span>
          <input type="number" min={0} max={3650} step={1} value={days}
            onChange={(e) => { setDays(e.target.value); const n = Number(e.target.value); if (Number.isFinite(n)) setInboxDays(n) }}
            onBlur={() => setDays(String(inboxDays()))}
            className={field + ' max-w-[8rem]'} />
          <span className="mt-0.5 block text-xs text-slate-500">{t('transfers.inboxDaysHint')}</span>
        </label>
      </section>

      <section data-setting-id="updatesBadge">
        {/* ── Insigna de update-uri OS (lib/updatesPref) ── */}
        {/* Nivelul global al „mascării"; cel per host stă în meniul ⋯ al hostului şi în modalul de
            update-uri, iar aici doar numărăm hosturile ascunse şi le putem readuce pe toate. */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('updates.prefTitle')}<HelpTip id="updatesBadge" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('updates.prefDesc')}</p>
        <select value={updPref.mode} aria-label={t('updates.prefTitle')}
          onChange={(e) => setUpdatesMode(e.target.value as UpdatesMode)} className={field + ' mt-2'}>
          <option value="all">{t('updates.modeAll')}</option>
          <option value="security">{t('updates.modeSecurity')}</option>
          <option value="off">{t('updates.modeOff')}</option>
        </select>
        {updPref.muted.size > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span>{t('updates.prefMuted', { count: updPref.muted.size })}</span>
            <button type="button" onClick={unmuteAllHosts} className="wt-link">{t('updates.prefUnmuteAll')}</button>
          </div>
        )}
      </section>

      <section data-setting-id="appUpdate">
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
                        onRetry: () => { setUpdBusy(true); api<UpdateInfo>('/api/version/refresh', { method: 'POST' }).then(setUpd).catch(() => {}).finally(() => setUpdBusy(false)) } }} />
          </div>
        )}
      </section>
    </div>
  )
}
