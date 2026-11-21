import { useEffect, useState } from 'react'
import { useI18n } from '../../lib/i18n'
import { allTimezones, browserTimezone, getTimezone, setTimezone, timeInZone } from '../../lib/tz'
import { lsGet, lsSet } from '../../lib/storage'
import { isWalkthroughDone, markWalkthroughDone, resetWalkthrough } from '../../lib/walkthrough'
import { resetAllTips } from '../../lib/coachtips'
import { INBOX_REL, PasteDest, inboxDays, pasteDest, setInboxDays, setPasteDest } from '../../lib/transfers'
import { UpdatesMode, setUpdatesMode, unmuteAllHosts, useUpdatesPref } from '../../lib/updatesPref'
import { field, heading } from './ui'
import HelpTip from '../HelpTip'

// Terminal şi spaţiu de lucru (fostele Preferinţe; id-ul `preferinte` rămâne): fus orar, accesibilitate
// (mod screen-reader), turul, sfaturile, terminalul, transferurile, insigna de update-uri OS — tot
// preferinţe ale TALE, per browser. Extras din SettingsModal ca tab de sine stătător. 3.7.1 (auditul
// UX Setări M2/M3): notificările de task au plecat în MyNotificationsTab, verificarea de versiune
// (o setare a instanţei, lângă fusul tău orar) în UpdatesTab.

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
  // renderer-ul terminalului (3.6.19): webgl (implicit) | canvas | dom — per browser, aplicat pe loc
  const [renderer, setRenderer] = useState(() => { const v = lsGet('wt_renderer'); return v === 'canvas' || v === 'dom' ? v : 'webgl' })
  // transferuri: unde ajung fişierele lipite în terminal + retenţia inbox-ului (lib/transfers.ts)
  const [dest, setDest] = useState<PasteDest>(pasteDest)
  const [days, setDays] = useState<string>(() => String(inboxDays()))
  const updPref = useUpdatesPref()

  useEffect(() => {
    const iv = setInterval(() => setClock(timeInZone(tz)), 1000)
    return () => clearInterval(iv)
  }, [tz])


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
        <label className="mt-3 block text-sm text-slate-300">
          <span>{t('settings.renderer')}</span>
          <select value={renderer} aria-describedby="wt-renderer-hint"
            onChange={(e) => {
              const v = e.target.value
              setRenderer(v)
              lsSet('wt_renderer', v)
              window.dispatchEvent(new Event('wt-renderer'))   // terminalele deschise se reîncarcă pe loc
            }}
            className={`${field} mt-1 max-w-xs`}>
            <option value="webgl">{t('settings.renderer.webgl')}</option>
            <option value="canvas">{t('settings.renderer.canvas')}</option>
            <option value="dom">{t('settings.renderer.dom')}</option>
          </select>
        </label>
        <p id="wt-renderer-hint" className="mt-0.5 text-xs text-slate-500">{t('settings.rendererHint')}</p>
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
    </div>
  )
}
