import { useEffect, useState } from 'react'
import { useI18n } from '../../lib/i18n'
import { allTimezones, browserTimezone, getTimezone, setTimezone, timeInZone } from '../../lib/tz'
import { lsGet, lsSet } from '../../lib/storage'
import { isWalkthroughDone, markWalkthroughDone, resetWalkthrough } from '../../lib/walkthrough'
import { resetAllTips } from '../../lib/coachtips'
import { INBOX_REL, PasteDest, inboxDays, pasteDest, setInboxDays, setPasteDest } from '../../lib/transfers'
import { UpdatesMode, setUpdatesMode, unmuteAllHosts, useUpdatesPref } from '../../lib/updatesPref'
import { field } from './ui'
import HelpTip from '../HelpTip'
import { Button, Field, SegmentedControl, SettingsSection, Switch } from '../ui'

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

  // 3.7.1 (audit UX Setări Me1/M6/Mi1): secţiuni-card; preferinţele se aplică IMEDIAT, deci
  // comutatoare (nu bife) şi niciun Save; fiecare select/câmp are eticheta lui vizibilă (Field).
  return (
    <div className="flex flex-col gap-4">
      {/* ── Fus orar ── */}
      <SettingsSection data-setting-id="timezone" title={t('settings.timezone')} titleExtra={<HelpTip id="timezone" />}
        description={t('settings.timezoneDesc')}>
        <Field label={t('settings.timezoneZone')}>
          <select value={tz} onChange={(e) => chooseTz(e.target.value)} className={field}>
            {allTimezones().map((z) => (
              <option key={z} value={z}>{z}</option>
            ))}
          </select>
        </Field>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-sm">
          <span className="font-mono tabular-nums text-slate-300">{clock}</span>
          <Button type="button" variant="ghost" size="sm" onClick={() => chooseTz(browserTimezone())}>
            {t('settings.useDeviceTimezone', { tz: browserTimezone() })}
          </Button>
        </div>
      </SettingsSection>

      {/* ── Accesibilitate ── */}
      <SettingsSection data-setting-id="accessibility" title={t('settings.accessibility')}>
        <Switch checked={srMode} label={t('settings.screenReaderMode')}
          hint={<>{t('settings.screenReaderHintA')} <code className="font-mono">Ctrl+M</code> {t('settings.screenReaderHintB')}</>}
          onChange={(v) => { setSrMode(v); lsSet('wt_sr', v ? '1' : '0') }} />
      </SettingsSection>

      {/* ── Turul de bun venit ── */}
      <SettingsSection data-setting-id="walkthrough" title={t('walkthrough.settingsTitle')}>
        <Switch checked={showWalk} label={t('walkthrough.settingsToggle')}
          onChange={(v) => {
            setShowWalk(v)
            // pornit → ştergem cheia (reapare la prima rulare); oprit → marcăm gata (nu mai apare)
            if (v) resetWalkthrough()
            else markWalkthroughDone()
          }} />
        {/* Redeschidere imediată: App ţine starea modalului, deci o cerem printr-un eveniment
            global (acelaşi tipar ca wt-focus-search/wt-session-insert) — nu atinge `wt_walkthrough_done`. */}
        <Button type="button" variant="secondary" size="sm" className="mt-3"
          onClick={() => window.dispatchEvent(new Event('wt-open-walkthrough'))}>
          {t('walkthrough.replayButton')}
        </Button>
      </SettingsSection>

      {/* ── Sfaturi contextuale ── */}
      {/* Complementare walkthrough-ului: hint-uri de o singură dată, lângă UI-ul concret. „Arată
          din nou" şterge toate cheile wt_tip_* (resetAllTips), deci reapar pe măsură ce ajungi
          la funcţiile lor — fără să redeschidă nimic acum (spre deosebire de „reia turul"). */}
      <SettingsSection data-setting-id="tips" title={t('tips.resetTitle')} description={t('tips.resetDesc')}>
        <Button type="button" variant="secondary" size="sm"
          onClick={() => { resetAllTips(); setTipsReset(true) }}>
          {t('tips.resetButton')}
        </Button>
        {/* `role="status"`: resetarea e anunţată, nu doar colorată în verde */}
        <span role="status" className={tipsReset ? 'mt-2 block text-xs wt-good' : 'sr-only'}>
          {tipsReset ? t('tips.resetDone') : ''}
        </span>
      </SettingsSection>

      {/* ── Terminal ── */}
      <SettingsSection data-setting-id="terminal" title={t('settings.terminal')} description={t('settings.termReloadHint')}>
        <div className="flex flex-col gap-3">
          <Switch checked={unicode11} label={t('settings.unicode11')} hint={t('settings.unicode11Hint')}
            onChange={(v) => { setUnicode11(v); lsSet('wt_unicode11', v ? '1' : '0') }} />
          <Field label={t('settings.renderer')} hint={t('settings.rendererHint')} className="max-w-xs">
            <select value={renderer}
              onChange={(e) => {
                const v = e.target.value
                setRenderer(v)
                lsSet('wt_renderer', v)
                window.dispatchEvent(new Event('wt-renderer'))   // terminalele deschise se reîncarcă pe loc
              }}
              className={field}>
              <option value="webgl">{t('settings.renderer.webgl')}</option>
              <option value="canvas">{t('settings.renderer.canvas')}</option>
              <option value="dom">{t('settings.renderer.dom')}</option>
            </select>
          </Field>
        </div>
      </SettingsSection>

      {/* ── Transferuri ── */}
      <SettingsSection data-setting-id="transfers" title={t('transfers.settingsTitle')} titleExtra={<HelpTip id="transfers" />}
        description={t('transfers.pasteDestHint')}>
        <div className="flex flex-col gap-3">
          <Field label={t('transfers.pasteDest')}>
            <select value={dest} onChange={(e) => { const d = e.target.value === 'cwd' ? 'cwd' : 'inbox'; setDest(d); setPasteDest(d) }} className={field}>
              <option value="inbox">{t('transfers.pasteDestInbox', { dir: `~/${INBOX_REL}` })}</option>
              <option value="cwd">{t('transfers.pasteDestCwd')}</option>
            </select>
          </Field>
          <Field label={t('transfers.inboxDays')} hint={t('transfers.inboxDaysHint')}>
            <input type="number" min={0} max={3650} step={1} value={days}
              onChange={(e) => { setDays(e.target.value); const n = Number(e.target.value); if (Number.isFinite(n)) setInboxDays(n) }}
              onBlur={() => setDays(String(inboxDays()))}
              className={field + ' max-w-[8rem]'} />
          </Field>
        </div>
      </SettingsSection>

      {/* ── Insigna de update-uri OS (lib/updatesPref) ── */}
      {/* Nivelul global al „mascării"; cel per host stă în meniul ⋯ al hostului şi în modalul de
          update-uri, iar aici doar numărăm hosturile ascunse şi le putem readuce pe toate. */}
      <SettingsSection data-setting-id="updatesBadge" title={t('updates.prefTitle')} titleExtra={<HelpTip id="updatesBadge" />}
        description={t('updates.prefDesc')}>
        {/* o alegere din trei, aplicată imediat → SegmentedControl (audit UX Setări M7) */}
        <SegmentedControl label={t('updates.prefTitle')} value={updPref.mode}
          onChange={(m) => setUpdatesMode(m)}
          options={[
            { value: 'all' as UpdatesMode, label: t('updates.modeAll') },
            { value: 'security' as UpdatesMode, label: t('updates.modeSecurity') },
            { value: 'off' as UpdatesMode, label: t('updates.modeOff') },
          ]} />
        {updPref.muted.size > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-slate-500">
            <span>{t('updates.prefMuted', { count: updPref.muted.size })}</span>
            <Button type="button" variant="ghost" size="sm" onClick={unmuteAllHosts}>{t('updates.prefUnmuteAll')}</Button>
          </div>
        )}
      </SettingsSection>
    </div>
  )
}
