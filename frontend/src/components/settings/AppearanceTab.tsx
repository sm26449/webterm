import { useEffect, useRef, useState } from 'react'
import { api, errText, WatermarkConfig } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { LANGS, LANG_ORDER } from '../../lang'
import { useTheme } from '../../lib/theme'
import {
  allSchemes, clearCustomTheme, COLOR_KEYS, currentTermScheme,
  customTheme, parseThemeFile, saveCustomTheme, setTermScheme, termTheme,
} from '../../lib/termtheme'
import { heading } from './ui'

// Aspect: limbă, temă (light/dark/auto), schema de culori a terminalului (+ editor live şi import
// iTerm2/VS Code) şi watermark-ul de identitate. Extras din SettingsModal ca tab de sine stătător.
export default function AppearanceTab(props: { onAccountChanged: () => void }) {
  const { t, lang, setLang } = useI18n()
  const [themePrefValue, , setTheme] = useTheme()
  const [scheme, setScheme] = useState(currentTermScheme())
  const [editing, setEditing] = useState(false)     // editorul de schemă proprie
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [importErr, setImportErr] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // Watermark — persistat server-side, aplicat pe workspace + link-uri partajate.
  const [wm, setWm] = useState<WatermarkConfig>({
    enabled: false, content: '${email} · ${time}', opacity: 0.08, angle: -30, fontSize: 13,
  })
  const [wmMsg, setWmMsg] = useState('')
  useEffect(() => {
    api<WatermarkConfig>('/api/settings/watermark').then(setWm).catch(() => {})
  }, [])
  const saveWatermark = async () => {
    try {
      const saved = await api<WatermarkConfig>('/api/settings/watermark',
        { method: 'POST', body: JSON.stringify(wm) })
      setWm(saved)
      setWmMsg(t('settings.saved'))
      props.onAccountChanged()   // refetch /api/state → overlay-ul live se actualizează
      setTimeout(() => setWmMsg(''), 1500)
    } catch {
      setWmMsg(t('settings.saveError'))
    }
  }

  const openEditor = () => {
    const base = customTheme() ?? termTheme(scheme)
    setDraft(Object.fromEntries(COLOR_KEYS.map((k) => [k, (base as Record<string, string>)[k] ?? '#000000'])))
    setEditing(true)
  }
  const applyDraft = (next: Record<string, string>) => {
    setDraft(next)
    // preview LIVE în toate terminalele deschise (mecanismul wt-termscheme)
    saveCustomTheme({ ...next, cursorAccent: next.background })
    setTermScheme('custom')
    setScheme('custom')
  }
  const importTheme = async (file: File) => {
    setImportErr('')
    try {
      const theme = parseThemeFile(file.name, await file.text())
      saveCustomTheme(theme)
      setTermScheme('custom')
      setScheme('custom')
      setDraft(Object.fromEntries(COLOR_KEYS.map((k) => [k, (theme as Record<string, string>)[k] ?? '#000000'])))
      setEditing(true)
    } catch (e) {
      setImportErr(errText(e, t) || t('settings.importFailed'))
    }
  }

  return (
    <div>
      {/* ── Limbă ── */}
      <h3 className={heading + ' !mt-0'}>{t('settings.language')}</h3>
      <div className="mt-2 flex flex-wrap gap-2">
        {LANG_ORDER.map((code) => (
          <button key={code} onClick={() => setLang(code)}
            className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ring-1 transition ${
              lang === code
                ? 'bg-sky-600/20 wt-accent ring-sky-500/40'
                : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
            <span className="text-base leading-none">{LANGS[code].meta.flag}</span> {LANGS[code].meta.name}
          </button>
        ))}
      </div>
      <p className="mt-1 text-[12px] text-slate-500">{t('settings.languageHint')}</p>

      {/* ── Temă ── */}
      <h3 className={heading}>{t('settings.theme')}</h3>
      <div className="mt-2 flex gap-2">
        {([['macos', 'Aurora'], ['dark', 'Midnight'], ['auto', t('settings.themeAuto')]] as const).map(([value, label]) => (
          <button key={value} onClick={() => setTheme(value)}
            className={`rounded-lg px-3 py-1.5 text-sm ring-1 ${
              themePrefValue === value
                ? 'bg-sky-600 text-white ring-sky-600'
                : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
            {label}
          </button>
        ))}
      </div>

      {/* ── Schema de culori a terminalului ── */}
      <h3 className={heading}>{t('settings.termColors')}</h3>
      <div className="mt-2 flex flex-wrap gap-2">
        {allSchemes().map((s) => (
          <button key={s.id} onClick={() => { setTermScheme(s.id); setScheme(s.id) }}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm ring-1 ${
              scheme === s.id
                ? 'bg-sky-600 text-white ring-sky-600'
                : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
            <span className="flex gap-0.5" aria-hidden="true">
              {[s.theme.red, s.theme.green, s.theme.blue, s.theme.magenta].map((c, i) => (
                <span key={i} className="h-3 w-1.5 rounded-sm" style={{ background: c }} />
              ))}
            </span>
            {s.id === 'custom' ? t('settings.customSchemeName') : s.name}
          </button>
        ))}
      </div>

      {/* schemă proprie: editor + import iTerm2/VS Code */}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button onClick={openEditor}
          className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
          {customTheme() ? t('settings.editMyScheme') : t('settings.customScheme')}
        </button>
        <button onClick={() => fileRef.current?.click()}
          className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
          title={t('settings.importThemeTitle')}>
          {t('settings.importTheme')}
        </button>
        <input ref={fileRef} type="file" accept=".itermcolors,.json,application/json,text/xml" className="hidden"
          onChange={(e) => e.target.files?.[0] && importTheme(e.target.files[0])} />
        {customTheme() && (
          <button onClick={() => { clearCustomTheme(); setTermScheme('webterm-dark'); setScheme('webterm-dark'); setEditing(false) }}
            className="rounded-lg px-2 py-1.5 text-xs wt-danger hover:bg-ink-800">
            {t('settings.deleteMyScheme')}
          </button>
        )}
      </div>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.importThemeHintA')}<code className="font-mono">.itermcolors</code>{t('settings.importThemeHintB')} <span className="font-mono">iTerm2-Color-Schemes</span> {t('settings.importThemeHintC')}
      </p>
      {importErr && <div className="mt-1 text-sm wt-danger">{importErr}</div>}

      {editing && (
        <div className="mt-3 rounded-xl border border-ink-700 p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium text-slate-300">{t('settings.mySchemeLive')}</span>
            <button onClick={() => setEditing(false)} className="text-xs text-slate-400 hover:text-slate-200">
              {t('settings.done')}
            </button>
          </div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 sm:grid-cols-3">
            {COLOR_KEYS.map((k) => (
              <label key={k} className="flex items-center gap-2 text-xs text-slate-400">
                <input type="color" value={draft[k] ?? '#000000'} aria-label={t('color.' + k)}
                  onChange={(e) => applyDraft({ ...draft, [k]: e.target.value })}
                  className="h-6 w-8 shrink-0 cursor-pointer rounded border border-ink-700 bg-transparent" />
                <span className="truncate">{t('color.' + k)}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* ── Watermark ── */}
      <h3 className={heading}>{t('settings.watermark')}</h3>
      <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
        <input type="checkbox" checked={wm.enabled}
          onChange={(e) => setWm({ ...wm, enabled: e.target.checked })}
          className="mt-0.5 h-4 w-4 rounded accent-sky-600" />
        <span>
          {t('settings.watermarkToggle')}
          <span className="mt-0.5 block text-xs text-slate-500">
            {t('settings.watermarkHint')} <code className="font-mono">{'${email}'}</code>{' '}
            <code className="font-mono">{'${host}'}</code> <code className="font-mono">{'${date}'}</code>{' '}
            <code className="font-mono">{'${time}'}</code>.
          </span>
        </span>
      </label>
      {wm.enabled && (
        <div className="mt-3 space-y-3">
          <label className="block text-xs text-slate-400">
            {t('settings.text')}
            <input type="text" value={wm.content} maxLength={200}
              onChange={(e) => setWm({ ...wm, content: e.target.value })}
              className="mt-1 w-full rounded-lg border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-sm text-slate-200 focus:border-sky-500 focus:outline-none" />
          </label>
          <div className="grid grid-cols-3 gap-3">
            <label className="block text-xs text-slate-400">
              {t('settings.opacity')} <span className="text-slate-500">{wm.opacity.toFixed(2)}</span>
              <input type="range" min={0.02} max={0.5} step={0.01} value={wm.opacity}
                onChange={(e) => setWm({ ...wm, opacity: parseFloat(e.target.value) })}
                className="mt-1 w-full accent-sky-600" />
            </label>
            <label className="block text-xs text-slate-400">
              {t('settings.angle')} <span className="text-slate-500">{wm.angle}°</span>
              <input type="range" min={-90} max={90} step={5} value={wm.angle}
                onChange={(e) => setWm({ ...wm, angle: parseInt(e.target.value, 10) })}
                className="mt-1 w-full accent-sky-600" />
            </label>
            <label className="block text-xs text-slate-400">
              {t('settings.size')} <span className="text-slate-500">{wm.fontSize}px</span>
              <input type="range" min={8} max={40} step={1} value={wm.fontSize}
                onChange={(e) => setWm({ ...wm, fontSize: parseInt(e.target.value, 10) })}
                className="mt-1 w-full accent-sky-600" />
            </label>
          </div>
        </div>
      )}
      <div className="mt-3 flex items-center gap-3">
        <button onClick={saveWatermark}
          className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500">
          {t('settings.saveWatermark')}
        </button>
        {wmMsg && <span className="text-xs text-slate-400">{wmMsg}</span>}
      </div>
    </div>
  )
}
