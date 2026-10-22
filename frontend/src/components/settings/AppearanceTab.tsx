import { useEffect, useRef, useState } from 'react'
import { api, errText, WatermarkConfig } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { LANG_META, LANG_ORDER } from '../../lang'
import { useTheme } from '../../lib/theme'
import { FAMILIES, VARIANTS, type Swatch, type ThemeMode } from '../../lib/themeModel'
import {
  allSchemes, clearCustomTheme, COLOR_KEYS, currentTermScheme, explicitTermScheme, FAMILY_SCHEME,
  customTheme, followThemeTermScheme, parseThemeFile, saveCustomTheme, setTermScheme, termTheme,
} from '../../lib/termtheme'
import { heading } from './ui'
import { Button } from '../ui'
import { canSave, type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'

// Aspect: limbă, temă (light/dark/auto), schema de culori a terminalului (+ editor live şi import
// iTerm2/VS Code) şi watermark-ul de identitate. Extras din SettingsModal ca tab de sine stătător.
export default function AppearanceTab(props: { onAccountChanged: () => void }) {
  const { t, lang, setLang } = useI18n()
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  const [pref, , setTheme] = useTheme()
  const [scheme, setScheme] = useState(currentTermScheme())
  // „Potrivit cu tema" (fără alegere explicită): schema terminalului urmează familia temei
  const [schemeAuto, setSchemeAuto] = useState(explicitTermScheme() === null)
  const pickScheme = (id: string) => { setTermScheme(id); setScheme(id); setSchemeAuto(false) }
  const followTheme = () => { followThemeTermScheme(); setSchemeAuto(true); setScheme(FAMILY_SCHEME[pref.family]) }
  // altă familie de temă → altă schemă implicită (contează pentru editorul de schemă proprie)
  useEffect(() => { if (schemeAuto) setScheme(FAMILY_SCHEME[pref.family]) }, [schemeAuto, pref.family])
  const [editing, setEditing] = useState(false)     // editorul de schemă proprie
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [importErr, setImportErr] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  // Watermark — persistat server-side, aplicat pe workspace + link-uri partajate.
  const [wm, setWm] = useState<WatermarkConfig>({
    enabled: false, content: '${email} · ${time}', opacity: 0.08, angle: -30, fontSize: 13,
  })
  const [wmMsg, setWmMsg] = useState('')
  const [wmErr, setWmErr] = useState(false)   // acelaşi text, dar rol diferit: `alert` la eşec
  // U04: un fetch picat lăsa valorile implicite („dezactivat") afişate ca setare — iar „Salvează"
  // OPREA un watermark activ pe server. Formularul apare doar peste valorile încărcate.
  const [wmState, setWmState] = useState<LoadState>({ status: 'loading' })
  const loadWm = () => {
    setWmState({ status: 'loading' })
    api<WatermarkConfig>('/api/settings/watermark')
      .then((r) => { setWm(r); setWmState({ status: 'ok' }) })
      .catch((e) => setWmState({ status: 'error', error: errText(e, t) }))
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { loadWm() }, [])
  const saveWatermark = async () => {
    if (!canSave(wmState)) return
    try {
      const saved = await api<WatermarkConfig>('/api/settings/watermark',
        { method: 'POST', body: JSON.stringify(wm) })
      setWm(saved)
      setWmErr(false); setWmMsg(t('settings.saved'))
      props.onAccountChanged()   // refetch /api/state → overlay-ul live se actualizează
      setTimeout(() => setWmMsg(''), 1500)
    } catch {
      setWmErr(true); setWmMsg(t('settings.saveError'))
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
    pickScheme('custom')
  }
  const importTheme = async (file: File) => {
    setImportErr('')
    try {
      const theme = parseThemeFile(file.name, await file.text())
      saveCustomTheme(theme)
      pickScheme('custom')
      setDraft(Object.fromEntries(COLOR_KEYS.map((k) => [k, (theme as Record<string, string>)[k] ?? '#000000'])))
      setEditing(true)
    } catch (e) {
      setImportErr(errText(e, t) || t('settings.importFailed'))
    }
  }

  return (
    <div>
      <section data-setting-id="language">
        {/* ── Limbă ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.language')}</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          {LANG_ORDER.map((code) => (
            <button key={code} onClick={() => setLang(code)} aria-pressed={lang === code}
              className={`flex items-center gap-2 rounded-md px-3 py-2 text-sm ring-1 transition ${
                lang === code
                  ? 'wt-chip-accent ring-sky-500/40'
                  : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
              <span className="text-base leading-none">{LANG_META[code].flag}</span> {LANG_META[code].name}
            </button>
          ))}
        </div>
        <p className="mt-1 text-xs text-slate-500">{t('settings.languageHint')}</p>
      </section>

      <section data-setting-id="theme">
        {/* ── Temă: familia (stilul) ── */}
        <h3 className={heading} id="theme-style-h">{t('settings.theme')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('theme.styleHint')}</p>
        <div role="group" aria-labelledby="theme-style-h" className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
          {FAMILIES.map((f) => {
            const on = pref.family === f.id
            return (
              <button key={f.id} onClick={() => setTheme({ family: f.id, mode: pref.mode })} aria-pressed={on}
                data-theme-family={f.id}
                className={`flex flex-col gap-2 rounded-xl p-2 text-left ring-1 transition ${
                  on ? 'bg-ink-800 ring-2 ring-sky-500' : 'bg-ink-900 ring-ink-700 hover:bg-ink-800'}`}>
                <span className="flex h-12 w-full overflow-hidden rounded-md ring-1 ring-ink-700" aria-hidden="true">
                  <ThemePreview s={VARIANTS[f.light].swatch} />
                  <ThemePreview s={VARIANTS[f.dark].swatch} />
                </span>
                <span className="block px-0.5">
                  <span className="block text-sm font-medium text-slate-200">{t(`theme.family.${f.id}`)}</span>
                  <span className="block text-xs text-slate-500">{t(`theme.familySub.${f.id}`)}</span>
                </span>
              </button>
            )
          })}
        </div>
      </section>

      <section data-setting-id="themeMode">
        {/* ── Temă: modul (deschis / închis / după sistem), în familia aleasă ── */}
        <h4 id="theme-mode-h" className="mt-4 text-sm font-medium text-slate-300">{t('theme.mode')}</h4>
        <div role="group" aria-labelledby="theme-mode-h" className="mt-2 flex flex-wrap gap-2">
          {(['light', 'dark', 'auto'] as const satisfies readonly ThemeMode[]).map((mode) => {
            const label = mode === 'auto' ? t('settings.themeAuto') : t(`theme.mode.${mode}`)
            // pe WebTerm modurile au nume proprii (Aurora / Midnight) — rămân vizibile
            const proper = pref.family === 'webterm' && mode !== 'auto' ? (mode === 'light' ? 'Aurora' : 'Midnight') : ''
            return (
              <button key={mode} onClick={() => setTheme({ family: pref.family, mode })} aria-pressed={pref.mode === mode}
                className={`rounded-md px-3 py-1.5 text-sm ring-1 ${
                  pref.mode === mode
                    ? 'bg-sky-600 text-white ring-sky-600'
                    : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
                {label}{proper && <span> · {proper}</span>}
              </button>
            )
          })}
        </div>
      </section>

      <section data-setting-id="termColors">
        {/* ── Schema de culori a terminalului ── */}
        <h3 className={heading}>{t('settings.termColors')}</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          <button onClick={followTheme} aria-pressed={schemeAuto} title={t('settings.termMatchThemeTitle')}
            className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-sm ring-1 ${
              schemeAuto
                ? 'bg-sky-600 text-white ring-sky-600'
                : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
            {t('settings.termMatchTheme')}
          </button>
          {allSchemes().map((s) => (
            <button key={s.id} onClick={() => pickScheme(s.id)} aria-pressed={!schemeAuto && scheme === s.id}
              className={`flex items-center gap-2 rounded-md px-3 py-1.5 text-sm ring-1 ${
                !schemeAuto && scheme === s.id
                  ? 'bg-sky-600 text-white ring-sky-600'
                  : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
              <span className="flex gap-0.5" aria-hidden="true">
                {[s.theme.red, s.theme.green, s.theme.blue, s.theme.magenta].map((c, i) => (
                  <span key={i} className="h-3 w-1.5 rounded-md" style={{ background: c }} />
                ))}
              </span>
              {s.id === 'custom' ? t('settings.customSchemeName') : s.name}
            </button>
          ))}
        </div>

        {/* schemă proprie: editor + import iTerm2/VS Code */}
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button onClick={openEditor}
            className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
            {customTheme() ? t('settings.editMyScheme') : t('settings.customScheme')}
          </button>
          <button onClick={() => fileRef.current?.click()}
            className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
            title={t('settings.importThemeTitle')}>
            {t('settings.importTheme')}
          </button>
          <input ref={fileRef} type="file" accept=".itermcolors,.json,application/json,text/xml" className="hidden"
            onChange={(e) => e.target.files?.[0] && importTheme(e.target.files[0])} />
          {customTheme() && (
            <button onClick={() => { clearCustomTheme(); followTheme(); setEditing(false) }}
              className="rounded-md px-2 py-1.5 text-xs wt-danger hover:bg-ink-800">
              {t('settings.deleteMyScheme')}
            </button>
          )}
        </div>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.importThemeHintA')}<code className="font-mono">.itermcolors</code>{t('settings.importThemeHintB')} <span className="font-mono">iTerm2-Color-Schemes</span> {t('settings.importThemeHintC')}
        </p>
        <div role="alert" className={importErr ? 'mt-1 text-sm wt-danger' : 'sr-only'}>{importErr}</div>

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
                    className="h-6 w-8 shrink-0 cursor-pointer rounded-md border border-ink-700 bg-transparent" />
                  <span className="truncate">{t('color.' + k)}</span>
                </label>
              ))}
            </div>
          </div>
        )}
      </section>

      <section data-setting-id="watermark" hidden={!vis('watermark')}>
        {/* ── Watermark ── */}
        <h3 className={heading}>{t('settings.watermark')}</h3>
        <NotLoaded state={wmState} onRetry={loadWm} />
        {canSave(wmState) && (<>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input type="checkbox" checked={wm.enabled}
            onChange={(e) => setWm({ ...wm, enabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600" />
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
                className="mt-1 w-full rounded-md border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-sm text-slate-200 focus:border-sky-500 focus:outline-none" />
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
          <Button variant="primary" onClick={saveWatermark}>
            {t('settings.saveWatermark')}
          </Button>
          {/* două regiuni, nu una cu rol variabil: schimbarea rolului pe acelaşi nod nu e anunţată */}
          <span role="status" className={wmMsg && !wmErr ? 'text-xs wt-good' : 'sr-only'}>{wmErr ? '' : wmMsg}</span>
          <span role="alert" className={wmMsg && wmErr ? 'text-xs wt-danger' : 'sr-only'}>{wmErr ? wmMsg : ''}</span>
        </div>
        </>)}
      </section>
    </div>
  )
}

/** Miniatura unei variante în cardul de familie: sidebar + suprafaţă + accent (decorativ, aria-hidden). */
function ThemePreview({ s }: { s: Swatch }) {
  return (
    <span className="flex flex-1" style={{ background: s.bg }}>
      <span className="w-1/4" style={{ background: s.side, borderRight: `1px solid ${s.line}` }} />
      <span className="flex flex-1 flex-col justify-center gap-1 px-1.5">
        <span className="block h-1.5 w-3/4 rounded-full" style={{ background: s.text, opacity: 0.7 }} />
        <span className="block h-3 rounded-md" style={{ background: s.surface, border: `1px solid ${s.line}` }} />
        <span className="block h-1.5 w-1/3 rounded-full" style={{ background: s.accent }} />
      </span>
    </span>
  )
}
