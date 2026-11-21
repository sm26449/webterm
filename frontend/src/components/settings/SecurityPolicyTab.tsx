import { useEffect, useState } from 'react'
import { errText, api, CommandGuard, DeployKeyPolicy, WatermarkConfig } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { CloseIcon } from '../Icons'
import { field, fieldBase } from './ui'
import HelpTip from '../HelpTip'
import { Button, Field, IconButton, SettingsSection, Switch } from '../ui'
import { canSave, type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'

// Politici de securitate (3.7.1, auditul UX Setări C2/M2): regulile care se aplică TUTUROR — guardrail-ul
// de comenzi, politica cheilor de deploy şi watermark-ul. Primele două erau în „Infrastructure &
// tokens", watermark-ul în Appearance, lângă tema personală (un Admin nu ştia că schimbă ceva pentru
// toţi). Logica secţiunilor e mutată ca atare din InfrastructureTab / AppearanceTab.
export default function SecurityPolicyTab(props: { onAccountChanged: () => void }) {
  const { t } = useI18n()
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar

  // Guardrail de comenzi — verificat client-side la Enter (via OSC 133)
  const [guard, setGuard] = useState<CommandGuard>({ enabled: true, rules: [] })
  const [guardMsg, setGuardMsg] = useState('')
  const [guardBase, setGuardBase] = useState('')   // ultima stare de pe server (pentru „Unsaved changes")
  // U04 — controale de SECURITATE: pe un fetch picat, formularul arăta „nicio regulă" şi un Save
  // ŞTERGEA toate regulile guardrail-ului de pe server (la fel, o bifă a politicii cheilor de
  // deploy trimitea celălalt câmp ca `false`). Formularele apar doar peste valorile încărcate.
  const [guardState, setGuardState] = useState<LoadState>({ status: 'loading' })
  const loadGuard = () => {
    setGuardState({ status: 'loading' })
    api<CommandGuard>('/api/settings/command-guard')
      .then((g) => { setGuard(g); setGuardBase(JSON.stringify(g)); setGuardState({ status: 'ok' }) })
      .catch((e) => setGuardState({ status: 'error', error: errText(e, t) }))
  }
  const saveGuard = async () => {
    if (!canSave(guardState)) return
    // Serverul validează cu `re` din Python, terminalul potriveşte cu RegExp din JS: un pattern
    // valid doar în Python (ex. `(?P<n>…)`, `\Z`) trecea la salvare şi era apoi SĂRIT tăcut în
    // terminal. Îl refuzăm aici, numindu-l, ca regula să se comporte la fel peste tot.
    for (const r of guard?.rules ?? []) {
      try { new RegExp(r.pattern, 'i') } catch {
        setGuardMsg(t('settings.guardJsInvalid', { pattern: r.pattern }))
        return
      }
    }
    try {
      const saved = await api<CommandGuard>('/api/settings/command-guard',
        { method: 'POST', body: JSON.stringify(guard) })
      setGuard(saved); setGuardBase(JSON.stringify(saved))
      setGuardMsg(t('settings.saved'))
      props.onAccountChanged()   // refetch /api/state → guardrail-ul live se actualizează
      setTimeout(() => setGuardMsg(''), 1500)
    } catch (e) {
      setGuardMsg(errText(e, t) || t('settings.saveError'))
    }
  }

  // ── Politica cheilor de deploy (opţională): 2FA pe surse + numai chei restricţionate ──
  const [dkPolicy, setDkPolicy] = useState<DeployKeyPolicy>({ require_2fa_source: false, require_restrict: false })
  const [dkPolicyMsg, setDkPolicyMsg] = useState('')
  const [dkState, setDkState] = useState<LoadState>({ status: 'loading' })
  const loadDkPolicy = () => {
    setDkState({ status: 'loading' })
    api<DeployKeyPolicy>('/api/settings/deploy-key-policy')
      .then((p) => { setDkPolicy(p); setDkState({ status: 'ok' }) })
      .catch((e) => setDkState({ status: 'error', error: errText(e, t) }))
  }
  const saveDkPolicy = async (next: DeployKeyPolicy) => {
    if (!canSave(dkState)) return
    setDkPolicy(next)
    try {
      await api<DeployKeyPolicy>('/api/settings/deploy-key-policy', { method: 'POST', body: JSON.stringify(next) })
      setDkPolicyMsg(t('settings.saved')); setTimeout(() => setDkPolicyMsg(''), 1500)
    } catch (e) { setDkPolicyMsg(errText(e, t) || t('settings.saveError')) }
  }

  // Watermark — persistat server-side, aplicat pe workspace + link-uri partajate.
  const [wm, setWm] = useState<WatermarkConfig>({
    enabled: false, content: '${email} · ${time}', opacity: 0.08, angle: -30, fontSize: 13,
  })
  const [wmMsg, setWmMsg] = useState('')
  const [wmErr, setWmErr] = useState(false)
  const [wmBase, setWmBase] = useState('')   // acelaşi text, dar rol diferit: `alert` la eşec
  // U04: un fetch picat lăsa valorile implicite („dezactivat") afişate ca setare — iar „Salvează"
  // OPREA un watermark activ pe server. Formularul apare doar peste valorile încărcate.
  const [wmState, setWmState] = useState<LoadState>({ status: 'loading' })
  const loadWm = () => {
    setWmState({ status: 'loading' })
    api<WatermarkConfig>('/api/settings/watermark')
      .then((r) => { setWm(r); setWmBase(JSON.stringify(r)); setWmState({ status: 'ok' }) })
      .catch((e) => setWmState({ status: 'error', error: errText(e, t) }))
  }
  const saveWatermark = async () => {
    if (!canSave(wmState)) return
    try {
      const saved = await api<WatermarkConfig>('/api/settings/watermark',
        { method: 'POST', body: JSON.stringify(wm) })
      setWm(saved); setWmBase(JSON.stringify(saved))
      setWmErr(false); setWmMsg(t('settings.saved'))
      props.onAccountChanged()   // refetch /api/state → overlay-ul live se actualizează
      setTimeout(() => setWmMsg(''), 1500)
    } catch {
      setWmErr(true); setWmMsg(t('settings.saveError'))
    }
  }

  // se încarcă la montarea tab-ului (= la deschiderea categoriei)
  useEffect(() => {
    loadGuard()
    loadDkPolicy()
    loadWm()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // 3.7.1 (audit UX Setări M6): formularele salvate cu un buton arată „Unsaved changes" până la Save
  const guardDirty = canSave(guardState) && guardBase !== '' && JSON.stringify(guard) !== guardBase
  const wmDirty = canSave(wmState) && wmBase !== '' && JSON.stringify(wm) !== wmBase
  return (
    <div className="flex flex-col gap-4">
      {/* ── Guardrail de comenzi ── bifa (nu comutator): face parte din formularul salvat cu „Save guardrail" */}
      <SettingsSection data-setting-id="guardrail" hidden={!vis('guardrail')} instanceWide
        title={t('settings.guardrail')} titleExtra={<HelpTip id="guardrail" />}
        description={t('settings.guardrailDesc')} dirty={guardDirty}
        footer={canSave(guardState) ? <>
          <Button variant="primary" type="button" onClick={saveGuard}>{t('settings.saveGuardrail')}</Button>
          {guardMsg && <span role="status" className="text-xs text-slate-400">{guardMsg}</span>}
        </> : undefined}>
        <NotLoaded state={guardState} onRetry={loadGuard} />
        {canSave(guardState) && (<>
        <label className="flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={guard.enabled}
            onChange={(e) => setGuard({ ...guard, enabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
          />
          <span>
            {t('settings.guardrailToggle')}
            <span className="mt-0.5 block text-xs text-slate-500">
              {t('settings.guardrailHint')}
            </span>
          </span>
        </label>
        {guard.enabled && (
          <div className="mt-3 space-y-2">
            {/* rânduri repetate: un antet vizibil pe coloane + nume accesibil pe fiecare câmp */}
            {guard.rules.length > 0 && (
              <div aria-hidden="true" className="flex gap-2 text-xs font-medium text-slate-400">
                <span className="min-w-0 flex-1">{t('settings.guardrailPattern')}</span>
                <span className="w-28 shrink-0">{t('settings.guardrailAction')}</span>
                <span className="w-8 shrink-0" />
              </div>
            )}
            {guard.rules.map((r, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  type="text"
                  value={r.pattern}
                  spellCheck={false}
                  placeholder={t('settings.guardrailRegexPlaceholder')}
                  aria-label={t('settings.guardrailPatternN', { n: i + 1 })}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, pattern: e.target.value } : x) })}
                  className={fieldBase + ' min-w-0 flex-1 font-mono'}
                />
                <select
                  value={r.action}
                  aria-label={t('settings.guardrailActionFor', { pattern: r.pattern || String(i + 1) })}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, action: e.target.value as 'confirm' | 'block' } : x) })}
                  className={fieldBase + ' w-28 shrink-0'}
                >
                  <option value="confirm">{t('settings.guardrailConfirm')}</option>
                  <option value="block">{t('settings.guardrailBlock')}</option>
                </select>
                <IconButton type="button" variant="ghost" size="md" label={t('settings.deleteRule')}
                  onClick={() => setGuard({ ...guard, rules: guard.rules.filter((_, j) => j !== i) })}>
                  <CloseIcon size={14} />
                </IconButton>
              </div>
            ))}
            <Button type="button" variant="secondary" size="sm"
              onClick={() => setGuard({ ...guard, rules: [...guard.rules, { pattern: '', action: 'confirm' }] })}
            >{t('settings.addRule')}</Button>
          </div>
        )}
        </>)}
      </SettingsSection>

      {/* ── Politica cheilor de deploy ── comutatoare: fiecare se salvează imediat (ca înainte) */}
      <SettingsSection data-setting-id="deployKeyPolicy" hidden={!vis('deployKeyPolicy')} instanceWide
        title={t('settings.dkpolicy.title')} titleExtra={<HelpTip id="deployKeyPolicy" />}
        description={t('settings.dkpolicy.hint')}>
        <NotLoaded state={dkState} onRetry={loadDkPolicy} />
        {canSave(dkState) && (<div className="flex flex-col gap-3">
          <Switch checked={dkPolicy.require_2fa_source} label={t('settings.dkpolicy.require2fa')}
            hint={t('settings.dkpolicy.require2faHint')}
            onChange={(v) => { void saveDkPolicy({ ...dkPolicy, require_2fa_source: v }) }} />
          <Switch checked={dkPolicy.require_restrict} label={t('settings.dkpolicy.requireRestrict')}
            hint={t('settings.dkpolicy.requireRestrictHint')}
            onChange={(v) => { void saveDkPolicy({ ...dkPolicy, require_restrict: v }) }} />
          <span role="status" className={dkPolicyMsg ? 'text-xs text-slate-400' : 'sr-only'}>{dkPolicyMsg}</span>
        </div>)}
      </SettingsSection>

      {/* ── Filigran (watermark) ── bifa face parte din formularul salvat cu „Save watermark" */}
      <SettingsSection data-setting-id="watermark" hidden={!vis('watermark')} instanceWide
        title={t('settings.watermark')} description={t('settings.watermarkDesc')} dirty={wmDirty}
        footer={canSave(wmState) ? <>
          <Button variant="primary" type="button" onClick={saveWatermark}>
            {t('settings.saveWatermark')}
          </Button>
          {/* două regiuni, nu una cu rol variabil: schimbarea rolului pe acelaşi nod nu e anunţată */}
          <span role="status" className={wmMsg && !wmErr ? 'text-xs wt-good' : 'sr-only'}>{wmErr ? '' : wmMsg}</span>
          <span role="alert" className={wmMsg && wmErr ? 'text-xs wt-danger' : 'sr-only'}>{wmErr ? wmMsg : ''}</span>
        </> : undefined}>
        <NotLoaded state={wmState} onRetry={loadWm} />
        {canSave(wmState) && (<>
        <label className="flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input type="checkbox" checked={wm.enabled}
            onChange={(e) => setWm({ ...wm, enabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600" />
          <span>{t('settings.watermarkToggle')}</span>
        </label>
        {wm.enabled && (
          <div className="mt-3 space-y-3">
            <Field label={t('settings.text')} hint={<>
              {t('settings.watermarkHint')} <code className="font-mono">{'${email}'}</code>{' '}
              <code className="font-mono">{'${host}'}</code> <code className="font-mono">{'${date}'}</code>{' '}
              <code className="font-mono">{'${time}'}</code>
            </>}>
              <input type="text" value={wm.content} maxLength={200}
                onChange={(e) => setWm({ ...wm, content: e.target.value })}
                className={field + ' font-mono'} />
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <Field label={<>{t('settings.opacity')} <span className="font-normal text-slate-500">{wm.opacity.toFixed(2)}</span></>}>
                <input type="range" min={0.02} max={0.5} step={0.01} value={wm.opacity}
                  onChange={(e) => setWm({ ...wm, opacity: parseFloat(e.target.value) })}
                  className="w-full accent-sky-600" />
              </Field>
              <Field label={<>{t('settings.angle')} <span className="font-normal text-slate-500">{wm.angle}°</span></>}>
                <input type="range" min={-90} max={90} step={5} value={wm.angle}
                  onChange={(e) => setWm({ ...wm, angle: parseInt(e.target.value, 10) })}
                  className="w-full accent-sky-600" />
              </Field>
              <Field label={<>{t('settings.size')} <span className="font-normal text-slate-500">{wm.fontSize}px</span></>}>
                <input type="range" min={8} max={40} step={1} value={wm.fontSize}
                  onChange={(e) => setWm({ ...wm, fontSize: parseInt(e.target.value, 10) })}
                  className="w-full accent-sky-600" />
              </Field>
            </div>
          </div>
        )}
        </>)}
      </SettingsSection>
    </div>
  )
}
