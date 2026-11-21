import { useEffect, useState } from 'react'
import { errText, api, CommandGuard, DeployKeyPolicy, WatermarkConfig } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { CloseIcon } from '../Icons'
import { heading } from './ui'
import HelpTip from '../HelpTip'
import { Button } from '../ui'
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
  // U04 — controale de SECURITATE: pe un fetch picat, formularul arăta „nicio regulă" şi un Save
  // ŞTERGEA toate regulile guardrail-ului de pe server (la fel, o bifă a politicii cheilor de
  // deploy trimitea celălalt câmp ca `false`). Formularele apar doar peste valorile încărcate.
  const [guardState, setGuardState] = useState<LoadState>({ status: 'loading' })
  const loadGuard = () => {
    setGuardState({ status: 'loading' })
    api<CommandGuard>('/api/settings/command-guard')
      .then((g) => { setGuard(g); setGuardState({ status: 'ok' }) })
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
      setGuard(saved)
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

  // se încarcă la montarea tab-ului (= la deschiderea categoriei)
  useEffect(() => {
    loadGuard()
    loadDkPolicy()
    loadWm()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div>
      <section data-setting-id="guardrail" hidden={!vis('guardrail')}>
        {/* ── Guardrail de comenzi ── */}
        <h3 className={heading + ' !mt-0 flex items-center gap-2'}>{t('settings.guardrail')}<HelpTip id="guardrail" /></h3>
        <NotLoaded state={guardState} onRetry={loadGuard} />
        {canSave(guardState) && (<>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
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
            {guard.rules.map((r, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  type="text"
                  value={r.pattern}
                  spellCheck={false}
                  placeholder={t('settings.guardrailRegexPlaceholder')}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, pattern: e.target.value } : x) })}
                  className="min-w-0 flex-1 rounded-md border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                />
                <select
                  value={r.action}
                  aria-label={t('settings.guardrailActionFor', { pattern: r.pattern || String(i + 1) })}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, action: e.target.value as 'confirm' | 'block' } : x) })}
                  className="shrink-0 rounded-md border border-ink-700 bg-ink-900 px-2 py-1.5 text-xs text-slate-200"
                >
                  <option value="confirm">{t('settings.guardrailConfirm')}</option>
                  <option value="block">{t('settings.guardrailBlock')}</option>
                </select>
                <button
                  onClick={() => setGuard({ ...guard, rules: guard.rules.filter((_, j) => j !== i) })}
                  aria-label={t('settings.deleteRule')}
                  className="shrink-0 rounded-md px-2 py-1 text-slate-500 hover:bg-ink-800 hover:text-danger"
                ><CloseIcon size={14} /></button>
              </div>
            ))}
            <button
              onClick={() => setGuard({ ...guard, rules: [...guard.rules, { pattern: '', action: 'confirm' }] })}
              className="text-xs wt-link hover:underline"
            >{t('settings.addRule')}</button>
          </div>
        )}
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary"
            onClick={saveGuard}>{t('settings.saveGuardrail')}</Button>
          {guardMsg && <span className="text-xs text-slate-400">{guardMsg}</span>}
        </div>
        </>)}
      </section>

      <section data-setting-id="deployKeyPolicy" hidden={!vis('deployKeyPolicy')}>
        {/* ── Politica cheilor de deploy ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.dkpolicy.title')}<HelpTip id="deployKeyPolicy" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.dkpolicy.hint')}</p>
        <NotLoaded state={dkState} onRetry={loadDkPolicy} />
        {canSave(dkState) && (<>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input type="checkbox" checked={dkPolicy.require_2fa_source} className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
            onChange={(e) => saveDkPolicy({ ...dkPolicy, require_2fa_source: e.target.checked })} />
          <span>{t('settings.dkpolicy.require2fa')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.dkpolicy.require2faHint')}</span></span>
        </label>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input type="checkbox" checked={dkPolicy.require_restrict} className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
            onChange={(e) => saveDkPolicy({ ...dkPolicy, require_restrict: e.target.checked })} />
          <span>{t('settings.dkpolicy.requireRestrict')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.dkpolicy.requireRestrictHint')}</span></span>
        </label>
        {dkPolicyMsg && <div className="mt-1 text-xs text-slate-500">{dkPolicyMsg}</div>}
        </>)}
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
