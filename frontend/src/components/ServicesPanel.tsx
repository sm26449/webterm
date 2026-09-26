import { useCallback, useEffect, useState } from 'react'
import { errText, api, ApiError, Host, withStepup } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { RefreshIcon } from './Icons'

// Panou Servicii systemd: listă (nume/stare/descriere) + start/stop/restart. TOTUL prin op-ul
// `run` al agentului (systemctl rulat pe host) — niciun op nou în agent, deci fără re-semnare.
// Doar host-uri de agent. Rulează ca userul agentului: fără root, acţiunile pe unităţi de sistem
// pot eşua cu „access denied" — surfaced ca atare.
type Svc = { unit: string; load: string; active: string; sub: string; desc: string }
type Action = 'start' | 'stop' | 'restart'

export default function ServicesPanel(props: { host: Host; onClose: () => void; overlay?: boolean }) {
  const { t } = useI18n()
  const [rows, setRows] = useState<Svc[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')          // unitatea pe care rulează o acţiune
  const [filter, setFilter] = useState('')

  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const load = useCallback(async () => {
    setError(''); setRows(null)
    try {
      const r = await api<{ rows: Svc[] }>(`/api/hosts/${props.host.id}/services`)
      setRows(r.rows)
    } catch (e) {
      setError(errText(e, t) || (e instanceof ApiError ? e.message : t('services.error')))
      setRows([])
    }
  }, [props.host.id, t])

  useEffect(() => { load() }, [load])

  async function act(unit: string, action: Action) {
    setBusy(unit); setError('')
    try {
      await withStepup(props.host.id, () => api(`/api/hosts/${props.host.id}/services/action`,
        { method: 'POST', body: JSON.stringify({ unit, action }) }))
      await load()
    } catch (e) {
      setError(errText(e, t) || (e instanceof ApiError ? e.message : t('services.error')))
    } finally { setBusy('') }
  }

  const view = (rows || []).filter((s) => !filter || s.unit.includes(filter) || s.desc.toLowerCase().includes(filter.toLowerCase()))
  const dot = (s: Svc) => s.active === 'active' ? 'bg-emerald-400'
    : s.active === 'failed' ? 'bg-rose-400' : 'bg-slate-500'

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      <aside className={asideCls} aria-label={t('services.title')}>
        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
          <span className="text-sm font-semibold text-slate-200">{t('services.title')}</span>
          <button onClick={load} className="wt-touch ml-auto shrink-0 rounded px-1.5 text-slate-400 hover:bg-ink-800"
            title={t('services.reload')}><RefreshIcon /></button>
          <button onClick={props.onClose} aria-label={t('common.close')}
            className="wt-touch shrink-0 rounded px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
        </div>
        <div className="border-b border-ink-800 px-3 py-1.5">
          <input value={filter} onChange={(e) => setFilter(e.target.value)}
            placeholder={t('services.filterPh')}
            className="w-full rounded bg-ink-800/60 px-2 py-1 text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
        </div>
        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}
        <div className="min-h-0 flex-1 overflow-y-auto">
          {rows === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('services.loading')}</div>
          ) : view.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('services.empty')}</div>
          ) : view.map((s) => (
            <div key={s.unit} className="group flex items-center gap-2 border-b border-ink-800/60 px-3 py-1.5">
              <span className={`h-2 w-2 shrink-0 rounded-full ${dot(s)}`}
                title={`${s.active} · ${s.sub}`} aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <div className="truncate font-mono text-[12px] text-slate-200" title={s.unit}>
                  {s.unit.replace(/\.service$/, '')}
                </div>
                {s.desc && <div className="truncate text-[11px] text-slate-500" title={s.desc}>{s.desc}</div>}
              </div>
              <div className="flex shrink-0 items-center gap-0.5 opacity-0 group-hover:opacity-100 [@media(hover:none)]:opacity-100">
                {(['start', 'stop', 'restart'] as Action[]).map((a) => (
                  <button key={a} onClick={() => act(s.unit, a)} disabled={busy === s.unit}
                    title={t('services.' + a)} aria-label={t('services.' + a) + ' ' + s.unit}
                    className="rounded px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-ink-700 hover:text-slate-100 disabled:opacity-40">
                    {a === 'start' ? '▶' : a === 'stop' ? '■' : '↻'}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </aside>
    </>
  )
}
