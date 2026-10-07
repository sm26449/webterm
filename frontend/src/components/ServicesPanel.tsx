import { useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, Host, withGuardConfirm, withStepup } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS } from '../lib/sheet'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { CloseIcon, PlayIcon, RefreshIcon, SquareIcon } from './Icons'

// Panou Servicii systemd: listă (nume/stare/descriere) + start/stop/restart. TOTUL prin op-ul
// `run` al agentului (systemctl rulat pe host) — niciun op nou în agent, deci fără re-semnare.
// Doar host-uri de agent. Rulează ca userul agentului: fără root, acţiunile pe unităţi de sistem
// pot eşua cu „access denied" — surfaced ca atare.
type Svc = { unit: string; load: string; active: string; sub: string; desc: string }
type Action = 'start' | 'stop' | 'restart'

export default function ServicesPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean; embed?: boolean
  /** deschide o sesiune care urmăreşte `journalctl -u <unit> -f` */
  onJournal?: (unit: string) => void
}) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const asideRef = useRef<HTMLElement>(null)
  const drawer = useDrawer(asideRef, props.onClose, !props.embed)
  const [rows, setRows] = useState<Svc[] | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')   // notă neutră (guardrail anulat) — nu eroare
  const [busy, setBusy] = useState('')          // unitatea pe care rulează o acţiune
  const [filter, setFilter] = useState('')
  const [failedOnly, setFailedOnly] = useState(false)   // triaj „ce e stricat pe hostul ăsta"

  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const load = useCallback(async () => {
    setError(''); setRows(null)
    try {
      const r = await api<{ rows: Svc[] }>(`/api/hosts/${props.host.id}/services${failedOnly ? '?failed=1' : ''}`)
      setRows(r.rows)
    } catch (e) {
      setError(errText(e, t) || (e instanceof ApiError ? e.message : t('services.error')))
      setRows([])
    }
  }, [props.host.id, failedOnly, t])

  useEffect(() => { load() }, [load])

  async function act(unit: string, action: Action) {
    // stop/restart taie un serviciu VIU pe host (sshd, nginx, baza de date) dintr-un singur
    // click pe o ţintă de 24px — confirmăm, numind unitatea (audit 2026-10-04 §5). Start nu.
    if (action !== 'start' && !(await confirm({
      title: `${t('services.' + action)} ${unit}`,
      message: t(action === 'stop' ? 'services.confirmStop' : 'services.confirmRestart', { unit }),
      confirmLabel: t('services.' + action), danger: true,
    }))) return
    setBusy(unit); setError(''); setNote('')
    try {
      // null = guardrail refuzat de om: nimic nu s-a rulat — o spunem, neutru
      const r = await withStepup(props.host.id, () => withGuardConfirm((pattern) => confirm({ title: t('guard.confirmTitle'), message: t('guard.confirmMsg', { pattern }), danger: true, confirmLabel: t('guard.confirmRun') }),
        (confirmed) => api(`/api/hosts/${props.host.id}/services/action`,
          { method: 'POST', body: JSON.stringify({ unit, action, confirmed }) })))
      if (r === null) { setNote(t('guard.cancelled')); return }
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
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
      <aside ref={asideRef} className={asideCls} aria-label={t('services.title')} onKeyDown={drawer.onKeyDown}>
        {drawer.sheet && <SheetBar title={t('services.title')} onBack={props.onClose} />}
        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
          <span className="text-sm font-semibold text-slate-200">{t('services.title')}</span>
          <button onClick={load} className="wt-touch ml-auto shrink-0 rounded-md px-1.5 text-slate-400 hover:bg-ink-800"
            title={t('services.reload')} aria-label={t('services.reload')}><RefreshIcon /></button>
          {!props.embed && (
            <button onClick={props.onClose} aria-label={t('common.close')}
              className="wt-touch shrink-0 rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800"><CloseIcon size={14} /></button>
          )}
        </div>
        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1.5">
          <input value={filter} onChange={(e) => setFilter(e.target.value)}
            placeholder={t('services.filterPh')}
            className="min-w-0 flex-1 rounded-md bg-ink-800/60 px-2 py-1 text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
          <button onClick={() => setFailedOnly((v) => !v)} aria-pressed={failedOnly}
            className={`shrink-0 rounded-md px-2 py-1 text-2xs font-medium ${failedOnly
              ? 'bg-rose-500/20 wt-danger' : 'text-slate-400 hover:bg-ink-800'}`}
            title={t('services.failedOnly')}>{t('services.failed')}</button>
        </div>
        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger">{error}</div>}
        {note && !error && <div role="status" className="border-b border-ink-800 bg-ink-800/60 px-3 py-1.5 text-2xs text-slate-400">{note}</div>}
        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          {rows === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('services.loading')}</div>
          ) : view.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('services.empty')}</div>
          ) : (
            <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))' }}>
              {view.map((s) => {
                const tone = s.active === 'active' ? 'wt-good' : s.active === 'failed' ? 'wt-danger' : 'text-slate-500'
                return (
                  <div key={s.unit} className="flex flex-col gap-2 rounded-xl border border-ink-700/70 bg-ink-800/40 p-3">
                    <div className="flex items-start gap-2">
                      <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${dot(s)}`} aria-hidden="true" />
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-mono text-xs font-medium text-slate-200" title={s.unit}>
                          {s.unit.replace(/\.service$/, '')}
                        </div>
                        <div className={`text-2xs ${tone}`}>{s.active}{s.sub && s.sub !== s.active ? ` · ${s.sub}` : ''}</div>
                      </div>
                    </div>
                    {s.desc && <div className="line-clamp-2 text-2xs text-slate-500" title={s.desc}>{s.desc}</div>}
                    <div className="mt-auto flex flex-wrap items-center gap-1 border-t border-ink-800/60 pt-2">
                      {props.onJournal && (
                        <button onClick={() => props.onJournal!(s.unit)}
                          title={t('services.logsHint')} aria-label={t('services.logs') + ' ' + s.unit}
                          className="rounded-md px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-link">
                          {t('services.logs')}
                        </button>
                      )}
                      <span className="ml-auto flex items-center gap-0.5">
                        {(['start', 'stop', 'restart'] as Action[]).map((a) => (
                          <button key={a} onClick={() => act(s.unit, a)} disabled={busy === s.unit}
                            title={t('services.' + a)} aria-label={t('services.' + a) + ' ' + s.unit}
                            className="grid h-6 w-6 place-items-center rounded-md text-2xs text-slate-400 hover:bg-ink-700 hover:text-slate-100 disabled:opacity-40">
                            {a === 'start' ? <PlayIcon size={11} /> : a === 'stop' ? <SquareIcon size={11} /> : <RefreshIcon size={13} />}
                          </button>
                        ))}
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
