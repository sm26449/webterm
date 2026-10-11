import { useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, Host, withGuardConfirm, withStepup } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS, useMediaQuery } from '../lib/sheet'
import { useFocusTrap } from '../lib/useFocusTrap'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { Button, ErrorState } from './ui'
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
  // U25 (3.6.3): pe touch, start/stop/restart ca trei pictograme de 24px una lângă alta erau uşor
  // de confundat la 3 noaptea. Sub pointer grosier: UN buton „Acţiuni" de 44px, cu numele unităţii,
  // care deschide o foaie cu acţiunile etichetate. Pe desktop rămân pictogramele compacte.
  const coarse = useMediaQuery('(pointer: coarse)')
  const [sheetUnit, setSheetUnit] = useState<string | null>(null)

  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  // U18 — eroare ≠ gol: o încărcare picată arăta ŞI eroarea, ŞI „niciun serviciu". Acum: prima
  // încărcare picată = ErrorState cu Reîncearcă; un refresh picat păstrează ultima listă bună
  // (a aceluiaşi host + filtru), marcată veche. Erorile de ACŢIUNE (start/stop) sunt separate, `alert`.
  const viewKey = `${props.host.id}:${failedOnly ? 'f' : 'a'}`
  const [loadErr, setLoadErr] = useState('')
  const [rowsKey, setRowsKey] = useState('')
  const loadSeq = useRef(0)
  const load = useCallback(async () => {
    const my = ++loadSeq.current
    setLoadErr('')
    try {
      const r = await api<{ rows: Svc[] }>(`/api/hosts/${props.host.id}/services${failedOnly ? '?failed=1' : ''}`)
      if (my !== loadSeq.current) return            // răspuns întârziat (alt host / alt filtru)
      setRows(r.rows); setRowsKey(viewKey)
    } catch (e) {
      if (my !== loadSeq.current) return
      setLoadErr(errText(e, t) || (e instanceof ApiError ? e.message : t('services.error')))
    }
  }, [props.host.id, failedOnly, viewKey, t])

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

  // lista arătată e DOAR a vederii curente (host + filtru); a altei vederi nu se arată nici veche
  const shown = rowsKey === viewKey ? rows : null
  const stale = shown !== null && loadErr !== ''
  const view = (shown || []).filter((s) => !filter || s.unit.includes(filter) || s.desc.toLowerCase().includes(filter.toLowerCase()))
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
            // nume accesibil PERMANENT (U18): placeholder-ul dispare la tastare
            aria-label={t('services.filterAria')}
            className="min-w-0 flex-1 rounded-md bg-ink-800/60 px-2 py-1 text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
          <button onClick={() => setFailedOnly((v) => !v)} aria-pressed={failedOnly}
            className={`shrink-0 rounded-md px-2 py-1 text-2xs font-medium ${failedOnly
              ? 'bg-rose-500/20 wt-danger' : 'text-slate-400 hover:bg-ink-800'}`}
            title={t('services.failedOnly')}>{t('services.failed')}</button>
        </div>
        {/* eroarea de ACŢIUNE: regiune `alert` montată permanent */}
        <div role="alert" className={error ? 'border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger' : 'sr-only'}>{error}</div>
        {note && !error && <div role="status" className="border-b border-ink-800 bg-ink-800/60 px-3 py-1.5 text-2xs text-slate-400">{note}</div>}
        {stale && (
          <div role="status" className="flex flex-wrap items-center gap-2 border-b border-ink-800 bg-ink-800/60 px-3 py-1.5 text-2xs text-slate-400">
            <span>{t('services.stale')}</span>
            <button type="button" onClick={load} className="wt-link min-h-6 hover:underline">{t('common.retry')}</button>
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-y-auto p-3">
          {shown === null && loadErr ? (
            <ErrorState title={t('services.loadFailed')} message={loadErr} onRetry={load} />
          ) : shown === null ? (
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
                          className="wt-touch inline-flex min-h-6 items-center rounded-md px-1.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-link">
                          {t('services.logs')}
                        </button>
                      )}
                      {coarse ? (
                        <Button variant="secondary" size="md" type="button" className="wt-touch ml-auto"
                          disabled={busy === s.unit} onClick={() => setSheetUnit(s.unit)}
                          aria-haspopup="dialog" aria-label={t('services.actionsFor', { unit: s.unit })}
                          data-testid="svc-actions">
                          {t('services.actions')}
                        </Button>
                      ) : (
                      <span className="ml-auto flex items-center gap-0.5">
                        {(['start', 'stop', 'restart'] as Action[]).map((a) => (
                          <button key={a} onClick={() => act(s.unit, a)} disabled={busy === s.unit}
                            title={t('services.' + a)} aria-label={t('services.' + a) + ' ' + s.unit}
                            className="grid h-6 w-6 place-items-center rounded-md text-2xs text-slate-400 hover:bg-ink-700 hover:text-slate-100 disabled:opacity-40">
                            {a === 'start' ? <PlayIcon size={11} /> : a === 'stop' ? <SquareIcon size={11} /> : <RefreshIcon size={13} />}
                          </button>
                        ))}
                      </span>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </aside>
      {sheetUnit !== null && (
        <ServiceActionsSheet unit={sheetUnit} onClose={() => setSheetUnit(null)}
          onAction={(a) => {
            const unit = sheetUnit
            setSheetUnit(null)
            // după ce foaia s-a închis şi focusul s-a întors pe „Acţiuni": abia atunci confirmarea
            // (stop/restart), cu ACEEAŞI semantică ca pe desktop — act() decide, nu foaia
            setTimeout(() => { void act(unit, a) }, 0)
          }} />
      )}
    </>
  )
}

/** Foaia de acţiuni a unui serviciu (touch): dialog modal jos pe ecran, acţiuni etichetate de
    44px, numele unităţii în titlu. Escape / fundalul / „Anulează" închid; focusul revine pe
    butonul „Acţiuni" (useFocusTrap). Stop/Restart cer în continuare confirmarea din act(). */
function ServiceActionsSheet(props: { unit: string; onClose: () => void; onAction: (a: Action) => void }) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  const icon = (a: Action) => a === 'start' ? <PlayIcon size={14} /> : a === 'stop' ? <SquareIcon size={14} /> : <RefreshIcon size={16} />
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/50" onClick={props.onClose}>
      {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-noninteractive-element-interactions -- doar opreşte clicul să ajungă la fundal; Escape e în useFocusTrap */}
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="svc-sheet-title" data-testid="svc-sheet"
        onClick={(e) => e.stopPropagation()}
        className="wt-sheet-bottom w-full max-w-md rounded-t-2xl border-t border-ink-700 bg-ink-900 p-3 shadow-2xl">
        <h2 id="svc-sheet-title" className="mb-2 truncate px-1 font-mono text-sm font-semibold text-slate-200">{props.unit}</h2>
        <div className="flex flex-col gap-1.5">
          {(['start', 'stop', 'restart'] as Action[]).map((a) => (
            <Button key={a} type="button" variant="secondary" size="lg"
              className="wt-touch w-full justify-start" onClick={() => props.onAction(a)}>
              {icon(a)} {t('services.' + a)}
            </Button>
          ))}
          <Button type="button" variant="ghost" size="lg" className="wt-touch w-full" onClick={props.onClose}>
            {t('common.cancel')}
          </Button>
        </div>
      </div>
    </div>
  )
}
