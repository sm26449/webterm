import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import type { Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { lsGet, lsSet } from '../lib/storage'
import { cancelUpload, dirName, discardUpload, dismissUpload, fmtEta, fmtRate, openFilesAt, retryUpload } from '../lib/uploads'
import { UploadJob, isActive, uploadStore } from '../lib/uploadStore'
import { ChevronIcon, UploadIcon } from './Icons'

/* Bara globală de transferuri. Trăieşte sub cromul de sus şi deasupra workspace-ului, pe ORICE
   ecran: incidentul cu upload-ul de 17 GB (2026-10-04) a arătat că singurul loc unde se vedea un
   transfer era panoul de fişiere care l-a pornit — închis panoul, dispărută orice urmă. Vizual
   tăcută (32 px pe rând, cifre monospaţiate, fără emoji), pliabilă la o linie de sumar, şi
   complet operabilă de la tastatură (ţinte de 24 px). Tranziţiile de stare se anunţă o singură
   dată printr-o regiune `aria-live` politicoasă, montată PERMANENT (o regiune care apare odată
   cu primul mesaj nu e citită — vezi Toasts.tsx) — fără toast-uri. */
const COLLAPSED_KEY = 'wt_jobs_collapsed'
const MAX_ATTEMPTS_SHOWN = 8

const STATE_CLS: Record<UploadJob['state'], string> = {
  running: 'wt-info', retrying: 'wt-warn', stalled: 'wt-warn', err: 'wt-danger',
  done: 'wt-good', cancelled: 'wt-muted', orphan: 'wt-warn',
}
const BAR_CLS: Record<UploadJob['state'], string> = {
  running: 'bg-sky-500', retrying: 'bg-amber-500', stalled: 'bg-amber-500', err: 'bg-rose-500',
  done: 'bg-emerald-500', cancelled: 'bg-slate-500', orphan: 'bg-amber-500/60',
}

export default function JobsBar(props: { hosts: Host[] }) {
  const { t } = useI18n()
  const snap = useSyncExternalStore(uploadStore.subscribe, uploadStore.snapshot)
  const jobs = useMemo(() => [...snap.values()], [snap])
  const [collapsed, setCollapsed] = useState(() => lsGet(COLLAPSED_KEY) === '1')
  const toggle = () => { setCollapsed((c) => { lsSet(COLLAPSED_KEY, c ? '0' : '1'); return !c }) }

  // numele hostului: din job (scris la pornire); pentru cheile vechi (doar uid) îl căutăm în listă
  const hostName = (j: UploadJob) => j.hostName || props.hosts.find((h) => h.id === j.hostId)?.name || `#${j.hostId}`

  // Anunţuri: diferenţa de stare faţă de randarea anterioară, DOAR pentru tranziţiile care
  // contează (→stalled, →err, →done). Progresul nu se anunţă — ar vorbi la fiecare procent.
  const prev = useRef<Map<string, UploadJob['state']>>(new Map())
  const [announce, setAnnounce] = useState('')
  useEffect(() => {
    const msgs: string[] = []
    const next = new Map<string, UploadJob['state']>()
    for (const j of jobs) {
      const was = prev.current.get(j.id)
      next.set(j.id, j.state)
      if (was === j.state || was === undefined) continue
      if (j.state === 'stalled') msgs.push(t('jobs.srStalled', { name: j.name }))
      else if (j.state === 'err') msgs.push(t('jobs.srFailed', { name: j.name, error: j.error ?? '' }))
      else if (j.state === 'done') msgs.push(t('jobs.srDone', { name: j.name }))
    }
    prev.current = next
    if (msgs.length) setAnnounce(msgs.join('; '))
  }, [jobs, t])

  const live = jobs.filter(isActive)
  const stalled = jobs.filter((j) => j.state === 'stalled').length
  const failed = jobs.filter((j) => j.state === 'err').length
  const totalSize = live.reduce((a, j) => a + j.size, 0)
  const totalPos = live.reduce((a, j) => a + j.pos, 0)
  const overallPct = totalSize ? Math.round((totalPos / totalSize) * 100) : (live.length ? 0 : 100)

  const statusText = (j: UploadJob): string => {
    switch (j.state) {
      case 'running': return `${j.pct}% · ${fmtRate(j.bytesPerSec)} · ${t('jobs.eta')} ${fmtEta(j.etaSec, t)}`
      case 'stalled': return `${j.pct}% · ${t('jobs.stateStalled')}`
      case 'retrying': return `${j.pct}% · ${t('jobs.stateRetrying', { n: j.attempts, max: MAX_ATTEMPTS_SHOWN })}`
      case 'err': return j.error || t('files.uploadFailed')
      case 'done': return `100% · ${t('jobs.stateDone')}`
      case 'cancelled': return t('jobs.stateCancelled')
      case 'orphan': return `${j.pct}% · ${t('jobs.stateOrphan')}`
    }
  }

  const btn = 'wt-touch inline-flex h-6 min-w-6 shrink-0 items-center justify-center rounded px-1.5 text-[11px] font-medium hover:bg-ink-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400'

  return (
    <>
      {/* regiune live permanentă (goală când nu e nimic de spus) */}
      <div aria-live="polite" className="sr-only">{announce}</div>
      {jobs.length > 0 && (
        <section aria-label={t('jobs.title')} className="wt-jobsbar shrink-0 px-2 text-xs">
          {/* linia de sumar + chevron; pliat = doar atât */}
          <div className="flex h-8 items-center gap-2">
            <button type="button" onClick={toggle} aria-expanded={!collapsed}
              aria-label={collapsed ? t('jobs.expand') : t('jobs.collapse')}
              className={`${btn} text-slate-300`}>
              <ChevronIcon open={!collapsed} />
            </button>
            <span aria-hidden="true" className="wt-info"><UploadIcon /></span>
            <span className="font-mono tabular-nums text-slate-200">
              {t('jobs.summary', { count: jobs.length })}
              {live.length > 0 && <> · {overallPct}%</>}
              {stalled > 0 && <> · <span className="wt-warn">{t('jobs.summaryStalled', { count: stalled })}</span></>}
              {failed > 0 && <> · <span className="wt-danger">{t('jobs.summaryFailed', { count: failed })}</span></>}
            </span>
          </div>
          {!collapsed && (
            <ul className="max-h-40 overflow-y-auto pb-1">
              {jobs.map((j) => {
                const name = `${hostName(j)} · ${j.name}`
                return (
                  <li key={j.id} className="flex h-8 items-center gap-2">
                    <span className="w-6 shrink-0" aria-hidden="true" />
                    <span className="min-w-0 flex-1 truncate text-slate-200" title={j.dest}>{name}</span>
                    <div role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={j.pct}
                      aria-label={t('jobs.progressAria', { name: j.name, pct: j.pct })}
                      className="h-1 w-16 shrink-0 overflow-hidden rounded-full bg-ink-700 sm:w-40">
                      <div className={`h-full rounded-full transition-[width] duration-200 ease-out motion-reduce:transition-none ${BAR_CLS[j.state]}`}
                        style={{ width: `${j.state === 'err' ? 100 : j.pct}%` }} />
                    </div>
                    <span className={`hidden min-w-0 truncate font-mono tabular-nums sm:inline ${STATE_CLS[j.state]}`}
                      title={statusText(j)}>
                      {statusText(j)}
                    </span>
                    <span className={`font-mono tabular-nums sm:hidden ${STATE_CLS[j.state]}`}>{j.pct}%</span>
                    {/* acţiuni după stare — nume accesibil = acţiune + fişier, ca în FilePanel */}
                    {(j.state === 'err' || j.state === 'stalled') && (
                      <button type="button" onClick={() => retryUpload(j.id)} className={`${btn} wt-info`}
                        aria-label={`${t('jobs.retry')} ${j.name}`}>{t('jobs.retry')}</button>
                    )}
                    {j.state === 'orphan' && (
                      <button type="button" onClick={() => openFilesAt(j.hostId, dirName(j.dest))}
                        className={`${btn} wt-info`} aria-label={`${t('jobs.openFolder')} ${j.name}`}>
                        {t('jobs.openFolder')}
                      </button>
                    )}
                    {isActive(j) && (
                      <button type="button" onClick={() => cancelUpload(j.id)} className={`${btn} text-slate-300`}
                        aria-label={`${t('jobs.cancel')} ${j.name}`}>{t('jobs.cancel')}</button>
                    )}
                    {j.state === 'orphan' && (
                      <button type="button" onClick={() => discardUpload(j.id)} className={`${btn} wt-danger`}
                        aria-label={`${t('jobs.discard')} ${j.name}`}>{t('jobs.discard')}</button>
                    )}
                    {(j.state === 'done' || j.state === 'err' || j.state === 'cancelled') && (
                      <button type="button" onClick={() => dismissUpload(j.id)} className={`${btn} text-slate-300`}
                        aria-label={`${t('jobs.dismiss')} ${j.name}`}>{t('jobs.dismiss')}</button>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </section>
      )}
    </>
  )
}
