import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import type { Host } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useI18n } from '../lib/i18n'
import { notify } from '../lib/notify'
import { lsGet, lsSet } from '../lib/storage'
import { insertPathInto } from '../lib/transfers'
import { cancelUpload, dirName, discardUpload, dismissUpload, fmtEta, fmtRate, openFilesAt, pauseUpload, resumeUpload, retryUpload } from '../lib/uploads'
import { cancelDownload, dismissDownload, pauseDownload, resumeDownload, retryDownload } from '../lib/downloads'
import { UploadJob, isActive, isDownload, uploadStore } from '../lib/uploadStore'
import { ChevronIcon, DownloadIcon, UploadIcon } from './Icons'

/* Bara globală de transferuri. Trăieşte sub cromul de sus şi deasupra workspace-ului, pe ORICE
   ecran: incidentul cu upload-ul de 17 GB (2026-10-04) a arătat că singurul loc unde se vedea un
   transfer era panoul de fişiere care l-a pornit — închis panoul, dispărută orice urmă.

   Faza 2 (transfers phase 1): bara apare DOAR când ceva cere o decizie — `stalled`, `err` sau
   `orphan` — şi dispare singură când s-a rezolvat. Progresul normal (running/done) stă în
   chip-ul din bara de stare a sesiunii (StatusBar → TransfersPopover), care foloseşte ACELAŞI
   rând (`JobRow`) cu aceleaşi acţiuni. O bară permanentă de 32 px pentru un upload sănătos
   fura spaţiu de terminal degeaba; una care apare doar la probleme chiar e citită.

   Vizual tăcută (cifre monospaţiate, fără emoji), complet operabilă de la tastatură (ţinte
   de 24 px). Tranziţiile de stare se anunţă o singură dată printr-o regiune `aria-live`
   politicoasă, montată PERMANENT (o regiune care apare odată cu primul mesaj nu e citită —
   vezi Toasts.tsx); când tab-ul e în fundal, `done`/`err` dau şi o notificare de browser. */
const COLLAPSED_KEY = 'wt_jobs_collapsed'
const MAX_ATTEMPTS_SHOWN = 8

const STATE_CLS: Record<UploadJob['state'], string> = {
  running: 'wt-info', retrying: 'wt-warn', stalled: 'wt-warn', paused: 'wt-muted', err: 'wt-danger',
  done: 'wt-good', cancelled: 'wt-muted', orphan: 'wt-warn',
}
const BAR_CLS: Record<UploadJob['state'], string> = {
  running: 'bg-sky-500', retrying: 'bg-amber-500', stalled: 'bg-amber-500', paused: 'bg-slate-500', err: 'bg-rose-500',
  done: 'bg-emerald-500', cancelled: 'bg-slate-500', orphan: 'bg-amber-500/60',
}

/** stările care cer o decizie a omului — singurele care aduc bara pe ecran */
export const needsAttention = (j: UploadJob) => j.state === 'stalled' || j.state === 'err' || j.state === 'orphan'

const BTN = 'wt-touch inline-flex h-6 min-w-6 shrink-0 items-center justify-center rounded px-1.5 text-[11px] font-medium hover:bg-ink-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400'

export function jobStatusText(j: UploadJob, t: (k: string, v?: Record<string, string | number>) => string): string {
  switch (j.state) {
    case 'running': return `${j.pct}% · ${fmtRate(j.bytesPerSec)} · ${t('jobs.eta')} ${fmtEta(j.etaSec, t)}`
    case 'stalled': return `${j.pct}% · ${t('jobs.stateStalled')}`
    case 'retrying': return `${j.pct}% · ${t('jobs.stateRetrying', { n: j.attempts, max: MAX_ATTEMPTS_SHOWN })}`
    case 'paused': return `${j.pct}% · ${t('jobs.statePaused')}`
    case 'err': return j.error || t('files.uploadFailed')
    case 'done': return `100% · ${t('jobs.stateDone')}`
    case 'cancelled': return t('jobs.stateCancelled')
    case 'orphan': return `${j.pct}% · ${t('jobs.stateOrphan')}`
  }
}

/** Un rând de transfer, cu acţiunile după stare — folosit de bară ŞI de popover-ul din bara de
    stare. `insertSid`/`insertHostId`: sesiunea activă în care „Insert path" poate tasta (doar
    dacă hostul job-ului e acelaşi — o cale de pe alt host n-are sens în acest shell). */
export function JobRow(props: { job: UploadJob; hostName: string; insertSid?: string; insertHostId?: number }) {
  const { t } = useI18n()
  const j = props.job
  const down = isDownload(j)
  const name = `${props.hostName} · ${j.name}`
  const canInsert = !down && !!props.insertSid && props.insertHostId === j.hostId
  // Acţiunile diferă pe sens: up → uploads.ts, down → downloads.ts. Rândul e identic altfel.
  const onRetry = () => (down ? retryDownload(j.id) : retryUpload(j.id))
  const onCancel = () => (down ? cancelDownload(j.id) : cancelUpload(j.id))
  const onDismiss = () => (down ? dismissDownload(j.id) : dismissUpload(j.id))
  const onPause = () => (down ? pauseDownload(j.id) : pauseUpload(j.id))
  const onResume = () => (down ? resumeDownload(j.id) : resumeUpload(j.id))
  return (
    <li className="flex h-8 items-center gap-2">
      <span aria-hidden="true" className={`shrink-0 ${STATE_CLS[j.state]}`}>
        {down ? <DownloadIcon /> : <UploadIcon size={12} />}
      </span>
      <span className="min-w-0 flex-1 truncate text-slate-200" title={j.dest}>{name}</span>
      <div role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={j.pct}
        aria-label={t('jobs.progressAria', { name: j.name, pct: j.pct })}
        className="h-1 w-12 shrink-0 overflow-hidden rounded-full bg-ink-700 sm:w-32">
        <div className={`h-full rounded-full transition-[width] duration-200 ease-out motion-reduce:transition-none ${BAR_CLS[j.state]}`}
          style={{ width: `${j.state === 'err' ? 100 : j.pct}%` }} />
      </div>
      <span className={`hidden min-w-0 truncate font-mono tabular-nums sm:inline ${STATE_CLS[j.state]}`}
        title={jobStatusText(j, t)}>
        {jobStatusText(j, t)}
      </span>
      <span className={`font-mono tabular-nums sm:hidden ${STATE_CLS[j.state]}`}>{j.pct}%</span>
      {/* acţiuni după stare — nume accesibil = acţiune + fişier, ca în FilePanel */}
      {(j.state === 'err' || j.state === 'stalled') && (
        <button type="button" onClick={onRetry} className={`${BTN} wt-info`}
          aria-label={`${t('jobs.retry')} ${j.name}`}>{t('jobs.retry')}</button>
      )}
      {/* Pauză pe un transfer viu; Resume pe unul pus pe pauză. Simetric upload/download. */}
      {isActive(j) && (
        <button type="button" onClick={onPause} className={`${BTN} text-slate-300`}
          aria-label={`${t('jobs.pause')} ${j.name}`}>{t('jobs.pause')}</button>
      )}
      {j.state === 'paused' && (
        <button type="button" onClick={onResume} className={`${BTN} wt-info`}
          aria-label={`${t('jobs.resume')} ${j.name}`}>{t('jobs.resume')}</button>
      )}
      {j.state === 'orphan' && (
        <button type="button" onClick={() => openFilesAt(j.hostId, dirName(j.dest))}
          className={`${BTN} wt-info`} aria-label={`${t('jobs.openFolder')} ${j.name}`}>
          {t('jobs.openFolder')}
        </button>
      )}
      {(isActive(j) || j.state === 'paused') && (
        <button type="button" onClick={onCancel} className={`${BTN} text-slate-300`}
          aria-label={`${t('jobs.cancel')} ${j.name}`}>{t('jobs.cancel')}</button>
      )}
      {j.state === 'orphan' && (
        <button type="button" onClick={() => discardUpload(j.id)} className={`${BTN} wt-danger`}
          aria-label={`${t('jobs.discard')} ${j.name}`}>{t('jobs.discard')}</button>
      )}
      {/* done upload: calea fişierului urcat e lucrul util — pentru un CLI care ia căi (Claude Code,
          aider) ea E rezultatul. Copiere mereu; inserare doar în sesiunea activă a aceluiaşi host.
          done download: fişierul e deja salvat, nu e nimic de copiat/inserat. */}
      {j.state === 'done' && canInsert && (
        <button type="button" onClick={() => insertPathInto(props.insertSid, j.dest)} className={`${BTN} wt-info`}
          aria-label={`${t('transfers.insertPath')} ${j.name}`}>{t('transfers.insertPath')}</button>
      )}
      {j.state === 'done' && !down && (
        <button type="button" onClick={() => { void copyText(j.dest) }} className={`${BTN} text-slate-300`}
          aria-label={`${t('transfers.copyPath')} ${j.name}`}>{t('transfers.copyPath')}</button>
      )}
      {(j.state === 'done' || j.state === 'err' || j.state === 'cancelled') && (
        <button type="button" onClick={onDismiss} className={`${BTN} text-slate-300`}
          aria-label={`${t('jobs.dismiss')} ${j.name}`}>{t('jobs.dismiss')}</button>
      )}
    </li>
  )
}

/** numele hostului: din job (scris la pornire); pentru cheile vechi (doar uid) îl căutăm în listă */
export const jobHostName = (j: UploadJob, hosts: Host[]) =>
  j.hostName || hosts.find((h) => h.id === j.hostId)?.name || `#${j.hostId}`

export default function JobsBar(props: { hosts: Host[] }) {
  const { t } = useI18n()
  const snap = useSyncExternalStore(uploadStore.subscribe, uploadStore.snapshot)
  const jobs = useMemo(() => [...snap.values()], [snap])
  const [collapsed, setCollapsed] = useState(() => lsGet(COLLAPSED_KEY) === '1')
  const toggle = () => { setCollapsed((c) => { lsSet(COLLAPSED_KEY, c ? '0' : '1'); return !c }) }

  // Anunţuri: diferenţa de stare faţă de randarea anterioară, DOAR pentru tranziţiile care
  // contează (→stalled, →err, →done). Progresul nu se anunţă — ar vorbi la fiecare procent.
  // Aceeaşi diferenţă alimentează notificarea de browser, dar numai cu tab-ul în fundal: cu
  // pagina în faţă chip-ul/bara spun deja totul, iar un pop-up de OS peste ea ar fi zgomot.
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
      else if (j.state === 'err') {
        msgs.push(t('jobs.srFailed', { name: j.name, error: j.error ?? '' }))
        if (document.hidden) notify(t('transfers.notifyFailed'), `${j.name} — ${j.error ?? ''}`, 'warn', `upload-${j.id}`)
      } else if (j.state === 'done') {
        msgs.push(t('jobs.srDone', { name: j.name }))
        if (document.hidden) notify(t('transfers.notifyDone'), j.name, 'info', `upload-${j.id}`)
      }
    }
    prev.current = next
    if (msgs.length) setAnnounce(msgs.join('; '))
  }, [jobs, t])

  const attention = jobs.filter(needsAttention)
  const stalled = attention.filter((j) => j.state === 'stalled').length
  const failed = attention.filter((j) => j.state === 'err').length
  const orphan = attention.filter((j) => j.state === 'orphan').length

  return (
    <>
      {/* regiune live permanentă (goală când nu e nimic de spus) */}
      <div aria-live="polite" className="sr-only">{announce}</div>
      {attention.length > 0 && (
        <section aria-label={t('jobs.title')} className="wt-jobsbar shrink-0 px-2 text-xs">
          {/* linia de sumar + chevron; pliat = doar atât */}
          <div className="flex h-8 items-center gap-2">
            <button type="button" onClick={toggle} aria-expanded={!collapsed}
              aria-label={collapsed ? t('jobs.expand') : t('jobs.collapse')}
              className={`${BTN} text-slate-300`}>
              <ChevronIcon open={!collapsed} />
            </button>
            <span aria-hidden="true" className="wt-warn"><UploadIcon /></span>
            <span className="font-mono tabular-nums text-slate-200">
              {t('transfers.needAttention', { count: attention.length })}
              {stalled > 0 && <> · <span className="wt-warn">{t('jobs.summaryStalled', { count: stalled })}</span></>}
              {failed > 0 && <> · <span className="wt-danger">{t('jobs.summaryFailed', { count: failed })}</span></>}
              {orphan > 0 && <> · <span className="wt-warn">{t('transfers.summaryOrphan', { count: orphan })}</span></>}
            </span>
          </div>
          {!collapsed && (
            <ul className="max-h-40 overflow-y-auto pb-1 pl-8">
              {attention.map((j) => <JobRow key={j.id} job={j} hostName={jobHostName(j, props.hosts)} />)}
            </ul>
          )}
        </section>
      )}
    </>
  )
}
