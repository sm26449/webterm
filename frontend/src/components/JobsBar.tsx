import type { Host } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useI18n } from '../lib/i18n'
import { insertPathInto } from '../lib/transfers'
import { cancelUpload, dirName, discardUpload, dismissUpload, fmtBytes, fmtEta, fmtRate, openFilesAt, pauseUpload, resumeUpload, retryUpload } from '../lib/uploads'
import { cancelDownload, discardDownload, dismissDownload, pauseDownload, restartDownload, resumeDownload, resumeInterrupted, retryDownload } from '../lib/downloads'
import { canRetryCopy, cancelCopy, dismissCopy, retryCopy } from '../lib/copyjobs'
import { UploadJob, canPause, isActive, isCopy, isDownload, sizeKnown } from '../lib/uploadStore'
import { CopyIcon, DownloadIcon, UploadIcon } from './Icons'
import { compactAction } from './ui'

/* Helper-ele pentru transferuri — rândul (`JobRow`) şi funcţiile lui de stare — folosite acum
   de widgetul plutitor (TransfersWidget). Incidentul cu upload-ul de 17 GB (2026-10-04) a arătat
   că singurul loc unde se vedea un transfer era panoul de fişiere care l-a pornit — închis
   panoul, dispărută orice urmă; de aici un loc GLOBAL, independent de panou.

   Fosta bandă `<JobsBar>` (progres în banda de sus doar pentru stalled/err/orphan) + chip-ul din
   bara de stare au fost unificate în TransfersWidget; aici rămâne doar logica partajată de rând,
   ca să nu se dubleze. Rândul e vizual tăcut (cifre monospaţiate, fără emoji) şi complet operabil
   de la tastatură (ţinte de 24 px). */
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

const BTN = compactAction   // design system (ui/classes)

type TFn = (k: string, v?: Record<string, string | number>) => string

/** Starea unui rând în DOUĂ părţi: `head` = scurt (%, viteză, Gata), pe linia numelui; `extra` =
    ce poate fi lung (fişierul copiat acum + numărători, rezumatul de la final, eroarea, nota de
    download, explicaţia „Incomplet"), pe o a doua linie. Înainte totul stătea pe o singură linie
    de 32 px, iar textul lung (o copiere de folder: „→ logs/access.log · files 6/14 · folders 2/3")
    strivea numele rândului la lăţime zero şi se tăia el însuşi în „…" — văzut în capturile 3.5.17. */
export function jobStatusParts(j: UploadJob, t: TFn): { head: string; extra: string } {
  if (j.state === 'err') {
    const why = j.error || t('files.uploadFailed')
    return { head: t('jobs.stateFailed'), extra: isCopy(j) && j.detail ? `${why} · ${j.detail}` : why }
  }
  // arhivă din mers: mărimea nu se ştie → octeţii primiţi (nu %); detaliul spune „se pregăteşte" /
  // „nu se poate relua". Copiere host → host: % + rezumatul fişierelor de pe server.
  if (!sizeKnown(j)) {
    const got = j.pos > 0 ? `${fmtBytes(j.pos)} · ${fmtRate(j.bytesPerSec)}` : ''
    const st = j.state === 'running' ? '' : j.state === 'stalled' ? t('jobs.stateStalled')
      : j.state === 'done' ? t('jobs.stateDone') : j.state === 'cancelled' ? t('jobs.stateCancelled') : ''
    return { head: [got, st].filter(Boolean).join(' · '), extra: j.detail ?? '' }
  }
  if (isCopy(j) && j.detail) {
    const head = j.state === 'running' ? `${j.pct}% · ${fmtRate(j.bytesPerSec)}`
      : j.state === 'done' ? `100% · ${t('jobs.stateDone')}` : t('jobs.stateCancelled')
    return { head, extra: j.detail }
  }
  // download: nota de stare (checkpoint pe disc, permisiune refuzată, fişier parţial dispărut)
  // merge pe a doua linie; un download întrerupt într-o sesiune anterioară e „Întrerupt"
  // (reluabil din rând), nu „orfan" ca la upload (acolo re-tragi fişierul)
  if (isDownload(j) && j.state !== 'done') {
    const head = j.state === 'orphan' ? `${j.pct}% · ${t('transfers.dlInterrupted')}` : jobStatusBase(j, t)
    return { head, extra: j.detail ?? '' }
  }
  // upload neterminat: explicaţia („trage acelaşi fişier…") e o propoziţie, nu o stare
  if (j.state === 'orphan') return { head: `${j.pct}%`, extra: t('jobs.stateOrphan') }
  return { head: jobStatusBase(j, t), extra: '' }
}

/** tot textul stării, pe un rând (titluri, anunţuri) */
export function jobStatusText(j: UploadJob, t: TFn): string {
  const { head, extra } = jobStatusParts(j, t)
  return [head, extra].filter(Boolean).join(' · ')
}

function jobStatusBase(j: UploadJob, t: (k: string, v?: Record<string, string | number>) => string): string {
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
  const copy = isCopy(j)
  // copiere: hostName e deja „A → B" (scris de motor)
  const name = `${copy ? j.hostName : props.hostName} · ${j.name}`
  const canInsert = !down && !copy && !!props.insertSid && props.insertHostId === j.hostId
  const known = sizeKnown(j)
  const status = jobStatusParts(j, t)
  // Acţiunile diferă pe sens: up → uploads.ts, down → downloads.ts (fişiere + arhive), copy →
  // copyjobs.ts (job pe server). Rândul e identic altfel.
  const onRetry = () => (copy ? void retryCopy(j.id) : down ? retryDownload(j.id) : retryUpload(j.id))
  const onCancel = () => (copy ? void cancelCopy(j.id) : down ? cancelDownload(j.id) : cancelUpload(j.id))
  const onDismiss = () => (copy ? dismissCopy(j.id) : down ? dismissDownload(j.id) : dismissUpload(j.id))
  const onPause = () => (down ? pauseDownload(j.id) : pauseUpload(j.id))
  const onResume = () => (down ? resumeDownload(j.id) : resumeUpload(j.id))
  return (
    <li className="py-0.5">
      <div className="flex min-h-[1.75rem] items-center gap-2">
      <span aria-hidden="true" className={`shrink-0 ${STATE_CLS[j.state]}`}>
        {copy ? <CopyIcon /> : down ? <DownloadIcon /> : <UploadIcon size={12} />}
      </span>
      {/* numele are o lăţime minimă: starea nu-l mai poate strivi la zero */}
      <span className="min-w-[7rem] flex-1 truncate text-slate-200" title={`${name} — ${j.dest}`}>{name}</span>
      {/* mărime necunoscută (arhivă din mers): bară nedeterminată — fără aria-valuenow */}
      <div role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={known ? j.pct : undefined}
        aria-label={known ? t('jobs.progressAria', { name: j.name, pct: j.pct }) : `${j.name}: ${fmtBytes(j.pos)}`}
        className="h-1 w-12 shrink-0 overflow-hidden rounded-full bg-ink-700 sm:w-20">
        <div className={`h-full rounded-full transition-[width] duration-200 ease-out motion-reduce:transition-none ${BAR_CLS[j.state]} ${!known && isActive(j) ? 'animate-pulse opacity-60 motion-reduce:animate-none' : ''}`}
          style={{ width: `${j.state === 'err' || (!known && j.state !== 'cancelled') ? 100 : j.pct}%` }} />
      </div>
      <span className={`hidden min-w-0 max-w-[10rem] shrink-0 truncate font-mono tabular-nums sm:inline ${STATE_CLS[j.state]}`}
        title={status.head}>
        {status.head}
      </span>
      {/* dimensiunea totală a fişierului — cerută la click pe chip; ascunsă pe ecrane înguste */}
      {/* la o copiere mărimea e totalul arborelui — încape doar dacă nu mai e nimic de spus */}
      <span className={`hidden shrink-0 font-mono tabular-nums text-slate-500 ${copy ? '' : 'md:inline'}`} title={`${fmtBytes(j.pos)} / ${fmtBytes(j.size)}`}>{known ? fmtBytes(j.size) : fmtBytes(j.pos)}</span>
      <span className={`font-mono tabular-nums sm:hidden ${STATE_CLS[j.state]}`}>{known ? `${j.pct}%` : fmtBytes(j.pos)}</span>
      {/* acţiuni după stare — nume accesibil = acţiune + fişier, ca în FilePanel */}
      {(j.state === 'err' || j.state === 'stalled') && (!copy || canRetryCopy(j.id)) && !j.restartable && (
        <button type="button" onClick={onRetry} className={`${BTN} wt-info`}
          aria-label={`${t('jobs.retry')} ${j.name}`}>{t('jobs.retry')}</button>
      )}
      {/* Pauză pe un transfer viu; Resume pe unul pus pe pauză. Simetric upload/download. */}
      {isActive(j) && canPause(j) && (
        <button type="button" onClick={onPause} className={`${BTN} text-slate-300`}
          aria-label={`${t('jobs.pause')} ${j.name}`}>{t('jobs.pause')}</button>
      )}
      {j.state === 'paused' && (
        <button type="button" onClick={onResume} className={`${BTN} wt-info`}
          aria-label={`${t('jobs.resume')} ${j.name}`}>{t('jobs.resume')}</button>
      )}
      {/* download întrerupt (sesiune anterioară): Resume cere permisiunea de scriere pe fişier — din
          click, de aceea rândul cheamă direct motorul */}
      {j.state === 'orphan' && down && (
        <button type="button" onClick={() => resumeInterrupted(j.id)} className={`${BTN} wt-info`}
          aria-label={`${t('jobs.resume')} ${j.name}`}>{t('jobs.resume')}</button>
      )}
      {j.restartable && down && (j.state === 'err' || j.state === 'orphan') && (
        <button type="button" onClick={() => restartDownload(j.id)} className={`${BTN} wt-warn`}
          aria-label={`${t('transfers.dlStartOver')} ${j.name}`}>{t('transfers.dlStartOver')}</button>
      )}
      {j.state === 'orphan' && !down && (
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
        <button type="button" onClick={() => (down ? discardDownload(j.id) : discardUpload(j.id))} className={`${BTN} wt-danger`}
          aria-label={`${t('jobs.discard')} ${j.name}`}>{t('jobs.discard')}</button>
      )}
      {/* done upload: calea fişierului urcat e lucrul util — pentru un CLI care ia căi (Claude Code,
          aider) ea E rezultatul. Copiere mereu; inserare doar în sesiunea activă a aceluiaşi host.
          done download: fişierul e deja salvat, nu e nimic de copiat/inserat. */}
      {j.state === 'done' && canInsert && (
        <button type="button" onClick={() => insertPathInto(props.insertSid, j.dest)} className={`${BTN} wt-info`}
          aria-label={`${t('transfers.insertPath')} ${j.name}`}>{t('transfers.insertPath')}</button>
      )}
      {j.state === 'done' && !down && !copy && (
        <button type="button" onClick={() => { void copyText(j.dest) }} className={`${BTN} text-slate-300`}
          aria-label={`${t('transfers.copyPath')} ${j.name}`}>{t('transfers.copyPath')}</button>
      )}
      {(j.state === 'done' || j.state === 'err' || j.state === 'cancelled') && (
        <button type="button" onClick={onDismiss} className={`${BTN} text-slate-300`}
          aria-label={`${t('jobs.dismiss')} ${j.name}`}>{t('jobs.dismiss')}</button>
      )}
      </div>
      {/* a doua linie: fişierul în lucru + numărători / rezumatul / eroarea — până la 2 rânduri,
          textul întreg în title; aliniată sub nume (după icon) */}
      {status.extra && (
        <p className={`line-clamp-2 pb-0.5 pl-5 text-2xs [overflow-wrap:anywhere] ${j.state === 'err' ? 'wt-danger' : j.state === 'orphan' ? 'wt-warn' : 'text-slate-400'}`}
          title={status.extra} data-testid="wt-job-detail">
          {status.extra}
        </p>
      )}
    </li>
  )
}

/** numele hostului: din job (scris la pornire); pentru cheile vechi (doar uid) îl căutăm în listă */
export const jobHostName = (j: UploadJob, hosts: Host[]) =>
  j.hostName || hosts.find((h) => h.id === j.hostId)?.name || `#${j.hostId}`

