import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { createPortal } from 'react-dom'
import type { Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { notify } from '../lib/notify'
import { lsGet, lsSet } from '../lib/storage'
import { dismissUpload, fmtBytes } from '../lib/uploads'
import { dismissDownload } from '../lib/downloads'
import { dismissCopy } from '../lib/copyjobs'
import { UploadJob, isActive, isCopy, isDownload, sizeKnown, uploadStore } from '../lib/uploadStore'
import { CopyIcon, DownloadIcon, UploadIcon } from './Icons'
import { JobRow, jobHostName, needsAttention } from './JobsBar'

/* Widget-ul plutitor de transferuri: UN SINGUR loc pentru tot progresul (upload/download),
   jos-dreapta, portat în <body>. Înlocuieşte fostul triptic (chip în bara de taburi + popover
   + banda de atenţie de sus): chip-ul înghesuia bara de taburi şi se suprapunea peste ele când
   erau multe, iar banda fura o linie de ecran. Un widget plutitor nu concurează cu niciun crom.

   Pliat (implicit / după preferinţă): o pilulă compactă cu un sumar (un job: `nume 63%`; mai
   multe: `N transferuri · 63%`). Extins: un card cu lista de `JobRow` (acelaşi rând folosit şi
   de panoul de fişiere — nume, mărime, progres, viteză, ETA, acţiuni). Pilula pulsează DISCRET
   doar cât ceva cere atenţie (stalled/retrying/err) — mişcarea e semnal, nu decor; respectă
   prefers-reduced-motion.

   Stratul lui e z-40: SUB dialoguri/modale (z-50/60/70), peste conţinutul paginii. Pe mobil se
   întinde între gutter-e şi stă DEASUPRA keybar-ului (vezi --wt-keybar-h din MobileKeybar), ca
   să nu acopere niciodată tastatura de comenzi sau inputul terminalului. */

// preferinţă de pliere: implicit PLIAT (pilulă) dacă nu există o alegere salvată explicit
const MIN_KEY = 'wt_transfers_min'

// „terminal" = nimic nu mai curge (nici în pauză); done/err/cancelled se pot curăţa în bloc.
// orphan e tot terminal, dar cere o decizie explicită (Discard din rând), deci nu-l curăţăm aici.
const isTerminal = (j: UploadJob) => !isActive(j) && j.state !== 'paused'
const isDismissable = (j: UploadJob) => j.state === 'done' || j.state === 'err' || j.state === 'cancelled'

// butoanele din header: ţintă ≥24 px (44 px la touch prin wt-touch), focus vizibil
const BTN = 'wt-touch inline-flex h-6 min-w-6 shrink-0 items-center justify-center rounded px-1.5 text-[11px] font-medium hover:bg-ink-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400'

export default function TransfersWidget(props: { hosts: Host[]; insertSid?: string; insertHostId?: number }) {
  const { t } = useI18n()
  const snap = useSyncExternalStore(uploadStore.subscribe, uploadStore.snapshot)
  const jobs = useMemo(() => [...snap.values()], [snap])
  // citit sincron la montare ca layout-ul să nu „sară" după primul render
  const [collapsed, setCollapsed] = useState(() => lsGet(MIN_KEY) !== '0')
  // toggle-ul manual PERSISTĂ (e o preferinţă); auto-extinderea de mai jos NU persistă
  const toggle = () => setCollapsed((c) => { lsSet(MIN_KEY, c ? '0' : '1'); return !c })

  // Anunţuri (aria-live) — doar tranziţiile care contează (→stalled/→err/→done); progresul nu se
  // anunţă (ar vorbi la fiecare procent). Cu tab-ul în fundal, done/err dau şi o notificare de
  // browser. Mutat aici din fosta JobsBar; acum e singura regiune live pentru transferuri.
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

  // Auto-extindere O SINGURĂ dată când un job NOU intră într-o stare de atenţie (stalled/err/
  // orphan) — asta înlocuieşte fosta bandă de sus. Urmărim mulţimea anterioară de id-uri „în
  // atenţie" şi reacţionăm doar la TRANZIŢIE: dacă userul re-pliază, nu ne batem cu el (nu
  // re-extindem cât timp acelaşi job rămâne în aceeaşi stare).
  const attentionRef = useRef<Set<string>>(new Set())
  useEffect(() => {
    const now = new Set(jobs.filter(needsAttention).map((j) => j.id))
    let fresh = false
    for (const id of now) if (!attentionRef.current.has(id)) { fresh = true; break }
    attentionRef.current = now
    if (fresh) setCollapsed(false)   // doar vizual; NU persistă (nu e alegerea userului)
  }, [jobs])

  if (jobs.length === 0) return null

  // sumar general: procentul pe octeţii transferurilor VII (ca în fostul chip)
  // doar job-urile cu mărime CUNOSCUTĂ intră în %: o arhivă din mers (size 0, pos în creştere) ar
  // împinge sumarul peste 100%
  const live = jobs.filter((j) => isActive(j) && sizeKnown(j))
  const totalSize = live.reduce((a, j) => a + j.size, 0)
  const totalPos = live.reduce((a, j) => a + j.pos, 0)
  const overallPct = totalSize ? Math.round((totalPos / totalSize) * 100) : null
  const worried = jobs.some((j) => j.state === 'stalled' || j.state === 'retrying')
  const failed = jobs.some((j) => j.state === 'err')
  const tone = failed ? 'wt-danger' : worried ? 'wt-warn' : 'wt-info'
  const pulse = worried || failed          // pulsează DOAR cât ceva cere atenţie
  const allTerminal = jobs.every(isTerminal)
  const canClear = allTerminal && jobs.some(isDismissable)
  const clearFinished = () => {
    for (const j of jobs) if (isDismissable(j)) (isCopy(j) ? dismissCopy : isDownload(j) ? dismissDownload : dismissUpload)(j.id)
  }
  // iconul = sensul când e un singur job; pentru mai multe rămâne „↑" (upload e cazul uzual)
  const icon = jobs.length === 1 && isCopy(jobs[0]) ? <CopyIcon />
    : jobs.length === 1 && isDownload(jobs[0]) ? <DownloadIcon /> : <UploadIcon size={12} />
  const countLabel = `${t('transfers.chipMany', { count: jobs.length })}${overallPct != null ? ` · ${overallPct}%` : ''}`
  // pliat: un job → `nume 63%`; mai multe → `N transferuri · 63%`
  const one = jobs[0]
  const summary = jobs.length === 1 ? `${one.name} ${sizeKnown(one) ? `${one.pct}%` : fmtBytes(one.pos)}` : countLabel

  return createPortal(
    <div role="region" aria-label={t('jobs.title')} className="wt-transfers-widget">
      {/* regiune live permanentă cât există widgetul (goală când nu e nimic de spus) */}
      <div aria-live="polite" className="sr-only">{announce}</div>
      {collapsed ? (
        <button type="button" onClick={toggle} aria-expanded={false}
          // numele accesibil CONŢINE textul vizibil (WCAG 2.5.3) + ce face apăsarea
          aria-label={`${t('jobs.title')}: ${summary} — ${t('transfers.expand')}`}
          title={t('transfers.chipTitle')}
          data-testid="wt-transfers-pill"
          className={`wt-transfers-surface ${tone} ${pulse ? 'wt-chip-pulse' : ''} wt-touch inline-flex h-8 max-w-[min(88vw,22rem)] items-center gap-1.5 rounded-full px-3 font-mono text-[12px] tabular-nums hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400`}>
          <span aria-hidden="true" className="shrink-0">{icon}</span>
          <span className="truncate">{summary}</span>
        </button>
      ) : (
        <div data-testid="wt-transfers-card"
          className="wt-transfers-surface flex max-h-[60vh] w-[min(92vw,26rem)] flex-col overflow-hidden rounded-xl text-xs">
          <div className="flex h-9 shrink-0 items-center gap-2 border-b border-ink-700 px-2">
            <span aria-hidden="true" className={`shrink-0 ${tone}`}>{icon}</span>
            <span className="font-semibold text-slate-200">{t('jobs.title')}</span>
            <span className="min-w-0 truncate font-mono tabular-nums text-slate-400">{countLabel}</span>
            {/* „Curăţă terminate" apare doar când totul s-a oprit şi chiar e ceva de curăţat */}
            {canClear && (
              <button type="button" onClick={clearFinished} className={`${BTN} ml-auto text-slate-300`}
                aria-label={t('transfers.clearFinished')}>{t('transfers.clearFinished')}</button>
            )}
            <button type="button" onClick={toggle} aria-label={t('transfers.minimize')} title={t('transfers.minimize')}
              className={`${BTN} ${canClear ? '' : 'ml-auto'} text-slate-300`}>
              {/* „–" = minimizează la pilulă (aria-label poartă sensul) */}
              <span aria-hidden="true" className="text-base leading-none">–</span>
            </button>
          </div>
          <ul className="min-h-0 flex-1 overflow-y-auto px-2 pb-1">
            {jobs.map((j) => (
              <JobRow key={j.id} job={j} hostName={jobHostName(j, props.hosts)}
                insertSid={props.insertSid} insertHostId={props.insertHostId} />
            ))}
          </ul>
        </div>
      )}
    </div>,
    document.body,
  )
}
