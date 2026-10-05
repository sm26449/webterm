import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import type { UploadJob } from '../lib/uploadStore'
import { JobRow } from './JobsBar'

/* Lista completă de transferuri, ancorată DEASUPRA chip-ului din bara de stare. Poziţionare
   `fixed` calculată din dreptunghiul ancorei, nu `absolute` în bară: rădăcina sesiunii e
   `overflow: hidden` (wt-window) şi ar tăia orice panou care iese din bara de 24 px. Dialog
   modal mic: focus-trap, Escape închide şi focusul se întoarce pe chip (useFocusTrap), click
   în afară închide. Rândurile sunt EXACT cele din JobsBar — aceleaşi acţiuni, plus
   Copy path / Insert path pentru upload-urile terminate. */
export default function TransfersPopover(props: {
  anchor: HTMLElement | null
  jobs: UploadJob[]
  hostName: (j: UploadJob) => string
  insertSid?: string
  insertHostId?: number
  onClose: () => void
}) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  const [pos, setPos] = useState<{ top?: number; bottom?: number; right: number } | null>(null)

  useLayoutEffect(() => {
    const place = () => {
      const r = props.anchor?.getBoundingClientRect()
      if (!r) { setPos({ top: 44, right: 8 }); return }
      const right = Math.max(4, window.innerWidth - r.right)
      // Chip-ul stă acum SUS (bara de taburi): deschidem în JOS, sub el. Dacă ancora e în jumătatea
      // de jos a ecranului (ex. viitoare mutare), deschidem în SUS. Fără asta, ancorarea pe `bottom`
      // împingea panoul deasupra ecranului → click „nu arăta nimic".
      if (r.top < window.innerHeight / 2) setPos({ top: Math.round(r.bottom + 6), right })
      else setPos({ bottom: Math.max(4, Math.round(window.innerHeight - r.top + 6)), right })
    }
    place()
    window.addEventListener('resize', place)
    return () => window.removeEventListener('resize', place)
  }, [props.anchor])

  // click/tap în afara panoului (şi nu pe chip — acela îşi face singur toggle-ul) → închide
  const onCloseRef = useRef(props.onClose)
  onCloseRef.current = props.onClose
  useEffect(() => {
    const onDown = (e: PointerEvent) => {
      const el = ref.current
      const tgt = e.target as Node
      if (!el || el.contains(tgt) || props.anchor?.contains(tgt)) return
      onCloseRef.current()
    }
    document.addEventListener('pointerdown', onDown)
    return () => document.removeEventListener('pointerdown', onDown)
  }, [props.anchor])

  // ultimul rând a dispărut (dismiss / expirare) → nu lăsăm un dialog gol pe ecran
  useEffect(() => { if (props.jobs.length === 0) onCloseRef.current() }, [props.jobs.length])

  return createPortal(
    <div ref={ref} role="dialog" aria-modal="true" aria-label={t('jobs.title')}
      className="wt-jobsbar fixed z-[60] max-h-[70vh] w-[min(92vw,38rem)] overflow-hidden rounded-lg border border-ink-700 px-2 pb-1 text-xs shadow-2xl"
      style={pos ? { top: pos.top, bottom: pos.bottom, right: pos.right } : { visibility: 'hidden' }}>
      <div className="flex h-8 items-center gap-2">
        <span className="font-semibold text-slate-200">{t('jobs.title')}</span>
        <span className="font-mono tabular-nums text-slate-400">{t('jobs.summary', { count: props.jobs.length })}</span>
        <button type="button" onClick={props.onClose} aria-label={t('transfers.close')}
          className="wt-touch ml-auto inline-flex h-6 min-w-6 items-center justify-center rounded px-1.5 text-slate-300 hover:bg-ink-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-sky-400">✕</button>
      </div>
      <ul className="max-h-48 overflow-y-auto">
        {props.jobs.map((j) => (
          <JobRow key={j.id} job={j} hostName={props.hostName(j)} insertSid={props.insertSid} insertHostId={props.insertHostId} />
        ))}
      </ul>
    </div>
    , document.body)
}
