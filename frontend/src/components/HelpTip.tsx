import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { copyText } from '../lib/clipboard'
import { docsUrl, HELP, HelpId } from '../lib/help'
import { useI18n } from '../lib/i18n'
import { ArrowRightIcon, CloseIcon, CopyIcon } from './Icons'

/* „?" lângă o setare: la CLICK (nu hover — pe touch tooltip-urile nu există) deschide un
   popover cu la ce folosește, un exemplu copiabil și linkul spre documentația versiunii care
   rulează. Popover-ul e randat în portal cu poziție `fixed`, ca să nu fie tăiat de containerele
   cu scroll (modalul Settings, panourile hostului).

   A11Y: butonul are aria-expanded/aria-controls; popover-ul e un dialog NON-modal — primește
   focusul la deschidere (ca un cititor de ecran să-l citească), Escape îl închide și întoarce
   focusul pe „?", iar un click în afară îl închide. Fără focus-trap: nu blochează nimic. */
export default function HelpTip(props: { id: HelpId; className?: string }) {
  const { t } = useI18n()
  const entry = HELP[props.id] as { doc: string; example?: (origin: string) => string }
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null)
  const btnRef = useRef<HTMLButtonElement>(null)
  const popRef = useRef<HTMLDivElement>(null)
  const popId = useId()
  const title = t(`help.${props.id}.title`)
  const example = entry.example?.(window.location.origin)

  const close = (refocus = true) => {
    setOpen(false)
    if (refocus) btnRef.current?.focus()
  }

  // poziția: sub buton, aliniat la stânga, ţinut în viewport (16px gutter, ca pe mobil)
  useLayoutEffect(() => {
    if (!open) return
    const place = () => {
      const b = btnRef.current?.getBoundingClientRect()
      const p = popRef.current
      if (!b || !p) return
      const w = p.offsetWidth, h = p.offsetHeight
      const vw = window.innerWidth, vh = window.innerHeight
      const left = Math.min(Math.max(16, b.left - 8), vw - w - 16)
      const below = b.bottom + 6
      const top = below + h > vh - 16 && b.top - 6 - h > 16 ? b.top - 6 - h : below
      setPos({ top, left })
    }
    place()
    window.addEventListener('resize', place)
    window.addEventListener('scroll', place, true)
    return () => {
      window.removeEventListener('resize', place)
      window.removeEventListener('scroll', place, true)
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    popRef.current?.focus()
    const onDown = (e: PointerEvent) => {
      const n = e.target as Node
      if (popRef.current?.contains(n) || btnRef.current?.contains(n)) return
      close(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); close() }
    }
    document.addEventListener('pointerdown', onDown, true)
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('pointerdown', onDown, true)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open])

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen((v) => !v) }}
        aria-label={t('help.aria', { topic: title })}
        aria-expanded={open}
        aria-controls={open ? popId : undefined}
        className={`wt-touch inline-grid h-5 w-5 shrink-0 place-items-center rounded-full border border-ink-700 align-middle text-2xs font-semibold leading-none text-slate-400 hover:border-sky-500/60 hover:text-sky-300 ${props.className ?? ''}`}
      >
        ?
      </button>
      {open && createPortal(
        <div
          ref={popRef}
          id={popId}
          role="dialog"
          aria-label={title}
          tabIndex={-1}
          style={{ top: pos?.top ?? -9999, left: pos?.left ?? -9999 }}
          className="glass fixed z-[70] w-[min(22rem,calc(100vw-2rem))] rounded-xl p-4 text-left shadow-2xl outline-none"
        >
          <div className="flex items-start justify-between gap-3">
            <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
            <button type="button" onClick={() => close()} aria-label={t('common.close')}
              className="wt-touch -mr-1 -mt-1 grid place-items-center rounded-md p-1 text-slate-400 hover:bg-ink-800">
              <CloseIcon size={14} />
            </button>
          </div>
          <p className="mt-2 whitespace-pre-line text-compact leading-relaxed text-slate-300">{t(`help.${props.id}.body`)}</p>
          {example && (
            <div className="mt-3 flex items-start gap-2 rounded-md border border-ink-800 bg-ink-950/60 p-2">
              <code className="min-w-0 flex-1 break-all font-mono text-xs text-slate-300">{example}</code>
              <button type="button" onClick={() => copyText(example)} aria-label={t('help.copyExample')}
                className="wt-touch grid shrink-0 place-items-center rounded-md p-1 text-slate-400 hover:bg-ink-800 hover:text-slate-200">
                <CopyIcon />
              </button>
            </div>
          )}
          <a href={docsUrl(entry.doc)} target="_blank" rel="noopener noreferrer"
            className="wt-link mt-3 inline-flex items-center gap-1 text-compact font-medium hover:underline">
            {t('help.readDocs')} <ArrowRightIcon />
          </a>
        </div>,
        document.body,
      )}
    </>
  )
}
