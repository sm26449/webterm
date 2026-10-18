import { ReactNode, useEffect, useLayoutEffect, useRef, useState, KeyboardEvent as ReactKeyboardEvent } from 'react'
import { createPortal } from 'react-dom'
import { menuNav } from '../lib/tablist'

/* Meniul de acţiuni al panoului de fişiere (3.6.14): click dreapta / Shift+F10 / tasta Menu pe un
   rând, „⋯" pe touch, click dreapta pe zona goală a listei şi butonul flotant „+".

   Acelaşi tipar ca meniul contextual al terminalului (SessionView: role=menu, iteme de ≥24px, Escape
   îl închide înainte să ajungă altundeva), dar ca componentă proprie: acela e legat de starea
   terminalului. Pe desktop e un popup lângă cursor / rând; pe touch o FOAIE de jos cu ţinte de 44px
   (safe-area jos). Tastatura (WAI-ARIA menu): focusul intră pe primul item, ↑/↓ cu ocol, Home/End,
   Enter/Space activează (nativ, sunt butoane), Escape / Tab închid — iar focusul se întoarce unde
   decide apelantul (lista, pe rândul de pe care s-a deschis). Randat într-un portal: foaia panoului
   are `overflow-hidden`, care ar tăia popup-ul. */
export interface MenuItem {
  key: string
  label: string
  icon?: ReactNode
  onSelect: () => void
  danger?: boolean
  disabled?: boolean
  /** de ce e dezactivat (FL-09, audit 2026-10-17: „needs files.write on this host") — arătat SUB
      etichetă (un item dezactivat nu primeşte hover pe touch, deci tooltip-ul nu ajunge) şi ca
      descriere accesibilă */
  reason?: string
  /** linie de separare ÎNAINTEA itemului */
  sep?: boolean
  hint?: string
}

export default function FileMenu(props: {
  items: MenuItem[]
  /** colţul de sus-stânga dorit (px, viewport); ignorat în modul foaie */
  at: { x: number; y: number }
  sheet: boolean
  /** titlul foii (numele fişierului) — doar pe touch */
  title?: string
  label: string
  /** elementul de care e legat meniul (lista de fişiere): doar derularea LUI (sau a paginii) îl închide */
  anchor?: HTMLElement | null
  onClose: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState<{ left: number; top: number }>({ left: props.at.x, top: props.at.y })

  // în ecran: măsurăm meniul randat şi îl împingem înăuntru (jos / dreapta)
  useLayoutEffect(() => {
    if (props.sheet || !ref.current) return
    const r = ref.current.getBoundingClientRect()
    setPos({
      left: Math.max(8, Math.min(props.at.x, window.innerWidth - r.width - 8)),
      top: Math.max(8, Math.min(props.at.y, window.innerHeight - r.height - 8)),
    })
  }, [props.at.x, props.at.y, props.sheet])

  useEffect(() => {
    ref.current?.querySelector<HTMLElement>('[role="menuitem"]:not([disabled])')?.focus({ preventScroll: true })
  }, [])

  // un click în afara meniului (sau pe scrim) îl închide; scroll / resize la fel (poziţia nu mai e bună)
  // `onClose` prin ref: abonarea se face O DATĂ la montare, nu la fiecare randare (review L6).
  // Scroll-ul (în captură: prinde şi lista derulată, nu doar fereastra) mută rândul de sub meniu.
  const onCloseRef = useRef(props.onClose)
  onCloseRef.current = props.onClose
  const anchorRef = useRef(props.anchor ?? null)
  anchorRef.current = props.anchor ?? null
  useEffect(() => {
    const onWin = () => onCloseRef.current()
    const t0 = Date.now()
    const onScroll = (e: Event) => {
      // scrollIntoView-ul rândului abia selectat (acelaşi click) nu e o derulare a userului
      if (Date.now() - t0 < 250) return
      // doar derularea paginii sau a unui element care CONŢINE ancora (lista de fişiere) mută rândul de
      // sub meniu — un terminal care derulează singur (tail -f, un build) nu-l închide (review R2)
      const tg = e.target
      const anchor = anchorRef.current
      if (tg === document || tg === window || tg === document.documentElement || tg === document.body
        || (anchor && tg instanceof Node && tg.contains(anchor))) onCloseRef.current()
    }
    window.addEventListener('resize', onWin)
    window.addEventListener('blur', onWin)
    window.addEventListener('scroll', onScroll, true)
    return () => {
      window.removeEventListener('resize', onWin)
      window.removeEventListener('blur', onWin)
      window.removeEventListener('scroll', onScroll, true)
    }
  }, [])

  const onKeyDown = (e: ReactKeyboardEvent) => {
    // auto-repeat: o tastă ţinută apăsată (Delete / Enter care a deschis meniul) nu activează un item
    if (e.repeat && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); e.stopPropagation(); return }
    const btns = [...(ref.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([disabled])') ?? [])]
    const i = btns.indexOf(document.activeElement as HTMLElement)
    if (e.key === 'Escape' || e.key === 'Tab') {
      e.preventDefault(); e.stopPropagation(); props.onClose(); return
    }
    const next = menuNav(e.key, i, btns.length)
    if (next != null) { e.preventDefault(); e.stopPropagation(); btns[next]?.focus(); return }
    // Enter/Space: activarea nativă a butonului; nu lăsăm tasta să urce în listă (ar deschide rândul)
    if (e.key === 'Enter' || e.key === ' ') e.stopPropagation()
  }

  const item = (it: MenuItem) => {
    const reasonId = it.disabled && it.reason ? `wt-files-menu-${it.key}-why` : undefined
    return (
    <button key={it.key} type="button" role="menuitem" disabled={it.disabled}
      data-testid={`wt-files-menu-${it.key}`}
      title={reasonId ? it.reason : undefined} aria-describedby={reasonId}
      onClick={() => { if (it.disabled) return; props.onClose(); it.onSelect() }}
      className={`flex w-full items-center gap-2.5 rounded-md px-2.5 text-left disabled:cursor-default ${reasonId ? 'disabled:opacity-60' : 'disabled:opacity-40'} ${
        props.sheet ? 'min-h-11 py-2 text-sm' : 'min-h-[28px] py-1 text-xs'} ${
        it.danger ? 'wt-danger hover:bg-rose-500/10 focus:bg-rose-500/10' : 'text-slate-300 hover:bg-ink-800 focus:bg-ink-800'} outline-none`}>
      <span className="grid h-4 w-4 shrink-0 place-items-center" aria-hidden="true">{it.icon}</span>
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="truncate">{it.label}</span>
        {/* motivul dezactivării, vizibil fără hover (telefon) — nu „un buton gri fără explicaţie" */}
        {reasonId && <span id={reasonId} className="whitespace-normal text-2xs font-normal text-slate-500">{it.reason}</span>}
      </span>
      {it.hint && !props.sheet && <span className="ml-3 shrink-0 font-mono text-2xs text-slate-500" aria-hidden="true">{it.hint}</span>}
    </button>
    )
  }

  const body = props.items.map((it) => (
    it.sep ? [<div key={`${it.key}-sep`} role="separator" className="my-1 border-t border-ink-800" />, item(it)] : item(it)
  ))

  return createPortal(
    <>
      <div className={`fixed inset-0 z-[55] ${props.sheet ? 'bg-black/50' : ''}`} aria-hidden="true"
        onClick={props.onClose} onContextMenu={(e) => { e.preventDefault(); props.onClose() }} />
      <div ref={ref} role="menu" tabIndex={-1} aria-label={props.label} onKeyDown={onKeyDown} data-testid="wt-files-menu"
        className={props.sheet
          ? 'wt-sheet-bottom fixed inset-x-0 bottom-0 z-[56] max-h-[80vh] overflow-y-auto rounded-t-2xl border-t border-ink-700 bg-ink-900 px-2 pt-2 shadow-2xl'
          : 'fixed z-[56] w-56 rounded-xl border border-ink-700 bg-ink-900 p-1 shadow-2xl'}
        style={props.sheet ? undefined : { left: pos.left, top: pos.top }}>
        {props.sheet && props.title && (
          <div className="truncate px-2.5 pb-2 pt-1 font-mono text-xs text-slate-400" aria-hidden="true">{props.title}</div>
        )}
        {body}
      </div>
    </>,
    document.body,
  )
}
