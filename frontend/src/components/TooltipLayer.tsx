import { useEffect, useLayoutEffect, useRef, useState } from 'react'

// Tooltip global. Înlocuiește tooltip-ul nativ al browserului (delay ~1.5s,
// controlat de OS, căsuță albă imposibil de stilizat) cu unul stilizat care
// apare rapid. Interceptează atributele `title` EXISTENTE din tot UI-ul — nicio
// modificare în componentele individuale, merge peste toate cele ~126 de title.
//
// Cum: la hover CU MOUSE-ul pe orice element cu `title`, mută textul într-un
// data-attr și scoate `title`-ul nativ (suprimă căsuța OS + dublarea), apoi
// afișează după DELAY ms tooltip-ul propriu. La ieșire îl restaurează. Doar
// mouse (fără tooltip pe touch) → navigarea cu tastatura/focus păstrează
// `title`-ul nativ; doar un SR acționat cu mouse-ul pierde numele pe durata hover-ului.

const DELAY = 250       // ms până apare (title nativ e ~1.5s)
const GAP = 8           // px între element și tooltip
const EDGE = 8          // px minim față de marginea ferestrei

type Tip = { text: string; cx: number; y: number; place: 'top' | 'bottom' }

export default function TooltipLayer() {
  const [tip, setTip] = useState<Tip | null>(null)
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null)
  const ref = useRef<HTMLDivElement>(null)
  const timer = useRef<number | null>(null)
  const active = useRef<HTMLElement | null>(null) // elementul al cărui title l-am scos

  useEffect(() => {
    const clearTimer = () => {
      if (timer.current !== null) { clearTimeout(timer.current); timer.current = null }
    }
    // pune `title`-ul înapoi pe elementul de la care l-am luat. Cât e afișat
    // tooltip-ul propriu, elementul e temporar fără `title` (deci un screen-reader
    // acționat cu MOUSE-ul pierde numele accesibil pentru acea clipă); navigarea cu
    // tastatura/focus nu e afectată (scoatem title-ul doar la hover cu mouse-ul).
    const restore = () => {
      const el = active.current
      if (el && el.dataset.wtt !== undefined) {
        // nu suprascrie un `title` nou pe care React l-ar fi pus între timp
        if (!el.hasAttribute('title')) el.setAttribute('title', el.dataset.wtt)
        delete el.dataset.wtt
      }
      active.current = null
    }
    const hide = () => { clearTimer(); restore(); setTip(null); setPos(null) }

    const show = (el: HTMLElement) => {
      if (!el.isConnected) { hide(); return }
      // dacă React a re-randat elementul între timp și a re-adăugat title, scoate-l iar
      const reAdded = el.getAttribute('title')
      if (reAdded) { el.dataset.wtt = reAdded; el.removeAttribute('title') }
      const text = (el.dataset.wtt ?? '').trim()
      if (!text) return
      const r = el.getBoundingClientRect()
      const place: Tip['place'] = r.top < 56 ? 'bottom' : 'top'
      setTip({
        text,
        cx: r.left + r.width / 2,
        y: place === 'top' ? r.top - GAP : r.bottom + GAP,
        place,
      })
    }

    const onOver = (e: PointerEvent) => {
      if (e.pointerType && e.pointerType !== 'mouse') return // fără tooltip pe touch/pen
      // elementul activ a fost scos din DOM cât era afișat (badge live / toast / rând
      // care se demontează prin state, nu prin click) — pe WebKit `pointerout` poate
      // să nu apară, lăsând tooltip-ul înghețat; curăță la prima mișcare de mouse
      if (active.current && !active.current.isConnected) hide()
      const target = e.target as Node | null
      const el = (target as Element | null)?.closest<HTMLElement>('[title]')
      if (!el) {
        // mișcare pe spațiu fără tooltip → ascunde doar dacă am PĂRĂSIT efectiv
        // elementul activ (nu și când intru pe un copil fără title al lui, ex. iconița
        // din interiorul unui buton, al cărui title tocmai l-am scos)
        if (active.current && !active.current.contains(target)) hide()
        return
      }
      if (el === active.current) return
      restore()          // veneam de pe alt element cu tooltip
      clearTimer()
      setTip(null); setPos(null)
      const title = el.getAttribute('title')
      if (title === null || title.trim() === '') return
      el.dataset.wtt = title
      el.removeAttribute('title')  // suprimă căsuța nativă + dublarea
      active.current = el
      timer.current = window.setTimeout(() => show(el), DELAY)
    }

    const onOut = (e: PointerEvent) => {
      const el = active.current
      if (!el) return
      const to = e.relatedTarget as Node | null
      if (to && el.contains(to)) return // mișcare între copiii aceluiași element
      hide()
    }

    // orice mișcare de layout ar rupe poziția fixă → ascunde
    const onScroll = () => hide()
    const onDown = () => hide()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') hide() }

    document.addEventListener('pointerover', onOver, true)
    document.addEventListener('pointerout', onOut, true)
    document.addEventListener('scroll', onScroll, true)
    document.addEventListener('pointerdown', onDown, true)
    document.addEventListener('keydown', onKey, true)
    window.addEventListener('blur', hide)
    window.addEventListener('resize', hide)

    return () => {
      clearTimer(); restore()
      document.removeEventListener('pointerover', onOver, true)
      document.removeEventListener('pointerout', onOut, true)
      document.removeEventListener('scroll', onScroll, true)
      document.removeEventListener('pointerdown', onDown, true)
      document.removeEventListener('keydown', onKey, true)
      window.removeEventListener('blur', hide)
      window.removeEventListener('resize', hide)
    }
  }, [])

  // după randare măsoară tooltip-ul și îl încadrează în fereastră (fără flash:
  // rulează înainte de paint)
  useLayoutEffect(() => {
    if (!tip || !ref.current) return
    const w = ref.current.offsetWidth
    const h = ref.current.offsetHeight
    const left = Math.min(Math.max(tip.cx - w / 2, EDGE), window.innerWidth - w - EDGE)
    let top = tip.place === 'top' ? tip.y - h : tip.y
    top = Math.min(Math.max(top, EDGE), window.innerHeight - h - EDGE)
    setPos({ left, top })
  }, [tip])

  if (!tip) return null
  return (
    <div
      ref={ref}
      role="tooltip"
      className="wt-tip pointer-events-none fixed z-[9999] max-w-xs whitespace-pre-line rounded-md border border-ink-600 bg-ink-950/95 px-2 py-1 text-xs leading-snug text-slate-100 shadow-lg shadow-black/40 backdrop-blur-sm"
      style={{
        left: pos ? pos.left : tip.cx,
        top: pos ? pos.top : tip.y,
        visibility: pos ? 'visible' : 'hidden', // ascuns până e măsurat/încadrat
      }}
    >
      {tip.text}
    </div>
  )
}
