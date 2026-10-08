import { RefObject, useEffect, useRef } from 'react'

/** Accessible modal behaviour for a dialog container: trap Tab focus inside it,
   close on Escape, move focus in on open and restore it to the trigger on close.
   Pair with role="dialog" aria-modal="true" and an aria-label on the container. */
/* Capcanele active, în ordinea deschiderii. Escape e ascultat pe DOCUMENT (vezi mai jos), deci cu
   două dialoguri suprapuse (ex. „Partajează replay" peste player) ambele îl primeau şi se închideau
   împreună — `stopPropagation` nu opreşte alţi ascultători de pe acelaşi nod. Doar cel din vârf
   reacţionează. */
const openTraps: HTMLElement[] = []

export function useFocusTrap(ref: RefObject<HTMLElement>, onClose: () => void): void {
  // onClose e aproape mereu o arrow inline (identitate nouă la fiecare render al
  // părintelui — inclusiv la poll-ul de 5s al aplicației). Dacă ar fi în deps,
  // efectul s-ar re-executa la fiecare poll și ar fura focusul din câmpul în
  // care tastezi. Îl ținem într-un ref, iar efectul depinde doar de ref.
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  // Capturat în RENDER, nu în efect. React aplică `autoFocus` în faza de commit, adică ÎNAINTE
  // de efecte — deci un `document.activeElement` citit din efect e deja câmpul din dialog. La
  // închidere „restauram" focusul pe un nod scos din DOM, iar focusul cădea pe <body>: cine
  // navighează din tastatură îşi pierdea locul la fiecare modal cu autoFocus (adică majoritatea).
  const prevRef = useRef<HTMLElement | null>(null)
  if (prevRef.current === null) prevRef.current = document.activeElement as HTMLElement | null
  useEffect(() => {
    const el = ref.current
    if (!el) return

    const focusables = () =>
      Array.from(el.querySelectorAll<HTMLElement>(
        'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])',
      )).filter((x) => x.offsetParent !== null || x === document.activeElement)

    // move focus into the dialog (first field, else the container itself)
    const first = focusables()[0]
    if (first) first.focus()
    else { el.setAttribute('tabindex', '-1'); el.focus() }

    // Escape la nivel de DOCUMENT: modalul se închide chiar dacă focusul a ieșit
    // din dialog (ex. butonul focusat s-a demontat după o acțiune async — cazul
    // grilei de rulare pe flotă). Tab-trapping rămâne pe dialog.
    const onEsc = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      if (openTraps[openTraps.length - 1] !== el) return    // un dialog deschis peste noi îl ia
      e.preventDefault()
      e.stopPropagation()
      onCloseRef.current()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      // Un widget din dialog care şi-a consumat deja Tab-ul (Monaco îl foloseşte la indentare şi
      // face preventDefault) nu trebuie „completat" cu un salt al focusului pe primul buton.
      // Acelaşi lucru la cerere explicită: un subarbore marcat `data-focus-trap-passthrough`
      // îşi gestionează singur Tab-ul. Restul dialogurilor păstrează wrap-around-ul clasic.
      if (e.defaultPrevented) return
      const active = document.activeElement
      if (active instanceof Element && active.closest('[data-focus-trap-passthrough]')) return
      const f = focusables()
      if (f.length === 0) { e.preventDefault(); return }
      const firstEl = f[0]
      const lastEl = f[f.length - 1]
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault()
        lastEl.focus()
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault()
        firstEl.focus()
      }
    }

    el.addEventListener('keydown', onKey)
    document.addEventListener('keydown', onEsc)
    openTraps.push(el)
    return () => {
      el.removeEventListener('keydown', onKey)
      document.removeEventListener('keydown', onEsc)
      const i = openTraps.lastIndexOf(el)
      if (i >= 0) openTraps.splice(i, 1)
      // restore focus to whatever opened the dialog — dacă mai e în pagină: butonul care a
      // deschis modalul poate să fi dispărut între timp (listă re-randată după acţiune)
      const prev = prevRef.current
      if (prev && document.contains(prev) && typeof prev.focus === 'function') prev.focus()
    }
  }, [ref])
}
