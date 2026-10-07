import { KeyboardEvent, RefObject, useEffect, useRef } from 'react'
import { claimSheetHistory, lockBodyScroll, useSheetMode } from './sheet'

/* Comportament de tastatură/focus pentru PANOURILE laterale (Files/Docker/Services/Forwards/
   Toolbox/Git/Commands) când sunt deschise ca drawer sau coloană, NU ca tab embed.
   De ce nu `useFocusTrap` (auditul 2026-10-04, a11y): panoul nu e modal pe desktop — e o coloană
   lângă terminalul viu, în care userul vrea să poată da Tab înapoi. Deci:
     - la deschidere focusul INTRĂ în panou (pe container, tabindex=-1: cititorul anunţă
       eticheta `aside`-ului, iar primul Tab cade pe primul control) — altfel butonul care
       l-a deschis rămâne focusat şi tastatura „nu găseşte" panoul;
     - Escape îl închide DOAR când focusul e înăuntru (handler React pe `aside`, nu pe
       document): nu fură Escape-ul terminalului, iar dialogurile deschise din panou
       (ConfirmModal/formulare cu focus-trap) îşi păstrează propriul Escape;
     - la închidere focusul se întoarce pe elementul care l-a deschis, dacă mai e în pagină.
   Un câmp inline care consumă el Escape-ul (redenumire, formular de adăugare) apelează
   `e.stopPropagation()` — exact ca la un dialog imbricat.

   Pe TELEFON (vezi lib/sheet.ts) acelaşi panou devine foaie pe tot ecranul: `sheet` = true, iar
   panoul îşi pune `SHEET_CLS` + bara „← Terminal" (SheetBar). Aici, o singură dată pentru toate:
   scroll-ul paginii din spate e blocat, iar Back-ul de Android / swipe-back închide foaia (o
   intrare de istoric cu acelaşi URL) în loc să părăsească aplicaţia. Focusul şi Escape — ca mai sus. */
export function useDrawer(ref: RefObject<HTMLElement>, onClose: () => void, active = true) {
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  const sheet = useSheetMode(active)
  // capturat în RENDER (ca în useFocusTrap): după commit, `activeElement` poate fi deja
  // un câmp cu autoFocus din panou, iar „înapoi" ar însemna „nicăieri"
  const prevRef = useRef<HTMLElement | null>(null)
  if (prevRef.current === null) prevRef.current = document.activeElement as HTMLElement | null

  useEffect(() => {
    const el = ref.current
    if (!active || !el) return
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '-1')
    el.focus({ preventScroll: true })
    return () => {
      const prev = prevRef.current
      if (prev && document.contains(prev) && typeof prev.focus === 'function') prev.focus()
    }
  }, [ref, active])

  useEffect(() => {
    if (!sheet) return
    const release = claimSheetHistory(() => onCloseRef.current())
    const unlock = lockBodyScroll()
    return () => { release(); unlock() }
  }, [sheet])

  const onKeyDown = (e: KeyboardEvent) => {
    if (!active || e.key !== 'Escape' || e.defaultPrevented) return
    const target = e.target as Element | null
    if (target?.closest('[role="dialog"],[role="alertdialog"]')) return
    e.preventDefault()
    e.stopPropagation()
    onCloseRef.current()
  }
  return { onKeyDown, sheet }
}
