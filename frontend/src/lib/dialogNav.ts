/* Navigarea din tastatură între butoanele unui dialog de confirmare (Anulează / Rulează).

   Până acum dialogurile se bazau pe ordinea NATIVĂ de Tab a browserului şi nu tratau deloc
   săgeţile. Două goluri, raportate împreună (2026-11):
     · săgeţile ← / → nu mutau focusul — pe un dialog cu două butoane pe un rând e gestul la
       care se aşteaptă oricine vine dintr-un dialog de sistem;
     · Tab-ul nativ nu e garantat: Safari (şi Firefox pe macOS fără „Keyboard navigation")
       sare implicit peste butoane, deci Tab pleca din dialog în loc să ajungă pe celălalt buton.
   Aici e doar decizia (testabilă fără DOM); cine o foloseşte mută focusul şi face preventDefault. */

export type NavDir = 'next' | 'prev'
/** direcţia + dacă se trece de capăt la celălalt (Tab da, săgeţile nu) */
export type Nav = { dir: NavDir; wrap: boolean }

type KeyLike = { key: string; shiftKey?: boolean; altKey?: boolean; ctrlKey?: boolean; metaKey?: boolean }

/** Tasta mută focusul între butoane? Tab / Shift+Tab (circular) şi → / ← (până la capăt, fără
    întoarcere). Cu Ctrl / Alt / Meta nu e a noastră (Alt+← e „înapoi" în browser, Ctrl+Tab schimbă
    tabul).

    ↑ / ↓ NU navighează, deliberat: dialogul apare peste un terminal, iar „↑ apoi Enter" e cel mai
    comun reflex de shell. Dacă ↑ ar muta focusul de pe Anulează (unde porneşte) pe Rulează, un
    reflex tastat în avans ar confirma exact dialogul care întreabă dacă rulezi. Butoanele stau pe
    un rând, deci ← / → ajung; şi tot de aceea săgeţile nu trec de capăt la celălalt buton: din
    Anulează, doar → (spre butonul pe care îl vezi în dreapta) te duce pe Rulează. */
export function dialogNavKey(e: KeyLike): Nav | null {
  if (e.altKey || e.ctrlKey || e.metaKey) return null
  if (e.key === 'Tab') return { dir: e.shiftKey ? 'prev' : 'next', wrap: true }
  if (e.shiftKey) return null
  if (e.key === 'ArrowRight') return { dir: 'next', wrap: false }
  if (e.key === 'ArrowLeft') return { dir: 'prev', wrap: false }
  return null
}

/** Indexul butonului care primeşte focusul. `current` = -1 când focusul e în dialog dar pe niciun
    buton (un click pe textul lui): Tab merge pe primul, Shift+Tab pe ultimul (ca Tab-ul nativ);
    o săgeată merge mereu pe PRIMUL — butonul sigur, niciodată direct pe cel de confirmare. */
export function dialogNavTarget(count: number, current: number, nav: Nav): number {
  if (count <= 0) return -1
  if (current < 0 || current >= count) return nav.wrap && nav.dir === 'prev' ? count - 1 : 0
  const next = current + (nav.dir === 'next' ? 1 : -1)
  if (nav.wrap) return (next + count) % count
  return Math.min(count - 1, Math.max(0, next))
}

/** Aplică navigarea pe butoanele active ale unui dialog. true = tasta a fost a dialogului
    (apelantul nu mai are nimic de făcut). Fără butoane, Tab e doar oprit — nu pleacă din dialog. */
export function navigateDialogButtons(e: KeyboardEvent, dialog: HTMLElement): boolean {
  const nav = dialogNavKey(e)
  if (!nav) return false
  const buttons = Array.from(dialog.querySelectorAll<HTMLElement>('button:not([disabled])'))
  if (buttons.length === 0) {
    if (e.key !== 'Tab') return false
    e.preventDefault()
    return true
  }
  e.preventDefault()
  const i = dialogNavTarget(buttons.length, buttons.indexOf(document.activeElement as HTMLElement), nav)
  buttons[i]?.focus()
  return true
}
