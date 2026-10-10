/* Unde a ajuns focusul faţă de modalul din vârf (3.6.1, U13) — logica pură din useFocusTrap.

   Un modal care îşi schimbă conţinutul (consola de flotă: faza „alegi" → „confirmi" → „grila")
   demontează butonul focalizat; focusul cade pe <body>, iar Tab-ul următor pleacă în pagina din
   spate (capcana asculta Tab doar pe dialog). Recuperăm focusul care a IEŞIT din modalul din vârf,
   dar NU pe cel care a intrat legitim într-un popup portalat în <body>: widget-urile Monaco
   (sugestii, hover, meniul contextual), HelpTip (role=dialog), un ConfirmModal deschis peste
   (alertdialog), tooltip-uri, meniuri, listbox-uri. Un popup nou se poate marca explicit cu
   `data-focus-trap-allow`. */

export const ALLOWED_OUTSIDE = [
  '[data-focus-trap-allow]',
  '[role="dialog"]', '[role="alertdialog"]', '[role="tooltip"]', '[role="menu"]', '[role="listbox"]',
  '.monaco-editor', '.monaco-aria-container', '.context-view', '[class*="monaco-"]',
].join(',')

/** Interfaţa minimă de DOM de care avem nevoie (testabil fără jsdom). */
export type NodeLike = { closest?(sel: string): unknown }
export type ContainerLike = { contains(n: unknown): boolean }

export type FocusPlace =
  | 'inside'    // în modal — totul e în regulă
  | 'allowed'   // într-un popup portalat legitim — lăsăm focusul acolo
  | 'lost'      // pe <body> / nicăieri (elementul focalizat a fost scos din DOM)
  | 'escaped'   // pe un element din pagina din spatele modalului — îl aducem înapoi

export function focusPlace(target: NodeLike | null | undefined, trap: ContainerLike, body: unknown): FocusPlace {
  if (!target || target === body) return 'lost'
  if (trap.contains(target)) return 'inside'
  if (typeof target.closest === 'function' && target.closest(ALLOWED_OUTSIDE)) return 'allowed'
  return 'escaped'
}
