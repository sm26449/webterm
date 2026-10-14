/** Drag & drop în split (review independent 3.6.12, L3): titlul unui panou (swap) şi un tab din
    bară (înlocuire) poartă tipuri proprii (`application/x-wt-pane` / `x-wt-session`). Dar orice
    pagină — sau alt tab WebTerm — poate pune aceleaşi tipuri pe un drag tras peste fereastra
    noastră, cu un sid ales de ea. Acceptăm o lăsare DOAR dacă drag-ul a pornit în ACEASTĂ pagină:
    sursa înregistrează aici ce trage, iar ţinta cere ca payload-ul să fie exact acela. */

export type DragKind = 'pane' | 'tab'

let current: { kind: DragKind; sid: string } | null = null
let timer: ReturnType<typeof setTimeout> | null = null

/** plasă de siguranţă: un drag „uitat" (sursa demontată în timpul drag-ului, deci fără onDragEnd)
    nu rămâne valabil la nesfârşit — după atât, o lăsare e refuzată (fail-closed) */
export const DRAG_MAX_MS = 60_000

// sfârşitul drag-ului văzut la nivel de fereastră (bubbling, deci DUPĂ handler-ele React ale
// ţintei, care apelează acceptDrop): dragend-ul sursei urcă până aici chiar dacă sursa a fost
// mutată în DOM, iar un drop oriunde închide drag-ul (re-review 3.6.12, INFO)
const onWindowEnd = () => endDrag()
function listen(on: boolean): void {
  if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return
  for (const type of ['dragend', 'drop']) {
    if (on) window.addEventListener(type, onWindowEnd)
    else window.removeEventListener(type, onWindowEnd)
  }
}

/** apelat din onDragStart-ul sursei (titlul panoului / tabul) */
export function beginDrag(kind: DragKind, sid: string): void {
  endDrag()
  current = { kind, sid }
  timer = setTimeout(endDrag, DRAG_MAX_MS)
  listen(true)
}

/** apelat din onDragEnd-ul sursei (şi după o lăsare) */
export function endDrag(): void {
  current = null
  if (timer) { clearTimeout(timer); timer = null }
  listen(false)
}

/** Ce drag din pagina asta e în curs (pentru dragover: tipurile se văd, payload-ul nu). */
export function ownDragKind(): DragKind | null {
  return current?.kind ?? null
}

/** sid-ul de folosit pentru o lăsare de tipul `kind` cu payload-ul `payload`, sau null când drag-ul
    nu e al nostru (pornit în altă pagină / alt tab) ori payload-ul nu e cel tras de noi. */
export function acceptDrop(kind: DragKind, payload: string): string | null {
  if (!current || current.kind !== kind || !payload || payload !== current.sid) return null
  return payload
}
