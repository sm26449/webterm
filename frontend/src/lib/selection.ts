/* Modelul de SELECŢIE MULTIPLĂ din panoul de fişiere (3.5.5) — pur, fără React, testat în
   selection.test.ts. Panoul doar îl ţine în state şi îl redă.

   Cheia unui rând e NUMELE lui în listarea curentă (unic într-un director); selecţia se goleşte
   la navigare. `anchor` = ultimul rând atins fără Shift — capătul fix al unui interval (Shift+click,
   Shift+săgeţi), ca în orice manager de fişiere: Shift+click extinde DE LA ancoră, nu de la ultimul
   interval. Intervalele se calculează pe ordinea VIZIBILĂ (`order`: după filtru şi sortare), deci
   „Selectează tot" şi Shift+click nu prind niciodată rânduri ascunse de filtru. */

export interface Selection {
  readonly keys: ReadonlySet<string>
  readonly anchor: string | null
}

export const EMPTY_SELECTION: Selection = { keys: new Set(), anchor: null }

/** Ctrl/Cmd+click, Space, bifa: comută un rând şi îl face ancoră. */
export function toggleKey(s: Selection, key: string): Selection {
  const keys = new Set(s.keys)
  if (keys.has(key)) keys.delete(key); else keys.add(key)
  return { keys, anchor: key }
}

/** Shift+click / Shift+săgeţi: intervalul ancoră…key (inclusiv) din ordinea vizibilă.
    `additive` (Ctrl+Shift): intervalul se ADAUGĂ la selecţia existentă; altfel o înlocuieşte.
    Fără ancoră validă (prima atingere, sau ancora a ieşit din filtru) = doar rândul acesta.
    Ancora NU se mută — un al doilea Shift+click re-calculează de la aceeaşi ancoră. */
export function rangeTo(s: Selection, order: readonly string[], key: string, additive = false): Selection {
  const to = order.indexOf(key)
  if (to < 0) return s
  const from = s.anchor != null ? order.indexOf(s.anchor) : -1
  if (from < 0) return { keys: new Set(additive ? [...s.keys, key] : [key]), anchor: key }
  const [lo, hi] = from <= to ? [from, to] : [to, from]
  const keys = new Set(additive ? s.keys : [])
  for (let i = lo; i <= hi; i++) keys.add(order[i])
  return { keys, anchor: s.anchor }
}

/** „Selectează tot" = tot ce se VEDE (filtrul activ şi fişierele ascunse respectate). Dacă tot
    ce se vede e deja selectat, a doua apăsare deselectează exact acele rânduri (bifa tri-state). */
export function toggleAll(s: Selection, visible: readonly string[]): Selection {
  if (visible.length && visible.every((k) => s.keys.has(k))) {
    const keys = new Set(s.keys)
    for (const k of visible) keys.delete(k)
    return { keys, anchor: null }
  }
  return { keys: new Set([...s.keys, ...visible]), anchor: s.anchor }
}

/** Starea bifei „Selectează tot" faţă de rândurile vizibile. */
export function allState(s: Selection, visible: readonly string[]): 'none' | 'some' | 'all' {
  let n = 0
  for (const k of visible) if (s.keys.has(k)) n++
  if (n === 0) return 'none'
  return n === visible.length ? 'all' : 'some'
}

/** După o re-listare (ştergere, rename, alt proces): păstrăm doar cheile care încă există.
    Rândurile ascunse de filtru RĂMÂN selectate (filtrul doar le ascunde) — dar acţiunile în
    bloc lucrează pe `visibleSelected`, ca să nu ştergi ceva ce nu vezi. */
export function prune(s: Selection, existing: readonly string[]): Selection {
  const ex = new Set(existing)
  const keys = new Set([...s.keys].filter((k) => ex.has(k)))
  if (keys.size === s.keys.size && (s.anchor == null || ex.has(s.anchor))) return s
  return { keys, anchor: s.anchor != null && ex.has(s.anchor) ? s.anchor : null }
}

/** Ce primeşte o acţiune în bloc: rândurile selectate ŞI vizibile, în ordinea afişată. */
export function visibleSelected(s: Selection, visible: readonly string[]): string[] {
  return visible.filter((k) => s.keys.has(k))
}

/** Primele `n` nume pentru textul confirmării („a, b, c şi încă 4"). */
export function previewNames(names: readonly string[], n = 5): { shown: string[]; more: number } {
  return { shown: names.slice(0, n), more: Math.max(0, names.length - n) }
}

/** Tastele listei (săgeţi, Enter, Space, Delete, F2, tastează-ca-să-sari…) — 3.6.14, roving focus.
    Până în 3.6.13 se aplicau DOAR când evenimentul venea chiar de pe containerul listei (U09): un
    keydown de pe un descendent — butoanele Descarcă/Şterge ale rândului, bifa, numele — urca până la
    listă, iar Enter pe „Şterge" deschidea fişierul selectat şi Space pe o bifă o comuta de două ori.
    Doar că focusul ajungea des pe un descendent (click pe nume) sau pe <body> (rândul dispărea la
    navigare), iar tastele erau moarte. Acum lista are focusul (click pe rând → container), iar de pe
    un descendent se aplică tot, CU EXCEPŢIA:
      - câmpurilor de text (redenumire inline, dosar nou) şi a bifelor — tastele sunt ale lor;
      - Enter / Space pe un control real (buton, link, element de meniu) — îl activează pe EL, nu
        deschid rândul (regula U09 rămâne). */
export interface KeyTarget {
  /** evenimentul vine chiar de pe containerul listei */
  isContainer: boolean
  /** tagName (majuscule, ca în DOM) */
  tag: string
  /** contenteditable */
  editable?: boolean
  role?: string | null
}
const FIELD_TAGS = new Set(['INPUT', 'TEXTAREA', 'SELECT'])
const CONTROL_TAGS = new Set(['BUTTON', 'A', 'SUMMARY', 'LABEL'])
const CONTROL_ROLES = new Set(['button', 'link', 'menuitem', 'checkbox', 'switch', 'option', 'tab'])
export function isListKeyTarget(t: KeyTarget, key: string): boolean {
  if (t.isContainer) return true
  if (FIELD_TAGS.has(t.tag) || t.editable) return false
  if ((key === 'Enter' || key === ' ') && (CONTROL_TAGS.has(t.tag) || (t.role != null && CONTROL_ROLES.has(t.role)))) return false
  return true
}
/** Descrierea ţintei unui eveniment DOM pentru `isListKeyTarget`. */
export function keyTargetOf(target: EventTarget | null, container: EventTarget | null): KeyTarget {
  const el = target as HTMLElement | null
  return {
    isContainer: !!el && el === container,
    tag: el?.tagName ?? '',
    editable: !!el?.isContentEditable,
    role: el?.getAttribute?.('role') ?? null,
  }
}
