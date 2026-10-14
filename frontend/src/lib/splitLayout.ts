/** Split-views (3.6.12): geometria layout-urilor şi mutările de panouri, ca funcţii PURE.

    Sursa de adevăr pentru forma unui split-view e serverul (api.SPLIT_LAYOUTS — aceeaşi tabelă,
    o schimbare se face în ambele locuri); aici doar o randăm şi o modificăm optimist. Totul e
    testat în splitLayout.test.ts: e exact logica pe care e2e-ul nu o poate acoperi combinatoric
    (dimensiuni la limită, mutări care ar pune aceeaşi sesiune de două ori). */

export type SplitLayout = 'cols2' | 'cols3' | 'main-left' | 'main-top' | 'grid'

/** forma → câte panouri ţine + grupurile de dimensiuni (fiecare grup însumează 1).
    `main-left` = [col0, col1, rând0, rând1 (stiva din dreapta)]; `main-top` = [rând0, rând1,
    col0, col1 (rândul de jos)]; `grid` = [col0, col1, rând0, rând1]. */
export const LAYOUTS: Record<SplitLayout, { panes: number; groups: number[] }> = {
  cols2: { panes: 2, groups: [2] },
  cols3: { panes: 3, groups: [3] },
  'main-left': { panes: 3, groups: [2, 2] },
  'main-top': { panes: 3, groups: [2, 2] },
  grid: { panes: 4, groups: [2, 2] },
}
export const DEFAULT_LAYOUT: Record<number, SplitLayout> = { 2: 'cols2', 3: 'main-left', 4: 'grid' }
export const SIZE_MIN = 0.1
export const SIZE_MAX = 0.9
/** distanţa dintre panouri (px) = grosimea dividerului; folosită şi în calculul poziţiilor */
export const GAP = 6

export const isLayout = (v: unknown): v is SplitLayout =>
  typeof v === 'string' && Object.prototype.hasOwnProperty.call(LAYOUTS, v)

/** formele posibile pentru n panouri, în ordinea din picker */
export function layoutsFor(n: number): SplitLayout[] {
  return (Object.keys(LAYOUTS) as SplitLayout[]).filter((l) => LAYOUTS[l].panes === n)
}

/** forma efectivă: cea cerută dacă se potriveşte cu numărul de panouri, altfel implicitul */
export function effectiveLayout(layout: unknown, n: number): SplitLayout {
  if (isLayout(layout) && LAYOUTS[layout].panes === n) return layout
  return DEFAULT_LAYOUT[n] ?? 'cols2'
}

const round4 = (x: number) => Math.round(x * 10000) / 10000

export function equalSizes(layout: SplitLayout): number[] {
  return LAYOUTS[layout].groups.flatMap((n) => Array<number>(n).fill(round4(1 / n)))
}

/** Clamp în [MIN, MAX] + renormalizare la suma 1 (iterativ, ca pe server). */
export function fitGroup(vals: number[]): number[] {
  let v = [...vals]
  for (let i = 0; i < 12; i++) {
    v = v.map((x) => Math.min(SIZE_MAX, Math.max(SIZE_MIN, x)))
    const tot = v.reduce((a, b) => a + b, 0)
    v = v.map((x) => x / tot)
    if (v.every((x) => x >= SIZE_MIN - 1e-9 && x <= SIZE_MAX + 1e-9)) break
  }
  return v.map(round4)
}

/** Dimensiunile unui layout din orice intrare: valide → clamp/renormalizate pe grup; altfel egale. */
export function normalizeSizes(layout: SplitLayout, sizes: unknown): number[] {
  const groups = LAYOUTS[layout].groups
  const want = groups.reduce((a, b) => a + b, 0)
  if (!Array.isArray(sizes) || sizes.length !== want
    || !sizes.every((x) => typeof x === 'number' && Number.isFinite(x) && x > 0 && x < 1)) {
    return equalSizes(layout)
  }
  const out: number[] = []
  let i = 0
  for (const n of groups) {
    const g = (sizes as number[]).slice(i, i + n)
    i += n
    if (Math.abs(g.reduce((a, b) => a + b, 0) - 1) > 0.02) return equalSizes(layout)
    out.push(...fitGroup(g))
  }
  return out
}

/** indexul primei dimensiuni din grupul care conţine `i` + mărimea grupului */
function groupOf(layout: SplitLayout, i: number): { start: number; n: number } {
  let start = 0
  for (const n of LAYOUTS[layout].groups) {
    if (i < start + n) return { start, n }
    start += n
  }
  return { start: 0, n: 0 }
}

/** CSS grid pentru o formă: şabloanele citesc variabilele `--wt-s{i}` (vezi sizeVars), ca un
    drag de divider să schimbe DOAR variabilele (fără re-randare React). `areas[i]` = zona panoului i. */
export function gridSpec(layout: SplitLayout): { columns: string; rows: string; template: string; areas: string[] } {
  const v = (i: number) => `minmax(0, var(--wt-s${i}))`
  switch (layout) {
    case 'cols2': return { columns: `${v(0)} ${v(1)}`, rows: 'minmax(0, 1fr)', template: '"p0 p1"', areas: ['p0', 'p1'] }
    case 'cols3': return { columns: `${v(0)} ${v(1)} ${v(2)}`, rows: 'minmax(0, 1fr)', template: '"p0 p1 p2"', areas: ['p0', 'p1', 'p2'] }
    case 'main-left': return { columns: `${v(0)} ${v(1)}`, rows: `${v(2)} ${v(3)}`, template: '"p0 p1" "p0 p2"', areas: ['p0', 'p1', 'p2'] }
    case 'main-top': return { columns: `${v(2)} ${v(3)}`, rows: `${v(0)} ${v(1)}`, template: '"p0 p0" "p1 p2"', areas: ['p0', 'p1', 'p2'] }
    case 'grid': return { columns: `${v(0)} ${v(1)}`, rows: `${v(2)} ${v(3)}`, template: '"p0 p1" "p2 p3"', areas: ['p0', 'p1', 'p2', 'p3'] }
  }
}

/** variabilele CSS ale dimensiunilor: `--wt-s{i}` = fracţia (în fr), `--wt-k{i}` = suma
    cumulată în grup până la i inclusiv (poziţia dividerului de după i). */
export function sizeVars(layout: SplitLayout, sizes: number[]): Record<string, string> {
  const out: Record<string, string> = {}
  let start = 0
  for (const n of LAYOUTS[layout].groups) {
    let cum = 0
    for (let j = 0; j < n; j++) {
      const x = sizes[start + j] ?? 1 / n
      cum += x
      out[`--wt-s${start + j}`] = `${round4(x)}fr`
      out[`--wt-k${start + j}`] = String(round4(cum))
    }
    start += n
  }
  return out
}

/** Un divider: mută graniţa dintre dimensiunile `a` şi `b` (vecine, în acelaşi grup). */
export interface DividerSpec {
  a: number
  b: number
  /** `vertical` = linie verticală, se trage stânga/dreapta (coloane) */
  orientation: 'vertical' | 'horizontal'
  /** câte piste are axa (coloane sau rânduri) şi indexul graniţei pe axă (0 = după prima pistă) */
  tracks: number
  k: number
  /** unde începe dividerul pe axa transversală (ex. stiva din dreapta la main-left): indexul
      variabilei cumulate care dă offsetul, sau null = pe toată lungimea */
  crossFrom: number | null
}

export function dividers(layout: SplitLayout): DividerSpec[] {
  switch (layout) {
    case 'cols2': return [{ a: 0, b: 1, orientation: 'vertical', tracks: 2, k: 0, crossFrom: null }]
    case 'cols3': return [
      { a: 0, b: 1, orientation: 'vertical', tracks: 3, k: 0, crossFrom: null },
      { a: 1, b: 2, orientation: 'vertical', tracks: 3, k: 1, crossFrom: null },
    ]
    case 'main-left': return [
      { a: 0, b: 1, orientation: 'vertical', tracks: 2, k: 0, crossFrom: null },
      { a: 2, b: 3, orientation: 'horizontal', tracks: 2, k: 0, crossFrom: 0 },
    ]
    case 'main-top': return [
      { a: 0, b: 1, orientation: 'horizontal', tracks: 2, k: 0, crossFrom: null },
      { a: 2, b: 3, orientation: 'vertical', tracks: 2, k: 0, crossFrom: 0 },
    ]
    case 'grid': return [
      { a: 0, b: 1, orientation: 'vertical', tracks: 2, k: 0, crossFrom: null },
      { a: 2, b: 3, orientation: 'horizontal', tracks: 2, k: 0, crossFrom: null },
    ]
  }
}

/** Poziţia absolută a dividerului în containerul grilei (CSS calc pe variabile). */
export function dividerStyle(d: DividerSpec): Record<string, string> {
  const along = `calc((100% - ${(d.tracks - 1) * GAP}px) * var(--wt-k${d.a}) + ${d.k * GAP}px)`
  const cross = d.crossFrom == null ? '0px' : `calc((100% - ${GAP}px) * var(--wt-k${d.crossFrom}) + ${GAP}px)`
  return d.orientation === 'vertical'
    ? { left: along, width: `${GAP}px`, top: cross, bottom: '0px' }
    : { top: along, height: `${GAP}px`, left: cross, right: '0px' }
}

/** Mută graniţa dividerului la `cum` (suma cumulată a grupului până la `a` inclusiv, 0..1).
    Doar `a` şi `b` se schimbă (suma lor rămâne aceeaşi), fiecare ≥ MIN. */
export function setBoundary(layout: SplitLayout, sizes: number[], d: DividerSpec, cum: number): number[] {
  const { start } = groupOf(layout, d.a)
  let before = 0
  for (let i = start; i < d.a; i++) before += sizes[i]
  const pair = sizes[d.a] + sizes[d.b]
  const lo = SIZE_MIN
  const hi = Math.min(SIZE_MAX, pair - SIZE_MIN)
  if (!Number.isFinite(cum) || hi < lo) return sizes
  const a = Math.min(hi, Math.max(lo, cum - before))
  const out = [...sizes]
  out[d.a] = round4(a)
  out[d.b] = round4(pair - a)
  return out
}

/** Poziţia pointerului → suma cumulată pentru setBoundary (scade golurile dintre piste). */
export function pointerToCum(d: DividerSpec, start: number, length: number, pos: number): number {
  const usable = length - (d.tracks - 1) * GAP
  if (usable <= 0) return 0.5
  return (pos - start - d.k * GAP - GAP / 2) / usable
}

/** Tastatura pe divider: ±pas, Home = minimul lui `a`, End = maximul lui `a`. */
export function nudge(layout: SplitLayout, sizes: number[], d: DividerSpec, key: 'dec' | 'inc' | 'min' | 'max', step = 0.02): number[] {
  const { start } = groupOf(layout, d.a)
  let before = 0
  for (let i = start; i < d.a; i++) before += sizes[i]
  const cur = before + sizes[d.a]
  const pair = sizes[d.a] + sizes[d.b]
  const target = key === 'dec' ? cur - step : key === 'inc' ? cur + step
    : key === 'min' ? before + SIZE_MIN : before + pair - SIZE_MIN
  return setBoundary(layout, sizes, d, target)
}

/** Etichetele poziţiilor (cheie i18n `split.pos.<x>`) pentru „Move to…" şi anunţuri. */
export function positionKeys(layout: SplitLayout): string[] {
  switch (layout) {
    case 'cols2': return ['left', 'right']
    case 'cols3': return ['left', 'middle', 'right']
    case 'main-left': return ['main', 'topRight', 'bottomRight']
    case 'main-top': return ['main', 'bottomLeft', 'bottomRight']
    case 'grid': return ['topLeft', 'topRight', 'bottomLeft', 'bottomRight']
  }
}

// ── mutări de panouri ─────────────────────────────────────────────────────────

export const isDistinct = (panes: string[]) => new Set(panes).size === panes.length

export type PaneMove =
  | { kind: 'swap'; from: string; to: string }
  /** pune sesiunea `with` în locul panoului `target` (drag dintr-un tab). Dacă `with` e deja
      un panou al split-ului, cele două panouri se SCHIMBĂ între ele — niciodată aceeaşi sesiune
      montată de două ori (două WS pe acelaşi PTY = război de detach tmux). */
  | { kind: 'replace'; target: string; with: string }

/** Noua listă de panouri după o mutare, sau null dacă mutarea nu are sens / ar duplica o sesiune. */
export function applyPaneMove(panes: string[], m: PaneMove): string[] | null {
  if (!isDistinct(panes)) return null
  let out: string[]
  if (m.kind === 'swap') {
    const i = panes.indexOf(m.from)
    const j = panes.indexOf(m.to)
    if (i < 0 || j < 0 || i === j) return null
    out = swapAt(panes, i, j)
  } else {
    const i = panes.indexOf(m.target)
    if (i < 0 || !m.with || m.with === m.target) return null
    const j = panes.indexOf(m.with)
    out = j >= 0 ? swapAt(panes, i, j) : panes.map((s, k) => (k === i ? m.with : s))
  }
  return isDistinct(out) ? out : null
}

export function swapAt(panes: string[], i: number, j: number): string[] {
  const out = [...panes]
  ;[out[i], out[j]] = [out[j], out[i]]
  return out
}

/** Panoul `sid` schimbă locul cu vecinul din direcţia `dir` (circular) — scurtătura „Move pane". */
export function movePaneBy(panes: string[], sid: string, dir: 1 | -1): string[] | null {
  const i = panes.indexOf(sid)
  if (i < 0 || panes.length < 2) return null
  return applyPaneMove(panes, { kind: 'swap', from: sid, to: panes[(i + dir + panes.length) % panes.length] })
}

/** Panoul care primeşte selecţia + focusul la intrarea într-un split: ultimul focalizat (dacă e
    încă acolo), altfel primul. */
export function entryPane(panes: string[], remembered: string | null | undefined): string | null {
  if (remembered && panes.includes(remembered)) return remembered
  return panes[0] ?? null
}

/** Primul nume „Split N" nefolosit (N ≥ 1) — nu `length + 1`, care repeta un nume după o ştergere. */
export function nextDefaultName(existing: string[], fmt: (n: number) => string): string {
  const used = new Set(existing.map((s) => s.trim()))
  for (let n = 1; n < 1000; n++) if (!used.has(fmt(n))) return fmt(n)
  return fmt(existing.length + 1)
}

/** Un split cu EXACT aceleaşi sesiuni (în orice ordine) — Alt+D îl refoloseşte în loc să dubleze. */
export function findSameSet<T extends { panes: string[]; hidden?: number }>(views: T[], panes: string[]): T | undefined {
  const want = [...panes].sort().join(',')
  return views.find((v) => !v.hidden && [...v.panes].sort().join(',') === want)
}

/** Ordinea nouă a chip-urilor după o mutare: noua listă + perechile (id, poziţie) de trimis —
    doar cele a căror poziţie STOCATĂ diferă de indexul nou (rândurile vechi au toate 0). */
export function reorderPositions<T extends { id: number; position: number }>(views: T[], from: number, to: number): { order: T[]; changed: { id: number; position: number }[] } {
  if (from < 0 || to < 0 || from >= views.length || to >= views.length || from === to) return { order: views, changed: [] }
  const order = [...views]
  order.splice(to, 0, order.splice(from, 1)[0])
  const changed = order.map((v, position) => ({ id: v.id, position, old: v.position }))
    .filter((x) => x.old !== x.position).map(({ id, position }) => ({ id, position }))
  return { order: order.map((v, position) => ({ ...v, position })), changed }
}
