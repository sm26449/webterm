/* Selecţia cu DEGETUL în terminal (3.6.32) — geometria şi textul, pure, testate în touchsel.test.ts.

   xterm.js n-are selecţie pe touch şi desenează pe canvas, deci mânerele sistemului (bulinele de
   pe iPhone) nu apar niciodată peste el. Le desenăm noi (components/TouchSelection.tsx) peste
   selecţia PROPRIE a xterm, condusă prin API-ul public `term.select(col, row, length)`.

   Coordonate: `col` = celulă (0-based), `row` = rând ABSOLUT în buffer (scrollback inclus), ca
   selecţia să rămână pe textul ei când viewport-ul derulează. Capetele sunt INCLUSIVE. */
import { logicalLines, type SelRow, type TermLike } from './seltext'

export interface Cell { col: number; row: number }
export interface CellRange { a: Cell; b: Cell }   // a ≤ b în ordinea de citire

export interface Grid {
  /** dreptunghiul ecranului xterm (`.xterm-screen`), în coordonate de viewport */
  left: number; top: number; width: number; height: number
  cols: number; rows: number
  /** primul rând de buffer vizibil */
  viewportY: number
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

/** Celula de sub un punct al ecranului (prins în marginile grilei). */
export function cellAt(g: Grid, x: number, y: number): Cell {
  const cw = g.width / g.cols
  const ch = g.height / g.rows
  return {
    col: clamp(Math.floor((x - g.left) / cw), 0, g.cols - 1),
    row: g.viewportY + clamp(Math.floor((y - g.top) / ch), 0, g.rows - 1),
  }
}

/** Celula pentru un MÂNER tras: mânerul stă pe o MUCHIE dintre celule, deci rotunjim la cea mai
    apropiată muchie. Capătul de început ia celula din dreapta muchiei, cel de sfârşit pe cea din
    stânga — altfel selecţia ar sări cu o literă în momentul în care atingi mânerul. */
export function cellAtEdge(g: Grid, x: number, y: number, end: boolean): Cell {
  const cw = g.width / g.cols
  const ch = g.height / g.rows
  const edge = Math.round((x - g.left) / cw)
  return {
    col: clamp(end ? edge - 1 : edge, 0, g.cols - 1),
    row: g.viewportY + clamp(Math.floor((y - g.top) / ch), 0, g.rows - 1),
  }
}

export function before(p: Cell, q: Cell): boolean {
  return p.row < q.row || (p.row === q.row && p.col < q.col)
}

export function ordered(p: Cell, q: Cell): CellRange {
  return before(q, p) ? { a: q, b: p } : { a: p, b: q }
}

/** Lungimea în celule pentru `term.select(a.col, a.row, length)`. */
export function rangeLength(r: CellRange, cols: number): number {
  return (r.b.row - r.a.row) * cols + (r.b.col - r.a.col) + 1
}

/** „Cuvântul" de sub deget = şirul de celule ne-goale dintre spaţii: într-un terminal vrei toată
    calea / tot URL-ul / tot flag-ul (`/etc/nginx/nginx.conf`, `--no-verify`), nu bucata dintre două
    semne de punctuaţie. `filled[i]` = celula i are conţinut (a doua jumătate a unui caracter lat
    contează ca plină). null = sub deget e gol → nu e nimic de selectat. */
export function wordAt(filled: readonly boolean[], col: number): [number, number] | null {
  if (!filled[col]) return null
  let c0 = col
  let c1 = col
  while (c0 > 0 && filled[c0 - 1]) c0--
  while (c1 < filled.length - 1 && filled[c1 + 1]) c1++
  return [c0, c1]
}

interface CellLike { getChars(): string; getWidth(): number }
interface LineLike {
  isWrapped: boolean
  translateToString(trimRight?: boolean, startColumn?: number, endColumn?: number): string
  getCell(x: number): CellLike | undefined
}
type SelTerm = Omit<TermLike, 'buffer'> & { buffer: { active: { length: number; getLine(y: number): LineLike | undefined } } }

/** Care celule ale unui rând au conţinut (spaţiul e gol). */
export function filledCells(term: SelTerm, row: number): boolean[] {
  const line = term.buffer.active.getLine(row)
  const out: boolean[] = []
  if (!line) return out
  for (let x = 0; x < term.cols; x++) {
    const c = line.getCell(x)
    if (!c) { out.push(false); continue }
    const ch = c.getChars()
    // lăţime 0 = a doua jumătate a caracterului lat din stânga
    out.push(c.getWidth() === 0 ? (out[x - 1] ?? false) : ch !== '' && ch.trim() !== '')
  }
  return out
}

/** Textul unei selecţii, cu aceleaşi reguli ca modul „Selectează text" (lib/seltext): un rând care
    ajunge în ultima celulă continuă în următorul — o comandă ruptă pe trei rânduri de ecran pleacă
    în clipboard ca O linie (`term.getSelection()` uneşte doar soft-wrap-ul xterm, nu şi rândurile
    repictate de tmux, şi ar strecura newline-uri în mijlocul comenzii). */
export function rangeText(term: SelTerm, r: CellRange): string {
  const rows: SelRow[] = []
  for (let y = r.a.row; y <= r.b.row; y++) {
    const line = term.buffer.active.getLine(y)
    if (!line) continue
    const from = y === r.a.row ? r.a.col : 0
    const to = y === r.b.row ? r.b.col + 1 : term.cols
    const last = line.getCell(term.cols - 1)
    const prev = term.cols >= 2 ? line.getCell(term.cols - 2) : undefined
    const full = !!last && (last.getChars() !== '' || (last.getWidth() === 0 && !!prev && prev.getWidth() === 2))
    rows.push({
      text: line.translateToString(false, from, to),
      wrapped: rows.length > 0 && line.isWrapped,
      // doar un rând selectat PÂNĂ la capăt se poate lipi de următorul
      full: to === term.cols && full,
    })
  }
  return logicalLines(rows).join('\n')
}
