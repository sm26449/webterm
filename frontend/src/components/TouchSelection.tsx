import { forwardRef, useCallback, useEffect, useImperativeHandle, useReducer, useRef, useState } from 'react'
import type { Terminal } from '@xterm/xterm'
import { useI18n } from '../lib/i18n'
import { cellAt, cellAtEdge, filledCells, ordered, rangeLength, rangeText, wordAt, type Cell, type CellRange, type Grid } from '../lib/touchsel'
import { CopyIcon, MoreIcon, PasteIcon } from './Icons'

/** Selecţia cu degetul, direct în terminalul viu (3.6.32) — ca pe iPhone: ţii apăsat pe un cuvânt,
    cuvântul se selectează, apar două mânere pe care le tragi şi o bulă cu „Copiază".

    De ce mânere PROPRII: xterm desenează pe canvas, deci sistemul nu vede text şi mânerele lui nu
    apar niciodată. Selecţia în sine e a xterm-ului (`term.select`), deci arată la fel ca cea cu
    mouse-ul şi o văd şi „Copiază" / „Deschide calea" din meniul terminalului.

    Stă într-un strat `pointer-events-none` peste panoul terminalului; doar mânerele şi bula prind
    atingeri. Părintele (SessionView) cheamă `startAt` la apăsarea lungă şi `clear` la orice altă
    atingere a terminalului. */
export interface TouchSelectionHandle {
  /** apăsare lungă la (x, y): selectează cuvântul de acolo; false = sub deget nu e text */
  startAt(x: number, y: number): boolean
  clear(): void
  /** „Selectează tot" pe touch: tot bufferul, CU bula de copiere (altfel ai o selecţie cu care nu
      poţi face nimic fără tastatură); false = bufferul e gol */
  selectAll(): boolean
  /** textul selecţiei cu degetul (rândurile rupte unite), sau null dacă nu există una */
  text(): string | null
}

const HANDLE = 44      // ţinta de atingere a unui mâner (px)
const DOT = 14         // bulina vizibilă

const TouchSelection = forwardRef<TouchSelectionHandle, {
  term: () => Terminal | null | undefined
  /** elementul în care e montat xterm (conţine `.xterm-screen`) */
  host: () => HTMLElement | null
  canPaste: boolean
  onCopy: (text: string) => Promise<boolean>
  onPaste: () => void
  /** „⋯": restul meniului terminalului, la poziţia dată */
  onMore: (x: number, y: number) => void
}>(function TouchSelection(props, ref) {
  const { t } = useI18n()
  const rootRef = useRef<HTMLDivElement>(null)
  const [sel, setSel] = useState<CellRange | null>(null)
  const selRef = useRef<CellRange | null>(null)
  selRef.current = sel
  const [dragging, setDragging] = useState(false)
  const [, repaint] = useReducer((n: number) => n + 1, 0)
  // în timpul unui `term.select` al NOSTRU, onSelectionChange nu trebuie să ne golească starea
  const applying = useRef(false)
  const { term: getTerm, host: getHost } = props

  const grid = useCallback((): Grid | null => {
    const term = getTerm()
    const screen = getHost()?.querySelector<HTMLElement>('.xterm-screen')
    if (!term || !screen) return null
    const r = screen.getBoundingClientRect()
    if (!r.width || !r.height) return null
    return { left: r.left, top: r.top, width: r.width, height: r.height, cols: term.cols, rows: term.rows, viewportY: term.buffer.active.viewportY }
  }, [getTerm, getHost])

  const apply = useCallback((r: CellRange | null) => {
    const term = getTerm()
    applying.current = true
    try {
      if (!term) return
      if (r) term.select(r.a.col, r.a.row, rangeLength(r, term.cols))
      else if (term.hasSelection()) term.clearSelection()
    } finally {
      applying.current = false
    }
    // ref-ul ÎNAINTEA render-ului: un `pointermove` nu forţează render sincron, iar dacă xterm îşi
    // goleşte selecţia între timp, „pune la loc" ar readuce intervalul VECHI peste cel abia tras
    selRef.current = r
    setSel(r)
  }, [getTerm])

  useImperativeHandle(ref, () => ({
    startAt(x, y) {
      const term = getTerm()
      const g = grid()
      if (!term || !g) return false
      // în afara ecranului (padding-ul panoului) nu e text
      if (x < g.left || x > g.left + g.width || y < g.top || y > g.top + g.height) return false
      const c = cellAt(g, x, y)
      const w = wordAt(filledCells(term, c.row), c.col)
      if (!w) return false
      apply({ a: { col: w[0], row: c.row }, b: { col: w[1], row: c.row } })
      return true
    },
    clear() { if (selRef.current) apply(null) },
    selectAll() {
      const term = getTerm()
      if (!term) return false
      const buf = term.buffer.active
      const blank = (y: number) => (buf.getLine(y)?.translateToString(true) ?? '') === ''
      let first = 0
      let last = buf.length - 1
      while (first <= last && blank(first)) first++
      while (last >= first && blank(last)) last--
      if (first > last) return false
      apply({ a: { col: 0, row: first }, b: { col: Math.max(0, filledCells(term, last).lastIndexOf(true)), row: last } })
      return true
    },
    text() {
      const term = getTerm()
      const cur = selRef.current
      return term && cur ? rangeText(term, cur) : null
    },
  }), [apply, grid, getTerm])

  // cât există o selecţie: urmărim terminalul. Selecţia golită de xterm (tastă, clic, buffer tăiat)
  // ne scoate mânerele; derularea / redimensionarea le mută (onRender prinde şi derularea cu degetul).
  const active = sel !== null
  useEffect(() => {
    if (!active) return
    const term = getTerm()
    if (!term) return
    let last = ''
    const cols = term.cols
    const subs = [
      // xterm îşi goleşte selecţia şi din motive care NU sunt ale utilizatorului: de fiecare dată când
      // aplicaţia (re)anunţă modul de mouse — tmux o face la fiecare redesenare — serviciul lui de
      // selecţie e „dezactivat" şi selecţia dispare, la o secundă-două după ce ai ales cuvântul
      // (prins în auditul mobil). Selecţia cu degetul e a NOASTRĂ: o punem la loc. O închid doar
      // gesturile de mai jos şi atingerea terminalului (SessionView).
      term.onSelectionChange(() => {
        const cur = selRef.current
        if (applying.current || term.hasSelection() || !cur) return
        applying.current = true
        try { term.select(cur.a.col, cur.a.row, rangeLength(cur, term.cols)) } finally { applying.current = false }
      }),
      // tastezi → selecţia nu mai e subiectul (ca în orice editor); alt buffer (vim, less) → alt text
      term.onKey(() => apply(null)),
      term.buffer.onBufferChange(() => apply(null)),
      term.onRender(() => {
        const g = grid()
        const key = g ? `${g.left},${g.top},${g.width},${g.height},${g.cols},${g.rows},${g.viewportY}` : ''
        if (key !== last) { last = key; repaint() }
      }),
      // Alt număr de COLOANE = textul a fost re-rupt, selecţia veche nu mai înseamnă nimic. Doar
      // rândurile (bara de stare care se rupe pe două linii, tastatura virtuală) nu mută nimic în
      // buffer: selecţia rămâne, mânerele se reaşază.
      term.onResize(() => { if (term.cols !== cols) apply(null); else repaint() }),
    ]
    const onWin = () => repaint()
    // tastatura virtuală nu trece prin onKey (input / compoziţie / lipire pe textarea ascunsă)
    const ta = term.textarea
    const onType = () => apply(null)
    for (const ev of ['input', 'compositionstart', 'paste'] as const) ta?.addEventListener(ev, onType)
    window.addEventListener('resize', onWin)
    window.visualViewport?.addEventListener('resize', onWin)
    return () => {
      subs.forEach((s) => s.dispose())
      for (const ev of ['input', 'compositionstart', 'paste'] as const) ta?.removeEventListener(ev, onType)
      window.removeEventListener('resize', onWin)
      window.visualViewport?.removeEventListener('resize', onWin)
    }
  }, [active, apply, grid, getTerm])

  // -- tragerea unui mâner ------------------------------------------------------------------
  // `fixed` = capătul care stă pe loc; `dx/dy` = de unde a prins degetul mânerul faţă de punctul
  // pe care îl ţinteşte (muchia celulei, la mijlocul rândului) — bulina e SUB rând, ca degetul să
  // nu acopere textul pe care îl alegi.
  const drag = useRef<{ fixed: Cell; dx: number; dy: number; end: boolean; scroll: number } | null>(null)
  const edgePoint = (g: Grid, c: Cell, end: boolean) => {
    const cw = g.width / g.cols
    const ch = g.height / g.rows
    return { x: g.left + (c.col + (end ? 1 : 0)) * cw, y: g.top + (c.row - g.viewportY + 0.5) * ch }
  }
  const onHandleDown = (end: boolean) => (e: React.PointerEvent<HTMLDivElement>) => {
    e.stopPropagation()
    e.preventDefault()
    const g = grid()
    const cur = selRef.current
    if (!g || !cur) return
    const p = edgePoint(g, end ? cur.b : cur.a, end)
    drag.current = { fixed: end ? cur.a : cur.b, dx: e.clientX - p.x, dy: e.clientY - p.y, end, scroll: 0 }
    // captura ţine tragerea pe mâner şi când degetul iese din ţinta lui; un pointer deja ridicat aruncă
    try { e.currentTarget.setPointerCapture(e.pointerId) } catch { /* fără captură: mişcările de pe mâner ajung oricum */ }
    setDragging(true)
  }
  const onHandleMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const d = drag.current
    const g = grid()
    const term = getTerm()
    if (!d || !g || !term) return
    e.stopPropagation()
    const x = e.clientX - d.dx
    const y = e.clientY - d.dy
    // la marginea de sus / jos derulăm scrollback-ul (cel mult un rând la ~60 ms), ca selecţia să
    // poată trece de un ecran
    const now = Date.now()
    if (now - d.scroll > 60) {
      const ch = g.height / g.rows
      if (y < g.top + ch * 0.5) { term.scrollLines(-1); d.scroll = now }
      else if (y > g.top + g.height - ch * 0.5) { term.scrollLines(1); d.scroll = now }
    }
    const g2 = grid() ?? g
    // capetele se pot încrucişa: mânerul tras devine celălalt capăt
    const moved = cellAtEdge(g2, x, y, d.end)
    const isEnd = !(moved.row < d.fixed.row || (moved.row === d.fixed.row && moved.col < d.fixed.col))
    const cell = isEnd === d.end ? moved : cellAtEdge(g2, x, y, isEnd)
    const next = ordered(d.fixed, cell)
    const cur = selRef.current
    if (!cur || cur.a.col !== next.a.col || cur.a.row !== next.a.row || cur.b.col !== next.b.col || cur.b.row !== next.b.row) apply(next)
  }
  const onHandleUp = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!drag.current) return
    e.stopPropagation()
    drag.current = null
    setDragging(false)
  }

  if (!sel) return <div ref={rootRef} className="pointer-events-none absolute inset-0 z-10" />

  const g = grid()
  const root = rootRef.current?.getBoundingClientRect()
  let body: React.ReactNode = null
  if (g && root) {
    const cw = g.width / g.cols
    const ch = g.height / g.rows
    const ox = g.left - root.left
    const oy = g.top - root.top
    const rowVisible = (row: number) => row >= g.viewportY && row < g.viewportY + g.rows
    const handle = (c: Cell, end: boolean) => {
      if (!rowVisible(c.row)) return null
      const x = ox + (c.col + (end ? 1 : 0)) * cw
      const yTop = oy + (c.row - g.viewportY) * ch
      // ţinta de atingere e împinsă spre EXTERIORUL selecţiei: la un cuvânt scurt cele două ţinte
      // s-ar suprapune şi ai prinde mereu acelaşi mâner
      const grip = HANDLE * (end ? 0.25 : 0.75)
      return (
        <div
          key={end ? 'end' : 'start'}
          data-testid={end ? 'wt-touchsel-end' : 'wt-touchsel-start'}
          aria-hidden="true"
          className="pointer-events-auto absolute touch-none"
          style={{ left: x - grip, top: yTop, width: HANDLE, height: ch + HANDLE }}
          onPointerDown={onHandleDown(end)}
          onPointerMove={onHandleMove}
          onPointerUp={onHandleUp}
          onPointerCancel={onHandleUp}
          onContextMenu={(e) => { e.preventDefault(); e.stopPropagation() }}
        >
          {/* tija pe înălţimea rândului + bulina de sub el */}
          <span className="absolute w-0.5 bg-sky-500" style={{ left: grip - 1, top: 0, height: ch + 2 }} />
          <span className="absolute rounded-full bg-sky-500 shadow"
            style={{ left: grip - DOT / 2, top: ch + 1, width: DOT, height: DOT }} />
        </div>
      )
    }
    // bula: deasupra începutului selecţiei; fără loc acolo → sub mânerul de sfârşit
    const BUBBLE_H = 44
    const BUBBLE_HALF = 124   // jumătate din lăţimea bulei + margine: nu iese din panou
    const startY = oy + (Math.max(sel.a.row, g.viewportY) - g.viewportY) * ch
    const endY = oy + (Math.min(sel.b.row, g.viewportY + g.rows - 1) - g.viewportY + 1) * ch
    const anyVisible = sel.b.row >= g.viewportY && sel.a.row < g.viewportY + g.rows
    let top = startY - BUBBLE_H - 8
    if (top < 4) top = Math.min(endY + DOT + 14, root.height - BUBBLE_H - 4)
    const midX = sel.a.row === sel.b.row ? ox + ((sel.a.col + sel.b.col + 1) / 2) * cw : ox + g.width / 2
    const item = 'wt-touch flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm text-slate-200 hover:bg-ink-800 active:bg-ink-700'
    // evidenţierea o desenăm şi NOI (pe lângă a xterm-ului): culoarea de selecţie a unor teme e abia
    // vizibilă în soare, iar aici trebuie să vezi dintr-o privire ce pleacă în clipboard
    const bands: React.ReactNode[] = []
    const r0 = Math.max(sel.a.row, g.viewportY)
    const r1 = Math.min(sel.b.row, g.viewportY + g.rows - 1)
    for (let row = r0; row <= r1; row++) {
      const c0 = row === sel.a.row ? sel.a.col : 0
      const c1 = row === sel.b.row ? sel.b.col : g.cols - 1
      bands.push(
        <span key={row} aria-hidden="true" className="absolute bg-sky-500/25"
          style={{ left: ox + c0 * cw, top: oy + (row - g.viewportY) * ch, width: (c1 - c0 + 1) * cw, height: ch }} />,
      )
    }
    body = (
      <>
        {bands}
        {handle(sel.a, false)}
        {handle(sel.b, true)}
        {anyVisible && !dragging && (
          <div
            role="toolbar"
            aria-label={t('touchsel.actions')}
            data-testid="wt-touchsel-bubble"
            className="pointer-events-auto absolute flex -translate-x-1/2 items-center rounded-xl border border-ink-700 bg-ink-900 p-0.5 shadow-2xl"
            style={{ top, left: Math.min(Math.max(midX, BUBBLE_HALF), Math.max(BUBBLE_HALF, root.width - BUBBLE_HALF)) }}
            // atingerile bulei nu sunt atingeri ale terminalului (care ar goli selecţia) şi nu-i iau focusul
            onPointerDown={(e) => e.stopPropagation()}
            onMouseDown={(e) => e.preventDefault()}
            onContextMenu={(e) => { e.preventDefault(); e.stopPropagation() }}
          >
            <button type="button" className={item} data-testid="wt-touchsel-copy"
              onClick={() => {
                const term = getTerm()
                const cur = selRef.current
                if (!term || !cur) return
                void props.onCopy(rangeText(term, cur)).then((ok) => { if (ok) apply(null) })
              }}>
              <CopyIcon /> {t('session.copy')}
            </button>
            {props.canPaste && (
              <button type="button" className={item} onClick={() => { apply(null); props.onPaste() }}>
                <PasteIcon /> {t('session.pasteMenu')}
              </button>
            )}
            <button type="button" className={item} aria-label={t('session.more')} title={t('session.more')}
              onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); props.onMore(r.left, r.bottom + 4) }}>
              <MoreIcon />
            </button>
          </div>
        )}
      </>
    )
  }
  return <div ref={rootRef} className="pointer-events-none absolute inset-0 z-10" data-testid="wt-touchsel">{body}</div>
})

export default TouchSelection
