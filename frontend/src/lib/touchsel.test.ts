import { describe, expect, it } from 'vitest'
import { cellAt, cellAtEdge, filledCells, ordered, rangeLength, rangeText, wordAt, type Grid } from './touchsel'

const grid: Grid = { left: 10, top: 100, width: 800, height: 240, cols: 80, rows: 24, viewportY: 50 }

function fakeTerm(cols: number, lines: { text: string; wrapped?: boolean }[]) {
  return {
    cols,
    buffer: {
      active: {
        length: lines.length,
        getLine: (y: number) => {
          const l = lines[y]
          if (!l) return undefined
          const padded = l.text.padEnd(cols, ' ')
          return {
            isWrapped: !!l.wrapped,
            translateToString: (_trim?: boolean, a = 0, b = cols) => padded.slice(a, b),
            getCell: (x: number) => ({ getChars: () => (padded[x] === ' ' ? '' : padded[x] ?? ''), getWidth: () => 1 }),
          }
        },
      },
    },
  }
}

describe('cellAt', () => {
  it('maps a point to a buffer cell (viewport offset included)', () => {
    expect(cellAt(grid, 10, 100)).toEqual({ col: 0, row: 50 })
    expect(cellAt(grid, 10 + 25, 100 + 15)).toEqual({ col: 2, row: 51 })
  })
  it('clamps points outside the screen', () => {
    expect(cellAt(grid, -50, 0)).toEqual({ col: 0, row: 50 })
    expect(cellAt(grid, 5000, 5000)).toEqual({ col: 79, row: 73 })
  })
})

describe('cellAtEdge', () => {
  it('a handle resting on its own edge keeps the selection where it was', () => {
    // capătul de început pe muchia stângă a celulei 5; capătul de sfârşit pe muchia dreaptă a celulei 9
    expect(cellAtEdge(grid, 10 + 50, 105, false).col).toBe(5)
    expect(cellAtEdge(grid, 10 + 100, 105, true).col).toBe(9)
  })
  it('snaps to the nearest edge', () => {
    expect(cellAtEdge(grid, 10 + 54, 105, false).col).toBe(5)
    expect(cellAtEdge(grid, 10 + 56, 105, false).col).toBe(6)
    expect(cellAtEdge(grid, 10 + 2, 105, true).col).toBe(0)
  })
})

describe('ordered / rangeLength', () => {
  it('orders the ends in reading order', () => {
    const p = { col: 5, row: 3 }
    const q = { col: 1, row: 4 }
    expect(ordered(q, p)).toEqual({ a: p, b: q })
    expect(ordered({ col: 7, row: 3 }, p)).toEqual({ a: p, b: { col: 7, row: 3 } })
  })
  it('counts cells across rows, ends inclusive', () => {
    expect(rangeLength({ a: { col: 2, row: 0 }, b: { col: 2, row: 0 } }, 80)).toBe(1)
    expect(rangeLength({ a: { col: 78, row: 0 }, b: { col: 1, row: 1 } }, 80)).toBe(4)
  })
})

describe('wordAt', () => {
  const f = (s: string) => [...s].map((c) => c !== ' ')
  it('takes the whole whitespace-delimited token', () => {
    expect(wordAt(f('cat /etc/nginx/nginx.conf | less'), 9)).toEqual([4, 24])
    expect(wordAt(f('git push --no-verify'), 12)).toEqual([9, 19])
  })
  it('returns null on empty space', () => {
    expect(wordAt(f('a  b'), 1)).toBeNull()
    expect(wordAt([], 0)).toBeNull()
  })
})

describe('filledCells / rangeText', () => {
  const term = fakeTerm(10, [
    { text: '$ echo 123' },   // umple ultima celulă → continuă pe rândul următor
    { text: '456 end' },
    { text: 'out' },
  ])
  it('marks non-blank cells', () => {
    expect(filledCells(term, 2)).toEqual([true, true, true, false, false, false, false, false, false, false])
  })
  it('copies a single-row range', () => {
    expect(rangeText(term, { a: { col: 2, row: 0 }, b: { col: 5, row: 0 } })).toBe('echo')
  })
  it('joins a command that fills the row with its continuation — no newline in the middle', () => {
    expect(rangeText(term, { a: { col: 2, row: 0 }, b: { col: 2, row: 1 } })).toBe('echo 123456')
  })
  it('keeps the newline between real lines', () => {
    expect(rangeText(term, { a: { col: 4, row: 1 }, b: { col: 2, row: 2 } })).toBe('end\nout')
  })
})
