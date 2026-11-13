import { describe, expect, it } from 'vitest'
import { cleanSelection, logicalLines, terminalLines, type SelRow, type TermLike } from './seltext'

const row = (text: string, o: Partial<SelRow> = {}): SelRow => ({ text, wrapped: false, full: false, ...o })

describe('logicalLines', () => {
  it('keeps separate rows as separate lines and trims trailing spaces', () => {
    expect(logicalLines([row('ls -la   '), row('total 4  ')])).toEqual(['ls -la', 'total 4'])
  })

  it('joins a soft-wrapped command into ONE line (no newline to execute half of it)', () => {
    expect(logicalLines([
      row('curl -fsSL https://example.com/a/very/long/'),
      row('path | sudo bash', { wrapped: true }),
    ])).toEqual(['curl -fsSL https://example.com/a/very/long/path | sudo bash'])
  })

  it('joins after a row that fills the last cell (tmux repaints without isWrapped)', () => {
    expect(logicalLines([row('aaaaaaaaaa', { full: true }), row('bbb'), row('next')]))
      .toEqual(['aaaaaaaaaabbb', 'next'])
  })

  it('does not trim inside a line: indentation and inner spaces survive', () => {
    expect(logicalLines([row('  key:   '), row('    - value')])).toEqual(['  key:', '    - value'])
    expect(logicalLines([row('echo a  ', { full: true }), row('  b', { wrapped: true })])).toEqual(['echo a    b'])
  })

  it('keeps inner blank lines, drops leading and trailing ones', () => {
    expect(logicalLines([row(''), row('a'), row('   '), row('b'), row(''), row('')])).toEqual(['a', '', 'b'])
  })

  it('handles an empty buffer', () => {
    expect(logicalLines([])).toEqual([])
    expect(logicalLines([row(''), row('  ')])).toEqual([])
  })
})

function fakeTerm(cols: number, lines: { text: string; wrapped?: boolean }[]): TermLike {
  return {
    cols,
    buffer: {
      active: {
        length: lines.length,
        getLine: (y) => {
          const l = lines[y]
          if (!l) return undefined
          const padded = l.text.padEnd(cols, ' ')
          return {
            isWrapped: !!l.wrapped,
            translateToString: (trim?: boolean) => (trim ? padded.trimEnd() : padded),
            getCell: (x) => ({ getChars: () => (padded[x] === ' ' ? '' : padded[x] ?? ''), getWidth: () => 1 }),
          }
        },
      },
    },
  }
}

describe('terminalLines', () => {
  it('reads the buffer into logical lines', () => {
    const term = fakeTerm(10, [
      { text: '$ echo 123' },                // umple ultima celulă → continuă
      { text: '456' },
      { text: 'out' },
      { text: '' },
    ])
    expect(terminalLines(term)).toEqual(['$ echo 123456', 'out'])
  })

  it('keeps only the most recent rows and never glues the first one to a dropped row', () => {
    const term = fakeTerm(10, [
      { text: 'old' },
      { text: 'tail', wrapped: true },
      { text: 'new' },
    ])
    expect(terminalLines(term, 2)).toEqual(['tail', 'new'])
  })

  it('returns nothing without a terminal', () => {
    expect(terminalLines(null)).toEqual([])
  })
})

describe('cleanSelection', () => {
  it('normalises NBSP and newlines, strips blank edges', () => {
    expect(cleanSelection('\n\na\xa0b\r\nc\n')).toBe('a b\nc')
  })
})
