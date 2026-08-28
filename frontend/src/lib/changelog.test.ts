import { describe, expect, it } from 'vitest'
import { parseChangelog, parseInline } from './changelog'

describe('parseInline', () => {
  it('text simplu → un singur span', () => {
    expect(parseInline('salut lume')).toEqual([{ text: 'salut lume' }])
  })
  it('**bold** și `code` devin span-uri marcate', () => {
    const s = parseInline('vezi **important** și `cod`.')
    expect(s).toEqual([
      { text: 'vezi ' },
      { text: 'important', bold: true },
      { text: ' și ' },
      { text: 'cod', code: true },
      { text: '.' },
    ])
  })
})

describe('parseChangelog', () => {
  const md = `# Changelog

Some preamble.

## [2.0.10] — 2026-08-28 · agent (45)

### Fixed — a thing

- first item that wraps
  onto a second line
- second **item** with \`code\`

## [2.0.9] — 2026-08-28

### Added

- older item
`

  it('titlul H1 e ignorat', () => {
    const blocks = parseChangelog(md)
    expect(blocks.some((b) => b.kind === 'version' && b.text.includes('Changelog'))).toBe(false)
  })

  it('versiunile devin blocuri version; cea curentă e marcată', () => {
    const versions = parseChangelog(md, '2.0.10').filter((b) => b.kind === 'version')
    expect(versions).toHaveLength(2)
    expect((versions[0] as { current: boolean }).current).toBe(true)
    expect((versions[1] as { current: boolean }).current).toBe(false)
  })

  it('secțiunile ### devin blocuri section', () => {
    const sections = parseChangelog(md).filter((b) => b.kind === 'section')
    expect(sections.map((s) => (s as { text: string }).text)).toEqual(['Fixed — a thing', 'Added'])
  })

  it('itemii de listă sunt corect uniți pe continuări indentate', () => {
    const items = parseChangelog(md).filter((b) => b.kind === 'item')
    expect(items).toHaveLength(3)
    const first = items[0] as { spans: { text: string }[] }
    expect(first.spans.map((s) => s.text).join('')).toBe('first item that wraps onto a second line')
  })

  it('fără versiune curentă, niciun bloc nu e marcat', () => {
    const versions = parseChangelog(md).filter((b) => b.kind === 'version')
    expect(versions.every((b) => !(b as { current: boolean }).current)).toBe(true)
  })
})
