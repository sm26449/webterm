import { describe, expect, it } from 'vitest'
import {
  RETENTION_BATCH, extFromMime, inboxName, isGenericName, selectExpired, shellQuote, stampFor,
} from './transfers'

const when = new Date(2026, 9, 4, 14, 3, 22)   // 2026-10-04 14:03:22 local

describe('numele din inbox (timestamp + MIME)', () => {
  it('timestamp local, fără `:` (cale sigură pe orice FS)', () => {
    expect(stampFor(when)).toBe('2026-10-04_14-03-22')
    expect(stampFor(new Date(2026, 0, 1, 0, 0, 0))).toBe('2026-01-01_00-00-00')
  })
  it('extensia vine din MIME; necunoscut → bin, parametrii se ignoră', () => {
    expect(extFromMime('image/png')).toBe('png')
    expect(extFromMime('image/jpeg')).toBe('jpg')
    expect(extFromMime('application/pdf')).toBe('pdf')
    expect(extFromMime('text/plain;charset=utf-8')).toBe('txt')
    expect(extFromMime('image/x-icon')).toBe('icon')
    expect(extFromMime('application/vnd.ms-excel')).toBe('bin')
    expect(extFromMime('')).toBe('bin')
  })
  it('numele generic al browserului (image.png / Pasted Graphic / gol) = fără nume', () => {
    expect(isGenericName('image.png')).toBe(true)
    expect(isGenericName('Image.jpeg')).toBe(true)
    expect(isGenericName('Pasted Graphic 3.tiff')).toBe(true)
    expect(isGenericName('')).toBe(true)
    expect(isGenericName('raport.pdf')).toBe(false)
    expect(isGenericName('image-final.png')).toBe(false)
  })
  it('captură lipită → <stamp>.<ext>; a doua în aceeaşi secundă → <stamp>-2.<ext>', () => {
    expect(inboxName({ name: 'image.png', type: 'image/png' }, when)).toBe('2026-10-04_14-03-22.png')
    expect(inboxName({ name: '', type: 'image/webp' }, when, 2)).toBe('2026-10-04_14-03-22-2.webp')
  })
  it('fişier cu nume → <stamp>_<nume>, curăţat de separatoare de cale', () => {
    expect(inboxName({ name: 'raport final.pdf', type: 'application/pdf' }, when)).toBe('2026-10-04_14-03-22_raport final.pdf')
    // `/` → `_`, punctele de la început cad (nu creăm dotfiles ascunse din greşeală)
    expect(inboxName({ name: '../x/y.txt', type: 'text/plain' }, when)).toBe('2026-10-04_14-03-22__x_y.txt')
    expect(inboxName({ name: '...', type: 'image/png' }, when)).toBe('2026-10-04_14-03-22_file.png')
  })
})

describe('citare shell pentru calea inserată', () => {
  it('căile „curate" rămân necitate', () => {
    expect(shellQuote('/root/.webterm/inbox/2026-10-04_14-03-22.png')).toBe('/root/.webterm/inbox/2026-10-04_14-03-22.png')
    expect(shellQuote('~/a-b_c.d')).toBe('~/a-b_c.d')
  })
  it('spaţii şi caractere speciale → apostrof simplu', () => {
    expect(shellQuote('/tmp/raport final.pdf')).toBe("'/tmp/raport final.pdf'")
    expect(shellQuote('/tmp/$HOME`x`!.txt')).toBe("'/tmp/$HOME`x`!.txt'")
    expect(shellQuote('/tmp/a"b.txt')).toBe(`'/tmp/a"b.txt'`)
  })
  it("apostroful din interior devine '\\''", () => {
    expect(shellQuote("/tmp/it's.txt")).toBe(`'/tmp/it'\\''s.txt'`)
  })
  it('calea goală se citează (nu dispare)', () => {
    expect(shellQuote('')).toBe("''")
  })
})

describe('retenţia inbox-ului', () => {
  const now = 1_800_000_000
  const day = 86400
  const entries = [
    { name: 'old1.png', dir: false, mtime: now - 10 * day },
    { name: 'old2.png', dir: false, mtime: now - 30 * day },
    { name: 'fresh.png', dir: false, mtime: now - 1 * day },
    { name: 'just.png', dir: false, mtime: now - 100 * day },   // tocmai urcat (mtime fals): protejat prin `keep`
    { name: 'subdir', dir: true, mtime: now - 100 * day },
    { name: 'nomtime.png', dir: false, mtime: 0 },
  ]
  it('şterge doar fişiere mai vechi de N zile, niciodată `keep`, directoare sau mtime necunoscut; cele mai vechi primele', () => {
    expect(selectExpired(entries, now, 7, 'just.png')).toEqual(['old2.png', 'old1.png'])
  })
  it('0 (sau negativ) = păstrează tot', () => {
    expect(selectExpired(entries, now, 0)).toEqual([])
    expect(selectExpired(entries, now, -3)).toEqual([])
  })
  it('plafon per rulare', () => {
    const many = Array.from({ length: 120 }, (_, i) => ({ name: `f${i}.png`, dir: false, mtime: now - (20 + i) * day }))
    expect(selectExpired(many, now, 7)).toHaveLength(RETENTION_BATCH)
  })
})
