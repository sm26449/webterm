import { describe, expect, it } from 'vitest'
import {
  RETENTION_BATCH, extFromMime, inboxName, isGenericName, pasteSubject, pasteSubjectText,
  pasteToastKey, selectExpired, shellQuote, stampFor,
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
  // Octeţii de control dintr-un nume ostil se scot: numele devine parte dintr-o cale tastată la
  // prompt, iar un `\r`/`\n`/`\x1b` ar ajunge la line discipline-ul PTY-ului nefiltrat de citare.
  it('octeţii de control din nume sunt scoşi', () => {
    const noCtl = (s: string) => !/[\x00-\x1f\x7f]/.test(s)
    expect(inboxName({ name: 'a\rb.txt', type: 'text/plain' }, when)).toBe('2026-10-04_14-03-22_ab.txt')
    expect(inboxName({ name: 'a\nb.txt', type: 'text/plain' }, when)).toBe('2026-10-04_14-03-22_ab.txt')
    expect(inboxName({ name: 'x\x1b[31m.txt', type: 'text/plain' }, when)).toBe('2026-10-04_14-03-22_x[31m.txt')
    // nume format DOAR din octeţi de control → cade pe `file.<ext>` (nu rămâne gol)
    expect(inboxName({ name: '\r\n\x00', type: 'image/png' }, when)).toBe('2026-10-04_14-03-22_file.png')
    expect(noCtl(inboxName({ name: 'q\x7f\x1bw', type: 'text/plain' }, when))).toBe(true)
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
  // Calea e TASTATĂ brut în terminal (send(), nu bracketed-paste): orice metacaracter de shell
  // dintr-un nume de fişier ostil (paste/drop) TREBUIE neutralizat prin citare. Caracterele de
  // injectare nu sunt în allowlist, deci rezultatul e mereu între apostrofuri (inerte în sh/bash/zsh).
  it('metacaracterele de injectare dintr-un nume ostil sunt mereu citate', () => {
    for (const evil of [
      '/root/.webterm/inbox/x;rm -rf ~',
      '/root/.webterm/inbox/x$(id)',
      '/root/.webterm/inbox/x`id`',
      '/root/.webterm/inbox/a&&b',
      '/root/.webterm/inbox/a|b',
      '/root/.webterm/inbox/a>b',
      '/root/.webterm/inbox/{a,b}',
      '/root/.webterm/inbox/x*',
    ]) {
      const q = shellQuote(evil)
      expect(q.startsWith("'") && q.endsWith("'")).toBe(true)
    }
  })
  // Căile inserate pornesc MEREU cu `/` (home absolut/cwd) sau cu `~/` (home propriu, expansiune
  // dorită): un nume controlat de atacator apare doar DUPĂ un `/`, deci nu poate fi un `-flag`
  // de început şi nici un `~user` de început. Fixăm invariantul.
  it('un nume controlat nu devine flag sau ~user (apare doar după un /)', () => {
    expect(shellQuote('/root/.webterm/inbox/-rf')).toBe('/root/.webterm/inbox/-rf')  // `-` nu e la început de cuvânt
    expect(shellQuote('/root/.webterm/inbox/~root')).toBe('/root/.webterm/inbox/~root')  // `~` nu e la început de cuvânt
  })
  // Octeţii de control (`\r \n \x1b \x00-\x1f \x7f`) nu sunt opriţi de citare — ajung la line
  // discipline-ul PTY-ului (un `\r` TRIMITE linia). Îi scoatem înainte de citare, deci rezultatul
  // e mereu fără octeţi de control; pentru restul rămâne o cale normală (citată doar dacă trebuie).
  it('octeţii de control sunt scoşi înainte de citare', () => {
    const noCtl = (s: string) => !/[\x00-\x1f\x7f]/.test(s)
    expect(shellQuote('/tmp/a\rb.txt')).toBe('/tmp/ab.txt')       // `\r` scos → cale curată, necitată
    expect(shellQuote('/tmp/a\nb.txt')).toBe('/tmp/ab.txt')       // `\n` scos
    expect(shellQuote('/tmp/a\x1b[31mb.txt')).toBe("'/tmp/a[31mb.txt'")  // ESC scos; `[` cere citare
    expect(shellQuote('/tmp/a\x00b.txt')).toBe('/tmp/ab.txt')     // NUL scos
    for (const evil of ['/tmp/x\r', '/tmp/x\n\rrm -rf ~', '/tmp/\x1b]0;x', '/tmp/\x7f']) {
      expect(noCtl(shellQuote(evil))).toBe(true)
    }
  })
})

describe('feedback de paste/drop (alegerea mesajului)', () => {
  it('subiectul: captură (nume generic) vs fişier cu nume vs N fişiere', () => {
    expect(pasteSubject([{ name: 'image.png' }])).toEqual({ kind: 'screenshot', name: 'image.png', count: 1 })
    expect(pasteSubject([{ name: 'Pasted Graphic.tiff' }]).kind).toBe('screenshot')
    expect(pasteSubject([{ name: 'raport.pdf' }])).toEqual({ kind: 'file', name: 'raport.pdf', count: 1 })
    expect(pasteSubject([{ name: 'a.png' }, { name: 'b.png' }])).toEqual({ kind: 'files', name: 'a.png', count: 2 })
    expect(pasteSubject([]).kind).toBe('files')
  })
  it('cheia toastului: fază × destinaţie × fel (singular vs N)', () => {
    expect(pasteToastKey('start', 'inbox', 'screenshot')).toBe('transfers.pasteStartInbox')
    expect(pasteToastKey('start', 'cwd', 'file')).toBe('transfers.pasteStartCwd')
    expect(pasteToastKey('done', 'inbox', 'screenshot')).toBe('transfers.pasteDoneInboxOne')
    expect(pasteToastKey('done', 'inbox', 'file')).toBe('transfers.pasteDoneInboxOne')
    expect(pasteToastKey('done', 'inbox', 'files')).toBe('transfers.pasteDoneInboxMany')
    expect(pasteToastKey('done', 'cwd', 'files')).toBe('transfers.pasteDoneCwdMany')
  })
  it('textul subiectului: captură → cuvânt tradus, fişier → numele, N → fragment cu count', () => {
    // `t` fals: captura întoarce cheia, N întoarce „N files" (ca să verificăm doar ramurile)
    const t = (k: string, v?: Record<string, string | number>) => (v ? `${k}:${v.count}` : k)
    expect(pasteSubjectText({ kind: 'screenshot', name: 'image.png', count: 1 }, t)).toBe('transfers.pasteSubjShot')
    expect(pasteSubjectText({ kind: 'file', name: 'raport.pdf', count: 1 }, t)).toBe('raport.pdf')
    expect(pasteSubjectText({ kind: 'files', name: 'a.png', count: 3 }, t)).toBe('transfers.pasteSubjMany:3')
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
