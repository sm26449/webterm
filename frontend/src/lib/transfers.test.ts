import { afterEach, describe, expect, it } from 'vitest'
import {
  RETENTION_BATCH, extFromMime, focusedTerminalRunsProgram, inboxName, registerInsertTarget, isGenericName, pasteSubject, pasteSubjectText,
  pasteToastKey, selectExpired, shellQuote, stampFor,
  PASTE_CONTEXT_BLIND_MS, PASTE_CONTEXT_MS, capturePasteContext, insertPathOutcome, insertPathPasted, isSafeToType, pasteContextStale, pasteStaleKey,
  typeIntoPasted, typePastedPaths, typingElsewhere,
} from './transfers'

const when = new Date(2026, 9, 4, 14, 3, 22)   // 2026-10-04 14:03:22 local

describe('focusedTerminalRunsProgram (Alt+E nu fură tasta unui program din terminal, review L4 + R1)', () => {
  const tgt = (focus: boolean, alt: boolean, running = false) => ({ send: () => true, bracketedPaste: () => false,
    hasFocus: () => focus, altScreen: () => alt, commandRunning: () => running })
  it('doar terminalul CU FOCUS contează; ecranul alternativ blochează', () => {
    registerInsertTarget('a', tgt(true, false))
    registerInsertTarget('b', tgt(false, true, true))
    expect(focusedTerminalRunsProgram()).toBe(false)     // promptul shell-ului: scurtătura rămâne
    registerInsertTarget('a', tgt(true, true))
    expect(focusedTerminalRunsProgram()).toBe(true)      // nano / emacs / mc fără tmux
    registerInsertTarget('a', null); registerInsertTarget('b', null)
    expect(focusedTerminalRunsProgram()).toBe(false)
  })
  it('sub tmux (ecran normal): o comandă pornită după OSC 133 blochează la fel (R1)', () => {
    registerInsertTarget('t', tgt(true, false, true))
    expect(focusedTerminalRunsProgram()).toBe(true)
    registerInsertTarget('t', tgt(true, false, false))
    expect(focusedTerminalRunsProgram()).toBe(false)     // fără shell integration: nu avem semnal
    registerInsertTarget('t', null)
  })
})

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
  // 3.6.9 re-review M2: în fish `\'` şi `\\` sunt escape-uri şi ÎN apostrof — `'a\'` nu se închide,
  // deci un nume `a\` + `x;id>pwn;#` ar ieşi din citare. Backslash-ul se scrie în AFARA citării.
  it('backslash-ul iese din apostrof ca \\\\ (inert şi în fish)', () => {
    expect(shellQuote('/tmp/a\\b')).toBe(`'/tmp/a'\\\\'b'`)
    expect(shellQuote("/tmp/a\\'b")).toBe(`'/tmp/a'\\\\''\\''b'`)
  })
  // Un parser minimal al citării (un cuvânt, fără expansiuni): sh/bash/zsh — totul literal în
  // apostrof; fish — în apostrof `\'` şi `\\` sunt escape-uri. În afară, `\x` → x în ambele.
  const unquote = (q: string, fish: boolean): string | null => {
    let out = ''
    let inQ = false
    for (let i = 0; i < q.length; i++) {
      const c = q[i]
      if (inQ) {
        if (c === "'") { inQ = false; continue }
        if (fish && c === '\\' && (q[i + 1] === "'" || q[i + 1] === '\\')) { out += q[++i]; continue }
        out += c
        continue
      }
      if (c === "'") { inQ = true; continue }
      if (c === '\\') { if (i + 1 >= q.length) return null; out += q[++i]; continue }
      if (/[\s;&|<>()$`"#*?!{}[\]]/.test(c)) return null      // metacaracter neprotejat
      out += c
    }
    return inQ ? null : out
  }
  it('fiecare cale ostilă se citeşte înapoi EXACT, în sh şi în fish', () => {
    for (const p of ['/tmp/a\\', '/tmp/a\\x;id>pwn;#', "/tmp/a\\'x;id;#", "/tmp/it's", "/tmp/\\\\'", '/tmp/a b\\',
      '/tmp/$(id)`id`', '/tmp/x;rm -rf ~', '/tmp/a"b\\"c', '/tmp/\\']) {
      const q = shellQuote(p)
      expect(unquote(q, false)).toBe(p)
      expect(unquote(q, true)).toBe(p)
    }
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

// ── 3.6.16: paste / drop de fişiere = un paste în ACEL terminal ──────────────────────────────
describe('paste context (capturePasteContext / pasteContextStale / typeIntoPasted / typePastedPaths)', () => {
  interface Fake {
    sent: string[]; seq: number; active: boolean; epoch: number; kbd: boolean
    bracketed: boolean; tmux: boolean; atPrompt: boolean; alt: boolean; running: boolean; refuse: boolean
    integrated: boolean
  }
  const mk = (o: Partial<Fake> = {}) => {
    const f: Fake = { sent: [], seq: 0, active: true, epoch: 0, kbd: true, bracketed: false, tmux: true,
      atPrompt: false, alt: false, running: true, refuse: false, integrated: true, ...o }
    const target = {
      // ca SessionView: o trimitere reuşită creşte contorul de input; garda reţinută → false
      send: (x: string) => { if (f.refuse) return false; f.sent.push(x); f.seq++; return true },
      bracketedPaste: () => f.bracketed,
      viaTmux: () => f.tmux,
      atPrompt: () => f.atPrompt,
      altScreen: () => f.alt,
      commandRunning: () => f.running,
      inputSeq: () => f.seq,
      isActive: () => f.active,
      activeEpoch: () => f.epoch,
      keyboardHere: () => f.kbd,
      shellIntegration: () => f.integrated,
    }
    return { f, target }
  }
  const T0 = 1_000_000
  const W = (s: string) => `\x1b[200~${s}\x1b[201~`
  const done: string[] = []
  const reg = (sid: string, t: Parameters<typeof registerInsertTarget>[1]) => { registerInsertTarget(sid, t); done.push(sid) }
  afterEach(() => { for (const s of done.splice(0)) registerInsertTarget(s, null) })
  const setup = (sid: string, o: Partial<Fake> = {}) => {
    const { f, target } = mk(o); reg(sid, target)
    return { f, target, ctx: capturePasteContext(sid, T0)! }
  }

  it('context neschimbat: tastează imediat, chiar dacă rulează un program (Claude Code sub tmux)', () => {
    const { f, ctx } = setup('p1')
    expect(insertPathPasted(ctx, '/home/u/.webterm/inbox/a.png', T0 + 2000)).toEqual({ outcome: 'typed', stale: null })
    // sub tmux: împachetat (tmux scoate marcajele dacă panoul nu le-a cerut), spaţiu la final, fără Enter
    expect(f.sent).toEqual([W('/home/u/.webterm/inbox/a.png ')])
    expect(f.sent.join('')).not.toMatch(/[\r\n]/)
  })
  it('împachetarea per backend: pty fără bracketed paste → text simplu; pty cu mod cerut → împachetat', () => {
    const a = setup('p2', { tmux: false, bracketed: false })
    expect(insertPathPasted(a.ctx, '/x/b c.png', T0).outcome).toBe('typed')
    expect(a.f.sent).toEqual(["'/x/b c.png' "])
    const b = setup('p3', { tmux: false, bracketed: true })
    expect(insertPathPasted(b.ctx, '/x/b.png', T0).outcome).toBe('typed')
    expect(b.f.sent).toEqual([W('/x/b.png ')])
  })
  it('input: o tastă între paste şi commit → regulile vechi (fără prompt = notPrompt), nimic tastat', () => {
    const { f, ctx } = setup('p4')
    f.seq++
    expect(pasteContextStale(ctx, T0 + 10)).toBe('input')
    expect(insertPathPasted(ctx, '/x/a.png', T0 + 10)).toEqual({ outcome: 'notPrompt', stale: 'input' })
    expect(f.sent).toEqual([])
  })
  it('input: …dar la un prompt real (OSC 133) regulile vechi tot tastează', () => {
    const { f, ctx } = setup('p5', { atPrompt: true, running: false })
    f.seq++
    expect(insertPathPasted(ctx, '/x/a.png', T0 + 10)).toEqual({ outcome: 'typed', stale: 'input' })
    expect(f.sent).toEqual([W('/x/a.png ')])
  })
  it('timeout: la at+30001 → stale; exact la limită (at+30000) încă tastează; ceas înapoi = stale', () => {
    const { f, ctx } = setup('p6')
    expect(pasteContextStale(ctx, T0 + PASTE_CONTEXT_MS + 1)).toBe('timeout')
    expect(insertPathPasted(ctx, '/x/a.png', T0 + 30_001).outcome).toBe('notPrompt')
    expect(f.sent).toEqual([])
    expect(insertPathPasted(ctx, '/x/a.png', T0 + PASTE_CONTEXT_MS).outcome).toBe('typed')
    expect(pasteContextStale(capturePasteContext('p6', T0)!, T0 - 1)).toBe('timeout')
  })
  it('inactive: panoul nu mai e cel activ → stale', () => {
    const { f, ctx } = setup('p7')
    f.active = false
    expect(pasteContextStale(ctx, T0)).toBe('inactive')
    expect(insertPathPasted(ctx, '/x/a.png', T0).outcome).toBe('notPrompt')
    expect(f.sent).toEqual([])
  })
  it('epoca: plecat şi revenit (activ din nou) în 30 s tot e alt context (review L1)', () => {
    const { f, ctx } = setup('p7b')
    f.epoch++                                         // a fost reactivat
    expect(f.active).toBe(true)
    expect(pasteContextStale(ctx, T0)).toBe('inactive')
    expect(insertPathPasted(ctx, '/x/a.png', T0).outcome).toBe('notPrompt')
    expect(f.sent).toEqual([])
  })
  it('focus: omul scrie în alt câmp al paginii (căutare, filtru, redenumire) → stale (review M1)', () => {
    const { f, ctx } = setup('p7c')
    f.kbd = false
    expect(pasteContextStale(ctx, T0)).toBe('focus')
    expect(insertPathPasted(ctx, '/x/a.png', T0)).toEqual({ outcome: 'notPrompt', stale: 'focus' })
    expect(f.sent).toEqual([])
  })
  it('mode: alt program în prim-plan (ecran alternativ / comandă / prompt / bracketed) → stale (review L2)', () => {
    for (const k of ['alt', 'running', 'atPrompt', 'bracketed'] as const) {
      const { f, ctx } = setup(`pm-${k}`)
      f[k] = !f[k]
      expect(pasteContextStale(ctx, T0)).toBe('mode')
      expect(insertPathPasted(ctx, '/x/a.png', T0).stale).toBe('mode')
    }
  })
  it('ţintă fără semnalele noi (isActive / keyboardHere lipsă) = fail-closed', () => {
    const sent: string[] = []
    reg('pf', { send: (x: string) => { sent.push(x); return true }, bracketedPaste: () => false, viaTmux: () => true })
    const ctx = capturePasteContext('pf', T0)!
    expect(pasteContextStale(ctx, T0)).toBe('inactive')
    expect(insertPathPasted(ctx, '/x/a.png', T0).outcome).toBe('notPrompt')
    expect(sent).toEqual([])
  })
  it('target: terminal remontat (alt obiect pe acelaşi sid) sau închis → nu tastează nicăieri', () => {
    const a = setup('p8')
    const b = mk(); reg('p8', b.target)
    expect(pasteContextStale(a.ctx, T0)).toBe('target')
    expect(insertPathPasted(a.ctx, '/x/a.png', T0).outcome).toBe('notPrompt')
    expect(a.f.sent).toEqual([]); expect(b.f.sent).toEqual([])
    registerInsertTarget('p8', null)
    expect(insertPathPasted(a.ctx, '/x/a.png', T0).outcome).toBe('noTarget')
    expect(capturePasteContext('nimeni', T0)).toBeUndefined()
  })
  it('garda reţine inputul (ecou / dialog): send refuză → refused, nimic tastat', () => {
    const { f, ctx } = setup('p9', { refuse: true })
    expect(insertPathPasted(ctx, '/x/a.png', T0)).toEqual({ outcome: 'refused', stale: null })
    expect(f.sent).toEqual([])
  })
  it('text nesigur (control, bidi, ESC, Cf) → unsafe, niciodată trimis; \\r din cale nu duce la Enter', () => {
    const { f, ctx } = setup('p10')
    expect(typeIntoPasted(ctx, 'a\x1b[201~; rm -rf ~\r', T0).outcome).toBe('unsafe')
    expect(typeIntoPasted(ctx, 'a\u202eb', T0).outcome).toBe('unsafe')
    expect(typeIntoPasted(ctx, 'a\u2060b', T0).outcome).toBe('unsafe')
    expect(typeIntoPasted(ctx, '', T0).outcome).toBe('unsafe')
    expect(f.sent).toEqual([])
    expect(insertPathPasted(ctx, '/x/a\r.png', T0).outcome).toBe('typed')
    expect(f.sent.join('')).not.toMatch(/[\r\n]/)
  })
  it('typePastedPaths: în ordinea selecţiei, propria tastare nu invalidează restul, contextul se închide', () => {
    const { f, ctx } = setup('p11')
    const r = typePastedPaths(ctx, ['/x/1.png', '/x/2 b.png', '/x/3.png'], () => T0 + 5)
    expect(r.map((x) => x.outcome)).toEqual(['typed', 'typed', 'typed'])
    expect(f.sent).toEqual([W('/x/1.png '), W("'/x/2 b.png' "), W('/x/3.png ')])
    expect(ctx.closed).toBe(true)
  })
  it('typePastedPaths: o cale nesigură nu le opreşte pe celelalte; o tastă a omului după paste, da', () => {
    const a = setup('p12')
    const r = typePastedPaths(a.ctx, ['/x/1.png', '/x/\u2066bad.png', '/x/3.png'], () => T0)
    expect(r.map((x) => x.outcome)).toEqual(['typed', 'unsafe', 'typed'])
    expect(a.f.sent).toEqual([W('/x/1.png '), W('/x/3.png ')])
    // o tastă a omului după paste (înainte ca upload-urile să se termine) → toate cad pe regulile vechi
    const b = setup('p12b')
    b.f.seq++
    const r2 = typePastedPaths(b.ctx, ['/x/1.png', '/x/2.png'], () => T0)
    expect(r2).toEqual([{ outcome: 'notPrompt', stale: 'input' }, { outcome: 'notPrompt', stale: 'input' }])
    expect(b.f.sent).toEqual([])
  })
  it('nu e broadcast: tastează DOAR în ţinta paste-ului, nu şi în alte terminale înregistrate', () => {
    const a = setup('pa')
    const b = mk(); reg('pb', b.target)
    expect(insertPathPasted(a.ctx, '/x/a.png', T0).outcome).toBe('typed')
    expect(a.f.sent).toHaveLength(1)
    expect(b.f.sent).toEqual([])
  })
  it('fără paste (Files panel, „Insert path"): regulile vechi neschimbate — un program în faţă = notPrompt', () => {
    const { f, target } = mk({ tmux: true, atPrompt: false, bracketed: true }); reg('p13', target)
    expect(insertPathOutcome('p13', '/x/a.png')).toBe('notPrompt')
    expect(f.sent).toEqual([])
  })
  it('pasteStaleKey: cheie i18n per motiv', () => {
    expect(pasteStaleKey('input')).toBe('transfers.pasteStale.input')
    expect(pasteStaleKey('focus')).toBe('transfers.pasteStale.focus')
    expect(pasteStaleKey('blind')).toBe('transfers.pasteStale.blind')
  })

  describe('FS-03 (audit 2026-10-17): sub tmux fără shell integration citirile de mod sunt oarbe → fereastra scade la 10 s', () => {
    // panou tmux fără OSC 133: nici prompt, nici comandă văzută — exact starea în care `mode` nu poate deveni stale
    const blind = { tmux: true, integrated: false, running: false, atPrompt: false }
    it('orb: în 10 s tastează; la 10 s + 1 ms → stale `blind` (nu `timeout`), regulile vechi, nimic tastat fără prompt', () => {
      const { f, ctx } = setup('b1', blind)
      expect(insertPathPasted(ctx, '/x/a.png', T0 + PASTE_CONTEXT_BLIND_MS)).toEqual({ outcome: 'typed', stale: null })
      expect(f.sent).toHaveLength(1)
      const { f: f2, ctx: c2 } = setup('b2', blind)
      expect(pasteContextStale(c2, T0 + PASTE_CONTEXT_BLIND_MS + 1)).toBe('blind')      // ÎNAINTE: null → tasta până la 30 s
      expect(insertPathPasted(c2, '/x/a.png', T0 + PASTE_CONTEXT_BLIND_MS + 1)).toEqual({ outcome: 'notPrompt', stale: 'blind' })
      expect(f2.sent).toEqual([])
      // peste 30 s motivul rămâne cel general
      expect(pasteContextStale(c2, T0 + PASTE_CONTEXT_MS + 1)).toBe('timeout')
    })
    it('cu shell integration văzută (tracker.integrated) sub tmux: fereastra de 30 s rămâne', () => {
      const { ctx } = setup('b3', { tmux: true, integrated: true, running: false, atPrompt: false })
      expect(pasteContextStale(ctx, T0 + PASTE_CONTEXT_MS)).toBeNull()
    })
    it('fără citirea nouă, dar cu un marcaj OSC 133 real la paste (prompt / comandă) → integrarea e dovedită: 30 s', () => {
      const a = setup('b4', { tmux: true, integrated: false, running: true })
      expect(pasteContextStale(a.ctx, T0 + PASTE_CONTEXT_MS)).toBeNull()
      const b = setup('b5', { tmux: true, integrated: false, running: false, atPrompt: true })
      expect(pasteContextStale(b.ctx, T0 + PASTE_CONTEXT_MS)).toBeNull()
    })
    it('fără tmux (pty / telnet) citirile sunt reale: 30 s chiar fără integration', () => {
      const { ctx } = setup('b6', { tmux: false, integrated: false, running: false, atPrompt: false })
      expect(pasteContextStale(ctx, T0 + PASTE_CONTEXT_MS)).toBeNull()
    })
    it('ţintă fără `shellIntegration` (SessionView vechi) sub tmux = oarbă (fail-closed)', () => {
      const sent: string[] = []
      reg('b7', { send: (x: string) => { sent.push(x); return true }, bracketedPaste: () => false, viaTmux: () => true,
                  inputSeq: () => 0, isActive: () => true, activeEpoch: () => 0, keyboardHere: () => true })
      const ctx = capturePasteContext('b7', T0)!
      expect(pasteContextStale(ctx, T0 + PASTE_CONTEXT_BLIND_MS)).toBeNull()
      expect(pasteContextStale(ctx, T0 + PASTE_CONTEXT_BLIND_MS + 1)).toBe('blind')
    })
    it('o citire care aruncă = fără integration (fail-closed)', () => {
      const { target, ctx } = setup('b8', { tmux: true, integrated: false, running: false })
      target.shellIntegration = () => { throw new Error('x') }
      expect(pasteContextStale(ctx, T0 + PASTE_CONTEXT_BLIND_MS + 1)).toBe('blind')
    })
  })
})

describe('isSafeToType: toată categoria Cf + tag-urile (review L4)', () => {
  it('refuză formatele invizibile', () => {
    for (const ch of ['\u061c', '\u180e', '\u2060', '\u2061', '\u2064', '\ufff9', '\ufffb', '\xad', '\u{e0001}', '\u{e0000}', '\u{e007f}', '\u200b', '\ufeff']) {
      expect(isSafeToType(`a${ch}b`), ch.codePointAt(0)!.toString(16)).toBe(false)
    }
  })
  it('acceptă căi normale (diacritice, spaţii, emoji)', () => {
    expect(isSafeToType('/home/u/raport ședință (2).png')).toBe(true)
    expect(isSafeToType('/tmp/😀.png')).toBe(true)
  })
})

describe('typingElsewhere (focusul nu e smuls dintr-un câmp al paginii — review M1)', () => {
  const el = (tagName: string, editable = false) => ({ tagName, isContentEditable: editable }) as unknown as Element
  it('câmpuri ale paginii → da; terminalul însuşi / nimic / buton → nu', () => {
    const own = el('TEXTAREA')
    expect(typingElsewhere(own, el('INPUT'))).toBe(true)
    expect(typingElsewhere(own, el('TEXTAREA'))).toBe(true)
    expect(typingElsewhere(own, el('DIV', true))).toBe(true)
    expect(typingElsewhere(own, own)).toBe(false)
    expect(typingElsewhere(own, null)).toBe(false)
    expect(typingElsewhere(own, el('BUTTON'))).toBe(false)
  })
})
