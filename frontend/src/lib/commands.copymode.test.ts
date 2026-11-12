import { describe, expect, it } from 'vitest'
import type { Terminal } from '@xterm/xterm'
import { CommandTracker } from './commands'
import type { CommandGuard } from './api'
import { judgeLocal } from './broadcastGuard'

// Rotiţa în tmux (mouse on) intră în copy-mode: tmux îşi pictează istoricul derulând în regiunea de
// deasupra barei de stare, deci rândurile împinse jos sunt ŞTERSE din bufferul xterm împreună cu
// markerii lor. La ieşire, ecranul e repictat pe loc, exact cum era. Ecranul fals de aici face la fel.
function tmuxScreen(init: string[], cursor: { row: number; col: number }, cols = 40) {
  const rows = init.slice()
  const markers: { line: number; isDisposed: boolean; dispose(): void }[] = []
  const buffer = {
    type: 'normal', baseY: 0,
    get cursorY() { return cursor.row }, get cursorX() { return cursor.col },
    getLine: (r: number) => (r >= 0 && r < rows.length
      ? { length: cols, isWrapped: false, translateToString: (trim: boolean, from = 0, to?: number) => {
          const s = rows[r].padEnd(cols).slice(from, to)
          return trim ? s.replace(/\s+$/, '') : s
        } }
      : undefined),
  }
  const term = {
    cols, rows: rows.length, buffer: { active: buffer },
    registerMarker: (off = 0) => {
      const m = { line: cursor.row + off, isDisposed: false, dispose() { m.isDisposed = true } }
      markers.push(m)
      return m
    },
  } as unknown as Terminal & { cols: number; rows: number }
  /** copy-mode: k rânduri de istoric intră sus, ultimele k din regiune (fără bara de jos) sunt şterse */
  const scrollHistory = (k: number) => {
    const last = rows.length - 2
    for (const m of markers) {
      if (m.isDisposed) continue
      if (m.line > last - k && m.line <= last) { m.isDisposed = true; m.line = -1 }
      else if (m.line <= last) m.line += k
    }
    for (let i = last; i >= 0; i--) rows[i] = i - k >= 0 ? rows[i - k] : `history ${i}`
    cursor.row = 0; cursor.col = 0                      // cursorul de copy-mode
  }
  /** ieşirea din copy-mode: tmux repictează rândurile pe loc (markerii nu se mişcă) */
  const repaint = (live: string[], cur: { row: number; col: number }) => {
    live.forEach((t, i) => { rows[i] = t })
    cursor.row = cur.row; cursor.col = cur.col
  }
  return { term, rows, cursor, markers, scrollHistory, repaint }
}

const guard: CommandGuard = { enabled: true, rules: [{ pattern: 'rm\\s+-rf', action: 'block' }] }
const verdict = (tr: CommandTracker) => judgeLocal({ atPrompt: tr.atPrompt(), echoed: true, pending: tr.pendingCommand(),
  pendingAlts: tr.pendingVariants(), pendingBelow: tr.pendingBelow(), unechoed: [], lineLost: tr.promptLost }, guard, true)

/** `ls` rulat, prompt la rândul 3, bara de stare tmux pe ultimul rând */
function setup(tmux = true) {
  const live = ['$ ls', 'a  b  c', '', '$ ', '', '', '[0] bash']
  const s = tmuxScreen(live, { row: 3, col: 2 })
  const tr = new CommandTracker(s.term)
  tr.tmuxBacked = tmux
  tr.handle('B')
  tr.notePromptPainted(true)
  return { ...s, tr, live }
}

describe('CommandTracker: linia supravieţuieşte copy-mode-ului tmux (rotiţă → tastare → Enter)', () => {
  it('fără instantaneu (logica veche): rândul promptului şters de copy-mode → linie necunoscută', () => {
    const { tr, scrollHistory, repaint, live } = setup()
    scrollHistory(5)
    repaint(live.map((t, i) => (i === 3 ? '$ rm -rf /srv' : t)), { row: 3, col: 13 })
    tr.endChunk()
    expect(tr.promptLostReason()).toBe('marker-gone')
    expect(verdict(tr).kind).toBe('unknown')
  })

  it('cu instantaneu la raportul de mouse: după repictare linia se citeşte din nou, regula prinde', () => {
    const { tr, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    scrollHistory(5)
    tr.endChunk()                                       // în copy-mode: ecranul nu se potriveşte, nimic refăcut
    expect(tr.promptLost).toBe(true)
    repaint(live.map((t, i) => (i === 3 ? '$ rm -rf /srv' : t)), { row: 3, col: 13 })
    tr.endChunk()
    expect(tr.promptLost).toBe(false)
    expect(tr.pendingCommand()).toBe('rm -rf /srv')
    const v = verdict(tr)
    expect(v.kind).toBe('rule')
  })

  it('o linie inofensivă tastată după scroll trece fără dialog', () => {
    const { tr, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    scrollHistory(3)
    repaint(live.map((t, i) => (i === 3 ? '$ echo hi' : t)), { row: 3, col: 9 })
    tr.endChunk()
    expect(verdict(tr).kind).toBe('ok')
  })

  it('output sosit cât era în istoric (ecranul s-a mişcat): nimic refăcut, linia rămâne necunoscută', () => {
    const { tr, scrollHistory, repaint } = setup()
    tr.noteMouseReport()
    scrollHistory(5)
    repaint(['a  b  c', '', '$ BGOUT', '$ rm -rf /srv', '', '', '[0] bash'], { row: 3, col: 13 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
    expect(verdict(tr).kind).toBe('unknown')
  })

  it('un rând de deasupra promptului schimbat → nimic refăcut', () => {
    const { tr, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    scrollHistory(5)
    repaint(live.map((t, i) => (i === 2 ? 'x' : i === 3 ? '$ rm -rf /' : t)), { row: 3, col: 10 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
  })

  it('cursorul mai sus decât la instantaneu → nimic refăcut', () => {
    const { tr, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    scrollHistory(5)
    repaint(live, { row: 1, col: 0 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
  })

  it('terminal redimensionat între timp → nimic refăcut', () => {
    const { tr, term, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    scrollHistory(5)
    ;(term as unknown as { cols: number }).cols = 41
    repaint(live, { row: 3, col: 2 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
  })

  it('fără tmux (pty simplu) nu se ia instantaneu', () => {
    const { tr, scrollHistory, repaint, live } = setup(false)
    tr.noteMouseReport()
    scrollHistory(5)
    repaint(live, { row: 3, col: 2 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
  })

  it('un B nou uită instantaneul (nu se reface o poziţie veche)', () => {
    const { tr, cursor, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    cursor.row = 5; cursor.col = 2
    tr.handle('B')                                      // prompt nou (rândul 5)
    scrollHistory(6)
    repaint(live, { row: 3, col: 2 })                   // ecranul de la vechiul instantaneu
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
  })

  it('instantaneul nu se ia cât linia e deja necunoscută', () => {
    const { tr, rows, cursor, scrollHistory, repaint } = setup()
    // promptul redesenat sus fără B (Ctrl+L): pierdut înainte de rotiţă
    for (let i = 0; i < 6; i++) rows[i] = ''
    rows[0] = '$ '; cursor.row = 0; cursor.col = 2
    expect(tr.promptLost).toBe(true)
    tr.noteMouseReport()
    const snap = rows.slice()
    scrollHistory(5)
    repaint(snap, { row: 0, col: 2 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
  })

  it('a doua derulare cu acelaşi prompt: instantaneul rămâne valabil cât textul doar a crescut', () => {
    const { tr, scrollHistory, repaint, live } = setup()
    tr.noteMouseReport()
    scrollHistory(4)
    repaint(live.map((t, i) => (i === 3 ? '$ echo a; ' : t)), { row: 3, col: 10 })
    tr.endChunk()
    expect(tr.promptLost).toBe(false)
    tr.noteMouseReport()                               // instantaneul există deja: nu se înlocuieşte
    scrollHistory(4)
    repaint(live.map((t, i) => (i === 3 ? '$ echo a; rm -rf /x' : t)), { row: 3, col: 19 })
    tr.endChunk()
    expect(tr.promptLost).toBe(false)
    expect(verdict(tr).kind).toBe('rule')
  })

  it('markeri vii dar mutaţi (nu şterşi): nu se reface nimic, chiar dacă ecranul arată ca instantaneul', () => {
    const { tr, markers, rows, repaint, live } = setup()
    tr.noteMouseReport()
    for (const m of markers) if (!m.isDisposed) m.line += 1   // mutat (ex. output), nu şters
    rows[4] = ''
    repaint(live.map((t, i) => (i === 3 ? '$ rm -rf /' : t)), { row: 3, col: 10 })
    tr.endChunk()
    expect(tr.promptLost).toBe(true)
    expect(verdict(tr).kind).toBe('unknown')
  })

  it('o tastă trimisă cât linia e cunoscută uită instantaneul; una trimisă cât e pierdută nu', () => {
    const a = setup()
    a.tr.noteMouseReport()
    a.tr.noteKeySent()                                  // linia cunoscută: instantaneul nu mai e valabil
    a.scrollHistory(5)
    a.repaint(a.live, { row: 3, col: 2 })
    a.tr.endChunk()
    expect(a.tr.promptLost).toBe(true)
    const b = setup()
    b.tr.noteMouseReport()
    b.scrollHistory(5)
    b.tr.noteKeySent()                                  // tasta care scoate din copy-mode: linia e pierdută
    b.repaint(b.live.map((t, i) => (i === 3 ? '$ x' : t)), { row: 3, col: 3 })
    b.tr.endChunk()
    expect(b.tr.promptLost).toBe(false)
  })
})

// review (F1): un instantaneu vechi + text care ajunge la aceleaşi rânduri ale ecranului puneau promptul
// în MIJLOCUL liniei — se judeca doar coada („ls"), iar shell-ul rula `rm -rf ~ … $ ls`
describe('CommandTracker: instantaneul nu poate pune promptul în mijlocul liniei', () => {
  function poc(sendKey: boolean) {
    const cols = 10
    const lines: { t: string; w: boolean }[] = [{ t: 'out', w: false }, { t: '', w: false }, { t: '$ ', w: false }]
    const cur = { row: 2, col: 2 }
    let baseY = 0
    const markers: { line: number; isDisposed: boolean; dispose(): void }[] = []
    const mkLine = (r: number) => {
      const L = lines[r]
      if (!L) return undefined
      const s = L.t.padEnd(cols)
      return { length: cols, isWrapped: L.w,
        translateToString: (trim: boolean, f = 0, to?: number) => { const x = s.slice(f, to); return trim ? x.replace(/\s+$/, '') : x },
        getCell: (x: number) => ({ getChars: () => (x < L.t.length ? L.t[x] : ''), getWidth: () => 1 }) }
    }
    const buffer = { type: 'normal', get baseY() { return baseY }, get cursorY() { return cur.row - baseY }, get cursorX() { return cur.col }, getLine: mkLine }
    const term = { cols, rows: 3, buffer: { active: buffer }, registerMarker: (off = 0) => {
      const m = { line: cur.row + off, isDisposed: false, dispose() { m.isDisposed = true } }
      markers.push(m)
      return m
    } } as unknown as Terminal
    const tr = new CommandTracker(term)
    tr.tmuxBacked = true
    tr.handle('B')
    tr.notePromptPainted(true)
    tr.noteMouseReport()
    // paste fără newline: `rm -rf ~`, un rând plin de spaţii, `$ ls` — ecranul derulează 2 rânduri
    if (sendKey) tr.noteKeySent()
    lines[2] = { t: '$ rm -rf ~', w: false }; lines[3] = { t: '          ', w: true }; lines[4] = { t: '$ ls', w: true }
    baseY = 2; cur.row = 4; cur.col = 4
    tr.endChunk()
    expect(verdict(tr).kind).toBe('rule')
    // a doua rotiţă: copy-mode şterge markerii, tmux repictează fără steagurile de wrap
    for (const m of markers) { m.isDisposed = true; m.line = -1 }
    lines[3].w = false; lines[4].w = false
    tr.endChunk()
    return tr
  }
  it('fără noteKeySent: rândul de deasupra continuă în „prompt" → refuzat, linia rămâne necunoscută', () => {
    const tr = poc(false)
    expect(tr.promptLost).toBe(true)
    expect(verdict(tr).kind).toBe('unknown')
  })
  it('cu tasta trimisă (calea reală din SessionView): instantaneul a fost uitat → necunoscută', () => {
    const tr = poc(true)
    expect(tr.promptLost).toBe(true)
    expect(verdict(tr).kind).toBe('unknown')
  })
})

