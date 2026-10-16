import { describe, expect, it } from 'vitest'
import {
  EMPTY_HISTORY, HISTORY_MAX, baseName, canBack, canForward, cdCommand, commonPrefix, completePath, crumbs,
  histPush, histStep, parentOf, splitForCompletion, targetPath, typeJump,
} from './filesNav'

describe('targetPath (ţinte vechi după schimbarea directorului, review M2)', () => {
  it('acelaşi director → calea completă', () => {
    expect(targetPath('/srv/a', '/srv/a', 'x.txt')).toBe('/srv/a/x.txt')
    expect(targetPath('/', '/', 'etc')).toBe('/etc')
  })
  it('directorul s-a schimbat (follow cwd / wt-open-files / navigare) → null, nu /nou/<acelaşi nume>', () => {
    expect(targetPath('/srv/a', '/srv/b', 'x.txt')).toBeNull()
    expect(targetPath('/srv/a', null, 'x.txt')).toBeNull()
    expect(targetPath('/srv/a', undefined, 'x.txt')).toBeNull()
  })
  it('nume / director gol → null', () => {
    expect(targetPath('', '', 'x')).toBeNull()
    expect(targetPath('/a', '/a', '')).toBeNull()
  })
})
import { filesShortcuts, matchFilesShortcut, matchShortcut } from './shortcuts'

describe('crumbs (firimiturile căii)', () => {
  it('cale absolută → rădăcina + fiecare segment cu calea lui', () => {
    expect(crumbs('/var/log/nginx')).toEqual([
      { label: '/', path: '/' }, { label: 'var', path: '/var' },
      { label: 'log', path: '/var/log' }, { label: 'nginx', path: '/var/log/nginx' },
    ])
  })
  it('rădăcina singură, slash-uri duble / finale', () => {
    expect(crumbs('/')).toEqual([{ label: '/', path: '/' }])
    expect(crumbs('//srv//data/')).toEqual([
      { label: '/', path: '/' }, { label: 'srv', path: '/srv' }, { label: 'data', path: '/srv/data' },
    ])
  })
  it('~ (înainte de prima listare) şi gol', () => {
    expect(crumbs('~')).toEqual([{ label: '~', path: '~' }])
    expect(crumbs('~/a/b')).toEqual([{ label: '~', path: '~' }, { label: 'a', path: '~/a' }, { label: 'b', path: '~/a/b' }])
    expect(crumbs('')).toEqual([])
  })
  it('nume cu spaţii / diacritice rămân un singur segment', () => {
    expect(crumbs('/tmp/raport ședință (2)').map((c) => c.label)).toEqual(['/', 'tmp', 'raport ședință (2)'])
  })
  it('parentOf / baseName', () => {
    expect(parentOf('/a/b')).toBe('/a')
    expect(parentOf('/a')).toBe('/')
    expect(parentOf('/')).toBe('/')
    expect(parentOf('/a/b/')).toBe('/a')
    expect(baseName('/a/b/')).toBe('b')
    expect(baseName('/')).toBe('')
  })
})

describe('istoric înapoi / înainte', () => {
  it('push, back, forward; un push nou taie „înainte"-ul', () => {
    let h = histPush(EMPTY_HISTORY, '/a')
    expect(canBack(h)).toBe(false)
    h = histPush(h, '/b')
    h = histPush(h, '/c')
    expect(canBack(h)).toBe(true)
    expect(canForward(h)).toBe(false)
    const b = histStep(h, -1)!
    expect(b.path).toBe('/b')
    expect(canForward(b.hist)).toBe(true)
    const f = histStep(b.hist, 1)!
    expect(f.path).toBe('/c')
    h = histPush(b.hist, '/x')                         // din /b pe /x: /c dispare
    expect(h.stack).toEqual(['/a', '/b', '/x'])
    expect(canForward(h)).toBe(false)
  })
  it('acelaşi director (reload, follow pe acelaşi cwd) nu adaugă nimic', () => {
    const h = histPush(histPush(EMPTY_HISTORY, '/a'), '/a')
    expect(h.stack).toEqual(['/a'])
  })
  it('la capete histStep întoarce null', () => {
    const h = histPush(EMPTY_HISTORY, '/a')
    expect(histStep(h, -1)).toBeNull()
    expect(histStep(h, 1)).toBeNull()
    expect(histStep(EMPTY_HISTORY, -1)).toBeNull()
  })
  it('plafonat la HISTORY_MAX intrări (cele mai vechi ies)', () => {
    let h = EMPTY_HISTORY
    for (let i = 0; i < HISTORY_MAX + 10; i++) h = histPush(h, `/d${i}`)
    expect(h.stack.length).toBe(HISTORY_MAX)
    expect(h.stack[0]).toBe('/d10')
    expect(h.idx).toBe(HISTORY_MAX - 1)
    expect(h.stack[h.idx]).toBe(`/d${HISTORY_MAX + 9}`)
  })
})

describe('typeJump (tastează ca să sari)', () => {
  const names = ['alpha', 'Apple', 'beta', 'bin', 'boot', 'etc']
  it('prefix, fără să ţină cont de majuscule, primul după rândul curent', () => {
    expect(typeJump(names, 'b', 0)).toBe(2)
    expect(typeJump(names, 'e', 0)).toBe(5)
    expect(typeJump(names, 'BO', 0)).toBe(4)
  })
  it('mai multe litere: rândul curent rămâne dacă se potriveşte deja', () => {
    expect(typeJump(names, 'bi', 3)).toBe(3)
    expect(typeJump(names, 'ap', 1)).toBe(1)
  })
  it('aceeaşi literă repetată ciclează prin numele cu acea literă (cu ocol)', () => {
    expect(typeJump(names, 'b', 2)).toBe(3)
    expect(typeJump(names, 'bb', 3)).toBe(4)
    expect(typeJump(names, 'bbb', 4)).toBe(2)
    expect(typeJump(names, 'a', 1)).toBe(0)
  })
  it('nicio potrivire / listă goală → -1', () => {
    expect(typeJump(names, 'z', 0)).toBe(-1)
    expect(typeJump([], 'a', 0)).toBe(-1)
    expect(typeJump(names, '', 0)).toBe(-1)
  })
  it('nume cu diacritice / spaţii / puncte', () => {
    expect(typeJump(['.bashrc', 'ședință', 'my file'], 'șe', 0)).toBe(1)
    expect(typeJump(['.bashrc', 'ședință', 'my file'], 'my ', 0)).toBe(2)
    expect(typeJump(['.bashrc', 'ședință', 'my file'], '.', 2)).toBe(0)
  })
})

describe('completarea cu Tab a ultimului segment', () => {
  it('splitForCompletion', () => {
    expect(splitForCompletion('/var/lo', '/x')).toEqual({ dir: '/var', prefix: 'lo' })
    expect(splitForCompletion('/var/', '/x')).toEqual({ dir: '/var', prefix: '' })
    expect(splitForCompletion('/va', '/x')).toEqual({ dir: '/', prefix: 'va' })
    expect(splitForCompletion('lo', '/x')).toEqual({ dir: '/x', prefix: 'lo' })
    expect(splitForCompletion('~/Do', '/x')).toEqual({ dir: '~', prefix: 'Do' })
    expect(splitForCompletion('~', '/x')).toEqual({ dir: '~', prefix: '' })
  })
  it('commonPrefix', () => {
    expect(commonPrefix(['local', 'locale', 'lock'])).toBe('loc')
    expect(commonPrefix(['a'])).toBe('a')
    expect(commonPrefix([])).toBe('')
  })
  const dirs = ['log', 'lib', 'local', 'lock', 'cache', '.hidden', 'Lab']
  it('un singur candidat → completat + /', () => {
    expect(completePath('/var/lo', '/', ['log'])).toEqual({ value: '/var/log/', candidates: [], more: 0 })
    expect(completePath('/var/ca', '/', dirs).value).toBe('/var/cache/')
  })
  it('mai mulţi → prefixul comun + candidaţii', () => {
    const r = completePath('/var/lo', '/', dirs)
    expect(r.value).toBe('/var/lo')                    // log / local / lock: nimic în comun peste „lo"
    expect(r.candidates).toEqual(['local', 'lock', 'log'])
    expect(completePath('/var/loc', '/', dirs)).toEqual({ value: '/var/loc', candidates: ['local', 'lock'], more: 0 })
    expect(completePath('/var/loca', '/', dirs).value).toBe('/var/local/')
  })
  it('majusculele: exact întâi, apoi fără', () => {
    expect(completePath('/v/La', '/', dirs).value).toBe('/v/Lab/')
    expect(completePath('/v/CA', '/', dirs).value).toBe('/v/cache/')
  })
  it('ascunsele doar când prefixul începe cu punct', () => {
    expect(completePath('/v/', '/', ['.hidden', 'x']).value).toBe('/v/x/')
    expect(completePath('/v/.h', '/', dirs).value).toBe('/v/.hidden/')
  })
  it('nume relativ → cale absolută din directorul listat; ~ → ~/', () => {
    expect(completePath('ca', '/var', dirs).value).toBe('/var/cache/')
    expect(completePath('~', '/var', ['Docs']).value).toBe('~/Docs/')
  })
  it('nimic → textul rămâne; candidaţii plafonaţi', () => {
    expect(completePath('/v/zz', '/', dirs)).toEqual({ value: '/v/zz', candidates: [], more: 0 })
    const many = Array.from({ length: 20 }, (_, i) => `d${String(i).padStart(2, '0')}`)
    const r = completePath('/v/d', '/', many)
    expect(r.candidates.length).toBe(8)
    expect(r.more).toBe(12)
    expect(r.value).toBe('/v/d')
  })
})

describe('cdCommand („cd aici" tastat în terminal, fără Enter)', () => {
  it('mereu între apostrofuri, cu --', () => {
    expect(cdCommand('/var/log')).toBe("cd -- '/var/log'")
    expect(cdCommand('/tmp/-rf')).toBe("cd -- '/tmp/-rf'")
    expect(cdCommand('~')).toBe("cd -- '~'")
  })
  it('caractere de shell rămân inerte (apostroful închide/redeschide citarea)', () => {
    expect(cdCommand("/tmp/it's")).toBe("cd -- '/tmp/it'\\''s'")
    expect(cdCommand('/tmp/$(id)`id`;rm -rf ~ &|>!')).toBe("cd -- '/tmp/$(id)`id`;rm -rf ~ &|>!'")
    expect(cdCommand('/tmp/a b')).toBe("cd -- '/tmp/a b'")
  })
  it('backslash-ul stă în afara apostrofului (fish: \\\' şi \\\\ sunt escape-uri şi între apostrofuri)', () => {
    expect(cdCommand('/tmp/a\\')).toBe("cd -- '/tmp/a'\\\\''")
    expect(cdCommand("/tmp/a\\'x;id;#")).toBe("cd -- '/tmp/a'\\\\''\\''x;id;#'")
  })
  it('refuză (null) controale, newline, ESC, bidi, zero-width, separatori de linie', () => {
    for (const bad of ['/tmp/a\nrm -rf /', '/tmp/a\r', '/tmp/\x1b[201~x', '/tmp/\x00', '/tmp/a‮b',
      '/tmp/a​b', '/tmp/a b', '/tmp/a⁦b', '/tmp/\x7f', '/tmp/\x9b', '']) {
      expect(cdCommand(bad)).toBeNull()
    }
  })
  it('diacritice / unicode obişnuit trec', () => {
    expect(cdCommand('/srv/ședință 日本')).toBe("cd -- '/srv/ședință 日本'")
  })
})

describe('scurtăturile listei de fişiere (registrul `files`)', () => {
  const ev = (key: string, code: string, o: Partial<KeyboardEvent> = {}) =>
    ({ key, code, altKey: false, metaKey: false, ctrlKey: false, shiftKey: false, ...o }) as KeyboardEvent
  const linux = filesShortcuts(false)
  const mac = filesShortcuts(true)
  it('tastele de bază', () => {
    expect(matchFilesShortcut(ev('F2', 'F2'), linux)).toBe('filesRename')
    expect(matchFilesShortcut(ev('F7', 'F7'), linux)).toBe('filesNewFolder')
    expect(matchFilesShortcut(ev('n', 'KeyN', { altKey: true }), linux)).toBe('filesNewFile')
    expect(matchFilesShortcut(ev('u', 'KeyU', { ctrlKey: true }), linux)).toBe('filesUpload')
    expect(matchFilesShortcut(ev('F5', 'F5'), linux)).toBe('filesReload')
    expect(matchFilesShortcut(ev('r', 'KeyR', { ctrlKey: true }), linux)).toBe('filesReload')
    expect(matchFilesShortcut(ev('l', 'KeyL', { ctrlKey: true }), linux)).toBe('filesFocusPath')
    expect(matchFilesShortcut(ev('/', 'Slash'), linux)).toBe('filesFilter')
    expect(matchFilesShortcut(ev('F10', 'F10', { shiftKey: true }), linux)).toBe('filesMenu')
    expect(matchFilesShortcut(ev('ContextMenu', 'ContextMenu'), linux)).toBe('filesMenu')
    expect(matchFilesShortcut(ev('Backspace', 'Backspace'), linux)).toBe('filesUp')
    expect(matchFilesShortcut(ev('[', 'BracketLeft', { ctrlKey: true }), linux)).toBe('filesBack')
    expect(matchFilesShortcut(ev(']', 'BracketRight', { ctrlKey: true }), linux)).toBe('filesForward')
  })
  it('Ctrl+Shift+C = calea, Ctrl+C = numele', () => {
    expect(matchFilesShortcut(ev('C', 'KeyC', { ctrlKey: true, shiftKey: true }), linux)).toBe('filesCopyPath')
    expect(matchFilesShortcut(ev('c', 'KeyC', { ctrlKey: true }), linux)).toBe('filesCopyName')
  })
  it('„sus": Alt+↑ pe Linux/Windows, ⌘↑ pe macOS (nu invers)', () => {
    expect(matchFilesShortcut(ev('ArrowUp', 'ArrowUp', { altKey: true }), linux)).toBe('filesUp')
    expect(matchFilesShortcut(ev('ArrowUp', 'ArrowUp', { metaKey: true }), linux)).toBeNull()
    expect(matchFilesShortcut(ev('ArrowUp', 'ArrowUp', { metaKey: true }), mac)).toBe('filesUp')
    expect(matchFilesShortcut(ev('[', 'BracketLeft', { metaKey: true }), mac)).toBe('filesBack')
    expect(matchFilesShortcut(ev('[', 'BracketLeft', { ctrlKey: true }), mac)).toBeNull()
  })
  it('macOS: Option+N care tastează „˜" nu e scurtătură', () => {
    expect(matchFilesShortcut(ev('Dead', 'KeyN', { altKey: true }), mac)).toBeNull()
  })
  it('nimic pe Alt+←/→ (taburile rămân ale lor)', () => {
    expect(matchFilesShortcut(ev('ArrowLeft', 'ArrowLeft', { altKey: true }), linux)).toBeNull()
    expect(matchFilesShortcut(ev('ArrowRight', 'ArrowRight', { altKey: true }), linux)).toBeNull()
  })
  it('handler-ul GLOBAL nu vede grupul `files` (F2/F7 n-au voie să acţioneze din terminal)', () => {
    expect(matchShortcut(ev('F2', 'F2'))).toBeNull()
    expect(matchShortcut(ev('F7', 'F7'))).toBeNull()
    expect(matchShortcut(ev('u', 'KeyU', { ctrlKey: true }))).toBeNull()
    expect(matchShortcut(ev('e', 'KeyE', { altKey: true }))).toBe('toggleFiles')
  })
})
