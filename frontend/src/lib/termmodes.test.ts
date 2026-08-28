import { describe, expect, it } from 'vitest'
import type { IModes } from '@xterm/xterm'
import { modeRestoreSeq } from './termmodes'

// Bug reparat în 2.0.9: la resume, term.reset() ștergea modurile DECSET pe care tmux
// le credea încă active — mouse-tracking (scroll-ul = copy-mode tmux), bracketed paste,
// focus events. Secvența de restaurare trebuie să refacă EXACT ce era activ, nimic în plus.
const base: IModes = {
  applicationCursorKeysMode: false,
  applicationKeypadMode: false,
  bracketedPasteMode: false,
  insertMode: false,
  mouseTrackingMode: 'none',
  originMode: false,
  reverseWraparoundMode: false,
  sendFocusMode: false,
  wraparoundMode: true,
}

describe('modeRestoreSeq', () => {
  it('starea implicită (post-reset) nu produce nimic', () => {
    expect(modeRestoreSeq(base)).toBe('')
  })

  it('profilul tmux (mouse on): tracking + SGR, paste, focus', () => {
    const s = modeRestoreSeq({
      ...base, mouseTrackingMode: 'drag', bracketedPasteMode: true, sendFocusMode: true,
    })
    expect(s).toContain('\x1b[?1002h')   // drag tracking — ce setează tmux cu mouse on
    expect(s).toContain('\x1b[?1006h')   // SGR: fără el, coordonatele >223 se strică
    expect(s).toContain('\x1b[?2004h')   // bracketed paste — altfel paste-ul intră „crud"
    expect(s).toContain('\x1b[?1004h')   // focus events (Claude Code, vim autoread)
  })

  it('fiecare nivel de mouse-tracking își are secvența', () => {
    expect(modeRestoreSeq({ ...base, mouseTrackingMode: 'x10' })).toContain('\x1b[?9h')
    expect(modeRestoreSeq({ ...base, mouseTrackingMode: 'vt200' })).toContain('\x1b[?1000h')
    expect(modeRestoreSeq({ ...base, mouseTrackingMode: 'any' })).toContain('\x1b[?1003h')
  })

  it('wraparound e singurul cu default ON: doar dezactivarea se re-asertează', () => {
    expect(modeRestoreSeq(base)).not.toContain('\x1b[?7')
    expect(modeRestoreSeq({ ...base, wraparoundMode: false })).toContain('\x1b[?7l')
  })

  it('săgețile în mod aplicație și restul modurilor booleene', () => {
    const s = modeRestoreSeq({
      ...base, applicationCursorKeysMode: true, applicationKeypadMode: true,
      originMode: true, reverseWraparoundMode: true, insertMode: true,
    })
    for (const seq of ['\x1b[?1h', '\x1b[?66h', '\x1b[?6h', '\x1b[?45h', '\x1b[4h']) {
      expect(s).toContain(seq)
    }
  })
})
