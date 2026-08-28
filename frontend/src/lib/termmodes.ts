import type { IModes } from '@xterm/xterm'

// Starea DECSET/SM a terminalului, ca secvențe care o refac după un reset().
// La resume, reset()-ul șterge modurile pe care tmux le crede încă active:
// mouse-tracking (fără el wheel-ul nu mai ajunge în copy-mode-ul tmux — „nu
// merge scroll-ul"), bracketed paste, focus events, săgețile în mod aplicație.
// tmux le retrimite DOAR la attach/resize — verificat empiric: refresh-client
// redesenează conținutul, nu și modurile; de-aia A± (un resize) „repara" scrollul.
// Replay-ul nu le conține aproape niciodată (au curs la attach, demult), deci le
// refacem local, ÎNAINTE de tail — comutările mai noi din tail câștigă oricum.
export function modeRestoreSeq(m: IModes): string {
  let s = ''
  if (m.applicationCursorKeysMode) s += '\x1b[?1h'
  if (m.applicationKeypadMode) s += '\x1b[?66h'
  if (m.originMode) s += '\x1b[?6h'
  if (!m.wraparoundMode) s += '\x1b[?7l'          // singurul cu default ON
  if (m.reverseWraparoundMode) s += '\x1b[?45h'
  if (m.sendFocusMode) s += '\x1b[?1004h'
  if (m.bracketedPasteMode) s += '\x1b[?2004h'
  if (m.insertMode) s += '\x1b[4h'
  const mouse = { x10: '\x1b[?9h', vt200: '\x1b[?1000h', drag: '\x1b[?1002h', any: '\x1b[?1003h' }[
    m.mouseTrackingMode as 'x10' | 'vt200' | 'drag' | 'any'] ?? ''
  if (mouse) {
    // xterm nu expune encoding-ul de mouse; singurul emitent aici e tmux, care
    // folosește SGR (?1006) — fără el, coordonatele peste coloana 223 se strică
    s += mouse + '\x1b[?1006h'
  }
  return s
}
