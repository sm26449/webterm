/* Modelul keybar-ului tactil (MobileKeybar), separat ca să fie testabil: CE taste sunt pe care
   rând şi CÂTE rânduri se văd. Secvenţele sunt aceleaşi ca înainte de împărţirea pe rânduri —
   s-a schimbat doar aşezarea (un singur rând derulant ascundea tastele din dreapta). */
import { lsGet, lsSet } from './storage'

const WHEEL_UP = '\x1b[<64;40;10M'.repeat(3) // rapoarte SGR de rotiță: tmux
const WHEEL_DOWN = '\x1b[<65;40;10M'.repeat(3) // derulează istoricul (copy-mode)

// `aria`: eticheta citită de cititorul de ecran — glifele (⇞ ↑ ^C |) sunt mute sau citite
// ca „caret C". Cheie de catalog (`keybar.*`) sau text neutru (Escape/Tab/Ctrl+C sunt la fel
// în orice limbă).
// `wheel`: rapoarte de rotiţă pentru tmux — NU primesc modificatori (n-ar mai fi rotiţă).
export type KeyDef = { label: string; seq: string; aria: string; wheel?: boolean }

/** Rândul 1: ce-ţi trebuie mereu (Ctrl/Alt sunt randate separat, ca modificatori latch-uiţi). */
export const ROW1: KeyDef[] = [
  { label: 'Esc', seq: '\x1b', aria: 'Escape' },
  { label: 'Tab', seq: '\t', aria: 'Tab' },
  { label: '↑', seq: '\x1b[A', aria: 'keybar.up' },
  { label: '↓', seq: '\x1b[B', aria: 'keybar.down' },
  { label: '←', seq: '\x1b[D', aria: 'keybar.left' },
  { label: '→', seq: '\x1b[C', aria: 'keybar.right' },
]

/** Rândul 2: restul, în ordinea frecvenţei (lipirea ⎘ e randată separat, prima). */
export const ROW2: KeyDef[] = [
  { label: '^C', seq: '\x03', aria: 'Ctrl+C' },
  { label: '^D', seq: '\x04', aria: 'Ctrl+D' },
  { label: '⇞', seq: WHEEL_UP, aria: 'keybar.scrollUp', wheel: true },
  { label: '⇟', seq: WHEEL_DOWN, aria: 'keybar.scrollDown', wheel: true },
  { label: '|', seq: '|', aria: 'keybar.pipe' },
  { label: '/', seq: '/', aria: 'keybar.slash' },
  { label: '-', seq: '-', aria: 'keybar.dash' },
  { label: '~', seq: '~', aria: 'keybar.tilde' },
  // tastele de navigare REALE (ce trimite xterm pentru Home/End/PgUp/PgDn), nu rotiţa tmux de
  // mai sus: less/vim/htop/readline le înţeleg; ⇞/⇟ rămân pentru derularea istoricului tmux
  { label: 'Home', seq: '\x1b[H', aria: 'keybar.home' },
  { label: 'End', seq: '\x1b[F', aria: 'keybar.end' },
  { label: 'PgUp', seq: '\x1b[5~', aria: 'keybar.pageUp' },
  { label: 'PgDn', seq: '\x1b[6~', aria: 'keybar.pageDown' },
  { label: '^Z', seq: '\x1a', aria: 'Ctrl+Z' },
  { label: '^R', seq: '\x12', aria: 'Ctrl+R' },
]

/** Rândurile pentru un backend: ⇞/⇟ injectează rapoarte de rotiţă SGR pe care doar tmux le
    interpretează; pe backend „pty" (fără tmux) octeţii ar ajunge tastaţi în shell ca gunoi. */
export function keybarRows(backend?: string | null): { row1: KeyDef[]; row2: KeyDef[] } {
  const keep = (k: KeyDef) => backend === 'tmux' || !k.wheel
  return { row1: ROW1.filter(keep), row2: ROW2.filter(keep) }
}

/** Sub înălţimea asta (telefon în peisaj ~390px) două rânduri de 40px mănâncă prea mult terminal:
    keybar-ul se strânge la rândul 1 + un comutator „mai multe taste". */
export const SHORT_VIEWPORT_PX = 420
export const SHORT_VIEWPORT_QUERY = `(max-height: ${SHORT_VIEWPORT_PX - 0.02}px)`

/** Câte rânduri se văd şi dacă apare comutatorul. Pe viewport înalt: mereu 2, fără comutator
    (preferinţa nu contează). Pe viewport scund: 1 rând implicit, 2 dacă userul a extins. */
export function keybarLayout(short: boolean, expanded: boolean): { rows: 1 | 2; toggle: boolean } {
  if (!short) return { rows: 2, toggle: false }
  return { rows: expanded ? 2 : 1, toggle: true }
}

/** Preferinţa „extins pe viewport scund" — per dispozitiv (localStorage), nu per cont: un telefon
    şi o tabletă ale aceluiaşi om vor alegeri diferite. */
export const KEYBAR_EXPANDED_KEY = 'wt_keybar_expanded'

export const readKeybarExpanded = (): boolean => lsGet(KEYBAR_EXPANDED_KEY) === '1'

export const writeKeybarExpanded = (v: boolean): void => lsSet(KEYBAR_EXPANDED_KEY, v ? '1' : '0')
