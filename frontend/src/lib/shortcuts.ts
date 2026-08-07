/** Registrul UNIC de scurtături: sursa de adevăr pentru handler-ul global,
    pentru overlay-ul „?" și pentru hint-urile din UI. O scurtătură nouă se
    adaugă AICI, nu într-un handler ad-hoc — altfel cheatsheet-ul minte.

    Reguli de proiectare (terminalul e prioritar):
    - nimic pe combinații pe care shell-ul le folosește (Ctrl+C/D/L/R/W/U…);
    - acțiunile de aplicație stau pe Ctrl/Cmd+Shift+* sau Alt+*;
    - identificarea se face pe `code` (Alt+cifră/literă pe macOS produce
      caractere alternative în `key`: „¡", „∑"…). */

export type ShortcutId =
  | 'palette' | 'help' | 'search' | 'closeTab' | 'reopenTab'
  | 'nextTab' | 'prevTab' | 'split' | 'popout'
  | 'fontUp' | 'fontDown' | 'snippets' | 'focusSidebar' | 'home'

export interface Shortcut {
  id: ShortcutId
  keys: string
  group: 'nav' | 'session' | 'app'
  match: (e: KeyboardEvent) => boolean
}

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)
/** modificatorul „de aplicație": ⌘ pe mac, Ctrl în rest */
const mod = (e: KeyboardEvent) => (isMac ? e.metaKey : e.ctrlKey)
const noAlt = (e: KeyboardEvent) => !e.altKey
const altOnly = (e: KeyboardEvent) => e.altKey && !e.metaKey && !e.ctrlKey

export const SHORTCUTS: Shortcut[] = [
  { id: 'palette', keys: 'Mod+K', group: 'app',
    // ⌘K oriunde; Ctrl+K doar în afara terminalului (în shell = kill-line);
    // Mod+Shift+K rămâne portița universală (tratată în handler)
    match: (e) => e.code === 'KeyK' && mod(e) && noAlt(e) },
  { id: 'help', keys: '?', group: 'app',
    match: (e) => e.key === '?' && !mod(e) && !e.altKey },
  { id: 'search', keys: 'Mod+Shift+F', group: 'session',
    match: (e) => e.code === 'KeyF' && mod(e) && e.shiftKey && noAlt(e) },
  { id: 'closeTab', keys: 'Mod+Shift+W', group: 'nav',
    match: (e) => e.code === 'KeyW' && mod(e) && e.shiftKey && noAlt(e) },
  { id: 'reopenTab', keys: 'Mod+Shift+T', group: 'nav',
    match: (e) => e.code === 'KeyT' && mod(e) && e.shiftKey && noAlt(e) },
  { id: 'nextTab', keys: 'Alt+→', group: 'nav',
    match: (e) => e.code === 'ArrowRight' && altOnly(e) },
  { id: 'prevTab', keys: 'Alt+←', group: 'nav',
    match: (e) => e.code === 'ArrowLeft' && altOnly(e) },
  { id: 'split', keys: 'Alt+D', group: 'session',
    match: (e) => e.code === 'KeyD' && altOnly(e) },
  { id: 'popout', keys: 'Alt+P', group: 'session',
    match: (e) => e.code === 'KeyP' && altOnly(e) },
  { id: 'fontUp', keys: 'Alt++', group: 'session',
    match: (e) => (e.code === 'Equal' || e.code === 'NumpadAdd') && altOnly(e) },
  { id: 'fontDown', keys: 'Alt+−', group: 'session',
    match: (e) => (e.code === 'Minus' || e.code === 'NumpadSubtract') && altOnly(e) },
  { id: 'snippets', keys: 'Alt+S', group: 'session',
    match: (e) => e.code === 'KeyS' && altOnly(e) },
  { id: 'focusSidebar', keys: '/', group: 'app',
    match: (e) => e.key === '/' && !mod(e) && !e.altKey },
  { id: 'home', keys: 'Alt+0', group: 'nav',
    match: (e) => e.code === 'Digit0' && altOnly(e) },
]

/** Eticheta pentru afișare, cu simbolurile potrivite platformei. */
export function fmt(keys: string): string {
  return isMac
    ? keys.replace('Mod', '⌘').replace('Alt', '⌥').replace('Shift', '⇧')
    : keys.replace('Mod', 'Ctrl')
}

/** Prima scurtătură care se potrivește evenimentului (sau null). */
export function matchShortcut(e: KeyboardEvent): ShortcutId | null {
  for (const s of SHORTCUTS) if (s.match(e)) return s.id
  return null
}

export const shortcutFor = (id: ShortcutId): string =>
  fmt(SHORTCUTS.find((s) => s.id === id)?.keys ?? '')
