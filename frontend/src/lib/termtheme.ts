import type { ITheme } from '@xterm/xterm'

/** Terminal color schemes. The 16 ANSI colors are what an operator actually sees
   99% of the time (errors, `git diff`, `ls`, vim, prompts) — xterm's built-in
   defaults are not calibrated for a near-black background, so we ship a proper
   palette. Selectable independently of the UI theme, persisted in localStorage. */
export type TermSchemeId = 'webterm-dark' | 'gruvbox-dark' | 'catppuccin-mocha'

export const TERM_SCHEMES: { id: TermSchemeId; name: string; theme: ITheme }[] = [
  {
    id: 'webterm-dark',
    name: 'WebTerm Dark',
    theme: {
      background: '#0b0e14', foreground: '#d6dee8',
      cursor: '#7dd3fc', cursorAccent: '#0b0e14',
      selectionBackground: '#2c3b57', selectionForeground: '#e6ebf1',
      black: '#3b4048', red: '#e06c75', green: '#98c379', yellow: '#e5c07b',
      blue: '#61afef', magenta: '#c678dd', cyan: '#56b6c2', white: '#abb2bf',
      brightBlack: '#5c6370', brightRed: '#ef8a94', brightGreen: '#b5e08f', brightYellow: '#f0d399',
      brightBlue: '#7ec5ff', brightMagenta: '#d99ae8', brightCyan: '#6fd0dd', brightWhite: '#e6ebf1',
    },
  },
  {
    id: 'gruvbox-dark',
    name: 'Gruvbox Dark',
    theme: {
      background: '#1d2021', foreground: '#ebdbb2',
      cursor: '#ebdbb2', cursorAccent: '#1d2021',
      selectionBackground: '#504945', selectionForeground: '#ebdbb2',
      black: '#282828', red: '#cc241d', green: '#98971a', yellow: '#d79921',
      blue: '#458588', magenta: '#b16286', cyan: '#689d6a', white: '#a89984',
      brightBlack: '#928374', brightRed: '#fb4934', brightGreen: '#b8bb26', brightYellow: '#fabd2f',
      brightBlue: '#83a598', brightMagenta: '#d3869b', brightCyan: '#8ec07c', brightWhite: '#ebdbb2',
    },
  },
  {
    id: 'catppuccin-mocha',
    name: 'Catppuccin Mocha',
    theme: {
      background: '#1e1e2e', foreground: '#cdd6f4',
      cursor: '#f5e0dc', cursorAccent: '#1e1e2e',
      selectionBackground: '#585b70', selectionForeground: '#cdd6f4',
      black: '#45475a', red: '#f38ba8', green: '#a6e3a1', yellow: '#f9e2af',
      blue: '#89b4fa', magenta: '#f5c2e7', cyan: '#94e2d5', white: '#bac2de',
      brightBlack: '#585b70', brightRed: '#f38ba8', brightGreen: '#a6e3a1', brightYellow: '#f9e2af',
      brightBlue: '#89b4fa', brightMagenta: '#f5c2e7', brightCyan: '#94e2d5', brightWhite: '#a6adc8',
    },
  },
]

const DEFAULT: TermSchemeId = 'webterm-dark'

// ── schemă proprie (editabilă din Setări / importată din iTerm2 sau VS Code) ──

const CUSTOM_KEY = 'wt_term_custom'

/** Cheile de culoare pe care le edităm/importăm (ordinea = ordinea din editor). */
export const COLOR_KEYS = [
  'background', 'foreground', 'cursor', 'selectionBackground',
  'black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',
  'brightBlack', 'brightRed', 'brightGreen', 'brightYellow',
  'brightBlue', 'brightMagenta', 'brightCyan', 'brightWhite',
] as const
export type ColorKey = (typeof COLOR_KEYS)[number]


/* Numele schemei importate. Era hardcodat „Schema mea" — românesc, într-un build englez,
   la doi paşi de cheile `settings.customScheme`. Modulul nu are acces la hook-ul de i18n
   (nu e componentă), deci exportăm identificatorul şi îl traduce cine îl afişează. */
export const CUSTOM_SCHEME_NAME = 'custom'

export function customTheme(): ITheme | null {
  try {
    const raw = localStorage.getItem(CUSTOM_KEY)
    if (!raw) return null
    const t = JSON.parse(raw) as ITheme
    return t && typeof t === 'object' && t.background ? t : null
  } catch {
    return null
  }
}

export function saveCustomTheme(theme: ITheme): void {
  localStorage.setItem(CUSTOM_KEY, JSON.stringify(theme))
  // cursorAccent lipsă ar lăsa cursorul invizibil pe fundaluri deschise
  window.dispatchEvent(new Event('wt-termscheme'))
}

export function clearCustomTheme(): void {
  localStorage.removeItem(CUSTOM_KEY)
  window.dispatchEvent(new Event('wt-termscheme'))
}

/** Schemele disponibile, inclusiv cea proprie (dacă există). */
export function allSchemes(): { id: string; name: string; theme: ITheme }[] {
  const custom = customTheme()
  return custom
    ? [...TERM_SCHEMES, { id: 'custom', name: CUSTOM_SCHEME_NAME, theme: custom }]
    : TERM_SCHEMES
}

export function currentTermScheme(): string {
  const v = localStorage.getItem('wt_term_scheme')
  return allSchemes().some((s) => s.id === v) ? v! : DEFAULT
}

export function setTermScheme(id: string): void {
  localStorage.setItem('wt_term_scheme', id)
  window.dispatchEvent(new Event('wt-termscheme'))
}

/** Schema unei sesiuni: override per-host (ex. „prod = roșiatic"), altfel cea globală. */
export function termTheme(id: string = currentTermScheme()): ITheme {
  return (allSchemes().find((s) => s.id === id) ?? TERM_SCHEMES[0]).theme
}

export function hostScheme(hostId: number | undefined): string {
  if (hostId == null) return currentTermScheme()
  try {
    const map = JSON.parse(localStorage.getItem('wt_host_schemes') || '{}')
    const id = map[String(hostId)]
    return id && allSchemes().some((s) => s.id === id) ? id : currentTermScheme()
  } catch {
    return currentTermScheme()
  }
}

/** Schema setată EXPLICIT pe host (null = urmează globala) — pentru UI-ul de selecție. */
export function hostSchemeRaw(hostId: number): string | null {
  try {
    const map = JSON.parse(localStorage.getItem('wt_host_schemes') || '{}')
    return map[String(hostId)] ?? null
  } catch {
    return null
  }
}

export function setHostScheme(hostId: number, id: string | null): void {
  let map: Record<string, string> = {}
  try { map = JSON.parse(localStorage.getItem('wt_host_schemes') || '{}') } catch { /* reset */ }
  if (id) map[String(hostId)] = id
  else delete map[String(hostId)]
  localStorage.setItem('wt_host_schemes', JSON.stringify(map))
  window.dispatchEvent(new Event('wt-termscheme'))
}

// ── import: iTerm2 (.itermcolors, plist XML) și VS Code (JSON cu terminal.ansi*) ──

const ITERM_MAP: Record<string, ColorKey> = {
  'Background Color': 'background', 'Foreground Color': 'foreground',
  'Cursor Color': 'cursor', 'Selection Color': 'selectionBackground',
  'Ansi 0 Color': 'black', 'Ansi 1 Color': 'red', 'Ansi 2 Color': 'green',
  'Ansi 3 Color': 'yellow', 'Ansi 4 Color': 'blue', 'Ansi 5 Color': 'magenta',
  'Ansi 6 Color': 'cyan', 'Ansi 7 Color': 'white',
  'Ansi 8 Color': 'brightBlack', 'Ansi 9 Color': 'brightRed',
  'Ansi 10 Color': 'brightGreen', 'Ansi 11 Color': 'brightYellow',
  'Ansi 12 Color': 'brightBlue', 'Ansi 13 Color': 'brightMagenta',
  'Ansi 14 Color': 'brightCyan', 'Ansi 15 Color': 'brightWhite',
}

const VSCODE_MAP: Record<string, ColorKey> = {
  'terminal.background': 'background', 'terminal.foreground': 'foreground',
  'terminalCursor.foreground': 'cursor', 'terminal.selectionBackground': 'selectionBackground',
  'terminal.ansiBlack': 'black', 'terminal.ansiRed': 'red', 'terminal.ansiGreen': 'green',
  'terminal.ansiYellow': 'yellow', 'terminal.ansiBlue': 'blue', 'terminal.ansiMagenta': 'magenta',
  'terminal.ansiCyan': 'cyan', 'terminal.ansiWhite': 'white',
  'terminal.ansiBrightBlack': 'brightBlack', 'terminal.ansiBrightRed': 'brightRed',
  'terminal.ansiBrightGreen': 'brightGreen', 'terminal.ansiBrightYellow': 'brightYellow',
  'terminal.ansiBrightBlue': 'brightBlue', 'terminal.ansiBrightMagenta': 'brightMagenta',
  'terminal.ansiBrightCyan': 'brightCyan', 'terminal.ansiBrightWhite': 'brightWhite',
}

const hex2 = (v: number) => Math.max(0, Math.min(255, Math.round(v * 255))).toString(16).padStart(2, '0')

/** Parsează un fișier de temă (iTerm2 sau VS Code) → ITheme parțial.
    Aruncă Error cu mesaj în română dacă nu recunoaște formatul. */
export function parseThemeFile(name: string, text: string): ITheme {
  const out: Record<string, string> = {}

  if (name.toLowerCase().endsWith('.itermcolors') || text.includes('<plist')) {
    const doc = new DOMParser().parseFromString(text, 'application/xml')
    if (doc.querySelector('parsererror')) throw new Error('invalid .itermcolors file (broken XML)')
    const dict = doc.querySelector('plist > dict')
    if (!dict) throw new Error('invalid .itermcolors file (missing dict)')
    const kids = [...dict.children]
    for (let i = 0; i < kids.length - 1; i++) {
      if (kids[i].tagName !== 'key') continue
      const target = ITERM_MAP[kids[i].textContent?.trim() ?? '']
      const val = kids[i + 1]
      if (!target || val.tagName !== 'dict') continue
      const comp: Record<string, number> = {}
      const sub = [...val.children]
      for (let j = 0; j < sub.length - 1; j++) {
        if (sub[j].tagName === 'key') comp[sub[j].textContent!.trim()] = Number(sub[j + 1].textContent)
      }
      const r = comp['Red Component'], g = comp['Green Component'], b = comp['Blue Component']
      if ([r, g, b].every((x) => typeof x === 'number' && !Number.isNaN(x))) {
        out[target] = `#${hex2(r)}${hex2(g)}${hex2(b)}`
      }
    }
  } else {
    // VS Code: fie tema completă ({"colors": {...}}), fie doar obiectul de culori.
    // Temele VS Code au adesea comentarii // și virgule finale — le tolerăm.
    const cleaned = text.replace(/\/\/.*$/gm, '').replace(/,\s*([}\]])/g, '$1')
    let json: Record<string, unknown>
    try {
      json = JSON.parse(cleaned)
    } catch {
      throw new Error('unrecognised format — expected .itermcolors or a VS Code theme (JSON)')
    }
    const colors = (json.colors ?? json) as Record<string, string>
    for (const [k, target] of Object.entries(VSCODE_MAP)) {
      const v = colors[k]
      if (typeof v === 'string' && /^#[0-9a-f]{6,8}$/i.test(v)) out[target] = v.slice(0, 7)
    }
  }

  const got = Object.keys(out).length
  if (got < 8) throw new Error(`only found ${got} colours — this does not look like a terminal theme`)
  // completăm ce lipsește din schema implicită, ca terminalul să fie mereu valid
  const base = TERM_SCHEMES[0].theme
  const theme: ITheme = { ...base, ...out }
  theme.cursorAccent = theme.background
  if (!out.selectionBackground) theme.selectionBackground = base.selectionBackground
  return theme
}
