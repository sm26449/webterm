/* Schemele de terminal ale mărcii (3.7.1): EverShell (fundal Petrol) şi Classic Dark (fostul „EverShell
   Dark", id `webterm-dark` neschimbat). Contrastul ANSI e verificat pe fundalul fiecărei scheme. */
import { describe, expect, it } from 'vitest'
import { FAMILY_SCHEME, schemeName, TERM_SCHEMES } from './termtheme'
import { FAMILIES } from './themeModel'

const hex = (h: string) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16))
const lin = (c: number) => { const x = c / 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4 }
const lum = (h: string) => { const [r, g, b] = hex(h).map(lin); return 0.2126 * r + 0.7152 * g + 0.0722 * b }
const ratio = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05) }

const scheme = (id: string) => TERM_SCHEMES.find((s) => s.id === id)!

describe('schemele mărcii', () => {
  it('EverShell: fundal Petrol, text Cream, cursor Phosphor', () => {
    const t = scheme('evershell-dark').theme
    expect(t.background).toBe('#0d3640')
    expect(t.foreground).toBe('#f6f4ee')
    expect(t.cursor).toBe('#f2a33a')
    expect(t.cursorAccent).toBe('#0d3640')
  })

  it('EverShell: textul ≥ 7:1, culorile ANSI ≥ 4,5:1, brightBlack ≥ 3:1, cursorul ≥ 3:1 pe Petrol', () => {
    const t = scheme('evershell-dark').theme as Record<string, string>
    const bg = t.background
    const bad: string[] = []
    const need = (k: string, min: number) => { const r = ratio(t[k], bg); if (r + 1e-9 < min) bad.push(`${k} ${r.toFixed(2)} < ${min}`) }
    need('foreground', 7)
    for (const k of ['red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white',
      'brightRed', 'brightGreen', 'brightYellow', 'brightBlue', 'brightMagenta', 'brightCyan', 'brightWhite']) need(k, 4.5)
    need('brightBlack', 3)
    need('cursor', 3)
    // textul selectat pe fundalul selecţiei
    if (ratio(t.selectionForeground, t.selectionBackground) < 4.5) bad.push('selection')
    expect(bad).toEqual([])
  })

  it('Classic Dark păstrează id-ul webterm-dark (preferinţele salvate) şi se afişează tradus', () => {
    const c = scheme('webterm-dark')
    expect(c.theme.background).toBe('#0b0e14')
    const t = (k: string) => `T(${k})`
    expect(schemeName(c, t)).toBe('T(theme.scheme.classicDark)')
    expect(schemeName(scheme('evershell-dark'), t)).toBe('T(theme.scheme.evershell)')
    expect(schemeName(scheme('gruvbox-dark'), t)).toBe('Gruvbox Dark')
    expect(schemeName({ id: 'custom', name: 'custom' }, t)).toBe('T(settings.customSchemeName)')
  })

  it('fiecare familie are o schemă implicită; EverShell → evershell-dark, Classic → webterm-dark', () => {
    for (const f of FAMILIES) expect(TERM_SCHEMES.some((s) => s.id === FAMILY_SCHEME[f.id])).toBe(true)
    expect(FAMILY_SCHEME.evershell).toBe('evershell-dark')
    expect(FAMILY_SCHEME.webterm).toBe('webterm-dark')
  })
})
