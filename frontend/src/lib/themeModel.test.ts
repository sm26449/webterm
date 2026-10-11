import { describe, expect, it } from 'vitest'
import {
  DEFAULT_PREF, FAMILIES, isLight, parseThemePref, resolveVariant, serializeThemePref,
  toggledPref, VARIANTS, variantName, type ThemeFamily, type ThemeMode, type ThemeVariant,
} from './themeModel'

const css = (import.meta.glob('../index.css', { query: '?raw', import: 'default', eager: true }) as Record<string, string>)['../index.css']

describe('migrarea `wt_theme` (valorile ≤ 3.6.3 arată EXACT la fel)', () => {
  it('dark → Midnight, macos → Aurora, auto → WebTerm după sistem', () => {
    expect(parseThemePref('dark')).toEqual({ family: 'webterm', mode: 'dark' })
    expect(parseThemePref('macos')).toEqual({ family: 'webterm', mode: 'light' })
    expect(parseThemePref('auto')).toEqual({ family: 'webterm', mode: 'auto' })
    expect(resolveVariant(parseThemePref('dark'), true)).toBe('dark')
    expect(resolveVariant(parseThemePref('macos'), false)).toBe('macos')
    expect(resolveVariant(parseThemePref('auto'), true)).toBe('macos')
    expect(resolveVariant(parseThemePref('auto'), false)).toBe('dark')
  })

  it('lipsă / necunoscut / stricat → default (Midnight), fără excepţii', () => {
    for (const raw of [null, undefined, '', 'light', 'Dark', 'aurora', 'kde:dark', 'mac:sepia', 'mac', ':dark',
      'mac:dark:x', '{"family":"mac"}', ' '.repeat(3)]) {
      expect(parseThemePref(raw)).toEqual(DEFAULT_PREF)
    }
    expect(resolveVariant(DEFAULT_PREF, true)).toBe('dark')
  })

  it('familiile noi: `<familie>:<mod>`, dus-întors', () => {
    const fams: ThemeFamily[] = ['webterm', 'mac', 'win', 'gnome']
    const modes: ThemeMode[] = ['light', 'dark', 'auto']
    for (const family of fams) for (const mode of modes) {
      expect(parseThemePref(serializeThemePref({ family, mode }))).toEqual({ family, mode })
    }
    expect(parseThemePref(' win:dark ')).toEqual({ family: 'win', mode: 'dark' })
  })

  it('WebTerm se scrie în formatul vechi (un downgrade la 3.6.3 citeşte aceeaşi temă)', () => {
    expect(serializeThemePref({ family: 'webterm', mode: 'dark' })).toBe('dark')
    expect(serializeThemePref({ family: 'webterm', mode: 'light' })).toBe('macos')
    expect(serializeThemePref({ family: 'webterm', mode: 'auto' })).toBe('auto')
    expect(serializeThemePref({ family: 'gnome', mode: 'light' })).toBe('gnome:light')
  })
})

describe('variante', () => {
  it('auto urmează sistemul ÎN familia aleasă', () => {
    expect(resolveVariant({ family: 'mac', mode: 'auto' }, true)).toBe('mac-light')
    expect(resolveVariant({ family: 'mac', mode: 'auto' }, false)).toBe('mac-dark')
    expect(resolveVariant({ family: 'win', mode: 'light' }, false)).toBe('win-light')
    expect(resolveVariant({ family: 'gnome', mode: 'dark' }, true)).toBe('gnome-dark')
  })

  it('isLight: toate variantele deschise (nu doar `macos`)', () => {
    const light = (Object.keys(VARIANTS) as ThemeVariant[]).filter(isLight).sort()
    expect(light).toEqual(['gnome-light', 'mac-light', 'macos', 'win-light'])
    for (const f of FAMILIES) {
      expect(isLight(f.light)).toBe(true)
      expect(isLight(f.dark)).toBe(false)
      expect(VARIANTS[f.light].family).toBe(f.id)
      expect(VARIANTS[f.dark].family).toBe(f.id)
    }
  })

  it('comutarea din paletă rămâne în familie', () => {
    expect(toggledPref({ family: 'win', mode: 'auto' }, 'win-dark')).toEqual({ family: 'win', mode: 'light' })
    expect(toggledPref({ family: 'webterm', mode: 'dark' }, 'dark')).toEqual({ family: 'webterm', mode: 'light' })
  })

  it('nume: Midnight/Aurora rămân nume proprii', () => {
    const t = (k: string) => k
    expect(variantName('dark', t)).toBe('Midnight')
    expect(variantName('macos', t)).toBe('Aurora')
    expect(variantName('gnome-dark', t)).toBe('theme.family.gnome · theme.mode.dark')
  })

  it('theme-color PWA: un hex valid pentru fiecare variantă; Midnight/Aurora neschimbate', () => {
    for (const v of Object.values(VARIANTS)) expect(v.themeColor).toMatch(/^#[0-9a-f]{6}$/)
    expect(VARIANTS.dark.themeColor).toBe('#0b0e14')
    expect(VARIANTS.macos.themeColor).toBe('#edf0f7')
  })
})

describe('index.css are tokenii fiecărei variante şi familii', () => {
  // setul complet de tokeni pe care îl defineşte o temă; un bloc incomplet ar moşteni în tăcere
  // valorile Aurora (blocul `:root`) — text închis pe fundal închis într-o variantă dark
  const TOKENS = ['ink-950', 'ink-900', 'ink-800', 'ink-700', 'ink-600', 'tx-100', 'tx-200', 'tx-300', 'tx-400',
    'tx-500', 'tx-600', 'link', 'focus', 'field-border', 'ok', 'warn', 'danger', 'info', 'accent', 'viz-ok',
    'viz-warn', 'viz-danger', 'glass-bg', 'glass-hairline', 'glass-shadow', 'window-shadow', 'app-gradient',
    'font-ui', 'scrollbar']
  const block = (selector: string) => {
    const i = css.indexOf(selector)
    if (i < 0) return ''
    return css.slice(css.indexOf('{', i), css.indexOf('\n}', i))
  }
  for (const v of Object.keys(VARIANTS) as ThemeVariant[]) {
    it(`varianta ${v}`, () => {
      const b = block(`:root[data-theme='${v}'] {`) || block(`:root[data-theme='${v}'],`)
      expect(b, `lipseşte blocul :root[data-theme='${v}']`).not.toBe('')
      const missing = TOKENS.filter((tk) => !new RegExp(`--${tk}:`).test(b))
      expect(missing).toEqual([])
      if (v !== 'dark' && v !== 'macos') {
        // familiile noi îşi restaurează tokenii şi pe Dashboard/pagina hostului (din workspace)
        expect(css).toContain(`:root[data-theme='${v}'] .wt-workspace .wt-canvas`)
      }
    })
  }
  it('fiecare familie nouă îşi defineşte accentul, razele şi cromul', () => {
    for (const f of FAMILIES.filter((x) => x.id !== 'webterm')) {
      const b = block(`:root[data-family='${f.id}'] {`)
      for (const tk of ['term-bg', 'chrome-bg', 'chrome-tx-dim', 'ws-800', 'command-bg', 'r-md', 'r-xl', 'r-2xl',
        'sky-200', 'sky-500', 'sky-600', 'sky-950']) {
        expect(b, `${f.id}: --${tk}`).toMatch(new RegExp(`--${tk}:`))
      }
    }
  })
  it('fonturi: doar stive de sistem — nimic încărcat de la distanţă (@font-face/url)', () => {
    expect(css).not.toMatch(/@font-face/)
    expect(css).not.toMatch(/font-ui:[^;]*url\(/)
  })
})
